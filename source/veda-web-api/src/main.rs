extern crate version;
#[macro_use]
extern crate log;

mod auth;
mod common;
mod files;
mod get;
mod multifactor;
mod nlp_processing;
mod query;
mod update;
mod user_activity;
mod vql_query_client;
mod webdav;

extern crate serde_derive;
extern crate serde_json;

use crate::auth::{authenticate_get, authenticate_post, get_membership, get_rights, get_rights_origin, get_ticket_trusted, is_ticket_valid, logout};
use crate::common::{db_connector, NLPServerConfig, UserContextCache, VQLClient, VQLClientConnectType};
use crate::files::{load_file, save_file};
use crate::get::{get_individual, get_individuals, get_operation_state};
use crate::multifactor::{handle_post_request, MultifactorProps};
use crate::nlp_processing::{augment_text, recognize_audio};
use crate::query::{query_get, query_post, stored_query, QueryEndpoints};
use crate::update::{add_to_individual, put_individual, put_individuals, remove_from_individual, remove_individual, set_in_individual};
use crate::user_activity::user_activity_manager;
use crate::vql_query_client::VQLHttpClient;
use crate::webdav::{
    handle_webdav_get_2, handle_webdav_get_3, handle_webdav_head, handle_webdav_lock, handle_webdav_options_2, handle_webdav_options_3, handle_webdav_propfind_2,
    handle_webdav_propfind_3, handle_webdav_proppatch, handle_webdav_put, handle_webdav_unlock,
};
use actix_files::{Files, NamedFile};
use actix_web::http::Method;
use actix_web::middleware::normalize::TrailingSlash;
use actix_web::middleware::{Logger, NormalizePath};
use actix_web::rt::System;
use actix_web::{get, guard, head, middleware, web, App, HttpResponse, HttpServer};
use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::{select, FutureExt};
use git_version::git_version;
use ini::Ini;
use rusty_tarantool::tarantool::ClientConfig;
use serde_derive::Deserialize;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use url::Url;
use v_common::az_impl::az_lmdb::LmdbAzContext;
use v_common::ft_xapian::xapian_reader::XapianReader;
use v_common::module::module_impl::{init_log_with_params, Module};
use v_common::search::clickhouse_client::CHClient;
use v_common::search::common::PrefixesCache;
use v_common::search::ft_client::FTClient;
use v_common::search::sparql_client::SparqlClient;
use v_common::v_api::api_client::{AuthClient, MStorageClient};
use version::version;

#[head("/")]
async fn head() -> std::io::Result<HttpResponse> {
    Ok(HttpResponse::Ok().finish())
}

#[get("/ping")]
async fn ping() -> std::io::Result<HttpResponse> {
    return Ok(HttpResponse::Ok().content_type("text/plain").body("pong"));
}

#[derive(Deserialize)]
struct Info {
    app_name: String,
    data: Option<String>,
}

async fn apps_doc(info: web::Path<Info>) -> std::io::Result<NamedFile> {
    if let Some(v) = &info.data {
        if v == "manifest" {
            return NamedFile::open(format!("public/{}/{}", info.app_name, &info.data.clone().unwrap()).parse::<PathBuf>().unwrap());
        }
    }
    NamedFile::open("public/index.html".parse::<PathBuf>().unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_server=info,actix_web=info");
    let module_name = "WEB_API";
    init_log_with_params(module_name, None, true);
    info!("{} {} {}", module_name, version!(), git_version!());

    let mut tt_config = None;
    if let Some(p) = Module::get_property::<String>("db_connection") {
        if p.contains("tcp://") {
            match Url::parse(&p) {
                Ok(url) => {
                    let host = url.host_str().unwrap_or("127.0.0.1");
                    let port = url.port().unwrap_or(3309);
                    let user = url.username();
                    let pass = url.password().unwrap_or("123");
                    info!("Trying to connect to Tarantool, host: {host}, port: {port}, user: {user}");
                    tt_config = Some(ClientConfig::new(format!("{host}:{port}"), user, pass).set_timeout_time_ms(2000).set_reconnect_time_ms(2000));
                },
                Err(e) => {
                    error!("fail parse {p}, err={e}");
                    return Ok(());
                },
            }
        }
    }

    let mut port = "8080".to_owned();
    let mut ext_usr_http_port = None;
    let mut are_external_users = false;
    let mut use_direct_ft_query = false;
    let mut workers = num_cpus::get();

    let args: Vec<String> = env::args().collect();
    for el in &args {
        if el.starts_with("--http_port") {
            port = el.split('=').collect::<Vec<&str>>()[1].to_owned().trim().to_owned();
        }
        if el.starts_with("--use-direct-ft-query") {
            use_direct_ft_query = el.split('=').collect::<Vec<&str>>()[1].to_owned().trim() == "true";
        }
        if el.starts_with("--workers") {
            workers = el.split('=').collect::<Vec<&str>>()[1].to_owned().trim().to_owned().parse::<usize>().unwrap();
        }
        if el.starts_with("--ext_usr_http_port") {
            ext_usr_http_port = Some(el.split('=').collect::<Vec<&str>>()[1].to_owned().trim().to_owned());
        }
    }

    if let Some(p) = ext_usr_http_port {
        if p == port {
            are_external_users = true;
        }
    }

    let (tx, rx) = mpsc::channel(1000);
    let t_config = tt_config.clone();
    thread::spawn(move || {
        System::new("user_activity_manager").block_on(user_activity_manager(rx, t_config));
    });

    info!("LISTEN {port}");

    let mut server_future = HttpServer::new(move || {
        let mut mfp = MultifactorProps::default();
        if let Ok(conf) = Ini::load_from_file("multifactor.ini") {
            let section = conf.section(Some("settings")).expect("Section 'settings' not found");

            mfp = MultifactorProps {
                api_key: section.get("api_key").expect("api_key not found").to_string(),
                api_secret: section.get("api_secret").expect("api_secret not found").to_string(),
                url: section.get("url").expect("url not found").to_string(),
                sign_url: section.get("sign_url").expect("sign_url not found").to_string(),
                audience: section.get("audience").expect("audience not found").to_string(),
                callback_scheme: section.get("callback_scheme").map(|s| s.to_string()),
            };
        }

        let db = db_connector(&tt_config);

        let mut ch = CHClient::new(Module::get_property("query_search_db").unwrap_or_default());
        ch.connect();

        let mut ft_client = VQLClient::default();

        if use_direct_ft_query {
            info!("use direct-ft-query");
            ft_client.xr = Some(XapianReader::new_without_init("russian").expect("fail init direct-ft-query"));
            ft_client.query_type = VQLClientConnectType::Direct;
        }

        if !use_direct_ft_query {
            info!("use ft-query-service");

            if let Ok(url) = Module::get_property::<String>("ft_query_service_url").unwrap_or_default().parse::<Url>() {
                if url.scheme() == "tcp" {
                    ft_client.nng_client = Some(FTClient::new(url.to_string()));
                    ft_client.query_type = VQLClientConnectType::Nng;
                } else {
                    ft_client.http_client = Some(VQLHttpClient::new(url.as_str()));
                    ft_client.query_type = VQLClientConnectType::Http;
                }
            }
        }

        let nlp_server_config = NLPServerConfig {
            whisper_server_url: Module::get_property("whisper_server_url").unwrap_or_else(|| "http://localhost:8086".to_string()),
            llama_server_url: Module::get_property("llama_server_url").unwrap_or_else(|| "http://localhost:8087".to_string()),
        };

        let check_ticket_ip = Module::get_property::<String>("check_ticket_ip").unwrap_or_default().parse::<bool>().unwrap_or(true);
        info!("PARAM [check_ticket_ip] = {check_ticket_ip}");
        let (ticket_cache_read, ticket_cache_write) = evmap::new();
        let (f2s_prefixes_cache_read, f2s_prefixes_cache_write) = evmap::new();
        let (s2f_prefixes_cache_read, s2f_prefixes_cache_write) = evmap::new();

        let json_cfg = web::JsonConfig::default().limit(5 * 1024 * 1024);

        let m_propfind = Method::from_bytes(b"PROPFIND").unwrap();
        let m_proppatch = Method::from_bytes(b"PROPPATCH").unwrap();
        let m_options = Method::from_bytes(b"OPTIONS").unwrap();
        let m_lock = Method::from_bytes(b"LOCK").unwrap();
        let m_unlock = Method::from_bytes(b"UNLOCK").unwrap();

        App::new()
            .wrap(Logger::default())
            .wrap(middleware::Compress::default())
            .wrap(
                middleware::DefaultHeaders::new()
                    .header("X-XSS-Protection", "1; mode=block")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "sameorigin")
                    .header("Pragma", "no-cache")
                    .header("Cache-Control", "no-cache, no-store, must-revalidate, private"), //.header("Content-Security-Policy", "default-src 'self'; frame-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; connect-src 'self' ws: wss:;"),
            )
            .app_data(json_cfg)
            .data(mfp)
            .app_data(web::Data::new(nlp_server_config))
            .data(Arc::new(Mutex::new(tx.clone())))
            .data(UserContextCache {
                read_tickets: ticket_cache_read,
                write_tickets: Arc::new(Mutex::new(ticket_cache_write)),
                check_ticket_ip,
                are_external_users,
            })
            .data(PrefixesCache {
                full2short_r: f2s_prefixes_cache_read,
                full2short_w: Arc::new(Mutex::new(f2s_prefixes_cache_write)),
                short2full_r: s2f_prefixes_cache_read,
                short2full_w: Arc::new(Mutex::new(s2f_prefixes_cache_write)),
            })
            .data(db)
            .data(QueryEndpoints {
                vql_client: Mutex::new(ft_client),
                ch_client: Mutex::new(ch),
                sparql_client: Mutex::new(SparqlClient::default()),
            })
            .data(Mutex::new(LmdbAzContext::new(1000)))
            .data(Mutex::new(AuthClient::new(Module::get_property("auth_url").unwrap_or_default())))
            .data(Mutex::new(MStorageClient::new(Module::get_property("main_module_url").unwrap_or_default())))
            //
            .service(get_ticket_trusted)
            .service(is_ticket_valid)
            .service(get_rights)
            .service(get_rights_origin)
            .service(get_membership)
            //
            .service(get_individual)
            .service(get_individuals)
            .service(get_operation_state)
            .service(remove_individual)
            .service(remove_from_individual)
            .service(put_individual)
            .service(put_individuals)
            .service(add_to_individual)
            .service(set_in_individual)
            .service(load_file)
            .service(ping)
            .service(head)
            .service(logout)
            .service(web::resource("/apps/{app_name}").route(web::get().to(apps_doc)))
            .service(web::resource("/files").route(web::post().to(save_file)))
            .service(web::resource("/query").route(web::get().to(query_get)).route(web::post().to(query_post)))
            .service(web::resource("/stored_query").route(web::post().to(stored_query)))
            .service(web::resource("/authenticate").route(web::get().to(authenticate_get)).route(web::post().to(authenticate_post)))
            .service(web::resource("/recognize_audio").route(web::post().to(recognize_audio)))
            .service(web::resource("/augment_text").route(web::post().to(augment_text)))
            .service(
                web::scope("/webdav")
                    // Применяем NormalizePath middleware
                    .wrap(NormalizePath::new(TrailingSlash::Trim))
                    .service(
                        web::resource("/{ticket_id}/{file_id}/{file_name}")
                            .route(web::put().to(handle_webdav_put))
                            .route(web::get().to(handle_webdav_get_3))
                            .route(web::head().to(handle_webdav_head))
                            .route(web::route().method(m_propfind.clone()).to(handle_webdav_propfind_3))
                            .route(web::route().method(m_proppatch.clone()).to(handle_webdav_proppatch))
                            .route(web::route().method(m_lock.clone()).to(handle_webdav_lock))
                            .route(web::route().method(m_unlock.clone()).to(handle_webdav_unlock))
                            .route(web::route().method(m_options.clone()).to(handle_webdav_options_3)),
                    )
                    .service(
                        web::resource("/{ticket_id}/{file_id}")
                            .route(web::get().to(handle_webdav_get_2))
                            .route(web::route().method(m_options.clone()).to(handle_webdav_options_2))
                            .route(web::route().method(m_propfind.clone()).to(handle_webdav_propfind_2)),
                    ),
            )
            .service(web::resource("/").guard(guard::Post()).route(web::post().to(handle_post_request)))
            .service(Files::new("/", "./public").redirect_to_slash_directory().index_file("index.html"))
    })
    .bind(format!("0.0.0.0:{port}"))?
    .workers(workers)
    .run()
    .fuse();

    select! {
        _r = server_future => println!("Server is stopped!"),
    };
    Ok(())
}
