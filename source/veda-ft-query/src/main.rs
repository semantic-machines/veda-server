extern crate version;

#[macro_use]
extern crate log;

use futures::executor::block_on;
use nng::options::{Options, RecvTimeout, SendTimeout};
use nng::{Error, Message, Protocol, Socket};
use serde_json::value::Value as JSONValue;
use std::process::exit;
use std::time::{Duration, Instant};
use std::{env, str, thread};
use v_common::ft_xapian::xapian_reader::XapianReader;
use v_common::init_module_log;
use v_common::module::common::load_onto;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{init_log, Module};
use v_common::module::veda_backend::Backend;
use v_common::onto::onto_index::OntoIndex;
use v_common::search::common::FTQuery;
use v_common::v_api::obj::*;

const TIMEOUT_INFO: u64 = 10;
const TIMEOUT_RECV: u64 = 30;
const TIMEOUT_SEND: u64 = 60;

fn main() {
    init_module_log!("FT_QUERY");
    let mut module_name = "ft-query".to_owned();

    let mut query_url = Module::get_property("ft_query_service_url").expect("param [search_query_url] not found in veda.properties");

    let args: Vec<String> = env::args().collect();
    for el in args.iter() {
        if el.starts_with("--bind") {
            let p: Vec<&str> = el.split('=').collect();
            query_url = p[1].to_owned().trim().to_owned();
            info!("Using bind argument: {}", query_url);
        } else if el.starts_with("--module-name") {
            let p: Vec<&str> = el.split('=').collect();
            module_name = p[1].to_owned().trim().to_owned();
            info!("Using module-name argument: {}", module_name);
        }
    }

    let module_info = ModuleInfo::new("./data", &module_name, true);
    if module_info.is_err() {
        error!("Failed to initialize module: {:?}", module_info.err());
        exit(0);
    }
    let mut module_info = module_info.unwrap();
    let mut count = 0;
    if let Err(e) = module_info.put_info(count, count) {
        error!("Failed to store module info: {:?}", e);
    }

    let mut backend = Backend::default();

    let mut w_sys_ticket = Err(-1);
    for attempt in 1..=5 {
        w_sys_ticket = backend.get_sys_ticket_id();
        if w_sys_ticket.is_ok() {
            info!("System ticket obtained on attempt {}", attempt);
            break;
        }
        
        error!("Failed to get system ticket, attempt {}/5", attempt);
        if attempt < 5 {
            info!("Waiting {} seconds before next attempt", attempt);
            thread::sleep(Duration::from_secs(attempt as u64));
        }
    }
    
    if w_sys_ticket.is_err() {
        error!("Failed to get system ticket after 5 attempts");
        exit(0);
    }
    
    let sys_ticket = w_sys_ticket.unwrap();
    let ticket = backend.get_ticket_from_db(&sys_ticket);
    if ticket.result != ResultCode::Ok {
        error!("Failed to load system ticket: {}", sys_ticket);
        exit(0);
    }
    let sys_user_uri = ticket.user_uri;

    if let Some(mut xr) = XapianReader::new("russian", &mut backend.storage) {
        let mut start = Instant::now();

        loop {
            info!("Initializing server socket");
            let server = Socket::new(Protocol::Rep0).unwrap();

            if let Err(e) = server.set_opt::<RecvTimeout>(Some(Duration::from_secs(TIMEOUT_RECV))) {
                error!("Failed to set receive timeout for {}: {}", query_url, e);
                return;
            }
            if let Err(e) = server.set_opt::<SendTimeout>(Some(Duration::from_secs(TIMEOUT_SEND))) {
                error!("Failed to set send timeout for {}: {}", query_url, e);
                return;
            }

            if let Err(e) = server.listen(&query_url) {
                error!("Failed to bind and listen on {}: {:?}", query_url, e);
                return;
            }

            info!("Server listening on {}", query_url);
            loop {
                if start.elapsed().as_secs() > TIMEOUT_INFO {
                    if let Err(e) = module_info.put_info(count, count) {
                        error!("Failed to update module statistics: {:?}", e);
                    }
                    start = Instant::now();
                }

                match server.recv() {
                    Ok(recv_msg) => {
                        count += 1;

                        let out_msg = if let Ok(s) = str::from_utf8(recv_msg.as_slice()) {
                            if s.len() > 2 {
                                req_prepare(&mut backend, s, &mut xr, &sys_user_uri)
                            } else {
                                Message::from("[]".as_bytes())
                            }
                        } else {
                            Message::from("[]".as_bytes())
                        };

                        if let Err(e) = server.send(out_msg) {
                            error!("Failed to send response: {:?}", e);
                            break;
                        }
                    },
                    Err(e) => match e {
                        Error::TimedOut => {
                            info!("Receive timeout, total processed requests: {}", count);
                            break;
                        },
                        _ => {
                            error!("Failed to receive request: {:?}", e);
                            break;
                        },
                    },
                }
            }
            server.close();
        }
    } else {
        error!("Failed to initialize full-text query engine");
    }
}

const TICKET: usize = 0;
const QUERY: usize = 1;
const SORT: usize = 2;
const DATABASES: usize = 3;
//const REOPEN: usize = 4;
const TOP: usize = 5;
const LIMIT: usize = 6;
const FROM: usize = 7;

fn req_prepare(backend: &mut Backend, s: &str, xr: &mut XapianReader, sys_user_uri: &str) -> Message {
    let v: JSONValue = if let Ok(v) = serde_json::from_slice(s.as_bytes()) {
        v
    } else {
        JSONValue::Null
    };

    if let Some(a) = v.as_array() {
        let ticket_id = a.get(TICKET).unwrap().as_str().unwrap_or_default();
        let mut query = a.get(QUERY).unwrap().as_str().unwrap_or_default().to_string();

        if !(query.contains("==") || query.contains("&&") || query.contains("||")) {
            query = "'*' == '".to_owned() + &query + "'";
        }

        query = query.replace('\n', " ");

        let sort = a.get(SORT).unwrap().as_str().unwrap_or_default().to_string();
        let databases = a.get(DATABASES).unwrap().as_str().unwrap_or_default().to_string();

        let top = a.get(TOP).unwrap().as_i64().unwrap_or_default() as i32;
        let limit = a.get(LIMIT).unwrap().as_i64().unwrap_or_default() as i32;
        let from = a.get(FROM).unwrap().as_i64().unwrap_or_default() as i32;

        let mut user_uri = "cfg:Guest".to_owned();
        if !ticket_id.is_empty() {
            if ticket_id.starts_with("UU=") {
                user_uri = ticket_id.trim_start_matches("UU=").to_owned();
            } else {
                let ticket = backend.get_ticket_from_db(ticket_id);
                if ticket.result == ResultCode::Ok {
                    user_uri = ticket.user_uri;
                }
            }
        }

        let mut ctx = vec![];
        fn add_out_element(id: &str, ctx: &mut Vec<String>) {
            ctx.push(id.to_owned());
        }
        
        let need_authorize = if sys_user_uri == user_uri {
            OptAuthorize::NO
        } else {
            OptAuthorize::YES
        };
        
        let request = FTQuery {
            ticket: "".to_string(),
            user: user_uri,
            query,
            sort,
            databases,
            reopen: false,
            top,
            limit,
            from,
        };
        
        info!(
            "{:?}, ticket = {}, user = {}, query = {}, sort = {}, db = {}, top = {}, limit = {}, from = {}",
            need_authorize, ticket_id, request.user, request.query, request.sort, request.databases, request.top, request.limit, request.from
        );

        if let Some(t) = OntoIndex::get_modified() {
            if t > xr.onto_modified {
                load_onto(&mut backend.storage, &mut xr.onto);
                xr.onto_modified = t;
            }
        }
        if xr.index_schema.is_empty() {
            xr.load_index_schema(&mut backend.storage);
        }
        
        match block_on(xr.query_use_collect_fn(&request, add_out_element, need_authorize, &mut ctx)) {
            Ok(mut res) => {
                res.result = ctx;
                info!("count = {}, time: query = {}, authorize = {}, total = {}", res.count, res.query_time, res.authorize_time, res.total_time);
                if let Ok(s) = serde_json::to_string(&res) {
                    return Message::from(s.as_bytes());
                }
            },
            Err(e) => {
                error!("{:?}", e);
            },
        }
    }
    Message::from("[]".as_bytes())
}
