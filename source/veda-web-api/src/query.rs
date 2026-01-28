#![allow(clippy::too_many_arguments)]

use crate::common::{get_ticket, QueryRequest, StoredQueryRequest, UserContextCache, UserId, UserInfo, VQLClientConnectType};
use crate::common::{get_user_info, log};
use crate::VQLClient;
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use serde_json::value::Value as JSONValue;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use v_authorization_impl::AzContext;
use v_common::module::common::c_load_onto;
use v_common::search::clickhouse_client::CHClient;
use v_common::search::common::{load_prefixes, AuthorizationLevel, FTQuery, PrefixesCache, QueryResult, ResultFormat};
use v_common::search::sparql_client::SparqlClient;
use v_common::search::sparql_params::prepare_sparql_params;
use v_common::search::sql_params::parse_sql_query_arguments;
use v_common::storage::async_storage::{get_individual_from_db, AStorage};
use v_common::v_api::common_type::{OptAuthorize, ResultCode};
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::json2individual::parse_json_to_individual;
use v_individual_model::onto::onto_index::OntoIndex;

pub(crate) struct QueryEndpoints {
    pub vql_client: Mutex<VQLClient>,
    pub ch_client: Mutex<CHClient>,
    pub sparql_client: Mutex<SparqlClient>,
}

pub(crate) async fn query_post(
    req: HttpRequest,
    params: web::Query<QueryRequest>,
    data: web::Json<QueryRequest>,
    query_endpoints: web::Data<QueryEndpoints>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    prefix_cache: web::Data<PrefixesCache>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let uinf = match get_user_info(get_ticket(&req, &params.ticket), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };
    match query(uinf, &data, query_endpoints, db, az, prefix_cache).await {
        Ok(res) => Ok(res),
        Err(_) => Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)),
    }
}

pub(crate) async fn query_get(
    data: web::Query<QueryRequest>,
    query_endpoints: web::Data<QueryEndpoints>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    prefix_cache: web::Data<PrefixesCache>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let uinf = match get_user_info(data.ticket.clone(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };
    match query(uinf, &data, query_endpoints, db, az, prefix_cache).await {
        Ok(res) => Ok(res),
        Err(_) => Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)),
    }
}

async fn query(
    uinf: UserInfo,
    data: &QueryRequest,
    query_endpoints: web::Data<QueryEndpoints>,
    db: web::Data<AStorage>,
    _az: web::Data<Mutex<AzContext>>,
    prefix_cache: web::Data<PrefixesCache>,
) -> io::Result<HttpResponse> {
    if uinf.ticket.id.is_empty() {
        return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::NotAuthorized as u16).unwrap()));
    }
    direct_query_impl(uinf, data, query_endpoints, db, &prefix_cache).await
}

pub(crate) async fn stored_query(
    data_0: web::Query<StoredQueryRequest>,
    data: web::Json<JSONValue>,
    query_endpoints: web::Data<QueryEndpoints>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    prefix_cache: web::Data<PrefixesCache>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let uinf = match get_user_info(data_0.ticket.clone(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };
    if uinf.ticket.id.is_empty() {
        return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::NotAuthorized as u16).unwrap()));
    }
    stored_query_impl(uinf, data, query_endpoints, db, az, prefix_cache).await
}

async fn stored_query_impl(
    uinf: UserInfo,
    data: web::Json<JSONValue>,
    query_endpoints: web::Data<QueryEndpoints>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    prefix_cache: web::Data<PrefixesCache>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();
    let mut params = Individual::default();

    if parse_json_to_individual(&data, &mut params) {
        let stored_query_id = if let Some(v) = params.get_first_literal("v-s:storedQuery") {
            v
        } else {
            return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::BadRequest as u16).unwrap()));
        };

        let (mut stored_query_indv, res_code) = get_individual_from_db(&stored_query_id, &uinf.ticket.user_uri, &db, Some(&az)).await?;
        if res_code != ResultCode::Ok {
            return Ok(HttpResponse::new(StatusCode::from_u16(res_code as u16).unwrap()));
        }

        let authorization_level = AuthorizationLevel::from_str(&stored_query_indv.get_first_literal("v-s:authorizationLevel").unwrap_or("query".to_owned()))
            .unwrap_or(AuthorizationLevel::Query);

        if let (Some(source), Some(mut query_string)) = (stored_query_indv.get_first_literal("v-s:source"), stored_query_indv.get_first_literal("v-s:queryString")) {
            // replace {paramN} to '{paramN}'
            for pr in &params.get_predicates() {
                if pr == "rdf:type" || pr == "v-s:storedQuery" || pr == "v-s:resultFormat" {
                    continue;
                }

                let pattern = format!("{{{}}}", pr);
                let replacement = format!("'{{{}}}'", pr);

                let mut new_query = String::new();
                let mut last_end = 0;
                for mat in query_string.match_indices(&pattern) {
                    let (start, end) = (mat.0, mat.0 + mat.1.len());
                    if !((start > 0 && &query_string[start - 1..start] == "'") && (end < query_string.len() && &query_string[end..end + 1] == "'")) {
                        new_query.push_str(&query_string[last_end..start]);
                        new_query.push_str(&replacement);
                        last_end = end;
                    }
                }
                new_query.push_str(&query_string[last_end..]);
                query_string = new_query;
            }

            let result_format = ResultFormat::from_str(&if let Some(p) = params.get_first_literal("v-s:resultFormat") {
                p
            } else {
                stored_query_indv.get_first_literal("v-s:resultFormat").unwrap_or("full".to_owned())
            })
            .unwrap_or(ResultFormat::Full);

            match source.as_str() {
                "clickhouse" => {
                    if let Ok(sql) = parse_sql_query_arguments(&query_string, &mut params, &source) {
                        //info!("{sql}");
                        let res = query_endpoints.ch_client.lock().await.query_select_async(&uinf.ticket.user_uri, &sql, result_format, authorization_level, &az).await?;
                        log(Some(&start_time), &uinf, "stored_query", &stored_query_id, ResultCode::Ok);
                        return Ok(HttpResponse::Ok().json(res));
                    }
                },
                "oxigraph" => {
                    if prefix_cache.full2short_r.is_empty() {
                        load_prefixes(&db, &prefix_cache).await;
                    }

                    if let Ok(sparql) = prepare_sparql_params(&query_string, &mut params, &prefix_cache) {
                        info!("{sparql}");
                        let res = query_endpoints
                            .sparql_client
                            .lock()
                            .await
                            .query_select(&uinf.ticket.user_uri, sparql, result_format, authorization_level, &az, &prefix_cache)
                            .await?;
                        log(Some(&start_time), &uinf, "stored_query", &stored_query_id, ResultCode::Ok);
                        return Ok(HttpResponse::Ok().json(res));
                    }
                    return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::NotImplemented as u16).unwrap()));
                },
                _ => {
                    return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::NotImplemented as u16).unwrap()));
                },
            }
        }
    }

    log(Some(&start_time), &uinf, "stored_query", &format!("{data:?}"), ResultCode::BadRequest);
    Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::BadRequest as u16).unwrap()))
}

fn add_out_element(id: &str, ctx: &mut Vec<String>) {
    ctx.push(id.to_owned());
}

async fn direct_query_impl(
    uinf: UserInfo,
    data: &QueryRequest,
    query_endpoints: web::Data<QueryEndpoints>,
    db: web::Data<AStorage>,
    prefix_cache: &PrefixesCache,
) -> io::Result<HttpResponse> {
    let mut res = QueryResult::default();
    let ticket_id = uinf.ticket.id.clone();

    if data.sparql.is_some() {
        if prefix_cache.full2short_r.is_empty() {
            load_prefixes(&db, &prefix_cache).await;
        }
        res = query_endpoints.sparql_client.lock().await.query_select_ids(&uinf.ticket.user_uri, data.sparql.clone().unwrap(), prefix_cache).await;
    } else if data.sql.is_some() {
        let mut req = FTQuery {
            ticket: String::new(),
            user: uinf.ticket.user_uri.clone(),
            query: data.sql.clone().unwrap_or_default(),
            sort: String::new(),
            databases: String::new(),
            reopen: false,
            top: data.top.unwrap_or_default(),
            limit: data.limit.unwrap_or_default(),
            from: data.from.unwrap_or_default(),
        };
        log(None, &uinf, "query", &format!("{}, top = {}, limit = {}, from = {}", &req.query, req.top, req.limit, req.from), ResultCode::Ok);

        match parse_sql_query_arguments(&req.query.replace('`', "\""), &mut Individual::default(), "clickhouse") {
            Ok(sql) => {
                //info!("{sql}");
                req.query = sql;
                res = query_endpoints.ch_client.lock().await.select_async(req, OptAuthorize::YES).await?;
            },
            Err(e) => {
                error!("{:?}", e);
                return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR));
            },
        }
    } else {
        let mut req = FTQuery {
            ticket: ticket_id.clone(),
            user: data.user.clone().unwrap_or_default(),
            query: data.query.clone().unwrap_or_default(),
            sort: data.sort.clone().unwrap_or_default(),
            databases: data.databases.clone().unwrap_or_default(),
            reopen: data.reopen.unwrap_or_default(),
            top: data.top.unwrap_or_default(),
            limit: data.limit.unwrap_or_default(),
            from: data.from.unwrap_or_default(),
        };

        let mut res_out_list = vec![];

        req.user = uinf.ticket.user_uri.clone();

        if !(req.query.contains("==") || req.query.contains("&&") || req.query.contains("||")) {
            req.query = "'*' == '".to_owned() + &req.query + "'";
        }

        req.query = req.query.replace('\n', " ");

        log(
            None,
            &uinf,
            "query",
            &format!("{}, sort = {}, db = {}, top = {}, limit = {}, from = {}", &req.query, req.sort, req.databases, req.top, req.limit, req.from),
            ResultCode::Ok,
        );

        let mut vc = query_endpoints.vql_client.lock().await;

        match vc.query_type {
            VQLClientConnectType::Direct => {
                if let Some(xr) = vc.xr.as_mut() {
                    if let Some(t) = OntoIndex::get_modified() {
                        if t > xr.onto_modified {
                            c_load_onto(&db, &mut xr.onto).await;
                            xr.onto_modified = t;
                        }
                    }
                    if xr.index_schema.is_empty() {
                        xr.c_load_index_schema(&db).await;
                    }

                    res = xr.query_use_collect_fn(&req, add_out_element, OptAuthorize::YES, &mut res_out_list).await.unwrap();
                    res.result = res_out_list;
                }
            },
            VQLClientConnectType::Http => {
                if let Some(n) = vc.http_client.as_mut() {
                    res = n.query(&ticket_id, &uinf.addr, req).await;
                }
            },
            VQLClientConnectType::Nng => {
                if let Some(n) = vc.nng_client.as_mut() {
                    res = n.query(req);
                }
            },
            VQLClientConnectType::Unknown => {},
        }
    }

    if res.result_code == ResultCode::Ok {
        log(
            None,
            &uinf,
            "",
            &format!("result: count = {}, time(ms): query = {}, authorize = {}, total = {}", res.count, res.query_time, res.authorize_time, res.total_time),
            ResultCode::Ok,
        );

        Ok(HttpResponse::Ok().json(res))
    } else {
        log(None, &uinf, "", "", res.result_code);

        Ok(HttpResponse::new(StatusCode::from_u16(res.result_code as u16).unwrap()))
    }
}
