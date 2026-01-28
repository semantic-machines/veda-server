#![allow(clippy::too_many_arguments)]

use crate::common::{get_user_info, AuthAccessConfig, UserContextCache, UserId};
use crate::files::{get_file, is_locked, put_file, to_file_item, update_lock_info, update_unlock_info, FileItem};
use actix_multipart::Multipart;
use actix_web::body::Body;
use actix_web::dev::HttpResponseBuilder;
use actix_web::http::header::HeaderValue;
use actix_web::http::header::CONTENT_TYPE;
use actix_web::http::{header, HeaderName, StatusCode};
use actix_web::Responder;
use actix_web::Result as ActixResult;
use actix_web::{web, HttpRequest, HttpResponse};
use async_std::io::ReadExt;
use async_std::{fs, io};
use chrono::{LocalResult, TimeZone, Utc};
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use mime::Mime;
use std::sync::Arc;
use v_authorization_impl::AzContext;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::api_client::MStorageClient;
use v_common::v_api::common_type::ResultCode;
use xml::escape::escape_str_pcdata;

pub(crate) async fn handle_webdav_put(
    path: web::Path<(String, String, String)>,
    bytes: web::Bytes,
    payload: Multipart,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> ActixResult<impl Responder> {
    let (ticket, file_id, _file_name) = path.into_inner();

    let uinf = match get_user_info(Some(ticket.clone()), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let file_item = match to_file_item(&uinf, &file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    let response_result = put_file(payload, Some(bytes), ticket_cache, &db, &az, req, &activity_sender, Some(ticket), Some(file_item), &auth_config).await;

    match response_result {
        Ok(mut response) => {
            *response.status_mut() = StatusCode::CREATED;
            Ok(response)
        },
        Err(e) => Err(e),
    }
}

pub(crate) async fn handle_webdav_options_2(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id) = path.into_inner();
    handle_webdav_options(ticket, file_id, req, ticket_cache, db, az, activity_sender).await
}
pub(crate) async fn handle_webdav_options_3(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _) = path.into_inner();
    handle_webdav_options(ticket, file_id, req, ticket_cache, db, az, activity_sender).await
}

async fn handle_webdav_options(
    ticket: String,
    file_id: String,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let uinf = match get_user_info(Some(ticket), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let _file_item = match to_file_item(&uinf, &file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    let mut res = HttpResponse::Ok();
    set_webdav_headers(&mut res).await;
    Ok(res.finish())
}

pub(crate) async fn handle_webdav_head(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();
    get_file(Some(ticket.to_string()), file_id.as_str(), ticket_cache, db, az, req, activity_sender, true, header::DispositionType::Inline, auth_config).await
}

async fn handle_webdav_propfind(
    ticket: String,
    file_id: String,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    is_file: bool,
) -> io::Result<HttpResponse> {
    let uinf = match get_user_info(Some(ticket.clone()), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let file_item = match to_file_item(&uinf, &file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    if is_file {
        Ok(res_multistatus(&file_item_to_dav_xml(&file_item, ticket)))
    } else {
        Ok(res_multistatus(&file_id_to_dav_xml(&file_item, ticket)))
    }
}

pub(crate) async fn handle_webdav_propfind_3(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();
    handle_webdav_propfind(ticket, file_id, req, ticket_cache, db, az, activity_sender, true).await
}

pub(crate) async fn handle_webdav_propfind_2(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id) = path.into_inner();
    handle_webdav_propfind(ticket, file_id, req, ticket_cache, db, az, activity_sender, false).await
}

pub(crate) async fn handle_webdav_proppatch(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();

    let uinf = match get_user_info(Some(ticket.clone()), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let file_item = match to_file_item(&uinf, &file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    Ok(res_multistatus(&file_item_to_dav_xml(&file_item, ticket)))
}
pub(crate) async fn handle_webdav_lock(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    mstorage: web::Data<Mutex<MStorageClient>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, file_name) = path.into_inner();

    let uinf = match get_user_info(Some(ticket.clone()), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let file_item = match to_file_item(&uinf, &file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    let token_in_request = extract_token_from_header(&req).await;

    match token_in_request {
        None => {
            // First lock request
            if is_locked(&file_item) {
                error_response(ResultCode::Locked)
            } else {
                let token = Utc::now().timestamp().to_string();
                match update_lock_info(&token, &file_item, uinf, mstorage).await {
                    ResultCode::Ok => Ok(build_lock_response(&token, &ticket, &file_id, &file_name)),
                    _ => error_response(ResultCode::InternalServerError),
                }
            }
        },
        Some(None) => error_response(ResultCode::BadRequest), // Invalid token format
        Some(Some(in_token)) => {
            // Update lock request
            if let Some(locked) = &file_item.locked {
                if locked.id == in_token {
                    if !is_locked(&file_item) {
                        // Update lock after lock is expired
                        return error_response(ResultCode::BadRequest);
                    };
                    match update_lock_info(&in_token, &file_item, uinf, mstorage).await {
                        ResultCode::Ok => Ok(build_lock_response(&in_token, &ticket, &file_id, &file_name)),
                        _ => error_response(ResultCode::InternalServerError),
                    }
                } else {
                    error_response(ResultCode::Locked)
                }
            } else {
                let token = Utc::now().timestamp().to_string();
                match update_lock_info(&token, &file_item, uinf, mstorage).await {
                    ResultCode::Ok => Ok(build_lock_response(&token, &ticket, &file_id, &file_name)),
                    _ => error_response(ResultCode::InternalServerError),
                }
            }
        },
    }
}

pub(crate) async fn handle_webdav_unlock(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    mstorage: web::Data<Mutex<MStorageClient>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();

    let uinf = match get_user_info(Some(ticket), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let file_item = match to_file_item(&uinf, &file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    let token_in_request = extract_token_from_header(&req).await;
    match token_in_request {
        None => error_response(ResultCode::BadRequest),
        Some(None) => error_response(ResultCode::BadRequest), // Invalid token format
        Some(Some(in_token)) => {
            // Update unlock request
            if let Some(locked) = &file_item.locked {
                if locked.id == in_token {
                    match update_unlock_info(&file_item, uinf, mstorage).await {
                        ResultCode::Ok => Ok(HttpResponse::new(StatusCode::OK)),
                        _ => error_response(ResultCode::InternalServerError),
                    }
                } else {
                    error_response(ResultCode::Locked)
                }
            } else {
                error_response(ResultCode::InternalServerError)
            }
        },
    }
}

async fn handle_webdav_get(
    ticket: String,
    file_id: String,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    get_file(Some(ticket.to_string()), file_id.as_str(), ticket_cache, db, az, req, activity_sender, false, header::DispositionType::Inline, auth_config).await
}

pub(crate) async fn handle_webdav_get_3(
    path: web::Path<(String, String, String)>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();
    handle_webdav_get(ticket, file_id, ticket_cache, db, az, req, activity_sender, auth_config).await
}

pub(crate) async fn handle_webdav_get_2(
    path: web::Path<(String, String)>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id) = path.into_inner();
    handle_webdav_get(ticket, file_id, ticket_cache, db, az, req, activity_sender, auth_config).await
}

fn encode_uri(v: &str) -> String {
    let parts: Vec<_> = v.split('/').map(urlencoding::encode).collect();
    parts.join("/")
}

fn file_item_to_dav_xml(fitem: &FileItem, ticket: String) -> String {
    let mtime = match Utc.timestamp_millis_opt(fitem.last_modified.timestamp()) {
        LocalResult::Single(v) => v.to_rfc2822(),
        _ => String::new(),
    };
    let href = encode_uri(&format!("/webdav/{}/{}/{}", ticket, fitem.info_id.replace(':', "_"), &fitem.original_name));
    let displayname = escape_str_pcdata(&fitem.original_name);
    format!(
        r#"<D:response>
<D:href>{}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{}</D:displayname>
<D:getcontentlength>{}</D:getcontentlength>
<D:getlastmodified>{}</D:getlastmodified>
<D:resourcetype></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
        href, displayname, fitem.size, mtime
    )
}
fn file_id_to_dav_xml(fitem: &FileItem, ticket: String) -> String {
    let mtime = match Utc.timestamp_millis_opt(fitem.last_modified.timestamp()) {
        LocalResult::Single(v) => v.to_rfc2822(),
        _ => String::new(),
    };
    let href = encode_uri(&format!("/webdav/{}/{}/{}", ticket, fitem.info_id.replace(':', "_"), fitem.original_name));
    format!(
        r#"<D:response>
<D:href>{}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{}</D:displayname>
<D:getlastmodified>{}</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
        href, fitem.original_name, mtime
    )
}

fn res_multistatus(content: &str) -> HttpResponse {
    let multi_status = StatusCode::from_u16(207).unwrap();
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{content}
</D:multistatus>"#,
        content = content
    );

    HttpResponse::build(multi_status).header(CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8")).body(Body::from(body))
}

async fn set_webdav_headers(res: &mut HttpResponseBuilder) {
    res.header(HeaderName::from_static("allow"), HeaderValue::from_static("GET,HEAD,PUT,OPTIONS,PROPFIND,PROPPATCH,LOCK,UNLOCK"))
        .header(HeaderName::from_static("dav"), HeaderValue::from_static("1,2"));
}

pub async fn get_content_type(path: &str, mime: &Option<Mime>) -> io::Result<String> {
    let mut buffer: Vec<u8> = vec![];
    fs::File::open(path).await?.take(1024).read_to_end(&mut buffer).await?;
    let is_text = content_inspector::inspect(&buffer).is_text();
    let content_type = if is_text {
        let mut detector = chardetng::EncodingDetector::new();
        detector.feed(&buffer, buffer.len() < 1024);
        let (enc, confident) = detector.guess_assess(None, true);
        let charset = if confident {
            format!("; charset={}", enc.name())
        } else {
            "".into()
        };
        match mime {
            Some(m) => format!("{m}{charset}"),
            None => format!("text/plain{charset}"),
        }
    } else {
        match mime {
            Some(m) => m.to_string(),
            None => "application/octet-stream".into(),
        }
    };
    Ok(content_type)
}

fn error_response(code: ResultCode) -> io::Result<HttpResponse> {
    let status_code = StatusCode::from_u16(code as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok(HttpResponse::build(status_code).finish())
}

// This function is defined outside `handle_webdav_lock` to construct the lock response
fn build_lock_response(token: &str, ticket: &str, file_id: &str, file_name: &str) -> HttpResponse {
    let lock_root = format!("/webdav/{}/{}/{}", ticket, file_id, file_name);
    let xml_body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
        <D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
        <D:locktoken><D:href>{}</D:href></D:locktoken>
        <D:lockroot><D:href>{}</D:href></D:lockroot>
        </D:activelock></D:lockdiscovery></D:prop>"#,
        token, lock_root
    );

    HttpResponse::Ok().content_type("application/xml; charset=utf-8").header("lock-token", format!("<{}>", token)).body(xml_body)
}

async fn extract_token_from_header(req: &HttpRequest) -> Option<Option<String>> {
    req.headers()
        .get("if")
        .map(|header_value| {
            header_value.to_str().ok().and_then(|value| {
                if value.len() >= 4 {
                    Some(value[2..value.len() - 2].to_owned())
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            req.headers().get("lock-token").map(|header_value| {
                header_value.to_str().ok().and_then(|value| {
                    if value.starts_with('<') && value.ends_with('>') {
                        Some(value[1..value.len() - 1].to_owned())
                    } else {
                        None
                    }
                })
            })
        })
}
