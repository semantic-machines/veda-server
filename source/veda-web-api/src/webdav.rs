use crate::common::{get_user_info, UserContextCache, UserId};
use crate::files::{get_file, put_file, to_file_item, FileItem};
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
use v_common::az_impl::az_lmdb::LmdbAzContext;
use v_common::storage::async_storage::AStorage;
use xml::escape::escape_str_pcdata;

pub(crate) async fn handle_webdav_put(
    path: web::Path<(String, String, String)>,
    bytes: web::Bytes,
    payload: Multipart,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
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

    let response_result = put_file(payload, bytes, ticket_cache, &db, &az, req, &activity_sender, Some(ticket), Some(file_item)).await;

    match response_result {
        Ok(mut response) => {
            *response.status_mut() = StatusCode::CREATED;
            Ok(response)
        },
        Err(e) => Err(e),
    }
}

pub(crate) async fn handle_webdav_options(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id) = path.into_inner();

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
    az: web::Data<Mutex<LmdbAzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();
    get_file(Some(ticket.to_string()), file_id.as_str(), ticket_cache, db, az, req, activity_sender, true, header::DispositionType::Inline).await
}

async fn handle_webdav_propfind(
    ticket: String,
    file_id: String,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
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

    return Ok(res_multistatus(&to_dav_xml(&file_item)));
}

pub(crate) async fn handle_webdav_propfind0(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();
    handle_webdav_propfind(ticket, file_id, req, ticket_cache, db, az, activity_sender).await
}

pub(crate) async fn handle_webdav_propfind1(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id) = path.into_inner();
    handle_webdav_propfind(ticket, file_id, req, ticket_cache, db, az, activity_sender).await
}

pub(crate) async fn handle_webdav_proppatch(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
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

    return Ok(res_multistatus(&to_dav_xml(&file_item)));
}
pub(crate) async fn handle_webdav_lock(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
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

    let token = Utc::now().timestamp().to_string();
    let xml_body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktoken><D:href>{token}</D:href></D:locktoken>
<D:lockroot><D:href>{file_id}</D:href></D:lockroot>
</D:activelock></D:lockdiscovery></D:prop>"#,
    );

    Ok(HttpResponse::Ok().content_type("application/xml; charset=utf-8").header("lock-token", format!("<{}>", token)).body(xml_body))
}

pub(crate) async fn handle_webdav_unlock(
    path: web::Path<(String, String, String)>,
    req: HttpRequest,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
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

    Ok(HttpResponse::new(StatusCode::OK))
}

pub(crate) async fn handle_webdav_get(
    path: web::Path<(String, String, String)>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let (ticket, file_id, _file_name) = path.into_inner();
    get_file(Some(ticket.to_string()), file_id.as_str(), ticket_cache, db, az, req, activity_sender, false, header::DispositionType::Inline).await
}

fn encode_uri(v: &str) -> String {
    let parts: Vec<_> = v.split('/').map(urlencoding::encode).collect();
    parts.join("/")
}

fn to_dav_xml(fitem: &FileItem) -> String {
    let mtime = match Utc.timestamp_millis_opt(fitem.last_modified.timestamp()) {
        LocalResult::Single(v) => v.to_rfc2822(),
        _ => String::new(),
    };
    let href = encode_uri(&format!("{}{}", "", fitem.id.replace(':', "_")));
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
    res.header(HeaderName::from_static("allow"), HeaderValue::from_static("GET,HEAD,PUT,OPTIONS,DELETE,PROPFIND,COPY,MOVE"))
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
