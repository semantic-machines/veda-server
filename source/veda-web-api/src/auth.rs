use crate::common::{
    check_external_enter, check_ticket, extract_addr, extract_initiator, log_w, validate_auth_method_access, AuthAccessConfig, AuthenticateRequest, GetTicketTrustedRequest, TicketRequest, TicketUriRequest, UserContextCache, UserId,
    UserInfo,
};
use crate::common::{get_user_info, log};
use crate::multifactor::{multifactor, MultifactorProps};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::http::StatusCode;
use actix_web::{get, HttpMessage, HttpRequest};
use actix_web::{web, HttpResponse};
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use v_common::az_impl::LmdbAzContext;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use async_std::task::sleep;

// Type alias for authorization context
type AzContext = LmdbAzContext;

// Initial average authentication duration in milliseconds (used before real stats are collected)
const INITIAL_AVG_AUTH_DURATION_MS: u64 = 10;

// Global timing context for preventing user enumeration via timing attacks
static AVG_SUCCESS_DURATION_MS: AtomicU64 = AtomicU64::new(INITIAL_AVG_AUTH_DURATION_MS);
use v_common::module::ticket::Ticket;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::api_client::AuthClient;
use v_common::v_api::common_type::ResultCode;
use v_common::v_authorization::common::{Access, AuthorizationContext, Trace, ACCESS_8_LIST, ACCESS_PREDICATE_LIST};
use v_individual_model::onto::datatype::Lang;
use v_individual_model::onto::individual::Individual;

/// Create HttpOnly cookie with ticket for secure session management.
/// Cookie is not accessible from JavaScript, protecting against XSS attacks.
pub fn create_ticket_cookie(ticket_id: &str, end_time: i64) -> Cookie<'static> {
    // Convert .NET ticks to Unix timestamp (seconds)
    let unix_seconds = (end_time - 621355968000000000) / 10000000;
    let expires = time::OffsetDateTime::from_unix_timestamp(unix_seconds);
    
    Cookie::build("ticket", ticket_id.to_owned())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .expires(expires)
        .finish()
}

/// Create expired cookie to clear ticket on logout
fn create_expired_ticket_cookie() -> Cookie<'static> {
    Cookie::build("ticket", "")
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .expires(time::OffsetDateTime::unix_epoch())
        .finish()
}

#[get("get_ticket_trusted")]
pub(crate) async fn get_ticket_trusted(
    req: HttpRequest,
    params: web::Query<GetTicketTrustedRequest>,
    ticket_cache: web::Data<UserContextCache>,
    tt: web::Data<AStorage>,
    auth: web::Data<Mutex<AuthClient>>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();
    let uinf = UserInfo {
        ticket: Ticket::default(),
        addr: extract_addr(&req),
    };

    // Get ticket from params or cookie
    let ticket_id = if !params.ticket.is_empty() {
        params.ticket.clone()
    } else {
        req.cookie("ticket").map(|c: Cookie| c.value().to_owned()).unwrap_or_default()
    };

    if let Err(e) = check_ticket(&Some(ticket_id.clone()), &ticket_cache, &uinf.addr, &tt, &activity_sender).await {
        log(Some(&start_time), &uinf, "get_ticket_trusted", &format!("login={:?}, ip={:?}", params.login, params.ip), e);
        return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap()));
    }

    let user_addr = if let Some(ip) = &params.ip {
        if let Ok(i) = ip.parse::<IpAddr>() {
            Some(i)
        } else {
            None
        }
    } else {
        uinf.addr
    };

    return match auth.lock().await.get_ticket_trusted(&ticket_id, params.login.as_ref(), user_addr, Some("veda")) {
        Ok(r) => {
            log(Some(&start_time), &uinf, "get_ticket_trusted", &format!("login={:?}, ip={:?}", params.login, params.ip), ResultCode::Ok);
            
            // Update HttpOnly cookie with new ticket
            let new_ticket = Ticket::from(r.clone());
            let cookie = create_ticket_cookie(&new_ticket.id, new_ticket.end_time);
            Ok(HttpResponse::Ok().cookie(cookie).json(r))
        },
        Err(e) => {
            log(Some(&start_time), &uinf, "get_ticket_trusted", &format!("login={:?}, ip={:?}", params.login, params.ip), e.result);
            Ok(HttpResponse::new(StatusCode::from_u16(e.result as u16).unwrap()))
        },
    };
}

#[get("/logout")]
pub(crate) async fn logout(
    params: web::Query<TicketRequest>,
    ticket_cache: web::Data<UserContextCache>,
    tt: web::Data<AStorage>,
    auth: web::Data<Mutex<AuthClient>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();
    let uinf = UserInfo {
        ticket: Ticket::default(),
        addr: extract_addr(&req)
    };

    // Get ticket from params or cookie
    let ticket_id = params.ticket.clone().or_else(|| req.cookie("ticket").map(|c: Cookie| c.value().to_owned()));
    
    match check_ticket(&ticket_id, &ticket_cache, &uinf.addr, &tt, &activity_sender).await {
        Ok(_user_uri) => {
            return match auth.lock().await.logout(&ticket_id, uinf.addr) {
                Ok(r) => {
                    let mut t = ticket_cache.write_tickets.lock().await;
                    t.empty(ticket_id.clone().unwrap_or_default());
                    t.refresh();

                    log(Some(&start_time), &uinf, "logout", &format!("ticket={:?}, ip={:?}", ticket_id, uinf.addr), ResultCode::Ok);
                    
                    // Clear HttpOnly cookie
                    let cookie = create_expired_ticket_cookie();
                    Ok(HttpResponse::Ok().cookie(cookie).json(r))
                },
                Err(e) => {
                    log(Some(&start_time), &uinf, "logout", &format!("ticket={:?}, ip={:?}", ticket_id, uinf.addr), e.result);
                    Ok(HttpResponse::new(StatusCode::from_u16(e.result as u16).unwrap()))
                },
            }
        },
        Err(e) => {
            log_w(Some(&start_time), &ticket_id, &extract_addr(&req), "", "logout", "", e);
            // Still clear cookie even if ticket validation failed
            let cookie = create_expired_ticket_cookie();
            Ok(HttpResponse::Ok().cookie(cookie).json(false))
        },
    }
}

#[get("/is_ticket_valid")]
pub(crate) async fn is_ticket_valid(
    params: web::Query<TicketRequest>,
    ticket_cache: web::Data<UserContextCache>,
    tt: web::Data<AStorage>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();

    // Get ticket from params or cookie
    let ticket_id = params.ticket.clone().or_else(|| req.cookie("ticket").map(|c: Cookie| c.value().to_owned()));

    if ticket_id.is_none() {
        return Ok(HttpResponse::Ok().json(false));
    }

    match check_ticket(&ticket_id, &ticket_cache, &extract_addr(&req), &tt, &activity_sender).await {
        Ok(ticket) => {
            log_w(Some(&start_time), &ticket_id, &extract_addr(&req), &ticket.user_uri, "is_ticket_valid", "", ResultCode::Ok);
            Ok(HttpResponse::Ok().json(true))
        },
        Err(e) => {
            log_w(Some(&start_time), &ticket_id, &extract_addr(&req), "", "is_ticket_valid", "", e);
            Ok(HttpResponse::Ok().json(false))
        },
    }
}

pub(crate) async fn authenticate_post(
    data: web::Json<AuthenticateRequest>,
    auth: web::Data<Mutex<AuthClient>>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    mfp: web::Data<MultifactorProps>,
    req: HttpRequest,
) -> io::Result<HttpResponse> {
    authenticate(&data.login, &data.password, &data.secret, auth, ticket_cache, db, mfp, req).await
}

pub(crate) async fn authenticate_get(
    params: web::Query<AuthenticateRequest>,
    auth: web::Data<Mutex<AuthClient>>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    mfp: web::Data<MultifactorProps>,
    req: HttpRequest,
) -> io::Result<HttpResponse> {
    authenticate(&params.login, &params.password, &params.secret, auth, ticket_cache, db, mfp, req).await
}

#[allow(clippy::too_many_arguments)]
async fn authenticate(
    login: &str,
    password: &Option<String>,
    secret: &Option<String>,
    auth: web::Data<Mutex<AuthClient>>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    mfp: web::Data<MultifactorProps>,
    req: HttpRequest,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();
    let mut uinf = UserInfo {
        ticket: Ticket::default(),
        addr: extract_addr(&req),
    };
    let initiator = extract_initiator(&req);

    let response = match auth.lock().await.authenticate(login, password, extract_addr(&req), secret, Some("veda"), initiator.as_deref(), None) {
        Ok(r) => {
            uinf.ticket = Ticket::from(r.clone());
            if ticket_cache.check_external_users {
                if let Err(e) = check_external_enter(&uinf.ticket, &db).await {
                    log(Some(&start_time), &uinf, "authenticate", login, e);
                    return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap()));
                }
            }

            if !uinf.ticket.auth_origin.is_empty() {
                if uinf.ticket.auth_origin.to_uppercase() == "VEDA MULTIFACTOR" {
                    info!("detected [VEDA MULTIFACTOR] for user {}", uinf.ticket.user_uri);
                    return multifactor(req, &uinf, mfp.as_ref()).await;
                }
            }

            log(Some(&start_time), &uinf, "authenticate", &uinf.ticket.user_uri, ResultCode::Ok);
            
            // Set HttpOnly cookie with ticket for secure session management
            let cookie = create_ticket_cookie(&uinf.ticket.id, uinf.ticket.end_time);
            Ok(HttpResponse::Ok().cookie(cookie).json(r))
        },
        Err(e) => {
            log(Some(&start_time), &uinf, "authenticate", login, e.result);
            Ok(HttpResponse::new(StatusCode::from_u16(e.result as u16).unwrap_or(StatusCode::BAD_REQUEST)))
        },
    };

    // Timing attack protection: ensure consistent response time
    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    // Update average on successful authentication
    if uinf.ticket.result == ResultCode::Ok {
        let old_avg = AVG_SUCCESS_DURATION_MS.load(Ordering::Relaxed);
        let new_avg = ((old_avg as f64) * 0.9 + (elapsed_ms as f64) * 0.1) as u64;
        AVG_SUCCESS_DURATION_MS.store(new_avg, Ordering::Relaxed);
    }

    // Add delay if response was faster than target average
    let target_ms = AVG_SUCCESS_DURATION_MS.load(Ordering::Relaxed);
    if elapsed_ms < target_ms {
        sleep(Duration::from_millis(target_ms - elapsed_ms)).await;
    }

    response
}

#[get("/get_rights")]
pub(crate) async fn get_rights(
    params: web::Query<TicketUriRequest>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();

    let mut uinf = match get_user_info(params.ticket.to_owned(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &params.ticket, &extract_addr(&req), "", "get_rights", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    // Override user_uri if user_id parameter is provided (for checking other user's rights)
    if let Some(u) = &params.user_id {
        uinf.ticket.user_uri = u.to_owned();
    }

    // Check auth method access restrictions for this resource
    let auth_access_result = validate_auth_method_access(&uinf, &params.uri, Some(&az), &auth_config).await;
    if auth_access_result != ResultCode::Ok {
        log_w(Some(&start_time), &params.ticket, &extract_addr(&req), &uinf.ticket.user_uri, "get_rights", &params.uri, auth_access_result);
        return Ok(HttpResponse::new(StatusCode::from_u16(auth_access_result as u16).unwrap()));
    }

    let rights = az
        .lock()
        .await
        .authorize(&params.uri, &uinf.ticket.user_uri, Access::CanRead as u8 | Access::CanCreate as u8 | Access::CanDelete as u8 | Access::CanUpdate as u8, false)
        .unwrap_or(0);
    let mut pstm = Individual::default();

    pstm.set_id("_");
    pstm.add_uri("rdf:type", "v-s:PermissionStatement");
    for ch_access in ACCESS_8_LIST {
        if rights & ch_access > 0 {
            pstm.add_bool(ACCESS_PREDICATE_LIST[ch_access as usize], rights & ch_access > 0);
        }
    }

    log(Some(&start_time), &uinf, "get_rights", &params.uri, ResultCode::Ok);
    return Ok(HttpResponse::Ok().json(pstm.get_obj().as_json()));
}

#[get("/get_membership")]
pub(crate) async fn get_membership(
    params: web::Query<TicketUriRequest>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();

    let uinf = match get_user_info(params.ticket.to_owned(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &params.ticket, &extract_addr(&req), "", "get_membership", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    // Check auth method access restrictions for this resource
    let auth_access_result = validate_auth_method_access(&uinf, &params.uri, Some(&az), &auth_config).await;
    if auth_access_result != ResultCode::Ok {
        log_w(Some(&start_time), &params.ticket, &extract_addr(&req), &uinf.ticket.user_uri, "get_membership", &params.uri, auth_access_result);
        return Ok(HttpResponse::new(StatusCode::from_u16(auth_access_result as u16).unwrap()));
    }

    let mut acl_trace = Trace {
        acl: &mut String::new(),
        is_acl: false,
        group: &mut String::new(),
        is_group: true,
        info: &mut String::new(),
        is_info: false,
        str_num: 0,
    };

    if az.lock().await.authorize_and_trace(&params.uri, &uinf.ticket.user_uri, Access::CanRead as u8, false, &mut acl_trace).unwrap_or(0) == Access::CanRead as u8 {
        let mut mbshp = Individual::default();

        mbshp.set_id("_");
        mbshp.add_uri("rdf:type", "v-s:Membership");
        for el in acl_trace.group.split('\n') {
            let n = el.trim();
            if !n.is_empty() {
                mbshp.add_uri("v-s:memberOf", n);
            }
        }
        mbshp.add_uri("v-s:resource", &params.uri);

        log(Some(&start_time), &uinf, "get_membership", &params.uri, ResultCode::Ok);
        return Ok(HttpResponse::Ok().json(mbshp.get_obj().as_json()));
    }

    log(Some(&start_time), &uinf, "get_membership", &params.uri, ResultCode::BadRequest);
    Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::BadRequest as u16).unwrap()))
}

#[get("/get_rights_origin")]
pub(crate) async fn get_rights_origin(
    params: web::Query<TicketUriRequest>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<AzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    auth_config: web::Data<AuthAccessConfig>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();

    let uinf = match get_user_info(params.ticket.to_owned(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &params.ticket, &extract_addr(&req), "", "get_rights_origin", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    // Check auth method access restrictions for this resource
    let auth_access_result = validate_auth_method_access(&uinf, &params.uri, Some(&az), &auth_config).await;
    if auth_access_result != ResultCode::Ok {
        log_w(Some(&start_time), &params.ticket, &extract_addr(&req), &uinf.ticket.user_uri, "get_rights_origin", &params.uri, auth_access_result);
        return Ok(HttpResponse::new(StatusCode::from_u16(auth_access_result as u16).unwrap()));
    }

    let mut acl_trace = Trace {
        acl: &mut String::new(),
        is_acl: true,
        group: &mut String::new(),
        is_group: false,
        info: &mut String::new(),
        is_info: true,
        str_num: 0,
    };

    if az
        .lock()
        .await
        .authorize_and_trace(
            &params.uri,
            &uinf.ticket.user_uri,
            Access::CanRead as u8 | Access::CanCreate as u8 | Access::CanDelete as u8 | Access::CanUpdate as u8,
            false,
            &mut acl_trace,
        )
        .unwrap_or(0)
        & Access::CanRead as u8
        > 0
    {
        let mut out_res = vec![];

        for el in acl_trace.acl.split('\n') {
            let n = el.trim();
            if !n.is_empty() {
                let mut indv = Individual::default();
                indv.set_id("_");
                indv.add_uri("rdf:type", "v-s:PermissionStatement");

                let r = n.split(';').collect::<Vec<&str>>();
                if r.len() == 3 {
                    indv.add_uri("v-s:permissionObject", r[0].trim());
                    indv.add_uri("v-s:permissionSubject", r[1].trim());
                    indv.add_bool(r[2].trim(), true);
                }
                out_res.push(indv.get_obj().as_json());
            }
        }

        let mut indv = Individual::default();
        indv.set_id("_");
        indv.add_uri("rdf:type", "v-s:PermissionStatement");
        indv.add_uri("v-s:permissionSubject", "?");
        indv.add_string("rdfs:comment", acl_trace.info, Lang::none());
        out_res.push(indv.get_obj().as_json());

        log(Some(&start_time), &uinf, "get_rights_origin", &params.uri, ResultCode::Ok);
        return Ok(HttpResponse::Ok().json(out_res));
    }

    log(Some(&start_time), &uinf, "get_rights_origin", &params.uri, ResultCode::BadRequest);
    Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::BadRequest as u16).unwrap()))
}
