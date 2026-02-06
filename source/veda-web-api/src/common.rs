use crate::nlp_transcription::OpenAIConfig;
use crate::VQLHttpClient;
use actix_web::{web, HttpMessage, HttpRequest};
use anyhow::Result as AnyhowResult;
use async_std::io;
use config::{Config, File};
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use futures::SinkExt;
use log::{error, info, warn};
use rusty_tarantool::tarantool::{ClientConfig, IteratorType};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use v_common::ft_xapian::xapian_reader::XapianReader;
use v_common::module::ticket::Ticket;
use v_common::search::ft_client::FTClient;
use v_common::storage::async_storage::{get_individual_from_db, get_individual_use_storage_id, AStorage, TICKETS_SPACE_ID};
use v_storage::{Storage, StorageId, StorageMode};
use v_storage::lmdb_storage::LMDBStorage;
use v_common::v_api::common_type::ResultCode;
use v_authorization_impl_tt2_lmdb::AzContext;
use v_common::v_authorization::common::{Access, AuthorizationContext, Trace};
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::parser::parse_raw;

pub(crate) const LIMITATA_COGNOSCI: &[&str] = &["v-s:Credential", "v-s:Connection", "v-s:LinkedNode"];
pub(crate) const BASE_PATH: &str = "./data";
pub(crate) const EMPTY_SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub type UserId = String;

#[derive(Clone)]
pub struct NLPServerConfig {
    pub whisper_server_url: String,
    pub llama_server_url: String,
}

pub struct UserContextCache {
    pub read_tickets: evmap::ReadHandle<String, Ticket>,
    pub write_tickets: Arc<Mutex<evmap::WriteHandle<String, Ticket>>>,
    pub check_ticket_ip: bool,
    pub check_external_users: bool,
    pub reject_empty_ticket: bool,
    pub reject_guest_user: bool,
}

pub(crate) enum VQLClientConnectType {
    Direct,
    Http,
    Nng,
    Unknown,
}

pub(crate) struct VQLClient {
    pub(crate) query_type: VQLClientConnectType,
    pub(crate) http_client: Option<VQLHttpClient>,
    pub(crate) nng_client: Option<FTClient>,
    pub(crate) xr: Option<XapianReader>,
}

impl Default for VQLClient {
    fn default() -> Self {
        VQLClient {
            query_type: VQLClientConnectType::Unknown,
            http_client: None,
            nng_client: None,
            xr: None,
        }
    }
}

#[derive(Default)]
pub struct UserInfo {
    pub ticket: Ticket,
    pub addr: Option<IpAddr>,
}

pub async fn get_user_info(
    in_ticket: Option<String>,
    req: &HttpRequest,
    ticket_cache: &web::Data<UserContextCache>,
    db: &AStorage,
    activity_sender: &Arc<Mutex<Sender<UserId>>>,
) -> Result<UserInfo, ResultCode> {
    let ticket_id = if in_ticket.is_some() {
        in_ticket
    } else {
        get_ticket(req, &None)
    };

    let addr = extract_addr(req);
    let ticket = check_ticket(&ticket_id, ticket_cache, &addr, db, activity_sender).await?;

    Ok(UserInfo {
        ticket,
        addr
    })
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct GetTicketTrustedRequest {
    #[serde(default)]
    pub ticket: String,
    pub(crate) login: Option<String>,
    pub(crate) ip: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TicketRequest {
    pub ticket: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct GetOperationStateRequest {
    pub(crate) module_id: u64,
    wait_op_id: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct AuthenticateRequest {
    pub(crate) login: String,
    pub(crate) password: Option<String>,
    pub(crate) secret: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TicketUriRequest {
    pub(crate) ticket: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) uri: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct Uris {
    pub(crate) uris: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct QueryRequest {
    pub stored_query: Option<String>,
    pub params: Option<Value>,
    pub ticket: Option<String>,
    pub user: Option<String>,
    pub sparql: Option<String>,
    pub sql: Option<String>,
    pub query: Option<String>,
    pub sort: Option<String>,
    pub databases: Option<String>,
    pub reopen: Option<bool>,
    pub top: Option<i32>,
    pub limit: Option<i32>,
    pub from: Option<i32>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct StoredQueryRequest {
    pub ticket: Option<String>,
}
pub(crate) fn get_module_name(id: u64) -> &'static str {
    match id {
        1 => "subject_manager",
        2 => "acl_preparer",
        4 => "fulltext_indexer",
        8 => "fanout_email",
        16 => "scripts_main",
        32 => "ticket_manager",
        64 => "file_reader",
        128 => "fanout_sql_np",
        256 => "scripts_lp",
        512 => "ltr_scripts",
        1024 => "fanout_sql_lp",
        _ => "unknown",
    }
}

pub(crate) fn get_ticket(req: &HttpRequest, in_ticket: &Option<String>) -> Option<String> {
    if let Some(t) = in_ticket {
        return Some(t.clone());
    } else if let Some(c) = req.cookie("ticket") {
        return Some(c.value().to_owned());
    }

    None
}

pub(crate) fn extract_addr(req: &HttpRequest) -> Option<IpAddr> {
    if let Some(xf) = req.headers().get(actix_web::http::header::HeaderName::from_static("x-real-ip")) {
        if let Ok(xfu) = xf.to_str() {
            let (f1, _) = xfu.split_once(',').unwrap_or((xfu, ""));
            if let Ok(a) = f1.parse::<IpAddr>() {
                return Some(a);
            }
        }
    }

    if let Some(v) = req.peer_addr() {
        return Some(v.ip());
    }

    None
}

pub(crate) fn extract_initiator(req: &HttpRequest) -> Option<String> {
    // Try Referer header first
    if let Some(referer) = req.headers().get(actix_web::http::header::REFERER) {
        if let Ok(referer_str) = referer.to_str() {
            if !referer_str.is_empty() {
                return Some(referer_str.to_string());
            }
        }
    }
    
    // Try Origin header as fallback
    if let Some(origin) = req.headers().get(actix_web::http::header::ORIGIN) {
        if let Ok(origin_str) = origin.to_str() {
            if !origin_str.is_empty() {
                return Some(origin_str.to_string());
            }
        }
    }
    
    // No valid URL found
    None
}

pub(crate) fn log_w(start_time: Option<&Instant>, ticket: &Option<String>, addr: &Option<IpAddr>, user_id: &str, operation: &str, args: &str, res: ResultCode) {
    let ip = if let Some(a) = addr {
        a.to_string()
    } else {
        "?".to_string()
    };

    let ticket_id = if let Some(t) = &ticket {
        if let Some(part) = t.get(0..7) {
            part
        } else {
            "      ?"
        }
    } else {
        "      ?"
    };

    let action = if operation.is_empty() {
        "".to_string()
    } else {
        format!("action = {operation}, ")
    };

    let res_str = if res == ResultCode::Zero {
        "".to_string()
    } else {
        format!("{res:?}, ")
    };

    if res == ResultCode::InternalServerError {
        if let Some(t) = start_time {
            error!("{ip}, {ticket_id}, {action}user = {user_id}, {res_str}{args}, time = {:.3} ms", t.elapsed().as_secs_f64() * 1000.0);
        } else {
            error!("{ip}, {ticket_id}, {action}user = {user_id}, {res_str}{args}");
        }
    } else if let Some(t) = start_time {
        info!("{ip},  {ticket_id}, {action}user = {user_id}, {res_str}{args}, time = {:.3} ms", t.elapsed().as_secs_f64() * 1000.0);
    } else {
        info!("{ip},  {ticket_id}, {action}user = {user_id}, {res_str}{args}");
    }
}

pub(crate) fn log(start_time: Option<&Instant>, uinf: &UserInfo, operation: &str, args: &str, res: ResultCode) {
    let t = if uinf.ticket.id.is_empty() {
        None
    } else {
        Some(uinf.ticket.id.clone())
    };
    log_w(start_time, &t, &uinf.addr, &uinf.ticket.user_uri, operation, args, res);
}

pub(crate) async fn check_ticket(
    w_ticket_id: &Option<String>,
    user_context_cache: &UserContextCache,
    addr: &Option<IpAddr>,
    db: &AStorage,
    activity_sender: &Arc<Mutex<Sender<UserId>>>,
) -> Result<Ticket, ResultCode> {
    // Check if ticket is empty or invalid
    let is_empty_ticket = match w_ticket_id {
        None => true,
        Some(t) => t.is_empty() || t == "systicket" || t == EMPTY_SHA256_HASH,
    };

    if is_empty_ticket {
        if user_context_cache.reject_empty_ticket {
            return Err(ResultCode::TicketNotFound);
        }
        
        let guest_ticket = Ticket {
            id: "".to_string(),
            user_uri: "cfg:Guest".to_owned(),
            user_login: "".to_string(),
            result: ResultCode::Zero,
            start_time: 0,
            end_time: 0,
            user_addr: "".to_string(),
            auth_method: "".to_string(),
            domain: "".to_string(),
            initiator: "".to_string(),
            auth_origin: "".to_string(),
        };
        
        if user_context_cache.reject_guest_user {
            return Err(ResultCode::TicketNotFound);
        }
        
        return Ok(guest_ticket);
    }

    let ticket_id = w_ticket_id.as_ref().unwrap();

    if let Some(cached_ticket) = user_context_cache.read_tickets.get(ticket_id) {
        if let Some(ticket_obj) = cached_ticket.get_one() {
            if ticket_obj.is_ticket_valid(addr, user_context_cache.check_ticket_ip) != ResultCode::Ok {
                return Err(ResultCode::TicketNotFound);
            }
            send_user_activity(activity_sender, &ticket_obj.user_uri).await;
            Ok(ticket_obj.clone())
        } else {
            Err(ResultCode::TicketNotFound)
        }
    } else {
        let ticket_obj = read_ticket_obj(ticket_id, db).await?;

        if ticket_obj.is_ticket_valid(addr, user_context_cache.check_ticket_ip) != ResultCode::Ok {
            return Err(ResultCode::TicketNotFound);
        }

        let user_uri = ticket_obj.user_uri.clone();

        if user_context_cache.check_external_users {
            check_external_enter(&ticket_obj, db).await?;
        }

        send_user_activity(activity_sender, &user_uri).await;

        //info!("@ upd cache ticket={}", ticket_obj.id);
        let mut t = user_context_cache.write_tickets.lock().await;
        t.insert(ticket_id.to_owned(), ticket_obj.clone());
        t.refresh();

        Ok(ticket_obj)
    }
}

async fn send_user_activity(activity_sender: &Arc<Mutex<Sender<UserId>>>, user_id: &str) {
    {
        let mut sender = activity_sender.lock().await;
        sender.send(user_id.to_string()).await.unwrap();
    }
}

pub async fn read_system_ticket_id(db: &AStorage) -> io::Result<String> {
    let (mut systicket_info, res_code) = get_individual_use_storage_id(StorageId::Tickets, "systicket", "", db, None).await?;
    if res_code == ResultCode::Ok {
        if let Some(v) = systicket_info.get_first_literal("v-s:resource") {
            return Ok(v);
        }
    }
    Err(Error::new(ErrorKind::Other, format!("fail read system ticket id, err={:?}", res_code)))
}

async fn read_ticket_obj(ticket_id: &str, db: &AStorage) -> Result<Ticket, ResultCode> {
    let mut ticket_obj = Ticket::default();

    if let Some(tt) = &db.tt {
        let response = match tt.select(TICKETS_SPACE_ID, 0, &(&ticket_id,), 0, 100, IteratorType::EQ).await {
            Ok(r) => r,
            Err(_) => {
                return Err(ResultCode::TicketNotFound);
            },
        };

        let mut to = Individual::default();
        to.set_raw(&response.data[5..]);
        if parse_raw(&mut to).is_ok() {
            ticket_obj.update_from_individual(&mut to);
            ticket_obj.result = ResultCode::Ok;
        }
    }
    if let Some(lmdb) = &db.lmdb {
        let mut to = Individual::default();
        if lmdb.lock().await.get_individual(StorageId::Tickets, ticket_id, &mut to).is_ok() {
            ticket_obj.update_from_individual(&mut to);
            ticket_obj.result = ResultCode::Ok;
        }
    }
    if ticket_obj.result != ResultCode::Ok {
        return Err(ResultCode::TicketNotFound);
    }
    Ok(ticket_obj)
}

pub(crate) async fn check_external_enter(ticket: &Ticket, db: &AStorage) -> Result<(), ResultCode> {
    if ticket.auth_method.to_uppercase() == "SMS" && ticket.auth_origin.to_uppercase() == "MOBILE" {
        return Ok(());
    }

    if let Ok((mut user_indv, res)) = get_individual_from_db(&ticket.user_uri, "", db, None).await {
        if res == ResultCode::Ok {
            if let Some(o) = user_indv.get_first_literal("v-s:origin") {
                if o != "ExternalUser" {
                    error!("user {} is not external", ticket.user_uri);
                    return Err(ResultCode::AuthenticationFailed);
                }
            } else {
                error!("user {} not content field [origin]", ticket.user_uri);
                return Err(ResultCode::AuthenticationFailed);
            }
        } else {
            error!("fail read user {}, err={res:?}", ticket.user_uri);
            return Err(ResultCode::AuthenticationFailed);
        }
    } else {
        error!("fail read user {}", ticket.user_uri);
        return Err(ResultCode::AuthenticationFailed);
    }
    Ok(())
}

pub(crate) fn db_connector(tt_config: &Option<ClientConfig>) -> AStorage {
    if let Some(cfg) = &tt_config {
        AStorage {
            tt: Some(cfg.clone().build()),
            lmdb: None,
        }
    } else {
        AStorage {
            tt: None,
            lmdb: Some(Mutex::from(LMDBStorage::new(BASE_PATH, StorageMode::ReadOnly, Some(1000)))),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TranscriptionConfig {
    pub(crate) openai: OpenAIConfig,
    pub(crate) use_local_model: bool,
}

impl TranscriptionConfig {
    pub fn load() -> AnyhowResult<Self> {
        let config = Config::builder().add_source(File::with_name("./config/transcription.toml")).build()?;

        Ok(config.try_deserialize()?)
    }
}

/// Configuration for authentication method access restrictions
#[derive(Debug, Clone)]
pub struct AuthAccessConfig {
    pub restrictions: std::collections::HashMap<String, Vec<String>>,
}

impl Default for AuthAccessConfig {
    fn default() -> Self {
        // No default restrictions - all restrictions should be explicitly configured
        Self { 
            restrictions: std::collections::HashMap::new() 
        }
    }
}

/// Load authentication method access configuration from config file
pub fn load_auth_access_config() -> AuthAccessConfig {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::collections::HashMap;

    let mut restrictions = HashMap::new();

    if let Ok(file) = File::open("config/veda-web-api.ini") {
        let reader = BufReader::new(file);
        let mut current_section = String::new();
        
        for line in reader.lines().filter_map(|l| l.ok()) {
            let line = line.trim();
            
            // Check if this is a section header
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len()-1].to_string();
                continue;
            }
            
            // Check if this is an allowed_groups line in any section
            if !current_section.is_empty() && line.starts_with("allowed_groups") {
                if let Some(equals_pos) = line.find('=') {
                    let groups_str = &line[equals_pos + 1..].trim();
                    
                    let groups: Vec<String> = groups_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !groups.is_empty() {
                        restrictions.insert(current_section.clone(), groups);
                    }
                }
            }
        }
    }
    
    AuthAccessConfig { restrictions }
}

/// Check if resource belongs to allowed groups for authentication method
/// Returns true if access is allowed, false if access should be denied
pub async fn check_auth_method_resource_access(
    resource_uri: &str,
    auth_method: &str,
    az_context: Option<&web::Data<Mutex<AzContext>>>,
    config: &AuthAccessConfig,
) -> Result<bool, ResultCode> {
    // If no authorization context available, deny access by default
    let Some(az) = az_context else {
        return Ok(false);
    };

    // Get allowed groups for this authentication method
    let Some(allowed_groups) = config.restrictions.get(auth_method) else {
        // No restrictions for this auth method
        return Ok(true);
    };

    // Log the access attempt for audit purposes
    info!("Checking {} auth access to resource {}", auth_method, resource_uri);

    // Check if resource belongs to any of the allowed groups
    for group in allowed_groups {
        match check_object_in_group(resource_uri, group, Some(az)).await {
            Ok(true) => {
                // Resource is in an allowed group
                info!("{} access granted to resource {} - resource in group {}", 
                      auth_method, resource_uri, group);
                return Ok(true);
            }
            Ok(false) => continue,
            Err(_) => continue,
        }
    }

    // Resource is not in any allowed group
    Ok(false)
}

/// Check if authentication method access restrictions should be applied and validate access
/// Returns ResultCode::Ok if access allowed, error code if denied
pub async fn validate_auth_method_access(
    user_info: &UserInfo,
    resource_uri: &str,
    az_context: Option<&web::Data<Mutex<AzContext>>>,
    config: &AuthAccessConfig,
) -> ResultCode {
    // Skip empty auth methods
    if user_info.ticket.auth_method.is_empty() {
        return ResultCode::Ok;
    }

    // Check if there are restrictions for this auth method
    if !config.restrictions.contains_key(&user_info.ticket.auth_method) {
        return ResultCode::Ok;
    }

    match check_auth_method_resource_access(resource_uri, &user_info.ticket.auth_method, az_context, config).await {
        Ok(true) => ResultCode::Ok,
        Ok(false) => {
            if let Some(allowed_groups) = config.restrictions.get(&user_info.ticket.auth_method) {
                warn!("{} user {} denied access to resource {}: resource not in allowed groups {:?}",
                      user_info.ticket.auth_method, user_info.ticket.user_uri, resource_uri, allowed_groups);
            }
            ResultCode::NotAuthorized
        },
        Err(e) => {
            error!("Error checking {} resource access for user {}: {:?}",
                   user_info.ticket.auth_method, user_info.ticket.user_uri, e);
            ResultCode::InternalServerError
        }
    }
}

/// Check if an object belongs to a specific group
/// Uses system user for authorization context since we only care about object's group membership
pub async fn check_object_in_group(object_id: &str, group_id: &str, az: Option<&web::Data<Mutex<AzContext>>>) -> io::Result<bool> {
    if let Some(a) = az {
        let mut tr = Trace {
            acl: &mut "".to_string(),
            is_acl: false,
            group: &mut String::new(),
            is_group: true,
            info: &mut "".to_string(),
            is_info: false,
            str_num: 0,
        };
        // Use system user for authorization context to get object's group membership
        // We don't care about user permissions here, only object's groups
        if a.lock().await.authorize_and_trace(object_id, "cfg:VedaSystem", Access::CanRead as u8, false, &mut tr).is_ok() {
            for gr in tr.group.split('\n') {
                if gr.trim() == group_id {
                    return Ok(true);
                }
            }
        } else {
            return Err(Error::new(ErrorKind::Other, "fail authorize_and_trace for object"));
        }
    }

    Ok(false)
}
