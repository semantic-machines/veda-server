use chrono::{DateTime, Utc};
use data_encoding::HEXLOWER;
use log::{error, info, warn, debug};
use mustache::MapBuilder;
use lazy_static::lazy_static;
use parse_duration::parse;
use regex::Regex;
use ring::rand::SecureRandom;
use ring::{digest, pbkdf2, rand};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::str::from_utf8;
use uuid::Uuid;

use v_common::az_impl::az_lmdb::LmdbAzContext;
use v_common::ft_xapian::xapian_reader::XapianReader;
use v_common::module::module_impl::Module;
use v_common::module::ticket::Ticket;
use v_common::module::veda_backend::Backend;
use v_common::search::common::{FTQuery, QueryResult};
use v_storage::{StorageId, StorageResult, VStorage};
use v_common::v_api::api_client::IndvOp;
use v_common::v_authorization::common::{AuthorizationContext, Trace};
use v_individual_model::onto::datatype::Lang;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::individual2msgpack::to_msgpack;
use v_common::v_api::common_type::{OptAuthorize, ResultCode};

pub const EMPTY_SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const ALLOW_TRUSTED_GROUP: &str = "cfg:TrustedAuthenticationUserGroup";
const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
pub const N_ITER: u32 = 100_000;
pub const TICKS_TO_UNIX_EPOCH: i64 = 62_135_596_800_000;

#[derive(Default, Debug)]
pub struct UserStat {
    pub wrong_count_login: i32,
    pub last_wrong_login_date: i64,
    pub attempt_change_pass: i32,
    pub last_attempt_change_pass_date: i64,
}

#[derive(Debug)]
pub struct AuthConf {
    pub failed_auth_attempts: i32,
    pub failed_change_pass_attempts: i32,
    pub failed_auth_lock_period: i64,
    pub failed_pass_change_lock_period: i64,
    pub success_pass_change_lock_period: i64,
    pub ticket_lifetime: i64,
    pub secret_lifetime: i64,
    pub pass_lifetime: i64,
    pub expired_pass_notification_template: Option<(String, String)>,
    pub denied_password_expired_notification_template: Option<(String, String)>,
    pub check_ticket_ip: bool,
    // SMS configuration
    pub sms_rate_limit_seconds: i64,
    pub sms_daily_limit: i32,
    pub sms_code_min: u32,
    pub sms_code_max: u32,
}

impl Default for AuthConf {
    fn default() -> Self {
        AuthConf {
            failed_auth_attempts: 2,
            failed_change_pass_attempts: 2,
            failed_auth_lock_period: 30 * 60,
            failed_pass_change_lock_period: 30 * 60,
            success_pass_change_lock_period: 24 * 60 * 60,
            ticket_lifetime: 10 * 60 * 60,
            secret_lifetime: 12 * 60 * 60,
            pass_lifetime: 90 * 24 * 60 * 60,
            expired_pass_notification_template: None,
            denied_password_expired_notification_template: None,
            check_ticket_ip: true,
            // SMS default values
            sms_rate_limit_seconds: 20,
            sms_daily_limit: 5,
            sms_code_min: 100_000,
            sms_code_max: 999_999,
        }
    }
}

pub fn logout(_conf: &AuthConf, tr_ticket_id: Option<&str>, _ip: Option<&str>, backend: &mut Backend) -> Ticket {
    let tr_ticket_id = tr_ticket_id.unwrap_or_default();
    let mut ticket_obj = backend.get_ticket_from_db(tr_ticket_id);
    if ticket_obj.result == ResultCode::Ok {
        ticket_obj.end_time = Utc::now().timestamp();

        if store(&ticket_obj.to_individual(), &mut backend.storage) {
            let end_time_str = if let Some(end_time_dt) = DateTime::from_timestamp(ticket_obj.end_time, 0) {
                format!("{:?}", end_time_dt.naive_utc())
            } else {
                error!("logout: fail update ticket {:?}, fail timestamp", ticket_obj.id);
                ticket_obj.result = ResultCode::InternalServerError;
                return ticket_obj;
            };
            info!("logout: update ticket {}, user={}, addr={}, end={}", ticket_obj.id, ticket_obj.user_uri, ticket_obj.user_addr, end_time_str);
            ticket_obj.result = ResultCode::Ok;
        } else {
            error!("logout: fail update ticket {:?}", ticket_obj.id);
            ticket_obj.result = ResultCode::AuthenticationFailed;
        }
    } else {
        error!("logout: couldn't get a ticket from the database, ticket = {}", tr_ticket_id);
        ticket_obj.result = ResultCode::AuthenticationFailed;
    }

    ticket_obj
}

#[allow(clippy::too_many_arguments)]
pub fn get_ticket_trusted(
    conf: &AuthConf,
    tr_ticket_id: Option<&str>,
    login: Option<&str>,
    ip: Option<&str>,
    xr: &mut XapianReader,
    backend: &mut Backend,
    auth_data: &mut VStorage,
    az: &mut LmdbAzContext,
) -> Ticket {
    let tr_ticket_id = tr_ticket_id.unwrap_or_default();
    let mut tr_ticket = backend.get_ticket_from_db(tr_ticket_id);

    if tr_ticket.result == ResultCode::Ok {
        let login = if let Some(l) = login {
            if l.is_empty() {
                &tr_ticket.user_login
            } else {
                l
            }
        } else {
            &tr_ticket.user_login
        };
        info!("get_ticket_trusted: login = {}, ticket = {}", login, tr_ticket_id);

        if login.is_empty() || tr_ticket_id.len() < 6 {
            warn!("trusted authenticate: invalid login {} or ticket {}", login, tr_ticket_id);
            return Ticket::default();
        }

        let mut is_allow_trusted = false;

        let mut trace = Trace {
            acl: &mut String::new(),
            is_acl: false,
            group: &mut String::new(),
            is_group: true,
            info: &mut String::new(),
            is_info: false,
            str_num: 0,
        };

        match az.authorize_and_trace(&tr_ticket.user_uri, &tr_ticket.user_uri, 15, true, &mut trace) {
            Ok(_res) => {
                for gr in trace.group.split('\n') {
                    if gr == ALLOW_TRUSTED_GROUP {
                        is_allow_trusted = true;
                        break;
                    }
                }
            },
            Err(e) => error!("failed to get authorization group, user = {}, err = {}", &tr_ticket.user_uri, e),
        }

        let candidate_account_ids = get_candidate_users_of_login(login, backend, xr, auth_data);
        if candidate_account_ids.result_code != ResultCode::Ok {
            error!("get_ticket_trusted: query result={:?}", candidate_account_ids.result_code);
        }

        if candidate_account_ids.result_code == ResultCode::Ok && !candidate_account_ids.result.is_empty() {
            for check_account_id in &candidate_account_ids.result {
                if let Some(account) = backend.get_individual(check_account_id, &mut Individual::default()) {
                    let check_user_id = account.get_first_literal("v-s:owner").unwrap_or_default();
                    if check_user_id.is_empty() {
                        error!("user id is null, user_indv = {}", account);
                        continue;
                    }

                    let check_user_login = account.get_first_literal("v-s:login").unwrap_or_default();
                    if check_user_login.is_empty() {
                        warn!("user login {:?} not equal request login {}, skip", check_user_login, login);
                        continue;
                    }

                    if check_user_login.to_lowercase() != login.to_lowercase() {
                        warn!("user login {} not equal request login {}, skip", check_user_login, login);
                        continue;
                    }

                    let mut ticket = Ticket::default();
                    if is_allow_trusted || tr_ticket.user_login.to_lowercase() == check_user_login.to_lowercase() {
                        let addr = if conf.check_ticket_ip {
                            ip.unwrap_or_default()
                        } else {
                            "127.0.0.1"
                        };
                        create_new_ticket(login, &check_user_id, addr, conf.ticket_lifetime, &mut ticket, &mut backend.storage);
                        info!("trusted authenticate, result ticket = {:?}", ticket);

                        return ticket;
                    } else {
                        error!("failed trusted authentication: user {} must be a member of group {} or self", tr_ticket.user_uri, ALLOW_TRUSTED_GROUP);
                    }
                } else {
                    warn!("trusted authenticate: account {} not pass, login {}", check_account_id, login);
                }
            }
        } else {
            error!("failed trusted authentication: not found users for login {}", login);
        }
    } else {
        error!("trusted authenticate: couldn't get a ticket from the database, ticket = {}", tr_ticket_id);
    }

    tr_ticket.result = ResultCode::AuthenticationFailed;
    error!("failed trusted authentication, ticket = {}, login = {:?}", tr_ticket_id, login);

    tr_ticket
}

pub fn get_candidate_users_of_login(login: &str, backend: &mut Backend, xr: &mut XapianReader, auth_data: &mut VStorage) -> QueryResult {
    lazy_static! {
        static ref RE: Regex = Regex::new("[-]").unwrap();
    }

    if let StorageResult::Ok(account_id) = auth_data.get_value(StorageId::Az, &format!("_L:{}", login.to_lowercase())) {
        info!("az.db: found account={}, login={}", account_id, login);
        return QueryResult {
            result: Vec::from([account_id]),
            count: 0,
            estimated: 0,
            processed: 0,
            cursor: 0,
            total_time: 0,
            query_time: 0,
            authorize_time: 0,
            result_code: ResultCode::Ok,
        };
    }

    let query = format!("'v-s:login' == '{}'", RE.replace_all(login, " +"));

    let res = xr.query_use_authorize(FTQuery::new_with_user("cfg:VedaSystem", &query), &mut backend.storage, OptAuthorize::NO, true);

    if res.result_code == ResultCode::Ok && res.result.is_empty() {
        warn!("empty query result, retry");
        return xr.query_use_authorize(FTQuery::new_with_user("cfg:VedaSystem", &query), &mut backend.storage, OptAuthorize::NO, true);
    }

    res
}

pub fn create_new_credential(systicket: &str, module: &mut Backend, credential: &mut Individual, account: &mut Individual) -> bool {
    let password = account.get_first_literal("v-s:password").unwrap_or_default();

    credential.set_id(&(account.get_id().to_owned() + "-crdt"));
    credential.set_uri("rdf:type", "v-s:Credential");
    set_password(credential, &password);

    let res = module.mstorage_api.update(systicket, IndvOp::Put, credential);
    if res.result != ResultCode::Ok {
        error!("failed to update, uri = {}, result_code = {:?}", credential.get_id(), res.result);
        return false;
    } else {
        info!("create v-s:Credential {}, res = {:?}", credential.get_id(), res);

        account.remove("v-s:password");
        account.set_uri("v-s:usesCredential", credential.get_id());

        let res = module.mstorage_api.update(systicket, IndvOp::Put, account);
        if res.result != ResultCode::Ok {
            error!("failed to update, uri = {}, res = {:?}", account.get_id(), res);
            return false;
        }
        info!("update user {}, res = {:?}", account.get_id(), res);
    }
    true
}

pub fn set_password(credential: &mut Individual, password: &str) {
    let n_iter = NonZeroU32::new(N_ITER).unwrap();
    let rng = rand::SystemRandom::new();

    let mut salt = [0u8; CREDENTIAL_LEN];
    if rng.fill(&mut salt).is_ok() {
        let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, n_iter, &salt, password.as_bytes(), &mut pbkdf2_hash);

        debug!("Salt: {}", HEXLOWER.encode(&salt));
        debug!("PBKDF2 hash: {}", HEXLOWER.encode(&pbkdf2_hash));

        credential.set_string("v-s:salt", &HEXLOWER.encode(&salt), Lang::none());
        credential.set_string("v-s:password", &HEXLOWER.encode(&pbkdf2_hash), Lang::none());
    } else {
        credential.set_string("v-s:password", password, Lang::none());
    }
}

pub fn remove_secret(uses_credential: &mut Individual, person_id: &str, module: &mut Backend, systicket: &str) {
    if uses_credential.get_first_literal("v-s:secret").is_some() {
        uses_credential.remove("v-s:secret");

        let res = module.mstorage_api.update(systicket, IndvOp::Put, uses_credential);
        if res.result != ResultCode::Ok {
            error!("failed to remove secret code for user, user = {}", person_id);
        }
    }
}

pub fn read_duration_param(indv: &mut Individual, param: &str) -> Option<std::time::Duration> {
    if let Some(v) = indv.get_first_literal(param) {
        if let Ok(d) = parse(&v) {
            return Some(d);
        } else {
            error!("failed to parse auth param {}", param);
        }
    }
    None
}

pub fn read_auth_configuration(backend: &mut Backend) -> AuthConf {
    let mut res = AuthConf::default();

    res.check_ticket_ip = Module::get_property::<String>("check_ticket_ip").unwrap_or_default().parse::<bool>().unwrap_or(true);

    if let Some(mut node) = backend.get_individual_s("cfg:standart_node") {
        if let Some(d) = read_duration_param(&mut node, "cfg:user_password_lifetime") {
            res.pass_lifetime = d.as_secs() as i64;
        }
        if let Some(d) = read_duration_param(&mut node, "cfg:user_ticket_lifetime") {
            res.ticket_lifetime = d.as_secs() as i64;
        }
        if let Some(d) = read_duration_param(&mut node, "cfg:secret_lifetime") {
            res.secret_lifetime = d.as_secs() as i64;
        }
        if let Some(d) = read_duration_param(&mut node, "cfg:failed_pass_change_lock_period") {
            res.failed_pass_change_lock_period = d.as_secs() as i64;
        }
        if let Some(d) = read_duration_param(&mut node, "cfg:success_pass_change_lock_period") {
            res.success_pass_change_lock_period = d.as_secs() as i64;
        }
        if let Some(d) = read_duration_param(&mut node, "cfg:failed_auth_lock_period") {
            res.failed_auth_lock_period = d.as_secs() as i64;
        }
        if let Some(v) = node.get_first_integer("cfg:failed_auth_attempts") {
            res.failed_auth_attempts = v as i32;
        }
        if let Some(v) = node.get_first_integer("cfg:failed_change_pass_attempts") {
            res.failed_change_pass_attempts = v as i32;
        }

        // SMS configuration
        if let Some(d) = read_duration_param(&mut node, "cfg:sms_rate_limit_period") {
            res.sms_rate_limit_seconds = d.as_secs() as i64;
        }
        if let Some(v) = node.get_first_integer("cfg:sms_daily_limit") {
            res.sms_daily_limit = v as i32;
        }
        if let Some(v) = node.get_first_integer("cfg:sms_code_min") {
            res.sms_code_min = v as u32;
        }
        if let Some(v) = node.get_first_integer("cfg:sms_code_max") {
            res.sms_code_max = v as u32;
        }

        if let Some(v) = node.get_first_literal("cfg:expired_pass_notification_template") {
            if let Some(mut i) = backend.get_individual_s(&v) {
                if let Some(ss) = i.get_first_literal("v-s:notificationSubject") {
                    if let Some(sb) = i.get_first_literal("v-s:notificationBody") {
                        res.expired_pass_notification_template = Some((ss, sb));
                    }
                }
            }
        }

        if let Some(v) = node.get_first_literal("cfg:denied_password_expired_notification_template") {
            if let Some(mut i) = backend.get_individual_s(&v) {
                if let Some(ss) = i.get_first_literal("v-s:notificationSubject") {
                    if let Some(sb) = i.get_first_literal("v-s:notificationBody") {
                        res.denied_password_expired_notification_template = Some((ss, sb));
                    }
                }
            }
        }
    }

    info!("read configuration: {:?}", res);

    res
}

pub fn create_new_ticket(login: &str, user_id: &str, addr: &str, duration: i64, ticket: &mut Ticket, storage: &mut VStorage) {
    if addr.parse::<IpAddr>().is_err() {
        error!("fail create_new_ticket: invalid ip {}", addr);
        return;
    }

    let mut ticket_indv = Individual::default();

    ticket.result = ResultCode::FailStore;
    ticket_indv.add_string("rdf:type", "ticket:ticket", Lang::none());

    if !ticket.id.is_empty() && !ticket.id.is_empty() {
        ticket_indv.set_id(&ticket.id);
    } else {
        ticket_indv.set_id(&Uuid::new_v4().hyphenated().to_string());
    }

    ticket_indv.add_string("ticket:login", login, Lang::none());
    ticket_indv.add_string("ticket:accessor", user_id, Lang::none());
    ticket_indv.add_string("ticket:addr", addr, Lang::none());

    let now = Utc::now();
    let start_time_str = format!("{:?}", now.naive_utc());

    if start_time_str.len() > 28 {
        ticket_indv.add_string("ticket:when", &start_time_str[0..28], Lang::none());
    } else {
        ticket_indv.add_string("ticket:when", &start_time_str, Lang::none());
    }

    ticket_indv.add_string("ticket:duration", &duration.to_string(), Lang::none());

    if store(&ticket_indv, storage) {
        ticket.update_from_individual(&mut ticket_indv);
        ticket.result = ResultCode::Ok;
        ticket.start_time = (TICKS_TO_UNIX_EPOCH + now.timestamp_millis()) * 10_000;
        ticket.end_time = ticket.start_time + duration * 10_000_000;

        let end_time_str = if let Some(end_time_dt) = DateTime::from_timestamp((ticket.end_time / 10_000 - TICKS_TO_UNIX_EPOCH) / 1_000, 0) {
            format!("{:?}", end_time_dt.naive_utc())
        } else {
            "Invalid timestamp".to_string()
        };
        info!("create new ticket {}, login={}, user={}, addr={}, start={}, end={}", ticket.id, ticket.user_login, ticket.user_uri, addr, start_time_str, end_time_str);
    } else {
        error!("fail store ticket {:?}", ticket)
    }
}

pub fn create_sys_ticket(storage: &mut VStorage) -> Ticket {
    let mut ticket = Ticket::default();
    create_new_ticket("veda", "cfg:VedaSystem", "127.0.0.1", 90_000_000, &mut ticket, storage);

    if ticket.result == ResultCode::Ok {
        let mut sys_ticket_link = Individual::default();
        sys_ticket_link.set_id("systicket");
        sys_ticket_link.add_uri("rdf:type", "rdfs:Resource");
        sys_ticket_link.add_uri("v-s:resource", &ticket.id);
        if store(&sys_ticket_link, storage) {
            return ticket;
        } else {
            error!("fail store system ticket link")
        }
    } else {
        error!("fail create sys ticket")
    }

    ticket
}

fn store(ticket_indv: &Individual, storage: &mut VStorage) -> bool {
    let mut raw1: Vec<u8> = Vec::new();
    if to_msgpack(ticket_indv, &mut raw1).is_ok() {
        if matches!(storage.put_raw_value(StorageId::Tickets, ticket_indv.get_id(), raw1), StorageResult::Ok(_)) {
            return true;
        }
    }
    false
}

#[allow(dead_code)]
pub fn send_notification_email(
    template: &(String, String),
    mailbox: &str,
    user_name: &str,
    secret_code: Option<&str>,
    sys_ticket: &str,
    backend: &mut Backend,
) -> ResultCode {
    if mailbox.is_empty() || mailbox.len() <= 3 {
        error!("mailbox not found or invalid: {}", mailbox);
        return ResultCode::AuthenticationFailed;
    }

    let now = Utc::now().timestamp();
    let app_name = match backend.get_individual_s("v-s:vedaInfo") {
        Some(mut app_info) => {
            app_info.parse_all();
            app_info.get_first_literal("rdfs:label").unwrap_or_else(|| "Veda".to_string())
        },
        None => "Veda".to_string(),
    };

    let mut map_builder = MapBuilder::new().insert_str("app_name", app_name).insert_str("user_name", user_name);

    if let Some(code) = secret_code {
        map_builder = map_builder.insert_str("secret_code", code);
    }

    let map = map_builder.build();

    let (subject_t_str, body_t_str) = template;

    let mut subject = vec![];
    if let Ok(t) = mustache::compile_str(subject_t_str) {
        if let Err(e) = t.render_data(&mut subject, &map) {
            error!("failed to render subject from template, err = {:?}", e);
        }
    }

    let mut body = vec![];
    if let Ok(t) = mustache::compile_str(body_t_str) {
        if let Err(e) = t.render_data(&mut body, &map) {
            error!("failed to render body from template, err = {:?}", e);
        }
    }

    let mut new_mail = Individual::default();
    let uuid1 = "d:mail_".to_owned() + &Uuid::new_v4().to_string();
    new_mail.set_id(&uuid1);
    new_mail.add_uri("rdf:type", "v-s:Email");
    new_mail.add_string("v-s:recipientMailbox", mailbox, Lang::none());
    new_mail.add_datetime("v-s:created", now);
    new_mail.add_uri("v-s:creator", "cfg:VedaSystemAppointment");
    new_mail.add_uri("v-wf:from", "cfg:VedaSystemAppointment");
    new_mail.add_string("v-s:subject", from_utf8(subject.as_slice()).unwrap_or_default(), Lang::none());
    new_mail.add_string("v-s:messageBody", from_utf8(body.as_slice()).unwrap_or_default(), Lang::none());

    let res = backend.mstorage_api.update(sys_ticket, IndvOp::Put, &new_mail);
    if res.result != ResultCode::Ok {
        error!("failed to store email, id = {}", new_mail.get_id());
        ResultCode::AuthenticationFailed
    } else {
        info!("sent email {} to mailbox {}", new_mail.get_id(), mailbox);
        ResultCode::Ok
    }
}
