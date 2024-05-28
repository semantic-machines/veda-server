#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

mod auth;
mod common;

use crate::auth::*;
use crate::common::{create_sys_ticket, get_ticket_trusted, logout, read_auth_configuration, AuthConf, UserStat};
use nng::options::{Options, RecvTimeout, SendTimeout};
use nng::{Error, Message, Protocol, Socket};
use serde_json::json;
use serde_json::value::Value as JSONValue;
use std::collections::HashMap;
use std::time::Duration;
use v_common::az_impl::az_lmdb::LmdbAzContext;
use v_common::ft_xapian::xapian_reader::XapianReader;
use v_common::init_module_log;
use v_common::module::module_impl::{init_log, Module};
use v_common::module::veda_backend::Backend;
use v_common::storage::common::{StorageMode, VStorage};

const TIMEOUT_RECV: u64 = 30;
const TIMEOUT_SEND: u64 = 60;

fn main() -> std::io::Result<()> {
    init_module_log!("AUTH");

    let auth_url = Module::get_property::<String>("auth_url").expect("param [auth_url] not found in veda.properties");

    let mut backend = Backend::create(StorageMode::ReadWrite, false);
    info!("connect to AUTHORIZE DB...");
    let mut auth_data = VStorage::new_lmdb("./data", StorageMode::ReadOnly, None);

    let systicket = if let Ok(t) = backend.get_sys_ticket_id() {
        t
    } else {
        error!("failed to get system ticket, create new");
        create_sys_ticket(&mut backend.storage).id
    };

    let mut suspicious: HashMap<String, UserStat> = HashMap::new();

    let conf = read_auth_configuration(&mut backend);

    let mut az = LmdbAzContext::new(1000);

    let mut count = 0;
    if let Some(mut xr) = XapianReader::new("russian", &mut backend.storage) {
        loop {
            info!("init");
            let server = Socket::new(Protocol::Rep0)?;

            if let Err(e) = server.set_opt::<RecvTimeout>(Some(Duration::from_secs(TIMEOUT_RECV))) {
                error!("failed to set recv timeout, url = {}, err = {}", auth_url, e);
                return Ok(());
            }
            if let Err(e) = server.set_opt::<SendTimeout>(Some(Duration::from_secs(TIMEOUT_SEND))) {
                error!("failed to set send timeout, url = {}, err = {}", auth_url, e);
                return Ok(());
            }

            if let Err(e) = server.listen(&auth_url) {
                error!("failed to listen, err = {:?}", e);
                return Ok(());
            }
            info!("start listen {}", auth_url);

            loop {
                match server.recv() {
                    Ok(recv_msg) => {
                        count += 1;

                        let res = req_prepare(&conf, &recv_msg, &systicket, &mut xr, &mut backend, &mut suspicious, &mut auth_data, &mut az);
                        if let Err(e) = server.send(res) {
                            error!("failed to send, err = {:?}", e);
                        }
                    },
                    Err(e) => match e {
                        Error::TimedOut => {
                            info!("receive timeout, total prepared requests: {}", count);
                            break;
                        },
                        _ => {
                            error!("failed to get request, err = {:?}", e);
                            break;
                        },
                    },
                }
            }
            info!("close");
            server.close();
        }
    } else {
        error!("failed to init ft-query");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn req_prepare(
    conf: &AuthConf,
    request: &Message,
    systicket: &str,
    xr: &mut XapianReader,
    backend: &mut Backend,
    suspicious: &mut HashMap<String, UserStat>,
    auth_data: &mut VStorage,
    az: &mut LmdbAzContext,
) -> Message {
    let v: JSONValue = if let Ok(v) = serde_json::from_slice(request.as_slice()) {
        v
    } else {
        JSONValue::Null
    };

    match v["function"].as_str().unwrap_or_default() {
        "authenticate" => {
            let login = v["login"].as_str().unwrap_or_default();
            let password = v["password"].as_str().unwrap_or_default();
            let secret = v["secret"].as_str().unwrap_or_default();
            let ip = v["addr"].as_str().unwrap_or_default();

            let user_stat = suspicious.entry(login.to_owned()).or_default();

            let mut ah = AuthWorkPlace {
                conf,
                login,
                password,
                ip,
                secret,
                sys_ticket: systicket,
                xr,
                backend,
                auth_data,
                user_stat,
                stored_password: "".to_owned(),
                stored_salt: "".to_string(),
                edited: 0,
                credential: &mut Default::default(),
                is_permanent: false,
                origin: "VEDA".to_string(),
            };

            let ticket = ah.authenticate();

            info!("{:?}", ticket);

            let mut res = JSONValue::default();
            res["type"] = json!("ticket");
            res["id"] = json!(ticket.id);
            res["user_uri"] = json!(ticket.user_uri);
            res["user_login"] = json!(ticket.user_login);
            res["result"] = json!(ticket.result as i64);
            res["end_time"] = json!(ticket.end_time);
            res["auth_origin"] = json!(ah.origin);

            return Message::from(res.to_string().as_bytes());
        },
        "get_ticket_trusted" => {
            let ticket = get_ticket_trusted(conf, v["ticket"].as_str(), v["login"].as_str(), v["addr"].as_str(), xr, backend, auth_data, az);

            let mut res = JSONValue::default();
            res["type"] = json!("ticket");
            res["id"] = json!(ticket.id);
            res["user_uri"] = json!(ticket.user_uri);
            res["user_login"] = json!(ticket.user_login);
            res["result"] = json!(ticket.result as i64);
            res["end_time"] = json!(ticket.end_time);

            return Message::from(res.to_string().as_bytes());
        },
        "logout" => {
            let ticket = logout(conf, v["ticket"].as_str(), v["addr"].as_str(), backend);

            let mut res = JSONValue::default();
            res["type"] = json!("ticket");
            res["id"] = json!(ticket.id);
            res["result"] = json!(ticket.result as i64);
            res["end_time"] = json!(ticket.end_time);

            return Message::from(res.to_string().as_bytes());
        },
        _ => {
            error!("unknown command {:?}", v["function"].as_str());
        },
    }

    Message::default()
}
