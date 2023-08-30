use crate::app::App;
use chrono::prelude::*;
use std::fs::File;
use std::io::Write;
use std::process::{Child, Command};
use std::{fs, io, thread, time};
use sysinfo::{ProcessExt, ProcessStatus, SystemExt};
use teloxide::prelude::*;
use teloxide::types::Recipient;
use v_common::module::info::ModuleInfo;
use v_common::onto::individual::Individual;
use v_common::v_api::api_client::IndvOp;
use v_common::v_api::obj::ResultCode;

pub const MSTORAGE_ID: i64 = 1;

#[derive(Debug)]
#[repr(u8)]
pub enum ModuleError {
    Fatal = 101,
    //Recoverable = 102,
}

#[derive(Debug)]
pub struct VedaModule {
    pub(crate) alias_name: String,
    pub(crate) exec_name: String,
    pub(crate) args: Vec<String>,
    pub(crate) module_name: String,
    pub(crate) memory_limit: Option<u64>,
    pub(crate) order: u32,
    pub(crate) watchdog_timeout: Option<u64>,
    pub(crate) module_info: Option<ModuleInfo>,
}

pub struct TelegramDest {
    pub(crate) tg_notify_token: String,
    pub(crate) tg_notify_chat_id: i64,
}

pub fn auth_watchdog_check(app: &mut App) -> bool {
    while !app.backend.auth_api.connect() {
        info!("waiting for auth module start...");
        thread::sleep(std::time::Duration::from_millis(100));
    }

    // PING (use function logout)
    if let Err(e) = app.backend.auth_api.logout(&None, None) {
        if e.result == ResultCode::AuthenticationFailed {
            return true;
        }
    }
    false
}

pub fn mstorage_watchdog_check(app: &mut App) -> bool {
    let sys_ticket = app.get_sys_ticket().to_string();

    while !app.backend.mstorage_api.connect() {
        info!("waiting for main module start...");
        thread::sleep(std::time::Duration::from_millis(100));
    }

    let test_indv_id = "cfg:watchdog_test";
    let mut test_indv = Individual::default();
    test_indv.set_id(test_indv_id);
    test_indv.set_uri("rdf:type", "v-s:resource");
    if app.backend.mstorage_api.update_use_param(&sys_ticket, "", "", MSTORAGE_ID, IndvOp::Put, &test_indv).is_err() {
        error!("failed to store test individual, uri = {}", test_indv_id);
        return false;
    }
    true
}

pub fn is_ok_process(sys: &mut sysinfo::System, pid: u32) -> (bool, u64) {
    if let Some(proc) = sys.get_process(pid as i32) {
        match proc.status() {
            ProcessStatus::Idle => (true, proc.memory()),
            ProcessStatus::Run => (true, proc.memory()),
            ProcessStatus::Sleep => (true, proc.memory()),
            _ => (false, proc.memory()),
        }
    } else {
        (false, 0)
    }
}

pub async fn log_err_and_to_tg(tg: &Option<TelegramDest>, text: &str) {
    error!("{}", text);
    send_msg_to_tg(tg, &format!("ERROR: {}", text)).await;
}

pub async fn send_msg_to_tg(tg: &Option<TelegramDest>, text: &str) {
    if let Some(t) = tg {
        let bot = Bot::new(t.tg_notify_token.to_owned()).auto_send();
        let chat_id = Recipient::Id(ChatId(t.tg_notify_chat_id));

        if let Err(e) = bot.send_message(chat_id, text).await {
            error!("fail send message to telegram: err={:?}", e);
        }
    }
}

pub async fn start_module(module: &VedaModule) -> io::Result<Child> {
    let datetime: DateTime<Local> = Local::now();

    fs::create_dir_all("./logs").unwrap_or_default();

    let log_path = "./logs/veda-".to_owned() + &module.alias_name + "-" + &datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string() + ".log";
    let std_log_file = File::create(&log_path);
    let err_log_file = File::create(log_path);

    let mut args = module.args.clone();
    args.push(format!("--module-name={}", module.alias_name));

    let child = Command::new(&module.exec_name).stdout(std_log_file.unwrap()).stderr(err_log_file.unwrap()).args(&args).spawn();

    match child {
        Ok(p) => {
            info!("START *** {}", module.alias_name);
            info!("module exec path = {}", module.exec_name);

            if !&module.args.is_empty() {
                info!("args = {:?}", &module.args);
            }

            if let Some(v) = &module.memory_limit {
                info!("memory-limit = {} Kb", v);
            }

            if let Some(v) = &module.watchdog_timeout {
                info!("watchdog_timeout = {} s", v);
            }

            if let Ok(mut file) = File::create(".pids/__".to_owned() + &module.alias_name + "-pid") {
                if let Err(e) = file.write_all(format!("{}", p.id()).as_bytes()) {
                    error!("failed to create pid file, module = {}, process = {}, err = {:?}", &module.alias_name, p.id(), e);
                }
            }
            if module.alias_name == "mstorage" {
                thread::sleep(time::Duration::from_millis(100));
            }
            Ok(p)
        },
        Err(e) => Err(e),
    }
}
