#[macro_use]
extern crate log;

use crate::app::App;
use crate::common::{log_err_and_to_tg, TelegramDest};
use chrono::prelude::*;
use env_logger::Builder;
use log::LevelFilter;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::process;
use sysinfo::{get_current_pid, ProcessExt, SystemExt};
use v_common::module::module_impl::Module;

mod app;
mod common;

#[tokio::main]
async fn main() {
    let env_var = "RUST_LOG";
    match std::env::var_os(env_var) {
        Some(val) => println!("use env var: {}: {:?}", env_var, val.to_str()),
        None => std::env::set_var(env_var, "info"),
    }

    let app_dir = if let Ok(s) = std::env::var("APPDIR") {
        s.as_str().to_string() + "/"
    } else {
        "./".to_string()
    };

    Builder::new()
        .format(|buf, record| writeln!(buf, "{} [{}] - {}", Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"), record.level(), record.args()))
        .filter(None, LevelFilter::Info)
        .init();

    info!("app dir = {}", app_dir);
    let mut app = App {
        date_changed_modules_info: None,
        app_dir,
        modules_info: HashMap::new(),
        modules_start_order: vec![],
        started_modules: vec![],
        backend: Default::default(),
        sys_ticket: "".to_string(),
        tg: None,
    };

    if let (Some(v), Some(t)) = (Module::get_property("tg_notify_chat_id"), Module::get_property("tg_notify_token")) {
        if let Ok(d) = v.parse::<i64>() {
            app.tg = Some(TelegramDest {
                tg_notify_token: t,
                tg_notify_chat_id: d,
            });
        }
    } else {
        warn!("sending notifications to Telegram is not available.");
    }

    if let Err(e) = app.get_modules_info() {
        error!("failed to read modules info, err = {:?}", e);
        return;
    }

    let mut sys = sysinfo::System::new();
    sys.refresh_processes();

    let current_proc = sys.get_process(get_current_pid().unwrap()).unwrap();
    let current_user = current_proc.uid;

    for (pid, proc) in sys.get_processes() {
        if *pid == current_proc.pid() || current_user != proc.uid {
            continue;
        }

        if proc.name().starts_with("veda-") && app.modules_info.values().map(|x| x.exec_name[2..].to_string()).any(|x| x == *proc.name()) {
            error!("failed to start, found other running process, pid = {}, {:?} ({:?}) ", pid, proc.exe(), proc.status());
            return;
        }
    }

    let started = app.start_modules().await;
    if started.is_err() {
        log_err_and_to_tg(&app.tg, &format!("failed to start veda, err = {:?}", &started.err())).await;
        return;
    }

    if let Ok(mut file) = File::create(".pids/__".to_owned() + "bootstrap-pid") {
        if let Err(e) = file.write_all(format!("{}", process::id()).as_bytes()) {
            error!("failed to create pid file for bootstrap, id = {}, err = {:?}", process::id(), e);
        }
    }

    app.watch_started_modules().await;
    //info!("started {:?}", started);
}
