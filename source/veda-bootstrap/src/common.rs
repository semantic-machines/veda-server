use crate::app::App;
use chrono::prelude::*;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use reqwest::Client;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Child, Command};
use std::str::FromStr;
use std::time::Duration;
use std::{fs, io, thread, time};
use sysinfo::{ProcessExt, ProcessStatus, SystemExt};
use teloxide::prelude::*;
use teloxide::types::Recipient;
use v_common::module::info::ModuleInfo;
use v_common::v_api::api_client::IndvOp;
use v_common::v_api::common_type::ResultCode;
use v_individual_model::onto::individual::Individual;

pub const MSTORAGE_ID: i64 = 1;

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum ModuleError {
    Fatal = 101,
    MemoryLimit = 102,
}

// Причины перезапуска модулей для уведомлений в Telegram
#[derive(Debug, Clone)]
pub enum RestartReason {
    ProcessDead(i32),           // Процесс умер, код выхода
    MemoryLimit(u64, u64),      // Превышен лимит памяти (текущая, лимит)
    WatchdogTimeout,            // Превышен таймаут watchdog
    QueueStuck,                 // Зависание по анализу очередей
    PingFailed(String),         // Не отвечает на ping (модуль)
    MstorageNotReady,           // Модуль mstorage не готов
    ConfigurationRemoved,       // Модуль удален из конфигурации
}

impl RestartReason {
    pub fn to_telegram_message(&self, module_name: &str) -> String {
        match self {
            RestartReason::ProcessDead(exit_code) => {
                format!("🔄 Restarting module {} — process exited (code: {})", module_name, exit_code)
            },
            RestartReason::MemoryLimit(current, limit) => {
                format!("🔄 Restarting module {} — memory limit exceeded ({} KiB > {} KiB)", module_name, current, limit)
            },
            RestartReason::WatchdogTimeout => {
                format!("🔄 Restarting module {} — watchdog timeout exceeded", module_name)
            },
            RestartReason::QueueStuck => {
                format!("🔄 Restarting module {} — stuck by queue analysis", module_name)
            },
            RestartReason::PingFailed(module) => {
                format!("🔄 Restarting module {} — ping failed ({})", module_name, module)
            },
            RestartReason::MstorageNotReady => {
                format!("🔄 Restarting module {} — mstorage not ready", module_name)
            },
            RestartReason::ConfigurationRemoved => {
                format!("🛑 Stopping module {} — removed from configuration", module_name)
            },
        }
    }

    pub fn to_success_message(&self, module_name: &str) -> String {
        match self {
            RestartReason::ProcessDead(_) => {
                format!("✅ Module {} successfully restarted after process exit", module_name)
            },
            RestartReason::MemoryLimit(_, _) => {
                format!("✅ Module {} successfully restarted after memory limit exceeded", module_name)
            },
            RestartReason::WatchdogTimeout => {
                format!("✅ Module {} successfully restarted after watchdog timeout", module_name)
            },
            RestartReason::QueueStuck => {
                format!("✅ Module {} successfully restarted after queue stuck", module_name)
            },
            RestartReason::PingFailed(_) => {
                format!("✅ Module {} successfully restarted after ping failure", module_name)
            },
            RestartReason::MstorageNotReady => {
                format!("✅ Module {} successfully restarted after mstorage recovery", module_name)
            },
            RestartReason::ConfigurationRemoved => {
                format!("✅ Module {} successfully stopped", module_name)
            },
        }
    }
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
    pub(crate) prev_err: Option<ModuleError>,
    pub(crate) queue_check_enabled: bool,
    pub(crate) queue_check_period: Option<std::time::Duration>,
    pub(crate) queue_growth_threshold: u32,        // Абсолютный порог роста (задач за период)
    pub(crate) queue_growth_percentage: u32,       // Процентный порог роста (% от размера очереди)
}

#[derive(Clone)]
pub struct TelegramDest {
    pub(crate) tg_notify_token: String,
    pub(crate) tg_notify_chat_id: i64,
    pub(crate) sender_name: String,
}

pub fn auth_watchdog_check(app: &mut App) -> bool {
    // PING (use function logout)

    let res = match app.backend.auth_api.logout(&None, Some(IpAddr::from_str("127.0.0.1").unwrap())) {
        Ok(_) => true,
        Err(e) => {
            if e.result == ResultCode::AuthenticationFailed {
                true
            } else {
                false
            }
        }
    };
    res
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
    send_msg_to_tg(tg, &format!("🔴 {}", text)).await;
}

pub async fn log_info_and_to_tg(tg: &Option<TelegramDest>, text: &str) {
    info!("{}", text);
    send_msg_to_tg(tg, text).await;
}

pub async fn send_msg_to_tg(tg: &Option<TelegramDest>, text: &str) {
    if let Some(t) = tg {
        // Create a custom reqwest Client with a timeout
        let client = Client::builder()
            .timeout(Duration::from_secs(30)) // Set timeout to 30 seconds
            .build()
            .unwrap();

        // Create a new Bot instance with the custom reqwest Client
        let bot = Bot::with_client(t.tg_notify_token.to_owned(), client);
        let chat_id = Recipient::Id(ChatId(t.tg_notify_chat_id));

        if let Err(e) = bot.send_message(chat_id, format!("|{}| {}", t.sender_name, text)).await {
            error!("fail send message to telegram: err={:?}", e);
        }
    }
}

pub async fn start_module(module: &mut VedaModule) -> io::Result<Child> {
    let datetime: DateTime<Local> = Local::now();

    // Создаем директорию для логов, если она не существует
    fs::create_dir_all("./logs").unwrap_or_default();

    // Формируем путь для лог-файла
    let log_path = format!("./logs/veda-{}-{}.log", module.alias_name, datetime.format("%Y-%m-%d %H:%M:%S.%f"));

    // Создаем один файл для логирования stdout и stderr
    let log_file = File::create(&log_path)?;

    // Клонируем файл, чтобы записывать в него и stdout, и stderr
    let child = Command::new(&module.exec_name)
        .stdout(log_file.try_clone()?)  // Используем клон для stdout
        .stderr(log_file)               // Используем тот же файл для stderr
        .args(&module.args)
        .spawn();

    match child {
        Ok(p) => {
            // Логирование успешного запуска
            info!("START *** {}", module.alias_name);
            info!("module exec path = {}", module.exec_name);

            // Логирование аргументов, если они есть
            if !&module.args.is_empty() {
                info!("args = {:?}", &module.args);
            }

            // Логирование ограничения памяти, если оно указано
            if let Some(v) = &module.memory_limit {
                info!("memory-limit = {} Kb", v);
            }

            // Логирование watchdog timeout, если указан
            if let Some(v) = &module.watchdog_timeout {
                info!("watchdog_timeout = {} s", v);
            }

            // Записываем PID процесса в файл
            if let Ok(mut file) = File::create(".pids/__".to_owned() + &module.alias_name + "-pid") {
                if let Err(e) = file.write_all(format!("{}", p.id()).as_bytes()) {
                    error!("failed to create pid file, module = {}, process = {}, err = {:?}", &module.alias_name, p.id(), e);
                }
            }

            // Дополнительная задержка для модуля "mstorage"
            if module.alias_name == "mstorage" {
                thread::sleep(time::Duration::from_millis(100));
            }

            module.prev_err = None;
            Ok(p)
        },
        Err(e) => Err(e),
    }
}

// Метод для остановки процесса по его имени и идентификатору
pub fn stop_process(process_id: i32, process_name: &str) -> bool {
    if signal::kill(Pid::from_raw(process_id), Signal::SIGTERM).is_ok() {
        warn!("attempt to stop module, process = {}, name = {}", process_id, process_name);
        true
    } else {
        false
    }
}
