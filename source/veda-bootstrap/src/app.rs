use crate::common::{auth_watchdog_check, is_ok_process, log_err_and_to_tg, mstorage_watchdog_check, start_module, stop_process, TelegramDest, VedaModule, RestartReason};
use chrono::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::Child;
use std::time::SystemTime;
use std::time::{Duration, UNIX_EPOCH};
use std::{fs, io, thread, time};
use sysinfo::SystemExt;
use v_common::module::module_impl::Module;
use v_common::module::veda_backend::Backend;
use crate::queue_check::{QueueChecker};

pub struct App {
    pub(crate) name: String,
    pub(crate) app_dir: String,
    pub(crate) time_changed_modules_info: Option<SystemTime>,
    pub(crate) modules_info: HashMap<String, VedaModule>,
    pub(crate) modules_start_order: Vec<String>,
    pub(crate) started_modules: Vec<(String, Child)>,
    pub(crate) backend: Backend,
    sys_ticket: String,
    tg: Option<TelegramDest>,
    time_changed_properties: Option<SystemTime>,
}

impl App {
    pub(crate) fn new() -> Self {
        App {
            name: "VEDA".to_string(),
            time_changed_modules_info: None,
            app_dir: "".to_string(),
            modules_info: HashMap::new(),
            modules_start_order: vec![],
            started_modules: vec![],
            backend: Default::default(),
            sys_ticket: "".to_string(),
            tg: None,
            time_changed_properties: None,
        }
    }

    pub(crate) fn get_tg_dest(&mut self) -> Option<TelegramDest> {
        match self.properties_were_modified() {
            Ok(were_modified) => {
                if were_modified {
                    let chat_id_opt = self.get_property("tg_notify_chat_id").and_then(|v| v.parse::<i64>().ok());
                    let token_opt = self.get_property("tg_notify_token");

                    if let (Some(chat_id), Some(token)) = (chat_id_opt, token_opt) {
                        self.tg = Some(TelegramDest {
                            tg_notify_token: token,
                            tg_notify_chat_id: chat_id,
                            sender_name: self.name.clone(),
                        });
                    } else {
                        warn!("sending notifications to Telegram is not available.");
                    }
                }
            },
            Err(e) => error!("{:?}", e),
        }

        self.tg.clone()
    }

    pub(crate) async fn start_modules(&mut self) -> io::Result<()> {
        for name in self.modules_start_order.iter() {
            //info!("start {:?}", module);
            let module = self.modules_info.get_mut(name).unwrap();
            match start_module(module).await {
                Ok(child) => {
                    info!("pid = {}", child.id());
                    self.started_modules.push((module.alias_name.to_owned(), child));
                },
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, format!("failed to execute {}, err = {:?}", module.exec_name, e)));
                },
            }
        }

        let mut sys = sysinfo::System::new();
        thread::sleep(time::Duration::from_millis(500));
        sys.refresh_processes();

        let mut success_started = 0;
        for (name, process) in self.started_modules.iter() {
            if is_ok_process(&mut sys, process.id()).0 {
                success_started += 1;
            } else {
                log_err_and_to_tg(&self.tg, &format!("failed to start, process = {}, name = {}", process.id(), name)).await;
            }
        }

        if success_started < self.started_modules.len() {
            for (name, process) in self.started_modules.iter_mut() {
                stop_process(process.id() as i32, name);
            }

            return Err(Error::new(ErrorKind::Other, "failed to start"));
        }

        Ok(())
    }

    // Проверка каждого модуля на основе обращения к нему
    async fn check_modules_based_on_call(
        &mut self,
        watchdog_check_periods: &HashMap<String, Duration>,
        prev_check_times: &mut HashMap<String, i64>,
        module_check_results: &mut HashMap<String, bool>,
    ) {
        for (module_name, period) in watchdog_check_periods {
            let now = Utc::now().timestamp();
            if now - *prev_check_times.get(module_name).unwrap_or(&now) > period.as_secs() as i64 {
                prev_check_times.insert(module_name.to_string(), now);

                let check_result = if module_name == "mstorage" {
                    Some(mstorage_watchdog_check(self))
                } else if module_name == "auth" {
                    Some(auth_watchdog_check(self))
                } else {
                    None
                };

                if let Some(c) = check_result {
                    module_check_results.insert(module_name.to_string(), c);
                    if !c {
                        let restart_reason = RestartReason::PingFailed(module_name.clone());
                        log_err_and_to_tg(&self.tg, &restart_reason.to_telegram_message(module_name)).await;
                    }
                }
            }
        }

        for (module_name, process) in self.started_modules.iter_mut() {
            if let Some(r) = module_check_results.get(&module_name.to_string()) {
                if !r {
                    let mut sys = sysinfo::System::new();
                    sys.refresh_processes();
                    stop_process(process.id() as i32, module_name);
                }
            }
        }
    }

    // Запуск новых модулей из конфигурации
    async fn start_new_modules_from_config(&mut self, new_config_modules: &HashSet<String>) {
        for name in new_config_modules {
            if let Some(module) = self.modules_info.get_mut(name) {
                match start_module(module).await {
                    Ok(child) => {
                        info!("{} start module {}, {}, {:?}", child.id(), module.alias_name, module.exec_name, module.args);
                        self.started_modules.push((module.alias_name.to_owned(), child));
                    },
                    Err(e) => {
                        log_err_and_to_tg(&self.tg, &format!("failed to execute, name = {}, err = {:?}", module.exec_name, e)).await;
                    },
                }
            }
        }
    }

    // Проверка на зависшие модули на основе анализа очередей
    async fn check_stuck_modules_by_queue_analysis(&mut self, sys: &mut sysinfo::System) {
        let mut queue_checker = QueueChecker::new(
            "./data/queue".to_string(),
            "./data/queue_stats.json".to_string()
        );
        
        let tg_dest = self.get_tg_dest();
        
        for (name, process) in self.started_modules.iter_mut() {
            if let Some(module) = self.modules_info.get_mut(name) {
                // Сначала проверяем состояние очереди конкретного модуля
                let queue_status = queue_checker.check_single_module_queue_status(module, &tg_dest).await;
                
                // Затем проверяем на зависание, используя полученные данные
                if QueueChecker::check_module_stuck(module, process.id(), sys, queue_status, &tg_dest).await {
                    let restart_reason = RestartReason::QueueStuck;
                    log_err_and_to_tg(&tg_dest, &restart_reason.to_telegram_message(name)).await;
                    
                    // Останавливаем зависший процесс
                    stop_process(process.id() as i32, name);
                    
                    // Пытаемся перезапустить модуль
                    match start_module(module).await {
                        Ok(child) => {
                            info!("{} restart stuck module {}, {}", child.id(), module.alias_name, module.exec_name);
                            *process = child;
                            log_err_and_to_tg(&tg_dest, &restart_reason.to_success_message(name)).await;
                        },
                        Err(e) => {
                            log_err_and_to_tg(&tg_dest, &format!("❌ Failed to restart stuck module {}: {:?}", name, e)).await;
                        },
                    }
                }
            }
        }
    }

    pub(crate) async fn watch_started_modules(&mut self) {
        let (watchdog_check_periods, mut prev_check_times) = initialize_watchdog_data();

        loop {
            let mut new_config_modules = HashSet::new();

            if let Err(e) = self.get_modules_info() {
                if e.kind() != ErrorKind::NotFound {
                    log_err_and_to_tg(&self.tg, "failed to read modules info").await;
                }
            }

            for el in self.modules_start_order.iter() {
                new_config_modules.insert(el.to_owned());
            }

            let mut module_check_results = Default::default();
            self.check_modules_based_on_call(&watchdog_check_periods, &mut prev_check_times, &mut module_check_results).await;

            let mstorage_ready = *module_check_results.get("mstorage").unwrap_or(&true);
            if !mstorage_ready {
                log_err_and_to_tg(&self.tg, "detected a problem in module MSTORAGE, restart all modules").await;
            }

            self.check_started_processes(mstorage_ready, &mut new_config_modules).await;

            self.start_new_modules_from_config(&new_config_modules).await;

            // Проверяем на зависшие модули через анализ очередей (только если mstorage готов)
            if mstorage_ready {
                let mut sys = sysinfo::System::new();
                sys.refresh_processes();
                self.check_stuck_modules_by_queue_analysis(&mut sys).await;
            }

            thread::sleep(time::Duration::from_millis(10000));
        }
    }

    pub(crate) fn properties_were_modified(&mut self) -> Result<bool, io::Error> {
        let f = "./veda.properties";
        let metadata = fs::metadata(f)?;
        let modified_time = metadata.modified()?;
        let last_known_modification = self.time_changed_properties.unwrap_or(UNIX_EPOCH);

        if modified_time > last_known_modification {
            self.time_changed_properties = Some(modified_time);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn get_property(&mut self, prop_name: &str) -> Option<String> {
        Module::get_property(prop_name)
    }

    pub(crate) fn get_modules_info(&mut self) -> io::Result<()> {
        let f = File::open("veda.modules")?;
        let file = &mut BufReader::new(&f);
        let cur_modifed_date = f.metadata()?.modified()?;

        if let Some(d) = self.time_changed_modules_info {
            if d == cur_modifed_date {
                return Err(Error::new(ErrorKind::NotFound, ""));
            }
        }

        info!("reading modules configuration...");
        self.modules_info.clear();
        self.time_changed_modules_info = Some(cur_modifed_date);
        let mut order = 0;

        while let Some(l) = file.lines().next() {
            if let Ok(line) = l {
                if line.starts_with('#') || line.starts_with('\t') || line.starts_with('\n') || line.starts_with(' ') || line.is_empty() {
                    continue;
                }

                let mut params = HashMap::new();

                while let Some(p) = file.lines().next() {
                    if let Ok(p) = p {
                        if p.starts_with('\t') || p.starts_with(' ') {
                            //info!("param = {}", p);
                            if let Some(eq_pos) = p.find('=') {
                                let nm: &str = p[0..eq_pos].trim();
                                let vl: &str = p[eq_pos + 1..].trim();

                                params.insert(nm.to_string(), vl.to_string());
                            }
                        } else {
                            break;
                        }
                    }
                }

                let mut module = VedaModule {
                    alias_name: line.to_string(),
                    args: Vec::new(),
                    memory_limit: None,
                    order,
                    exec_name: String::new(),
                    watchdog_timeout: None,
                    module_info: None,
                    module_name: String::new(),
                    prev_err: None,
                    queue_check_enabled: false,
                    queue_check_period: None,
                    queue_growth_threshold: 50,     // По умолчанию 50 задач
                    queue_growth_percentage: 20,    // По умолчанию 20%
                };
                order += 1;

                if let Some(m) = params.get("args") {
                    let elements: Vec<&str> = m.split(' ').collect();
                    for el in elements {
                        module.args.push(el.to_string());
                    }
                }

                if let Some(m) = params.get("memory-limit") {
                    let elements: Vec<&str> = m.split(' ').collect();
                    if elements.len() == 2 {
                        if let Ok(meml) = elements.first().unwrap_or(&"").parse::<i32>() {
                            let m = match elements.get(1).unwrap_or(&"").to_uppercase().as_str() {
                                "GB" => 1024 * 1024,
                                "MB" => 1024,
                                _ => 1,
                            };

                            module.memory_limit = Some((meml * m) as u64);
                            //info!("{:?} Kb", module.memory_limit);
                        }
                    }

                    if module.memory_limit.is_none() {
                        error!("failed to parse param [memory-limit]");
                    }
                }

                if let Some(m) = params.get("watchdog-timeout") {
                    let elements: Vec<&str> = m.split(' ').collect();
                    if elements.len() == 1 {
                        if let Ok(v) = elements.first().unwrap_or(&"").parse::<i32>() {
                            module.watchdog_timeout = Some(v as u64);
                            //info!("watchdog_timeout {:?} s", module.watchdog_timeout);
                        }
                    }

                    if module.watchdog_timeout.is_none() {
                        error!("failed to parse param [watchdog_timeout]");
                    }
                }

                if let Some(m) = params.get("queue-check") {
                    module.queue_check_enabled = m.to_lowercase() == "true" || m == "1";
                    if module.queue_check_enabled {
                        info!("queue check enabled for module {}", module.alias_name);
                    }
                }

                if let Some(m) = params.get("queue-check-period") {
                    if let Ok(period) = parse_duration::parse(m) {
                        module.queue_check_period = Some(period);
                        info!("queue check period for module {} set to {}", module.alias_name, m);
                    } else {
                        error!("failed to parse queue-check-period '{}' for module {}", m, module.alias_name);
                    }
                }

                if let Some(m) = params.get("queue-growth-threshold") {
                    if let Ok(threshold) = m.parse::<u32>() {
                        module.queue_growth_threshold = threshold;
                        info!("queue growth threshold for module {} set to {}", module.alias_name, threshold);
                    } else {
                        error!("failed to parse queue-growth-threshold '{}' for module {}", m, module.alias_name);
                    }
                }

                if let Some(m) = params.get("queue-growth-percentage") {
                    if let Ok(percentage) = m.parse::<u32>() {
                        if percentage > 0 && percentage <= 100 {
                            module.queue_growth_percentage = percentage;
                            info!("queue growth percentage for module {} set to {}%", module.alias_name, percentage);
                        } else {
                            error!("queue-growth-percentage must be between 1 and 100, got '{}' for module {}", m, module.alias_name);
                        }
                    } else {
                        error!("failed to parse queue-growth-percentage '{}' for module {}", m, module.alias_name);
                    }
                }

                module.module_name = if let Some(m) = params.get("module") {
                    m.to_owned()
                } else {
                    line.trim().to_owned()
                };

                let module_path = format!("{}veda-{}", self.app_dir, module.module_name);
                if Path::new(&module_path).exists() {
                    module.exec_name = module_path;
                    self.modules_info.insert(line, module);
                } else {
                    return Err(Error::new(ErrorKind::Other, format!("failed to find module, path = {:?}", &module_path)));
                }
            }
        }

        let mut vmodules: Vec<&VedaModule> = Vec::new();
        for el in self.modules_info.values() {
            vmodules.push(el);
        }
        vmodules.sort_by(|a, b| a.order.partial_cmp(&b.order).unwrap());

        self.modules_start_order.clear();
        for el in vmodules {
            self.modules_start_order.push(el.alias_name.to_owned());
        }

        Ok(())
    }

    pub(crate) fn get_sys_ticket(&mut self) -> &str {
        if self.sys_ticket.is_empty() {
            let mut systicket = self.backend.get_sys_ticket_id();
            while systicket.is_err() {
                info!("waiting for systicket...");
                thread::sleep(std::time::Duration::from_millis(100));
                systicket = self.backend.get_sys_ticket_id();
            }
            self.sys_ticket = systicket.unwrap();
        }
        &self.sys_ticket
    }
}

// Инициализация хэш-карт для хранения периодов проверки, времени последней проверки
fn initialize_watchdog_data() -> (HashMap<String, Duration>, HashMap<String, i64>) {
    let mut watchdog_check_periods: HashMap<String, Duration> = Default::default();
    let mut prev_check_times: HashMap<String, i64> = Default::default();

    for n in ["mstorage", "auth"] {
        if let Some(p) = Module::get_property::<String>(&format!("{}_watchdog_period", n)) {
            if let Ok(t) = parse_duration::parse(&p) {
                watchdog_check_periods.insert(n.to_string(), t);
                prev_check_times.insert(n.to_string(), Utc::now().timestamp());
                info!("started {} watchdog, period = {}", n, p);
            }
        }
    }

    (watchdog_check_periods, prev_check_times)
}
