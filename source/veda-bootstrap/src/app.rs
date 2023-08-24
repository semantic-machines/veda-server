use crate::common::{auth_watchdog_check, is_ok_process, log_err_and_to_tg, mstorage_watchdog_check, start_module, ModuleError, TelegramDest, VedaModule};
use chrono::prelude::*;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::Child;
use std::time::Duration;
use std::time::SystemTime;
use std::{io, thread, time};
use sysinfo::SystemExt;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::Module;
use v_common::module::veda_backend::Backend;

pub struct App {
    pub(crate) date_changed_modules_info: Option<SystemTime>,
    pub(crate) app_dir: String,
    pub(crate) modules_info: HashMap<String, VedaModule>,
    pub(crate) modules_start_order: Vec<String>,
    pub(crate) started_modules: Vec<(String, Child)>,
    pub(crate) backend: Backend,
    pub(crate) sys_ticket: String,
    pub(crate) tg: Option<TelegramDest>,
}

impl App {
    pub(crate) async fn start_modules(&mut self) -> io::Result<()> {
        for name in self.modules_start_order.iter() {
            //info!("start {:?}", module);
            let module = self.modules_info.get(name).unwrap();
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
                if signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGTERM).is_ok() {
                    warn!("stop process {} {}", process.id(), name);
                }
            }

            return Err(Error::new(ErrorKind::Other, "failed to start"));
        }

        Ok(())
    }

    pub(crate) async fn watch_started_modules(&mut self) {
        // Инициализация хэш-карт для хранения периодов проверки, времени последней проверки и результатов проверки для каждого модуля
        let mut watchdog_check_periods: HashMap<String, Duration> = Default::default();
        let mut prev_check_times: HashMap<String, i64> = Default::default();
        let mut module_check_results: HashMap<String, bool> = Default::default();

        // Настройка периодов проверки для известных модулей
        for n in ["mstorage", "auth"] {
            if let Some(p) = Module::get_property(&format!("{}_watchdog_period", n)) {
                if let Ok(t) = parse_duration::parse(&p) {
                    watchdog_check_periods.insert(n.to_string(), t);
                    prev_check_times.insert(n.to_string(), Utc::now().naive_utc().timestamp());
                    info!("started {} watchdog, period = {}", n, p);
                }
            }
        }

        loop {
            let mut new_config_modules = HashSet::new();

            // Получение информации о модулях
            if let Err(e) = self.get_modules_info() {
                if e.kind() != ErrorKind::NotFound {
                    log_err_and_to_tg(&self.tg, "failed to read modules info").await;
                }
            }

            // Добавление модулей из текущей конфигурации в набор
            for el in self.modules_start_order.iter() {
                new_config_modules.insert(el.to_owned());
            }

            // Проверка каждого модуля на основе его периода проверки
            for (module_name, period) in &watchdog_check_periods {
                let now = Utc::now().naive_utc().timestamp();
                if now - *prev_check_times.get(module_name).unwrap_or(&now) > period.as_secs() as i64 {
                    prev_check_times.insert(module_name.to_string(), now);

                    // Логика проверки для каждого модуля
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
                            log_err_and_to_tg(&self.tg, &format!("detected a problem in module {}, restart it", module_name)).await;
                        }
                    }
                }
            }

            // Проверка готовности mstorage
            let mstorage_ready = *module_check_results.get("mstorage").unwrap_or(&true);
            if !mstorage_ready {
                log_err_and_to_tg(&self.tg, "detected a problem in module MSTORAGE, restart all modules").await;
            }

            let mut sys = sysinfo::System::new();
            sys.refresh_processes();

            // Проверка каждого запущенного процесса
            for (name, process) in self.started_modules.iter_mut() {
                let mut need_check = true;
                let (mut is_ok, memory) = is_ok_process(&mut sys, process.id());

                // Если mstorage не готов, попытка остановить процесс
                if !mstorage_ready && signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGTERM).is_ok() {
                    warn!("attempt stop module {} {}", process.id(), name);
                    is_ok = false;
                }

                debug!("name={}, memory={}", name, memory);
                if !is_ok {
                    let exit_code = if let Ok(c) = process.wait() {
                        c.code().unwrap_or_default()
                    } else {
                        0
                    };

                    // Если процесс завершился с ошибкой, попытка его перезапустить
                    if exit_code != ModuleError::Fatal as i32 {
                        log_err_and_to_tg(&self.tg, &format!("found dead module {} {}, exit code = {}, restart this", process.id(), name, exit_code)).await;

                        if signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGTERM).is_ok() {
                            warn!("attempt to stop module, process = {}, name = {}", process.id(), name);
                        }

                        if let Some(module) = self.modules_info.get(name) {
                            match start_module(module).await {
                                Ok(child) => {
                                    info!("{} restart module {}, {}, {:?}", child.id(), module.alias_name, module.exec_name, module.args);
                                    *process = child;
                                    need_check = false;
                                },
                                Err(e) => {
                                    log_err_and_to_tg(&self.tg, &format!("failed to execute, name = {}, err = {:?}", module.exec_name, e)).await;
                                },
                            }
                        } else {
                            log_err_and_to_tg(&self.tg, &format!("failed to find module, name = {}", name)).await;
                        }
                    }
                }

                // Проверка ограничений по памяти и таймауту для каждого модуля
                if let Some(module) = self.modules_info.get_mut(name) {
                    if need_check {
                        if let Some(memory_limit) = module.memory_limit {
                            if memory > memory_limit {
                                warn!("process = {}, memory = {} KiB, limit = {} KiB", name, memory, memory_limit);
                                if signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGTERM).is_ok() {
                                    warn!("attempt to stop module, process = {}, name = {}", process.id(), name);
                                }
                            }
                        }

                        if let Some(timeout) = module.watchdog_timeout {
                            if module.module_info.is_none() {
                                match ModuleInfo::new("./data", &module.alias_name, false) {
                                    Ok(m) => {
                                        module.module_info = Some(m);
                                    },
                                    Err(e) => {
                                        error!("fail open info file {}, err={:?}", module.alias_name, e)
                                    },
                                }
                            }

                            if let Some(m) = &module.module_info {
                                if let Ok(tm) = m.read_modified() {
                                    if tm + Duration::from_secs(timeout) < SystemTime::now() {
                                        let now: DateTime<Utc> = SystemTime::now().into();
                                        let a: DateTime<Utc> = (tm + Duration::from_secs(timeout)).into();
                                        warn!("watchdog: modified + timeout ={},  now={}", a.format("%d/%m/%Y %T"), now.format("%d/%m/%Y %T"));
                                        if signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGTERM).is_ok() {
                                            warn!("attempt to stop module, process = {}, name = {}", process.id(), name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    info!("process {} does not exist in the configuration, it will be killed", name);
                    if signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGTERM).is_ok() {
                        warn!("attempt to stop module, process = {}, name = {}", process.id(), name);
                    }
                }

                new_config_modules.remove(name);
            }

            // Запуск новых модулей из конфигурации
            for name in new_config_modules {
                if let Some(module) = self.modules_info.get(&name) {
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

            // Задержка перед следующей итерацией цикла
            thread::sleep(time::Duration::from_millis(10000));
        }
    }

    pub(crate) fn get_modules_info(&mut self) -> io::Result<()> {
        let f = File::open("veda.modules")?;
        let file = &mut BufReader::new(&f);
        let cur_modifed_date = f.metadata()?.modified()?;

        if let Some(d) = self.date_changed_modules_info {
            if d == cur_modifed_date {
                return Err(Error::new(ErrorKind::NotFound, ""));
            }
        }

        info!("reading modules configuration...");
        self.modules_info.clear();
        self.date_changed_modules_info = Some(cur_modifed_date);
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
}
