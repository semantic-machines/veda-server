use crate::app::App;
use crate::common::{is_ok_process, log_err_and_to_tg, start_module, stop_process, ModuleError};
use chrono::prelude::*;
use std::collections::HashSet;
use std::time::Duration;
use std::time::SystemTime;
use sysinfo::SystemExt;
use v_common::module::info::ModuleInfo;

impl App {
    // Проверка каждого запущенного процесса
    pub(crate) async fn check_started_processes(&mut self, mstorage_ready: bool, new_config_modules: &mut HashSet<String>) {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes();

        let tg = self.get_tg_dest();
        for (name, process) in self.started_modules.iter_mut() {
            if name.is_empty() {
                continue;
            }
            let mut need_check = true;
            let (mut is_ok, memory) = is_ok_process(&mut sys, process.id());

            if !mstorage_ready && stop_process(process.id() as i32, name) {
                warn!("mstorage not ready, attempt stop module {} {}", process.id(), name);
                is_ok = false;
            }

            debug!("name={}, memory={}", name, memory);
            if !is_ok {
                let exit_code = if let Ok(c) = process.wait() {
                    c.code().unwrap_or_default()
                } else {
                    0
                };

                if exit_code != ModuleError::Fatal as i32 {
                    if let Some(module) = self.modules_info.get(name) {
                        if *module.prev_err.as_ref().unwrap_or(&ModuleError::Fatal) != ModuleError::MemoryLimit {
                            log_err_and_to_tg(&tg, &format!("found dead module {}, restart this", name)).await;
                        }
                    }

                    error!("found dead module {} {}, exit code = {}, restart this", process.id(), name, exit_code);
                    stop_process(process.id() as i32, name);

                    if let Some(module) = self.modules_info.get_mut(name) {
                        match start_module(module).await {
                            Ok(child) => {
                                info!("{} restart module {}, {}, {:?}", child.id(), module.alias_name, module.exec_name, module.args);
                                *process = child;
                                need_check = false;
                            },
                            Err(e) => {
                                log_err_and_to_tg(&tg, &format!("failed to execute, name = {}, err = {:?}", module.exec_name, e)).await;
                            },
                        }
                    } else {
                        log_err_and_to_tg(&tg, &format!("failed to find module, name = {}", name)).await;
                    }
                }
            }

            if let Some(module) = self.modules_info.get_mut(name) {
                if need_check {
                    if let Some(memory_limit) = module.memory_limit {
                        if memory > memory_limit {
                            warn!("process = {}, memory = {} KiB, limit = {} KiB", name, memory, memory_limit);
                            stop_process(process.id() as i32, name);
                            module.prev_err = Some(ModuleError::MemoryLimit);
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
                                    stop_process(process.id() as i32, name);
                                }
                            }
                        }
                    }
                }
            } else {
                info!("process {} does not exist in the configuration, it will be killed", name);
                stop_process(process.id() as i32, name);
                let (is_run, _mem) = is_ok_process(&mut sys,process.id());
                if !is_run {
                    *name = String::new();
                }
            }

            new_config_modules.remove(name);
        }
    }
}
