use crate::common::{log_err_and_to_tg, TelegramDest};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use sysinfo::{ProcessExt, SystemExt};
use v_queue::consumer::Consumer;
use v_queue::queue::Queue;
use v_queue::record::Mode;

// Структура для мониторинга состояния очередей модулей
pub struct QueueChecker {
    queue_base_path: String,
    stats_file_path: String,
    queue_stats: HashMap<String, QueueStats>,
    last_check_times: HashMap<String, Instant>,
}

// Структура для хранения статистики очереди модуля
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub prev_pushed: Option<u32>,
    pub prev_popped: Option<u32>,
    pub last_updated: Option<DateTime<Utc>>,
    pub queue_part_id: Option<u32>,
    pub consumer_part_id: Option<u32>,
}

// Структура для передачи данных о состоянии очереди
pub struct QueueStatus {
    pub current_pushed: u32,
    pub current_popped: u32,
    pub queue_part_id: u32,
    pub consumer_part_id: u32,
    pub prev_pushed: Option<u32>,
    pub prev_popped: Option<u32>,
    pub prev_queue_part_id: Option<u32>,
    pub prev_consumer_part_id: Option<u32>,
}

impl QueueChecker {
    pub fn new(queue_base_path: String, stats_file_path: String) -> Self {
        let mut checker = Self { 
            queue_base_path,
            stats_file_path,
            queue_stats: HashMap::new(),
            last_check_times: HashMap::new(),
        };
        
        // Загружаем статистику из файла при создании
        checker.load_stats();
        checker
    }

    // Загрузка статистики из файла
    fn load_stats(&mut self) {
        if Path::new(&self.stats_file_path).exists() {
            match fs::read_to_string(&self.stats_file_path) {
                Ok(content) => {
                    match serde_json::from_str::<HashMap<String, QueueStats>>(&content) {
                        Ok(stats) => {
                            self.queue_stats = stats;
                            // Статистика загружена без логирования для уменьшения шума
                        },
                        Err(e) => {
                            error!("Failed to parse queue statistics: {:?}", e);
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to read statistics file {}: {:?}", self.stats_file_path, e);
                }
            }
        }
        // Файл статистики создается без логирования
    }

    // Сохранение статистики в файл
    fn save_stats(&self) {
        // Создаем директорию если она не существует
        if let Some(parent) = Path::new(&self.stats_file_path).parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                error!("Failed to create directory {:?}: {:?}", parent, e);
                return;
            }
        }

        match serde_json::to_string_pretty(&self.queue_stats) {
            Ok(content) => {
                if let Err(e) = fs::write(&self.stats_file_path, content) {
                    error!("Failed to write queue statistics to file {}: {:?}", self.stats_file_path, e);
                }
            },
            Err(e) => {
                error!("Failed to serialize queue statistics: {:?}", e);
            }
        }
    }


    // Проверка, завис ли конкретный модуль на основе данных о состоянии очереди
    // Модуль считается зависшим если:
    // 1. Процесс жив (статус Run или Sleep)
    // 2. В очередь добавились новые задачи (pushed увеличился)
    // 3. Модуль не обработал ни одной задачи (popped не изменился)
    pub async fn check_module_stuck(
        module: &crate::common::VedaModule,
        process_id: u32,
        sys: &mut sysinfo::System,
        queue_status: Option<QueueStatus>,
        tg_dest: &Option<TelegramDest>,
    ) -> bool {
        // Проверяем, включен ли мониторинг очередей для этого модуля
        if !module.queue_check_enabled {
            return false;
        }

        // Проверяем, что данные о состоянии очереди переданы
        let queue_status = match queue_status {
            Some(status) => status,
            None => return false, // Нет данных для анализа
        };

        // Проверяем, что процесс жив
        if let Some(proc) = sys.get_process(process_id as i32) {
            match proc.status() {
                sysinfo::ProcessStatus::Run | sysinfo::ProcessStatus::Sleep => {
                    // Процесс жив, проверяем состояние очереди
                },
                _ => {
                    // Процесс не в активном состоянии
                    return false;
                }
            }
        } else {
            // Процесс не найден
            return false;
        }

        // Проверяем, что у нас есть предыдущие данные для сравнения
        if let (Some(prev_pushed), Some(prev_popped), Some(prev_queue_part), Some(prev_consumer_part)) = 
            (queue_status.prev_pushed, queue_status.prev_popped, queue_status.prev_queue_part_id, queue_status.prev_consumer_part_id) {
            
            // Проверяем, что части очереди не изменились (если изменились, то сброс счетчиков нормален)
            if prev_queue_part == queue_status.queue_part_id && prev_consumer_part == queue_status.consumer_part_id {
                let pushed_diff = queue_status.current_pushed.saturating_sub(prev_pushed);
                let popped_diff = queue_status.current_popped.saturating_sub(prev_popped);

                // Модуль завис если:
                // 1. В очередь добавились новые задачи (pushed_diff > 0)
                // 2. Модуль не обработал ни одной задачи (popped_diff == 0)
                if pushed_diff > 0 && popped_diff == 0 {
                    let current_queue_size = queue_status.current_pushed.saturating_sub(queue_status.current_popped);
                    
                    warn!(
                        "Модуль {} (PID: {}, part {}/{}) may be stuck! For period: added +{}, processed +0, queue size: {}",
                        module.alias_name, process_id, queue_status.queue_part_id, queue_status.consumer_part_id, pushed_diff, current_queue_size
                    );

                    if let Some(tg) = tg_dest {
                        log_err_and_to_tg(&Some(tg.clone()), &format!(
                            "🚨 Module {} (PID: {}) stuck! Added: +{}, processed: 0, queue size: {}",
                            module.alias_name, process_id, pushed_diff, current_queue_size
                        )).await;
                    }

                    return true;
                }
            }
        }

        false
    }

    // Проверка состояния очереди конкретного модуля
    pub async fn check_single_module_queue_status(
        &mut self,
        module: &crate::common::VedaModule,
        tg_dest: &Option<TelegramDest>,
    ) -> Option<QueueStatus> {
        if !module.queue_check_enabled {
            return None;
        }

        let mut stats_changed = false;
        let now = Instant::now();

        // Проверяем, нужно ли проверять этот модуль сейчас
        let should_check = if let Some(period) = module.queue_check_period {
            if let Some(last_check) = self.last_check_times.get(&module.alias_name) {
                now.duration_since(*last_check) >= period
            } else {
                true // Первая проверка
            }
        } else {
            // Если период не задан, используем дефолтный период 5 минут
            if let Some(last_check) = self.last_check_times.get(&module.alias_name) {
                now.duration_since(*last_check) >= Duration::from_secs(300)
            } else {
                true
            }
        };

        if !should_check {
            return None;
        }

        // Обновляем время последней проверки
        self.last_check_times.insert(module.alias_name.clone(), now);

        let queue_name = format!("individuals-flow-{}", module.alias_name);
        let consumer_name = format!("{}-bootstrap-queue-checker", module.alias_name);
        
        // Подключаемся к очереди в режиме только для чтения
        match Queue::new(&self.queue_base_path, &queue_name, Mode::Read) {
            Ok(queue) => {
                let current_pushed = queue.count_pushed;
                let queue_part_id = queue.id;
                
                // Создаем consumer для получения count_popped
                match Consumer::new(&self.queue_base_path, &consumer_name, &queue_name) {
                    Ok(consumer) => {
                        let current_popped = consumer.count_popped;
                        let consumer_part_id = consumer.id;
                        
                        // Получаем или создаем статистику для модуля
                        let stats = self.queue_stats.entry(module.alias_name.clone()).or_insert_with(QueueStats::default);
                        
                        // Сохраняем предыдущие значения для возврата
                        let prev_pushed = stats.prev_pushed;
                        let prev_popped = stats.prev_popped;
                        let prev_queue_part_id = stats.queue_part_id;
                        let prev_consumer_part_id = stats.consumer_part_id;
                        
                        // Проверяем, изменились ли part ID с предыдущей проверки
                        let part_ids_changed = stats.queue_part_id != Some(queue_part_id) || 
                                             stats.consumer_part_id != Some(consumer_part_id);
                        
                        if let (Some(prev_pushed), Some(prev_popped)) = (stats.prev_pushed, stats.prev_popped) {
                            if part_ids_changed {
                                // Если part ID изменились, это означает, что очередь переключилась на новую часть
                                // В этом случае нужно учесть, что счетчики сбросились
                                // Логирование убрано для уменьшения шума в логах
                            } else {
                                // Part ID не изменились, можем сравнивать счетчики как обычно
                                let pushed_diff = current_pushed.saturating_sub(prev_pushed);
                                let popped_diff = current_popped.saturating_sub(prev_popped);
                                let queue_growth = pushed_diff.saturating_sub(popped_diff);
                                
                                // Предупреждение если очередь растет
                                if queue_growth > 0 {
                                    let current_queue_size = current_pushed.saturating_sub(current_popped);
                                    warn!(
                                        "Queue of module {} (part {}/{}) growing! Current size: {}, growth for period: +{}",
                                        module.alias_name, queue_part_id, consumer_part_id, current_queue_size, queue_growth
                                    );
                                    
                                    if let Some(tg) = tg_dest {
                                        log_err_and_to_tg(&Some(tg.clone()), &format!(
                                            "⚠️ Queue of module {} (part {}/{}) growing! Size: {}, growth: +{}",
                                            module.alias_name, queue_part_id, consumer_part_id, current_queue_size, queue_growth
                                        )).await;
                                    }
                                }
                            }
                        } else {
                            // Первая проверка модуля - инициализация без логирования
                        }
                        
                        // Обновляем предыдущие значения только если они изменились
                        if stats.prev_pushed != Some(current_pushed) || 
                           stats.prev_popped != Some(current_popped) ||
                           stats.queue_part_id != Some(queue_part_id) ||
                           stats.consumer_part_id != Some(consumer_part_id) {
                            stats.prev_pushed = Some(current_pushed);
                            stats.prev_popped = Some(current_popped);
                            stats.queue_part_id = Some(queue_part_id);
                            stats.consumer_part_id = Some(consumer_part_id);
                            stats.last_updated = Some(Utc::now());
                            stats_changed = true;
                        }

                        // Сохраняем статистику в файл только если она изменилась
                        if stats_changed {
                            self.save_stats();
                        }

                        // Возвращаем данные о состоянии очереди
                        return Some(QueueStatus {
                            current_pushed,
                            current_popped,
                            queue_part_id,
                            consumer_part_id,
                            prev_pushed,
                            prev_popped,
                            prev_queue_part_id,
                            prev_consumer_part_id,
                        });
                    },
                    Err(e) => {
                        error!("Failed to create consumer for queue {}: {:?}", queue_name, e);
                    }
                }
            },
            Err(e) => {
                error!("Failed to connect to queue {}: {:?}", queue_name, e);
            }
        }

        None
    }
}
