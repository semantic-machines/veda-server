use crate::common::Context;
use chrono::NaiveTime;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use humantime::format_duration;
use ini::Ini;
use parse_duration::parse;
use std::io;
use std::time::{Duration as StdDuration, Instant};
use v_common::az_impl::formats::{decode_rec_to_rightset, encode_record};
use v_common::module::module_impl::PrepareError;
use v_common::storage::common::StorageMode;
use v_common::storage::lmdb_storage::LmdbInstance;
use v_common::v_authorization::ACLRecordSet;

pub struct ACLCache {
    pub(crate) instance: LmdbInstance,
    keys: Vec<Vec<u8>>,
    keys_processed: usize,
    pub(crate) expiration: StdDuration,
    pub(crate) cleanup_time: NaiveTime,
    pub(crate) cleanup_in_progress: bool,
    pub(crate) cleanup_continue_interval: StdDuration,
    pub(crate) cleanup_batch_time_limit: StdDuration,
    pub(crate) min_identifier_count_threshold: usize,
    pub(crate) stat_processing_time_limit: StdDuration,
    pub(crate) stat_processing_interval: StdDuration,
    pub(crate) last_stat_processing_time: Option<DateTime<Utc>>,
    pub(crate) last_cleanup_batch_time: Option<DateTime<Utc>>,
    pub(crate) last_cleanup_date: Option<DateTime<Utc>>,
}

impl ACLCache {
    pub(crate) fn new(config: &Ini) -> Option<Self> {
        let write_az_cache = config.get_from(Some("authorization_cache"), "write").unwrap_or("false").parse::<bool>().unwrap_or_default();
        if !write_az_cache {
            return None;
        }

        let expiration_str = config.get_from(Some("authorization_cache"), "expiration").unwrap_or("30d").to_string();
        let cleanup_time_str = config.get_from(Some("authorization_cache"), "cleanup_time").unwrap_or("02:00:00");
        let cleanup_batch_time_limit_str = config.get_from(Some("authorization_cache"), "cleanup_batch_time_limit").unwrap_or("100ms").to_string();
        let cleanup_continue_interval_str = config.get_from(Some("authorization_cache"), "cleanup_continue_interval").unwrap_or("10s").to_string();

        let stat_processing_time_limit_str = config.get_from(Some("authorization_cache"), "stat_processing_time_limit").unwrap_or("5s").to_string();
        let stat_processing_interval_str = config.get_from(Some("authorization_cache"), "stat_processing_interval").unwrap_or("10m").to_string();

        let expiration = parse(&expiration_str).unwrap_or(StdDuration::from_secs(30 * 24 * 60 * 60));
        let cleanup_time = NaiveTime::parse_from_str(cleanup_time_str, "%H:%M:%S").unwrap_or_else(|_| NaiveTime::from_hms_opt(2, 0, 0).unwrap());
        let cleanup_batch_time_limit = parse(&cleanup_batch_time_limit_str).unwrap_or(StdDuration::from_millis(100));
        let cleanup_continue_interval = parse(&cleanup_continue_interval_str).unwrap_or(StdDuration::from_secs(50));
        let stat_processing_interval = parse(&stat_processing_interval_str).unwrap_or(StdDuration::from_secs(10 * 60));
        let stat_processing_time_limit = parse(&stat_processing_time_limit_str).unwrap_or(StdDuration::from_secs(10 * 60));

        let min_identifier_count_threshold = config.get_from(Some("authorization_cache"), "min_identifier_count_threshold").unwrap_or("100").parse().unwrap_or(100);

        info!("Cache, expiration: {}", format_duration(expiration));
        info!("Cache, cleanup time: {}", cleanup_time);
        info!("Cache, cleanup batch time limit: {}", format_duration(cleanup_batch_time_limit));
        info!("Cache, cleanup continue interval: {}", format_duration(cleanup_continue_interval));
        info!("Cache, min identifier count threshold: {}", min_identifier_count_threshold);
        info!("Cache, stat processing time limit: {}", format_duration(stat_processing_time_limit));
        info!("Cache, stat processing interval: {}", format_duration(stat_processing_interval));

        Some(ACLCache {
            instance: LmdbInstance::new("./data/acl-cache-indexes", StorageMode::ReadWrite),
            keys: vec![],
            keys_processed: 0,
            expiration,
            cleanup_time,
            cleanup_in_progress: false,
            cleanup_continue_interval,
            cleanup_batch_time_limit,
            min_identifier_count_threshold,
            stat_processing_time_limit,
            stat_processing_interval,
            last_stat_processing_time: None,
            last_cleanup_batch_time: None,
            last_cleanup_date: None,
        })
    }
}

pub fn clean_cache(ctx: &mut Context) -> Result<(), PrepareError> {
    if let Some(cache_ctx) = &mut ctx.acl_cache {
        let now = Utc::now();
        let current_time = now.time();

        // Check if it's time to start the cleanup
        if !cache_ctx.cleanup_in_progress {
            let should_start_cleanup = match cache_ctx.last_cleanup_date {
                Some(last_cleanup) => {
                    now.date_naive() > last_cleanup.date_naive()
                        && (current_time >= cache_ctx.cleanup_time || now.date_naive() > last_cleanup.date_naive().succ_opt().unwrap_or(last_cleanup.date_naive()))
                },
                None => true, // If we've never run a cleanup, start it immediately
            };

            if should_start_cleanup {
                info!("CACHE: Starting daily cleanup at {}", now);
                cache_ctx.cleanup_in_progress = true;
                cache_ctx.keys = cache_ctx.instance.iter().collect();
                info!("CACHE: Collected {} cache keys", cache_ctx.keys.len());
                cache_ctx.keys_processed = 0;
                cache_ctx.last_cleanup_batch_time = Some(now);
                cache_ctx.last_cleanup_date = Some(now);
            }
        }

        // Check if we can continue the cleanup
        if cache_ctx.cleanup_in_progress {
            if let Some(last_batch_time) = cache_ctx.last_cleanup_batch_time {
                if now - last_batch_time < ChronoDuration::from_std(cache_ctx.cleanup_continue_interval).unwrap() {
                    // Not enough time has passed since the last batch, skip this run
                    return Ok(());
                }
            }

            let start_time = Instant::now();
            let mut processed_keys = 0;
            let expiration_duration = ChronoDuration::from_std(cache_ctx.expiration).unwrap();

            for key in cache_ctx.keys.iter().skip(cache_ctx.keys_processed) {
                if let Ok(key_str) = std::str::from_utf8(key) {
                    if let Some(value) = cache_ctx.instance.get::<String>(key_str) {
                        let mut record_set = ACLRecordSet::new();
                        let (_, timestamp) = decode_rec_to_rightset(&value, &mut record_set);
                        if let Some(timestamp) = timestamp {
                            if now - timestamp > expiration_duration {
                                cache_ctx.instance.remove(key_str);
                                info!("CACHE: Removed expired cache entry: {:?}, timestamp: {:?}", key_str, timestamp);
                            }
                        } else {
                            warn!("CACHE: Failed to parse timestamp for key: {:?}, timestamp: {:?}", key_str, timestamp);
                        }
                    } else {
                        info!("CACHE: Value not found for key: {:?}", key_str);
                    }
                } else {
                    warn!("CACHE: Failed to convert key to string: {:?}", key);
                }

                processed_keys += 1;
                cache_ctx.keys_processed += 1;

                if start_time.elapsed() >= cache_ctx.cleanup_batch_time_limit {
                    info!("CACHE: Processed {} keys in {} ms", processed_keys, start_time.elapsed().as_millis());
                    cache_ctx.last_cleanup_batch_time = Some(now);
                    return Ok(());
                }
            }

            // All keys processed
            cache_ctx.keys_processed = 0;
            cache_ctx.cleanup_in_progress = false;
            cache_ctx.last_cleanup_batch_time = None;
            info!("CACHE: All keys processed, cleanup completed");
        }
    }

    Ok(())
}

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

pub fn process_stat_files(ctx: &mut Context) -> Result<bool, io::Error> {
    if let Some(cache_ctx) = &mut ctx.acl_cache {
        let now = Utc::now();

        // Проверка времени последнего запуска process_stat_files
        if let Some(last_processing_time) = cache_ctx.last_stat_processing_time {
            if now - last_processing_time < ChronoDuration::from_std(cache_ctx.stat_processing_interval).unwrap() {
                return Ok(false);
            }
        }

        cache_ctx.last_stat_processing_time = Some(now);

        let stat_dir = "./data/stat";
        let processed_extension = "processed";
        let state_file = "./data/stat/process_state.info";

        let start_time = Instant::now();

        // Переменные для хранения информации о состоянии обработки
        let mut processed_file = None;
        let mut line_number = 0;

        // Чтение состояния обработки из файла
        if let Ok(state_contents) = std::fs::read_to_string(state_file) {
            let state_lines: Vec<&str> = state_contents.lines().collect();
            if state_lines.len() >= 2 {
                processed_file = Some(state_lines[0].to_string());
                line_number = state_lines[1].parse().unwrap_or(0);
            }
        }

        let mut processed_file_found = false;

        // Обход файлов в директории stat_dir
        for entry in std::fs::read_dir(stat_dir)? {
            // Проверка превышения времени выполнения
            if start_time.elapsed() >= cache_ctx.stat_processing_time_limit {
                break;
            }

            let entry = entry?;
            let path = entry.path();

            // Проверка, что файл имеет расширение "dst"
            //if !path.is_file() || path.extension().map_or(true, |ext| ext != "dst") {
            //    continue;
            //}

            // Проверка наличия файла с расширением processed_extension
            let processed_path = path.with_extension(processed_extension);
            if !processed_path.exists() {
                continue;
            }

            // Проверка, что текущий файл соответствует файлу из состояния обработки
            if let Some(ref file) = processed_file {
                if file != &processed_path.to_str().unwrap().to_string() {
                    continue;
                }
            }

            processed_file_found = true;

            info!("CACHE: Processing file: {:?}", processed_path);

            let file = File::open(&processed_path)?;
            let reader = BufReader::new(file);

            // Обработка строк файла
            for (index, line) in reader.lines().enumerate() {
                // Проверка превышения времени выполнения
                if start_time.elapsed() >= cache_ctx.stat_processing_time_limit {
                    break;
                }

                // Пропуск строк, которые уже были обработаны
                if index < line_number {
                    continue;
                }

                let line = line?;
                let parts: Vec<&str> = line.split(';').collect();
                if parts.len() < 2 {
                    continue;
                }

                // Парсинг временной метки
                match parts[0].parse::<DateTime<Utc>>() {
                    Ok(timestamp) => timestamp,
                    Err(_) => {
                        error!("CACHE: Fail parse date: {:?}", parts[0]);
                        continue;
                    },
                };

                let identifiers = &parts[1..];
                // Обработка идентификаторов

                for identifier_str in identifiers {
                    let identifier_parts: Vec<&str> = identifier_str.split(',').collect();
                    if identifier_parts.len() != 2 {
                        continue;
                    }

                    // Парсинг количества запросов для идентификатора
                    let count = match identifier_parts[1].parse::<usize>() {
                        Ok(count) => count,
                        Err(_) => {
                            error!("CACHE: Fail parse count: {}", identifier_str);
                            continue;
                        },
                    };

                    let identifier = identifier_parts[0];

                    //info!("CACHE: id={}, count={}", identifier, count);

                    // Проверка, что количество запросов превышает пороговое значение
                    if count < cache_ctx.min_identifier_count_threshold {
                        continue;
                    }

                    // Проверка наличия идентификатора в кеше
                    if cache_ctx.instance.get::<String>(identifier).is_some() {
                        continue;
                    }

                    // Получение значения из основного хранилища и добавление в кеш
                    match ctx.storage.get::<String>(identifier) {
                        Some(value) => {
                            let mut record_set = ACLRecordSet::new();
                            let (_, _) = decode_rec_to_rightset(&value, &mut record_set);
                            let new_value = encode_record(Some(Utc::now()), &record_set, ctx.version_of_index_format);
                            if !cache_ctx.instance.put(identifier, new_value.clone()) {
                                error!("CACHE: Fail store to cache db: {}, {}", identifier_str, new_value);
                            } else {
                                info!("CACHE: Add: id={}, count={}", identifier, count);
                            }
                        },
                        None => continue,
                    }
                }

                line_number = index + 1;
            }

            // Проверка превышения времени выполнения
            if start_time.elapsed() >= cache_ctx.stat_processing_time_limit {
                break;
            }

            // Обработка завершена, переименование обработанного файла
            std::fs::rename(&processed_path, processed_path.with_extension("ok"))?;
            info!("CACHE: Complete processing file: {:?}", processed_path);
            processed_file = None;
            line_number = 0;
        }

        // Сохранение состояния обработки в файл
        if processed_file_found {
            if let Some(file) = processed_file {
                let mut state_file = File::create(state_file)?;
                writeln!(state_file, "{}", file)?;
                writeln!(state_file, "{}", line_number)?;
            } else {
                // Удаление файла состояния, если обработка завершена
                std::fs::remove_file(state_file)?;
            }
        }

        Ok(processed_file_found)
    } else {
        Ok(false)
    }
}
