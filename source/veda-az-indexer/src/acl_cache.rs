use crate::common::Context;
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
    last_cleanup_time: Option<DateTime<Utc>>,
    last_daily_cleanup_time: Option<DateTime<Utc>>,
    keys: Vec<Vec<u8>>,
    keys_processed: usize,
    pub(crate) expiration: StdDuration,
    pub(crate) cleanup_interval: StdDuration,
    pub(crate) daily_cleanup_interval: StdDuration,
    pub(crate) batch_time_limit: StdDuration,
    pub(crate) min_identifier_count_threshold: usize,
    pub(crate) stat_processing_time_limit: StdDuration,
    pub(crate) stat_processing_interval: StdDuration,
    pub(crate) last_stat_processing_time: Option<DateTime<Utc>>,
}

impl ACLCache {
    pub(crate) fn new(config: &Ini) -> Option<Self> {
        let write_az_cache = config.get_from(Some("authorization_cache"), "write").unwrap_or("false").parse::<bool>().unwrap_or_default();
        if !write_az_cache {
            return None;
        }

        let expiration_str = config.get_from(Some("authorization_cache"), "expiration").unwrap_or("30d").to_string();
        let cleanup_interval_str = config.get_from(Some("authorization_cache"), "cleanup_interval").unwrap_or("12h").to_string();
        let daily_cleanup_interval_str = config.get_from(Some("authorization_cache"), "daily_cleanup_interval").unwrap_or("24h").to_string();
        let batch_time_limit_str = config.get_from(Some("authorization_cache"), "batch_time_limit").unwrap_or("100ms").to_string();
        let stat_processing_time_limit_str = config.get_from(Some("authorization_cache"), "stat_processing_time_limit").unwrap_or("5s").to_string();
        let stat_processing_interval_str = config.get_from(Some("authorization_cache"), "stat_processing_interval").unwrap_or("10m").to_string();

        let expiration = parse(&expiration_str).unwrap_or(StdDuration::from_secs(30 * 24 * 60 * 60));
        let cleanup_interval = parse(&cleanup_interval_str).unwrap_or(StdDuration::from_secs(12 * 60 * 60));
        let daily_cleanup_interval = parse(&daily_cleanup_interval_str).unwrap_or(StdDuration::from_secs(24 * 60 * 60));
        let batch_time_limit = parse(&batch_time_limit_str).unwrap_or(StdDuration::from_millis(100));
        let stat_processing_time_limit = parse(&stat_processing_time_limit_str).unwrap_or(StdDuration::from_secs(5));
        let stat_processing_interval = parse(&stat_processing_interval_str).unwrap_or(StdDuration::from_secs(10 * 60));

        let min_identifier_count_threshold = config.get_from(Some("authorization_cache"), "min_identifier_count_threshold").unwrap_or("100").parse().unwrap_or(100);

        info!("Cache, expiration: {}", format_duration(expiration));
        info!("Cache, cleanup interval: {}", format_duration(cleanup_interval));
        info!("Cache, daily cleanup interval: {}", format_duration(daily_cleanup_interval));
        info!("Cache, batch time limit: {}", format_duration(batch_time_limit));
        info!("Cache, min identifier count threshold: {}", min_identifier_count_threshold);
        info!("Cache, stat processing time limit: {}", format_duration(stat_processing_time_limit));
        info!("Cache, stat processing interval: {}", format_duration(stat_processing_interval));

        Some(ACLCache {
            instance: LmdbInstance::new("./data/acl-cache-indexes", StorageMode::ReadWrite),
            last_cleanup_time: None,
            last_daily_cleanup_time: None,
            keys: vec![],
            keys_processed: 0,
            expiration,
            cleanup_interval,
            daily_cleanup_interval,
            batch_time_limit,
            min_identifier_count_threshold,
            stat_processing_time_limit,
            stat_processing_interval,
            last_stat_processing_time: None,
        })
    }
}

pub fn clean_cache(ctx: &mut Context) -> Result<(), PrepareError> {
    if let Some(cache_ctx) = &mut ctx.acl_cache {
        let now = Utc::now();

        if let Some(last_cleanup_time) = cache_ctx.last_cleanup_time {
            if now - last_cleanup_time < ChronoDuration::from_std(cache_ctx.cleanup_interval).unwrap() {
                return Ok(());
            }
        }

        cache_ctx.last_cleanup_time = Some(now);
        let total_count = cache_ctx.instance.count();
        info!("Records in cache: {}", total_count);
        info!("Updated last cleanup time: {}", now);

        let expiration_duration = ChronoDuration::from_std(cache_ctx.expiration).unwrap();
        info!("Expiration duration: {:?}", cache_ctx.expiration);

        if let Some(last_daily_cleanup_time) = cache_ctx.last_daily_cleanup_time {
            if now - last_daily_cleanup_time >= ChronoDuration::from_std(cache_ctx.daily_cleanup_interval).unwrap() {
                info!("Performing daily cleanup");
                cache_ctx.keys = cache_ctx.instance.iter().collect();
                info!("Collected {} cache keys", cache_ctx.keys.len());
                cache_ctx.last_daily_cleanup_time = Some(now);
                info!("Updated last daily cleanup time: {}", now);
            }
        } else {
            info!("Performing initial daily cleanup");
            cache_ctx.keys = cache_ctx.instance.iter().collect();
            info!("Collected {} cache keys", cache_ctx.keys.len());
            cache_ctx.last_daily_cleanup_time = Some(now);
            info!("Set last daily cleanup time: {}", now);
        }

        let start_time = Instant::now();
        let mut processed_keys = 0;

        for key in cache_ctx.keys.iter().skip(cache_ctx.keys_processed) {
            if let Ok(key_str) = std::str::from_utf8(key) {
                if let Some(value) = cache_ctx.instance.get::<String>(key_str) {
                    let mut record_set = ACLRecordSet::new();
                    let (_, timestamp) = decode_rec_to_rightset(&value, &mut record_set);
                    if let Some(timestamp) = timestamp {
                        if now - timestamp > expiration_duration {
                            cache_ctx.instance.remove(key_str);
                            info!("Removed expired cache entry: {:?}, timestamp: {:?}", key_str, timestamp);
                        }
                    } else {
                        warn!("Failed to parse timestamp for key: {:?}, timestamp: {:?}", key_str, timestamp);
                    }
                } else {
                    info!("Value not found for key: {:?}", key_str);
                }
            } else {
                warn!("Failed to convert key to string: {:?}", key);
            }

            processed_keys += 1;
            cache_ctx.keys_processed += 1;

            if start_time.elapsed() >= cache_ctx.batch_time_limit {
                info!("Processed {} keys in {} ms", processed_keys, start_time.elapsed().as_millis());
                break;
            }
        }

        if cache_ctx.keys_processed >= cache_ctx.keys.len() {
            cache_ctx.keys_processed = 0;
            info!("All keys processed, resetting processed count");
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

            info!("Processing file: {:?}", processed_path);

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
                        error!("CACHE: fail parse date: {:?}", parts[0]);
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
                            error!("CACHE: fail parse count: {}", identifier_str);
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
                                error!("CACHE: fail store to cache db: {}, {}", identifier_str, new_value);
                            } else {
                                info!("CACHE: add: id={}, count={}", identifier, count);
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
            info!("Processed file: {:?}", processed_path);
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
