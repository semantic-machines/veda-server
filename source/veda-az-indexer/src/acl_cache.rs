use crate::common::Context;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use humantime::format_duration;
use ini::Ini;
use parse_duration::parse;
use std::time::{Duration as StdDuration, Instant};
use v_common::az_impl::formats::decode_rec_to_rightset;
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
    expiration: StdDuration,
    cleanup_interval: StdDuration,
    daily_cleanup_interval: StdDuration,
    batch_time_limit: StdDuration,
}

impl ACLCache {
    pub(crate) fn new(config: &Ini) -> Option<Self> {
        let write_az_cache = config.get_from(Some("az_cache"), "write").unwrap_or("false").parse::<bool>().unwrap_or_default();
        if !write_az_cache {
            return None;
        }

        let expiration_str = config.get_from(Some("az_cache"), "expiration").unwrap_or("30d").to_string();
        let cleanup_interval_str = config.get_from(Some("az_cache"), "cleanup_interval").unwrap_or("12h").to_string();
        let daily_cleanup_interval_str = config.get_from(Some("az_cache"), "daily_cleanup_interval").unwrap_or("24h").to_string();
        let batch_time_limit_str = config.get_from(Some("az_cache"), "batch_time_limit").unwrap_or("100ms").to_string();

        let expiration = parse(&expiration_str).unwrap_or(StdDuration::from_secs(30 * 24 * 60 * 60));
        let cleanup_interval = parse(&cleanup_interval_str).unwrap_or(StdDuration::from_secs(12 * 60 * 60));
        let daily_cleanup_interval = parse(&daily_cleanup_interval_str).unwrap_or(StdDuration::from_secs(24 * 60 * 60));
        let batch_time_limit = parse(&batch_time_limit_str).unwrap_or(StdDuration::from_millis(100));

        info!("Expiration: {}", format_duration(expiration));
        info!("Cleanup interval: {}", format_duration(cleanup_interval));
        info!("Daily cleanup interval: {}", format_duration(daily_cleanup_interval));
        info!("Batch time limit: {}", format_duration(batch_time_limit));

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
