use crate::{MinuteStats, TOP_AUTH_COUNT};
use chrono::{DateTime, SecondsFormat, Utc};
use humantime::format_duration;
use log::{debug, error};
use std::collections::BTreeMap;
use std::fs;
use std::io::BufRead;
use std::process;
use std::{io::Write, time::Duration as StdDuration};

pub fn process_file(file_name: &str, quantum: &str) -> std::io::Result<()> {
    let mut result = BTreeMap::new();

    let file = fs::File::open(file_name)?;
    let reader = std::io::BufReader::new(file);

    let mut cache_count = 0;
    let mut db_count = 0;
    let mut cache_miss_count = 0;
    let mut total_auth_count = 0;
    let mut total_auth_time = 0;
    let mut per_minute_auth_time = BTreeMap::new();
    let mut top_auth_times: Vec<(u64, String, String, u32)> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() < 3 {
            debug!("Skipping line: {}", line);
            continue;
        }

        let timestamp_sender = parts[0];
        let auth_time_str = parts[1];
        let identifiers = parts[2];

        let auth_time: u64 = match auth_time_str.parse() {
            Ok(time) => time,
            Err(e) => {
                error!("Error parsing authentication time: {}", auth_time_str);
                error!("Error message: {}", e);
                debug!("Full line: {}", line);
                continue;
            },
        };

        total_auth_count += 1;
        total_auth_time += auth_time;

        let (timestamp, sender) = match timestamp_sender.split_once('|') {
            Some((timestamp, sender)) => (timestamp, sender),
            None => {
                debug!("Skipping line: {}", line);
                continue;
            },
        };

        let timestamp = match DateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.3fZ") {
            Ok(ts) => ts.with_timezone(&Utc),
            Err(e) => {
                error!("Error parsing timestamp: {}", timestamp);
                error!("Error message: {}", e);
                debug!("Full line: {}", line);
                continue;
            },
        };

        let mut db_requests_count = 0;
        for identifier in identifiers.split(';') {
            let (_, source) = match identifier.split_once('/') {
                Some((identifier, source)) => (identifier.to_string(), source),
                None => {
                    debug!("Skipping identifier: {}", identifier);
                    continue;
                },
            };

            match source {
                "C" => cache_count += 1,
                "B" => {
                    db_count += 1;
                    db_requests_count += 1;
                },
                "cB" => {
                    cache_miss_count += 1;
                    db_count += 1;
                    db_requests_count += 1;
                },
                _ => {
                    debug!("Unknown source: {}", source);
                    continue;
                },
            }
        }

        top_auth_times.push((auth_time, timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true), sender.to_string(), db_requests_count));
        top_auth_times.sort_by(|a, b| b.0.cmp(&a.0));
        if top_auth_times.len() > TOP_AUTH_COUNT {
            top_auth_times.pop();
        }

        let key = match quantum {
            "hour" => timestamp.format("%Y-%m-%d %H:00:00Z").to_string(),
            "day" => timestamp.format("%Y-%m-%d 00:00:00Z").to_string(),
            "month" => timestamp.format("%Y-%m-01 00:00:00Z").to_string(),
            _ => {
                error!("Invalid quantum: {}", quantum);
                process::exit(1);
            },
        };

        let counter = result.entry(key).or_insert_with(BTreeMap::new);
        for identifier in identifiers.split(';') {
            let (identifier, _) = match identifier.split_once('/') {
                Some((identifier, source)) => (identifier.to_string(), source),
                None => {
                    debug!("Skipping identifier: {}", identifier);
                    continue;
                },
            };

            *counter.entry(identifier).or_insert(0) += 1;
        }

        let minute_key = timestamp.format("%Y-%m-%d %H:%M:00Z").to_string();
        let minute_stats = per_minute_auth_time.entry(minute_key).or_insert(MinuteStats::default());
        minute_stats.total_time += auth_time;
        minute_stats.count += 1;
    }

    let log_file_name = format!("{}.log", file_name);
    let mut log_file = fs::File::create(&log_file_name)?;
    writeln!(log_file, "Cache requests: {}", cache_count)?;
    writeln!(log_file, "Database requests: {}", db_count)?;
    writeln!(log_file, "Cache misses: {}", cache_miss_count)?;
    writeln!(log_file, "Total authentications: {}", total_auth_count)?;
    writeln!(log_file, "Total authentication time: {}", format_duration(StdDuration::from_micros(total_auth_time)))?;

    writeln!(log_file, "Top {} longest authentications:", TOP_AUTH_COUNT)?;
    writeln!(log_file, "Time (μs) | Timestamp           | Sender ID | DB Requests")?;
    for (auth_time, timestamp, sender, db_requests) in &top_auth_times {
        writeln!(log_file, "{:>9} | {} | {} | {:>11}", auth_time, timestamp, sender, db_requests)?;
    }

    let processed_file_name = format!("{}.processed", file_name);
    let mut processed_file = fs::File::create(&processed_file_name)?;

    for (timestamp, identifiers) in result {
        let mut sorted_identifiers: Vec<(String, i32)> = identifiers.into_iter().collect();
        sorted_identifiers.sort_by(|a, b| b.1.cmp(&a.1));

        let identifier_counts: Vec<String> = sorted_identifiers.into_iter().map(|(identifier, count)| format!("{},{}", identifier, count)).collect();

        writeln!(processed_file, "{};{}", timestamp, identifier_counts.join(";"))?;
    }

    let avg_auth_time_file_name = format!("{}.avg_auth_time.csv", file_name);
    let mut avg_auth_time_file = fs::File::create(&avg_auth_time_file_name)?;

    for (minute, stats) in &per_minute_auth_time {
        let avg_time = stats.total_time / stats.count;
        writeln!(avg_auth_time_file, "{},{},{}", minute, avg_time, stats.count)?;
    }

    Ok(())
}
