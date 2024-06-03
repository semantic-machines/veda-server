use chrono::prelude::*;
use chrono::Duration;
use flate2::write::GzEncoder;
use flate2::Compression;
use humantime::format_duration;
use log::{debug, error, info};
use nng::{
    options::{protocol::pubsub::Subscribe, Options},
    Error, Protocol, Socket,
};
use std::env;
use std::fs;
use std::process;
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::Write,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration as StdDuration,
};
use std::io::BufRead;

const DATA_DIR: &str = "./data/stat";

fn process_file(file_name: &str, quantum: &str) -> std::io::Result<()> {
    let mut result = std::collections::BTreeMap::new();

    let file = fs::File::open(file_name)?;
    let reader = std::io::BufReader::new(file);

    let mut cache_count = 0;
    let mut db_count = 0;
    let mut cache_miss_count = 0;
    let mut total_auth_count = 0;
    let mut total_auth_time = 0;

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
            }
        };

        total_auth_count += 1;
        total_auth_time += auth_time;

        let timestamp = match timestamp_sender.split_once('|') {
            Some((timestamp, _sender)) => timestamp,
            None => {
                debug!("Skipping line: {}", line);
                continue;
            }
        };

        let timestamp = match NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.3fZ") {
            Ok(ts) => ts,
            Err(e) => {
                error!("Error parsing timestamp: {}", timestamp);
                error!("Error message: {}", e);
                debug!("Full line: {}", line);
                continue;
            }
        };

        let key = match quantum {
            "hour" => timestamp.format("%Y-%m-%d %H:00:00Z").to_string(),
            "day" => timestamp.format("%Y-%m-%d 00:00:00Z").to_string(),
            "month" => timestamp.format("%Y-%m-01 00:00:00Z").to_string(),
            _ => {
                error!("Invalid quantum: {}", quantum);
                process::exit(1);
            }
        };

        let counter = result.entry(key).or_insert_with(std::collections::BTreeMap::new);
        for identifier in identifiers.split(';') {
            let (identifier, source) = match identifier.split_once('/') {
                Some((identifier, source)) => (identifier.to_string(), source),
                None => {
                    debug!("Skipping identifier: {}", identifier);
                    continue;
                }
            };

            match source {
                "C" => cache_count += 1,
                "B" => db_count += 1,
                "cB" => {
                    cache_miss_count += 1;
                    db_count += 1;
                }
                _ => {
                    debug!("Unknown source: {}", source);
                    continue;
                }
            }

            *counter.entry(identifier).or_insert(0) += 1;
        }
    }

    let log_file_name = format!("{}.log", file_name);
    let mut log_file = fs::File::create(&log_file_name)?;
    writeln!(log_file, "Cache requests: {}", cache_count)?;
    writeln!(log_file, "Database requests: {}", db_count)?;
    writeln!(log_file, "Cache misses: {}", cache_miss_count)?;
    writeln!(log_file, "Total authentications: {}", total_auth_count)?;
    writeln!(log_file, "Total authentication time: {}", format_duration(StdDuration::from_micros(total_auth_time)))?;

    let processed_file_name = format!("{}.processed", file_name);
    let mut processed_file = fs::File::create(&processed_file_name)?;

    for (timestamp, identifiers) in result {
        let mut sorted_identifiers: Vec<(String, i32)> = identifiers.into_iter().collect();
        sorted_identifiers.sort_by(|a, b| b.1.cmp(&a.1));

        let identifier_counts: Vec<String> = sorted_identifiers
            .into_iter()
            .map(|(identifier, count)| format!("{},{}", identifier, count))
            .collect();

        writeln!(processed_file, "{};{}", timestamp, identifier_counts.join(";"))?;
    }

    Ok(())
}

fn archive_file(file_name: &str, quantum: &str) {
    let gz_file_name = format!("{}.gz", file_name);
    match fs::File::create(&gz_file_name) {
        Ok(gz_file) => {
            let mut encoder = GzEncoder::new(gz_file, Compression::default());
            match fs::File::open(file_name) {
                Ok(mut input) => {
                    if let Err(e) = std::io::copy(&mut input, &mut encoder) {
                        error!("Error compressing file {}: {}", file_name, e);
                    }
                },
                Err(e) => {
                    error!("Error opening file {} for compression: {}", file_name, e);
                },
            }
            if let Err(e) = encoder.finish() {
                error!("Error finishing compression for file {}: {}", file_name, e);
            }
        },
        Err(e) => {
            error!("Error creating compressed file {}: {}", gz_file_name, e);
        },
    }

    if let Err(e) = process_file(file_name, quantum) {
        error!("Error processing file {}: {}", file_name, e);
    }

    if let Err(e) = fs::remove_file(file_name) {
        error!("Error removing file {}: {}", file_name, e);
    }

    info!("Archived file: {}", file_name);
}

fn archive_existing_files(quantum: &str) {
    if let Ok(entries) = fs::read_dir(DATA_DIR) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(extension) = path.extension() {
                    if extension != "txt" {
                        continue;
                    }
                    if let Some(file_name) = path.to_str() {
                        archive_file(file_name, quantum);
                    }
                }
            }
        }
    }
}

fn main() -> Result<(), nng::Error> {
    env_logger::init();

    if let Err(e) = fs::create_dir_all(DATA_DIR) {
        error!("Ошибка при создании каталога: {}", e);
        return Err(Error::Internal);
    }

    // Получаем URL, размер батча и квант времени из аргументов командной строки
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        error!("Usage: {} <url> <batch_size> <quantum>", args[0]);
        error!("Example: {} tcp://127.0.0.1:40899 100 hour", args[0]);
        process::exit(1);
    }
    let url = args[1].clone();
    let batch_size = args[2].parse::<usize>().unwrap();
    let quantum = args[3].clone();

    // Архивируем незаархивированные файлы при запуске программы
    archive_existing_files(&quantum);

    // Создаем сокет подписчика и устанавливаем опцию подписки
    let s = Socket::new(Protocol::Sub0)?;
    s.listen(&url)?;
    s.set_opt::<Subscribe>(vec![])?;

    // Создаем очередь сообщений и клонируем ее для передачи в поток
    let queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
    let q = queue.clone();

    // Поток для обработки и сохранения сообщений из очереди
    thread::spawn(move || {
        let (lock, cvar) = &*q;
        let mut count = 0;
        let mut file_name = String::new();
        let mut file: Option<fs::File> = None;
        let mut last_log_time = Utc::now();
        let log_interval = Duration::minutes(1);
        let mut total_messages = 0;

        loop {
            // Ожидаем появления сообщений в очереди
            let mut queue = lock.lock().unwrap();
            while queue.is_empty() {
                queue = cvar.wait(queue).unwrap();
            }

            while let Some(message_str) = queue.pop_front() {
                total_messages += 1;

                // Если счетчик равен 0 или достиг значения batch_size,
                // создаем новый файл для записи и архивируем предыдущий в отдельном потоке
                if count == 0 || count >= batch_size {
                    if let Some(f) = file.take() {
                        if let Err(e) = f.sync_all() {
                            error!("Error syncing file {}: {}", file_name, e);
                        }
                        let prev_file_name = file_name.clone();
                        let quantum = quantum.clone();
                        thread::spawn(move || {
                            archive_file(&prev_file_name, &quantum);
                        });
                    }
                    let now: DateTime<Utc> = Utc::now();
                    let timestamp = now.format("%Y-%m-%d_%H-%M-%S%.3f");
                    file_name = format!("./data/stat/az_stat-{}.txt", timestamp);
                    match OpenOptions::new().append(true).create(true).open(&file_name) {
                        Ok(f) => file = Some(f),
                        Err(e) => {
                            error!("Error opening file {}: {}", file_name, e);
                            process::exit(1);
                        },
                    }
                    count = 0;
                }

                // Записываем сообщение в файл с добавлением даты, времени, миллисекунд и адреса отправителя, используя разделитель '|', и увеличиваем счетчик
                if let Some(ref mut f) = file {
                    let now: DateTime<Utc> = Utc::now();
                    let timestamp = now.format("%Y-%m-%d %H:%M:%S%.3fZ");
                    if let Err(e) = writeln!(f, "{}|{}", timestamp, message_str) {
                        error!("Error writing to file {}: {}", file_name, e);
                        process::exit(1);
                    }
                    count += 1;
                }
            }

            // Логгирование количества принятых сообщений каждую минуту, если их количество больше 0
            let now = Utc::now();
            if now - last_log_time >= log_interval {
                if total_messages > 0 {
                    info!("Received {} messages in the last minute", total_messages);
                    total_messages = 0;
                }
                last_log_time = now;
            }
        }
    });

    loop {
        match s.recv() {
            Ok(msg) => {
                // Преобразуем Message в строку
                let message_bytes = msg.to_vec();
                let message_str = String::from_utf8(message_bytes).expect("Failed to convert message to String");

                // Добавляем сообщение и адрес отправителя в очередь и уведомляем поток обработки
                let (lock, cvar) = &*queue;
                let mut queue = lock.lock().unwrap();
                queue.push_back(message_str);
                cvar.notify_one();
            },
            Err(e) => error!("Failed to receive message: {}", e),
        }
    }
}