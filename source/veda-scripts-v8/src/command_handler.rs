use nng::{Protocol, Socket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use crate::stat_file::{StatsFile, initialize_stats_file};

pub struct StatsCollector {
    pub collect_stats: AtomicBool,
    pub stats_file: Mutex<Option<StatsFile>>,
}

impl StatsCollector {
    pub fn new() -> Self {
        StatsCollector {
            collect_stats: AtomicBool::new(false),
            stats_file: Mutex::new(None),
        }
    }
}

pub fn handle_nng_commands(stats_collector: Arc<StatsCollector>, consumer_name: String) -> Result<(), nng::Error> {
    let socket = Socket::new(Protocol::Rep0)?;
    socket.listen("ipc:///tmp/script_v8_control")?;

    loop {
        let msg = socket.recv()?;
        let command = String::from_utf8_lossy(&msg);

        let response = match command.trim() {
            "start_stats" => {
                if !stats_collector.collect_stats.load(Ordering::Relaxed) {
                    stats_collector.collect_stats.store(true, Ordering::Relaxed);
                    match initialize_stats_file(&consumer_name) {
                        Ok(file) => {
                            let mut stats_file = stats_collector.stats_file.lock().unwrap();
                            *stats_file = Some(file);
                            "Statistics collection started".to_string()
                        },
                        Err(e) => {
                            stats_collector.collect_stats.store(false, Ordering::Relaxed);
                            format!("Failed to initialize statistics file: {:?}", e)
                        }
                    }
                } else {
                    "Statistics collection is already active".to_string()
                }
            }
            "stop_stats" => {
                if stats_collector.collect_stats.load(Ordering::Relaxed) {
                    stats_collector.collect_stats.store(false, Ordering::Relaxed);
                    let mut stats_file = stats_collector.stats_file.lock().unwrap();
                    *stats_file = None;
                    "Statistics collection stopped".to_string()
                } else {
                    "Statistics collection is already inactive".to_string()
                }
            }
            _ => "Unknown command".to_string(),
        };

        socket.send(response.as_bytes())?;
    }
}