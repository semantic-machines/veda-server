use std::collections::HashMap;
use std::process::Command;
use std::fs;
use crate::config::{DispatcherConfig, substitute_template};

// Worker process management
#[derive(Debug)]
pub struct WorkerManager {
    config: DispatcherConfig,
    running_workers: HashMap<u32, u32>, // worker_index -> pid
}

impl WorkerManager {
    pub fn new(config: DispatcherConfig) -> Self {
        Self {
            config,
            running_workers: HashMap::new(),
        }
    }

    pub fn get_pid_file_path(&self, worker_index: u32) -> String {
        let pids_dir = format!("{}/worker_pids", self.config.worker_base_path);
        format!("{}/{}-{}.pid", pids_dir, self.config.sub_queue_prefix, worker_index)
    }

    pub fn is_process_alive(&self, pid: u32) -> bool {
        // Check if process exists by sending signal 0
        match std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn read_pid_from_file(&self, worker_index: u32) -> Option<u32> {
        let pid_file = self.get_pid_file_path(worker_index);
        match fs::read_to_string(&pid_file) {
            Ok(content) => content.trim().parse().ok(),
            Err(_) => None,
        }
    }

    pub fn spawn_worker(&self, worker_index: u32) -> Result<u32, String> {
        let sub_queue_name = format!("{}-{}", self.config.sub_queue_prefix, worker_index);

        // Parse worker_module string to separate command and arguments
        let parts: Vec<String> = self.config.worker_module.split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if parts.is_empty() {
            return Err("worker_module configuration is empty".to_string());
        }

        let mut cmd = Command::new(&parts[0]);
        let args: Vec<String> = parts[1..].to_vec();

        // Substitute variables in template and parse arguments
        let template_args_str = substitute_template(
            &self.config.worker_args_template,
            &self.config.worker_base_path,
            &sub_queue_name,
            self.config.sleep_empty_sec
        );

        // Split template arguments by whitespace
        let template_args: Vec<String> = template_args_str.split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Combine module args with template args
        let mut all_args = args;
        all_args.extend(template_args);

        cmd.args(&all_args);

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();

                // Create pids directory if needed
                let pids_dir = format!("{}/worker_pids", self.config.worker_base_path);
                if let Err(e) = fs::create_dir_all(&pids_dir) {
                    warn!("Failed to create pids directory {}: {}", pids_dir, e);
                }

                // Write PID file
                let pid_file = self.get_pid_file_path(worker_index);
                if let Err(e) = fs::write(&pid_file, pid.to_string()) {
                    warn!("Failed to write PID file {}: {}", pid_file, e);
                }

                info!("Spawned worker {} with PID {} for queue {} using command: {}",
                      worker_index, pid, sub_queue_name, self.config.worker_module);
                Ok(pid)
            }
            Err(e) => {
                error!("Failed to spawn worker {}: {}", worker_index, e);
                Err(e.to_string())
            }
        }
    }

    pub fn ensure_worker_running(&mut self, worker_index: u32) -> bool {
        if let Some(pid) = self.read_pid_from_file(worker_index) {
            if self.is_process_alive(pid) {
                // Worker is running
                let workers = &mut self.running_workers;
                workers.insert(worker_index, pid);
                return true;
            } else {
                // Stale PID file, remove it
                let pid_file = self.get_pid_file_path(worker_index);
                let _ = fs::remove_file(&pid_file);
            }
        }

        // Need to spawn new worker
        match self.spawn_worker(worker_index) {
            Ok(pid) => {
                let workers = &mut self.running_workers;
                workers.insert(worker_index, pid);
                true
            }
            Err(e) => {
                error!("Failed to ensure worker {} is running: {}", worker_index, e);
                false
            }
        }
    }

    pub fn get_active_worker_count(&mut self) -> u32 {
        // Use cached running workers for efficiency
        let mut active_count = 0;
        let mut dead_workers = Vec::new();

        // First pass: check which workers are alive and collect dead ones
        {
            let workers = &self.running_workers;
            for (&worker_index, &pid) in workers.iter() {
                if self.is_process_alive(pid) {
                    active_count += 1;
                } else {
                    dead_workers.push(worker_index);
                }
            }
        }

        // Remove dead workers from cache and clean up PID files
        for &dead_worker in &dead_workers {
            self.running_workers.remove(&dead_worker);
            let pid_file = self.get_pid_file_path(dead_worker);
            let _ = fs::remove_file(&pid_file);
        }

        // Ensure minimum workers are running
        if active_count < self.config.min_workers {
            for i in 0..self.config.min_workers {
                if !self.running_workers.contains_key(&i) {
                    if self.ensure_worker_running(i) {
                        active_count += 1;
                    }
                }
            }
        }

        active_count
    }

    pub fn cleanup_dead_workers(&mut self) {
        // Clean up dead workers from cache and remove stale PID files
        let mut dead_workers = Vec::new();

        // First pass: collect dead workers
        {
            let workers = &self.running_workers;
            for (&worker_index, &pid) in workers.iter() {
                if !self.is_process_alive(pid) {
                    dead_workers.push(worker_index);
                }
            }
        }

        // Remove dead workers from cache and clean up PID files
        for &dead_worker in &dead_workers {
            self.running_workers.remove(&dead_worker);
            let pid_file = self.get_pid_file_path(dead_worker);
            let _ = fs::remove_file(&pid_file);
        }
    }

    pub fn ensure_minimum_workers(&mut self) {
        for i in 0..self.config.min_workers {
            self.ensure_worker_running(i);
        }
    }
}
