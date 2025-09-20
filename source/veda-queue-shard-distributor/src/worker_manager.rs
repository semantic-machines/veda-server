use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::fs::{self, OpenOptions};
use crate::config::{DispatcherConfig, substitute_template};

// Worker information structure
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub unique_id: String,
    pub pid: u32,
}

// Worker process management
#[derive(Debug)]
pub struct WorkerManager {
    config: DispatcherConfig,
    running_workers: HashMap<String, WorkerInfo>, // worker_unique_id -> WorkerInfo
}

impl WorkerManager {
    pub fn new(config: DispatcherConfig) -> Self {
        Self {
            config,
            running_workers: HashMap::new(),
        }
    }
    
    fn generate_unique_worker_id(&self) -> String {
        // Generate 6-character alphanumeric ID using nanoseconds timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Use last 6 digits of nanoseconds for 6-char hex ID
        format!("{:06x}", (now % 1_000_000) as u32)
    }

    pub fn get_pid_file_path(&self, worker_id: &str) -> String {
        let pids_dir = &self.config.worker_pids_dir;
        format!("{}/worker-{}.pid", pids_dir, worker_id)
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

    #[allow(dead_code)]
    pub fn read_pid_from_file(&self, worker_id: &str) -> Option<u32> {
        let pid_file = self.get_pid_file_path(worker_id);
        match fs::read_to_string(&pid_file) {
            Ok(content) => content.trim().parse().ok(),
            Err(_) => None,
        }
    }

    pub fn spawn_worker(&self) -> Result<WorkerInfo, String> {
        let worker_id = self.generate_unique_worker_id();
        let sub_queue_name = format!("{}-{}", self.config.sub_queue_prefix, worker_id);

        // Substitute variables in worker_module
        let worker_module_processed = substitute_template(
            &self.config.worker_module,
            &self.config.worker_base_path,
            &sub_queue_name,
            self.config.sleep_empty_sec
        );

        let mut cmd = if worker_module_processed.starts_with("bash -c '") {
            let mut cmd = Command::new("bash");
            
            // Extract the command inside single quotes
            let start_quote = worker_module_processed.find('\'').unwrap();
            let end_quote = worker_module_processed.rfind('\'').unwrap();
            let mut bash_command = worker_module_processed[start_quote + 1..end_quote].to_string();

            let template_args_str = substitute_template(
                &self.config.worker_args_template,
                &self.config.worker_base_path,
                &sub_queue_name,
                self.config.sleep_empty_sec
            );

            // Add arguments to the bash command
            bash_command = format!("{} {}", bash_command, template_args_str);

            let args = vec!["-c".to_string(), bash_command];
            cmd.args(&args);
            cmd
        } else {
            // Parse worker_module string to separate command and arguments
            let parts: Vec<String> = worker_module_processed.split_whitespace()
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
            cmd
        };

        // Set working directory to worker base path
        cmd.current_dir(&self.config.worker_base_path);

        // Set environment variables for Python virtual environment if configured
        if let Some(ref venv_path) = self.config.worker_virtual_env {
            cmd.env("VIRTUAL_ENV", venv_path);
            let venv_bin = format!("{}/bin", venv_path);
            
            // Get current PATH and prepend venv bin directory
            let current_path = std::env::var("PATH").unwrap_or_else(|_| 
                self.config.default_path.clone()
            );
            cmd.env("PATH", format!("{}:{}", venv_bin, current_path));
        }
        
        // Set PYTHONPATH environment variable (add to existing or create new)
        let worker_src_path = "./src".to_string();
        if let Ok(existing_pythonpath) = std::env::var("PYTHONPATH") {
            let new_pythonpath = format!("{}:{}", worker_src_path, existing_pythonpath);
            cmd.env("PYTHONPATH", new_pythonpath);
        } else {
            cmd.env("PYTHONPATH", worker_src_path);
        }

        // Create log directory if needed
        let log_dir = &self.config.worker_log_dir;
        if let Err(e) = fs::create_dir_all(log_dir) {
            warn!("Failed to create log directory {}: {}", log_dir, e);
        }

        // Setup log files for stdout and stderr
        let log_file_path = format!("{}/worker-{}.log", log_dir, worker_id);
        let error_log_file_path = format!("{}/worker-{}.error.log", log_dir, worker_id);

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)
            .and_then(|stdout_file| {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&error_log_file_path)
                    .map(|stderr_file| (stdout_file, stderr_file))
            }) 
        {
            Ok((stdout_file, stderr_file)) => {
                cmd.stdout(Stdio::from(stdout_file));
                cmd.stderr(Stdio::from(stderr_file));
            }
            Err(e) => {
                warn!("Failed to create log files for worker {}: {}, using null stdio", worker_id, e);
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
            }
        }

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();

                // Create pids directory if needed
                let pids_dir = &self.config.worker_pids_dir;
                if let Err(e) = fs::create_dir_all(&pids_dir) {
                    warn!("Failed to create pids directory {}: {}", pids_dir, e);
                }

                // Write PID file
                let pid_file = self.get_pid_file_path(&worker_id);
                if let Err(e) = fs::write(&pid_file, pid.to_string()) {
                    warn!("Failed to write PID file {}: {}", pid_file, e);
                }

                let worker_info = WorkerInfo {
                    unique_id: worker_id.clone(),
                    pid,
                };

                info!("Spawned worker {} with PID {} for queue {} using command: {}. Logs: {}/worker-{}.log",
                      worker_id, pid, sub_queue_name, self.config.worker_module, self.config.worker_log_dir, worker_id);
                Ok(worker_info)
            }
            Err(e) => {
                error!("Failed to spawn worker: {}", e);
                Err(e.to_string())
            }
        }
    }

    pub fn spawn_new_worker(&mut self) -> Option<String> {
        match self.spawn_worker() {
            Ok(worker_info) => {
                let worker_id = worker_info.unique_id.clone();
                self.running_workers.insert(worker_id.clone(), worker_info);
                Some(worker_id)
            }
            Err(e) => {
                error!("Failed to spawn new worker: {}", e);
                None
            }
        }
    }
    
    fn cleanup_dead_worker(&mut self, worker_id: &str) {
        if let Some(_worker_info) = self.running_workers.remove(worker_id) {
            // Clean up PID file
            let pid_file = self.get_pid_file_path(worker_id);
            let _ = fs::remove_file(&pid_file);
            
            info!("Cleaned up dead worker {}", worker_id);
        }
    }

    pub fn get_active_worker_count(&mut self) -> u32 {
        // Clean up dead workers first
        self.cleanup_dead_workers();
        
        // Return current worker count
        self.running_workers.len() as u32
    }

    pub fn cleanup_dead_workers(&mut self) {
        let mut dead_worker_ids = Vec::new();

        // Find dead workers
        for (worker_id, worker_info) in self.running_workers.iter() {
            if !self.is_process_alive(worker_info.pid) {
                dead_worker_ids.push(worker_id.clone());
            }
        }

        // Clean up dead workers
        for worker_id in dead_worker_ids {
            self.cleanup_dead_worker(&worker_id);
        }
    }

    pub fn ensure_minimum_workers(&mut self) {
        let current_count = self.get_active_worker_count();
        let needed = if current_count < self.config.min_workers {
            self.config.min_workers - current_count
        } else {
            0
        };
        
        for _ in 0..needed {
            if let Some(worker_id) = self.spawn_new_worker() {
                info!("Spawned additional worker {} to meet minimum requirement", worker_id);
            }
        }
    }
    
    /// Get all active workers and their queue names
    pub fn get_active_workers(&self) -> Vec<(String, String)> {
        let mut workers = Vec::new();
        for (worker_id, _worker_info) in self.running_workers.iter() {
            let queue_name = format!("{}-{}", self.config.sub_queue_prefix, worker_id);
            workers.push((worker_id.clone(), queue_name));
        }
        workers.sort_by_key(|(worker_id, _)| worker_id.clone());
        workers
    }
    
    /// Get worker IDs as a list
    pub fn get_worker_ids(&self) -> Vec<String> {
        self.running_workers.keys().cloned().collect()
    }
}

