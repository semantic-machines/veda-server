use crate::config::{substitute_template, DispatcherConfig};
use crate::nng_client::NngClient;
use shell_words::split as split_shell_words;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// Worker state enum
#[derive(Debug, Clone, PartialEq)]
pub enum WorkerState {
    Free,
    Busy,
    Unavailable(Instant), // Temporarily unavailable until this time
}

// Worker information structure for NNG-based workers
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub unique_id: String,
    pub pid: u32,
    pub nng_address: String,
}

// Async worker state tracker
pub type WorkerStateMap = Arc<Mutex<HashMap<String, WorkerState>>>;

// Worker process management
#[derive(Debug)]
pub struct WorkerManager {
    config: DispatcherConfig,
    running_workers: HashMap<String, WorkerInfo>, // worker_unique_id -> WorkerInfo
    worker_states: WorkerStateMap,
    base_port: u16, // Starting port for NNG workers
    nng_client: Arc<NngClient>,
}

impl WorkerManager {
    pub fn new(config: DispatcherConfig, nng_client: Arc<NngClient>) -> Self {
        Self {
            config,
            running_workers: HashMap::new(),
            worker_states: Arc::new(Mutex::new(HashMap::new())),
            base_port: 5555, // Default starting port for NNG workers
            nng_client,
        }
    }

    // Get available (free) worker, auto-restore from Unavailable if time passed
    pub async fn get_free_worker(&self) -> Option<String> {
        let mut states = self.worker_states.lock().await;
        let now = Instant::now();

        // First pass: restore unavailable workers whose timeout expired
        let mut to_restore = Vec::new();
        for (worker_id, state) in states.iter() {
            if let WorkerState::Unavailable(until_time) = state {
                if now >= *until_time {
                    to_restore.push(worker_id.clone());
                }
            }
        }

        // Restore expired unavailable workers to Free
        for worker_id in to_restore {
            if self.running_workers.contains_key(&worker_id) {
                states.insert(worker_id.clone(), WorkerState::Free);
                info!("Worker {} restored from unavailable state", worker_id);
            }
        }

        // Second pass: find free worker
        for (worker_id, state) in states.iter() {
            if *state == WorkerState::Free && self.running_workers.contains_key(worker_id) {
                return Some(worker_id.clone());
            }
        }

        None
    }

    // Mark worker as busy
    pub async fn mark_worker_busy(&self, worker_id: &str) {
        let mut states = self.worker_states.lock().await;
        states.insert(worker_id.to_string(), WorkerState::Busy);
    }

    // Mark worker as free
    pub async fn mark_worker_free(&self, worker_id: &str) {
        let mut states = self.worker_states.lock().await;
        states.insert(worker_id.to_string(), WorkerState::Free);
    }

    // Mark worker as temporarily unavailable (due to network errors)
    pub async fn mark_worker_unavailable(&self, worker_id: &str, unavailable_duration: Duration) {
        let mut states = self.worker_states.lock().await;
        let until_time = Instant::now() + unavailable_duration;
        states.insert(worker_id.to_string(), WorkerState::Unavailable(until_time));

        // Count remaining available workers
        let available_count = states
            .iter()
            .filter(|(id, state)| {
                if let WorkerState::Free = state {
                    self.running_workers.contains_key(*id)
                } else {
                    false
                }
            })
            .count();

        let active_connections = self.nng_client.get_active_connections_count().await;

        warn!(
            "Worker {} marked as unavailable for {:?} (remaining available workers: {}, active NNG sockets: {})",
            worker_id, unavailable_duration, available_count, active_connections
        );
    }

    // Get worker by ID
    pub fn get_worker(&self, worker_id: &str) -> Option<&WorkerInfo> {
        self.running_workers.get(worker_id)
    }

    fn generate_unique_worker_id(&self) -> String {
        // Generate 6-character alphanumeric ID using nanoseconds timestamp
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();

        // Use last 6 digits of nanoseconds for 6-char hex ID
        format!("{:06x}", (now % 1_000_000) as u32)
    }

    pub fn get_pid_file_path(&self, worker_id: &str) -> String {
        let pids_dir = &self.config.worker_pids_dir;
        format!("{}/worker-{}.pid", pids_dir, worker_id)
    }

    pub fn is_process_alive(&self, pid: u32) -> bool {
        // Check if process exists by sending signal 0
        match std::process::Command::new("kill").arg("-0").arg(pid.to_string()).output() {
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

        // Calculate port for this worker
        let port = self.base_port + self.running_workers.len() as u16;
        let nng_address = format!("tcp://0.0.0.0:{}", port);
        // Prepare substitution map for templates
        let mut substitutions: HashMap<&str, String> = HashMap::new();
        substitutions.insert("worker_base_path", self.config.worker_base_path.clone());
        substitutions.insert("sleep_empty_sec", self.config.sleep_empty_sec.to_string());
        substitutions.insert("worker_id", worker_id.clone());
        substitutions.insert("worker_name", format!("worker-{}", worker_id));
        substitutions.insert("nng_address", nng_address.clone());
        substitutions.insert("src", "queue-shard-distributor".to_string());

        // Substitute placeholders in worker_module and worker_args_template
        let worker_module_processed = substitute_template(&self.config.worker_module, &substitutions);
        let worker_args_processed = substitute_template(&self.config.worker_args_template, &substitutions);

        // Determine command and arguments, supporting shell-style definitions
        let module_parts = split_shell_words(&worker_module_processed)
            .map_err(|e| format!("Failed to parse worker_module '{}': {}", worker_module_processed, e))?;

        if module_parts.is_empty() {
            return Err("worker_module configuration is empty".to_string());
        }

        let mut cmd = Command::new(&module_parts[0]);

        if module_parts[0] == "bash" && module_parts.len() >= 3 && module_parts[1] == "-c" {
            let mut shell_command = module_parts[2].clone();
            if !worker_args_processed.trim().is_empty() {
                shell_command = format!("{} {}", shell_command, worker_args_processed);
            }

            cmd.arg("-c");
            cmd.arg(shell_command);

            if module_parts.len() > 3 {
                cmd.args(&module_parts[3..]);
            }
        } else {
            if module_parts.len() > 1 {
                cmd.args(&module_parts[1..]);
            }

            if !worker_args_processed.trim().is_empty() {
                let args = split_shell_words(&worker_args_processed)
                    .map_err(|e| format!("Failed to parse worker_args '{}': {}", worker_args_processed, e))?;
                cmd.args(args);
            }
        }

        // Set working directory to worker base path
        cmd.current_dir(&self.config.worker_base_path);

        // Set environment variables for Python virtual environment if configured
        if let Some(ref venv_path) = self.config.worker_virtual_env {
            cmd.env("VIRTUAL_ENV", venv_path);
            let venv_bin = format!("{}/bin", venv_path);

            // Get current PATH and prepend venv bin directory
            let current_path = std::env::var("PATH").unwrap_or_else(|_| self.config.default_path.clone());
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
            .and_then(|stdout_file| OpenOptions::new().create(true).append(true).open(&error_log_file_path).map(|stderr_file| (stdout_file, stderr_file)))
        {
            Ok((stdout_file, stderr_file)) => {
                cmd.stdout(Stdio::from(stdout_file));
                cmd.stderr(Stdio::from(stderr_file));
            },
            Err(e) => {
                warn!("Failed to create log files for worker {}: {}, using null stdio", worker_id, e);
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
            },
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
                    nng_address: nng_address.clone(),
                };

                info!(
                    "Spawned NNG worker {} with PID {} listening on {}. Logs: {}/worker-{}.log",
                    worker_id, pid, nng_address, self.config.worker_log_dir, worker_id
                );
                Ok(worker_info)
            },
            Err(e) => {
                error!("Failed to spawn worker: {}", e);
                Err(e.to_string())
            },
        }
    }

    pub async fn spawn_new_worker(&mut self) -> Option<String> {
        match self.spawn_worker() {
            Ok(worker_info) => {
                let worker_id = worker_info.unique_id.clone();

                // Initialize worker state as Free
                {
                    let mut states = self.worker_states.lock().await;
                    states.insert(worker_id.clone(), WorkerState::Free);
                }

                self.running_workers.insert(worker_id.clone(), worker_info);
                Some(worker_id)
            },
            Err(e) => {
                error!("Failed to spawn new worker: {}", e);
                None
            },
        }
    }

    fn cleanup_dead_worker(&mut self, worker_id: &str) {
        if let Some(_worker_info) = self.running_workers.remove(worker_id) {
            // Clean up PID file
            let pid_file = self.get_pid_file_path(worker_id);
            let _ = fs::remove_file(&pid_file);

            // Remove from worker states (blocking call)
            let states = Arc::clone(&self.worker_states);
            let worker_id_clone = worker_id.to_string();
            tokio::spawn(async move {
                let mut states = states.lock().await;
                states.remove(&worker_id_clone);
            });

            let socket_cleanup_client = Arc::clone(&self.nng_client);
            let socket_worker_id = worker_id.to_string();
            tokio::spawn(async move {
                socket_cleanup_client.cleanup_worker_socket(&socket_worker_id).await;
            });

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

    pub async fn ensure_minimum_workers(&mut self) {
        let current_count = self.get_active_worker_count();
        let needed = if current_count < self.config.min_workers {
            self.config.min_workers - current_count
        } else {
            0
        };

        for _ in 0..needed {
            if let Some(worker_id) = self.spawn_new_worker().await {
                info!("Spawned additional worker {} to meet minimum requirement", worker_id);
            }
        }
    }

    /// Get worker IDs as a list
    pub fn get_worker_ids(&self) -> Vec<String> {
        self.running_workers.keys().cloned().collect()
    }
}
