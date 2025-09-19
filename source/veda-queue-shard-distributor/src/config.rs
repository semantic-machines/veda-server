use std::fs;
use std::path::Path;
use configparser::ini::Ini;

// Configuration structure
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    pub base_path: String,
    pub worker_base_path: String,
    pub main_queue_name: String,
    pub sub_queue_prefix: String,
    pub min_workers: u32,
    pub sleep_empty_sec: f64,
    pub worker_module: String,
    pub worker_args_template: String,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            base_path: "./data/queue-main".to_string(),
            worker_base_path: "./data/queue-workers".to_string(),
            main_queue_name: "individuals-flow".to_string(),
            sub_queue_prefix: "individuals-flow-shard".to_string(),
            min_workers: 4,
            sleep_empty_sec: 0.5,
            worker_module: "python3 -m src.queue_worker".to_string(),
            worker_args_template: "--base {worker_base_path} --sub {sub_queue_name} --src queue-shard-distributor --sleep-empty {sleep_empty_sec}".to_string(),
        }
    }
}

// Write default configuration to INI file
pub fn write_default_config_to_ini(ini_path: &str, config: &DispatcherConfig) -> Result<(), String> {
    let mut ini = Ini::new();

    // Set dispatcher configuration values
    ini.set("dispatcher", "base_path", Some(config.base_path.clone()));
    ini.set("dispatcher", "main_queue_name", Some(config.main_queue_name.clone()));
    ini.set("dispatcher", "min_workers", Some(config.min_workers.to_string()));

    // Set worker configuration values
    ini.set("worker", "worker_base_path", Some(config.worker_base_path.clone()));
    ini.set("worker", "sub_queue_prefix", Some(config.sub_queue_prefix.clone()));
    ini.set("worker", "sleep_empty_sec", Some(config.sleep_empty_sec.to_string()));
    ini.set("worker", "worker_module", Some(config.worker_module.clone()));
    ini.set("worker", "worker_args_template", Some(config.worker_args_template.clone()));

    // Create directory if it doesn't exist
    if let Some(parent_dir) = Path::new(ini_path).parent() {
        if let Err(e) = fs::create_dir_all(parent_dir) {
            return Err(format!("Failed to create config directory: {}", e));
        }
    }

    // Write to file
    match ini.write(ini_path) {
        Ok(_) => {
            info!("Created default configuration file: {}", ini_path);
            Ok(())
        },
        Err(e) => Err(format!("Failed to write config file {}: {}", ini_path, e))
    }
}

// Read configuration from INI file
pub fn read_config_from_ini(ini_path: &str) -> DispatcherConfig {
    let mut config = DispatcherConfig::default();

    if !Path::new(ini_path).exists() {
        info!("Config file not found: {}, creating with default values", ini_path);
        // Create the config file with default values
        if let Err(e) = write_default_config_to_ini(ini_path, &config) {
            warn!("Failed to create default config file: {}", e);
        }
        return config;
    }

    let mut ini = Ini::new();
    match ini.load(ini_path) {
        Ok(_) => {
            info!("Loading configuration from ini file: {}", ini_path);

            // Read dispatcher settings
            if let Some(base_path) = ini.get("dispatcher", "base_path") {
                config.base_path = base_path;
                info!("Config: base_path = {}", config.base_path);
            }

            if let Some(main_queue_name) = ini.get("dispatcher", "main_queue_name") {
                config.main_queue_name = main_queue_name;
                info!("Config: main_queue_name = {}", config.main_queue_name);
            }

            if let Some(min_workers) = ini.get("dispatcher", "min_workers").and_then(|s| s.parse::<u32>().ok()) {
                config.min_workers = min_workers;
                info!("Config: min_workers = {}", config.min_workers);
            }

            // Read worker settings
            if let Some(worker_base_path) = ini.get("worker", "worker_base_path") {
                config.worker_base_path = worker_base_path;
                info!("Config: worker_base_path = {}", config.worker_base_path);
            }

            if let Some(sub_queue_prefix) = ini.get("worker", "sub_queue_prefix") {
                config.sub_queue_prefix = sub_queue_prefix;
                info!("Config: sub_queue_prefix = {}", config.sub_queue_prefix);
            }

            if let Some(sleep_empty_sec) = ini.get("worker", "sleep_empty_sec").and_then(|s| s.parse::<f64>().ok()) {
                config.sleep_empty_sec = sleep_empty_sec;
                info!("Config: sleep_empty_sec = {}", config.sleep_empty_sec);
            }

            if let Some(worker_module) = ini.get("worker", "worker_module") {
                config.worker_module = worker_module;
                info!("Config: worker_module = {}", config.worker_module);
            }

            if let Some(worker_args_template) = ini.get("worker", "worker_args_template") {
                config.worker_args_template = worker_args_template;
                info!("Config: worker_args_template = {}", config.worker_args_template);
            }
        },
        Err(e) => {
            error!("Failed to read config from ini file {}: {}, using defaults", ini_path, e);
        },
    }

    config
}

// Function to substitute variables in template string
pub fn substitute_template(template: &str, worker_base_path: &str, sub_queue_name: &str, sleep_empty_sec: f64) -> String {
    let mut result = template.to_string();

    // Replace variables with actual values
    result = result.replace("{worker_base_path}", worker_base_path);
    result = result.replace("{sub_queue_name}", sub_queue_name);
    result = result.replace("{sleep_empty_sec}", &sleep_empty_sec.to_string());
    result = result.replace("{src}", "queue-shard-distributor");

    result
}
