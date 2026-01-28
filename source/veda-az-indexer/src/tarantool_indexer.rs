use ini::Ini;
use log::{error, info, warn};
use rusty_tarantool::tarantool::ClientConfig;
use std::sync::Mutex;
use std::time::Duration;
use tokio::runtime::Runtime;

/// General indexer configuration
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub consumer_suffix: String,
    pub tarantool: TarantoolConfig,
}

impl IndexerConfig {
    /// Load configuration from INI file
    pub fn from_ini(config: &Ini) -> Self {
        let consumer_suffix = config
            .get_from(Some("indexer"), "consumer_suffix")
            .unwrap_or("")
            .to_string();
        
        Self {
            consumer_suffix,
            tarantool: TarantoolConfig::from_ini(config),
        }
    }
    
    /// Get consumer name with suffix
    pub fn get_consumer_name(&self) -> String {
        if self.consumer_suffix.is_empty() {
            "az-indexer".to_string()
        } else {
            format!("az-indexer-{}", self.consumer_suffix)
        }
    }
}

/// Configuration for Tarantool connection
#[derive(Debug, Clone)]
pub struct TarantoolConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub space_id: i32,
    pub request_timeout: Duration,
}

impl Default for TarantoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 3301,
            user: "veda".to_string(),
            password: "veda_password".to_string(),
            space_id: 514, // Default AZ space ID
            request_timeout: Duration::from_secs(10),
        }
    }
}

impl TarantoolConfig {
    /// Load configuration from INI file
    pub fn from_ini(config: &Ini) -> Self {
        let section = "tarantool";
        
        let enabled = config
            .get_from(Some(section), "enabled")
            .unwrap_or("false")
            .parse::<bool>()
            .unwrap_or(false);
        
        let host = config
            .get_from(Some(section), "host")
            .unwrap_or("127.0.0.1")
            .to_string();
        
        let port = config
            .get_from(Some(section), "port")
            .unwrap_or("3301")
            .parse::<u16>()
            .unwrap_or(3301);
        
        let user = config
            .get_from(Some(section), "user")
            .unwrap_or("veda")
            .to_string();
        
        let password = config
            .get_from(Some(section), "password")
            .unwrap_or("")
            .to_string();
        
        let space_id = config
            .get_from(Some(section), "space_id")
            .unwrap_or("514")
            .parse::<i32>()
            .unwrap_or(514);
        
        let request_timeout_secs = config
            .get_from(Some(section), "request_timeout")
            .unwrap_or("10")
            .parse::<u64>()
            .unwrap_or(10);
        
        Self {
            enabled,
            host,
            port,
            user,
            password,
            space_id,
            request_timeout: Duration::from_secs(request_timeout_secs),
        }
    }
}

/// Tarantool indexer for writing ACL data
pub struct TarantoolIndexer {
    client: rusty_tarantool::tarantool::Client,
    space_id: i32,
    runtime: Mutex<Runtime>,
}

impl TarantoolIndexer {
    /// Create new TarantoolIndexer with given configuration
    pub fn new(config: &TarantoolConfig) -> Result<Self, String> {
        let addr = format!("{}:{}", config.host, config.port);
        
        info!("Connecting to Tarantool at {}", addr);
        
        let client_config = ClientConfig::new(
            addr,
            &config.user,
            &config.password,
        )
        .set_timeout_time_ms(config.request_timeout.as_millis() as u64)
        .set_reconnect_time_ms(1000);
        
        let client = client_config.build();
        
        let mut runtime = Runtime::new()
            .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;
        
        // Test connection
        let space_id = config.space_id;
        let test_result = runtime.block_on(async {
            client.ping().await
        });
        
        match test_result {
            Ok(_) => {
                info!("Successfully connected to Tarantool, space_id: {}", space_id);
                Ok(Self {
                    client,
                    space_id,
                    runtime: Mutex::new(runtime),
                })
            }
            Err(e) => {
                Err(format!("Failed to connect to Tarantool: {}", e))
            }
        }
    }
    
    /// Put key-value pair into Tarantool space
    /// Uses UPSERT semantics - insert if not exists, replace if exists
    pub fn put(&self, key: &str, value: &str) -> bool {
        let space_id = self.space_id;
        let key = key.to_string();
        let value = value.to_string();
        
        let mut runtime = match self.runtime.lock() {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to lock runtime: {}", e);
                return false;
            }
        };
        
        let result = runtime.block_on(async {
            self.client.replace(space_id, &(key.as_str(), value.as_str())).await
        });
        
        match result {
            Ok(_) => true,
            Err(e) => {
                error!("Tarantool put error for key '{}': {}", key, e);
                false
            }
        }
    }
    
    /// Remove key from Tarantool space
    pub fn remove(&self, key: &str) -> bool {
        let space_id = self.space_id;
        let key = key.to_string();
        
        let mut runtime = match self.runtime.lock() {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to lock runtime: {}", e);
                return false;
            }
        };
        
        let result = runtime.block_on(async {
            self.client.delete(space_id, &(key.as_str(),)).await
        });
        
        match result {
            Ok(_) => true,
            Err(e) => {
                // Key not found is not an error for remove operation
                warn!("Tarantool remove for key '{}': {}", key, e);
                true
            }
        }
    }
}
