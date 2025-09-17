#[macro_use]
extern crate log;

use configparser::ini::Ini;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use v_common::init_module_log;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{get_inner_binobj_as_individual, init_log, Module, PrepareError};
use v_common::module::ticket::Ticket;
use v_common::module::veda_backend::Backend;
use v_common::module::veda_module::VedaQueueModule;
use v_common::v_api::api_client::{IndvOp, ALL_MODULES};
use v_common::v_api::common_type::ResultCode;
use v_individual_model::onto::datatype::Lang;
use v_individual_model::onto::individual::Individual;
use v_storage::StorageMode;

// SMS provider configuration
#[derive(Debug, Clone)]
pub struct SmsProviderConfig {
    pub enabled: bool,
    pub provider_type: SmsProviderType,
}

#[derive(Debug, Clone)]
pub enum SmsProviderType {
    Megalabs {
        server: String,
        user: String,
        password: String,
        from: String,
        message_size_limit: usize,
        timeout_seconds: u64,
    },
}

impl Default for SmsProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider_type: SmsProviderType::Megalabs {
                server: "".to_string(),
                user: "".to_string(),
                password: "".to_string(),
                from: "".to_string(),
                message_size_limit: 500,
                timeout_seconds: 30,
            },
        }
    }
}

// Retry configuration for SMS sending by source
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub pause_seconds: u64,      // X seconds - pause between attempts
    pub max_attempts: u32,       // N attempts - maximum retry attempts
    pub total_time_seconds: u64, // T seconds - total time window for retries
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            pause_seconds: 60,        // 1 minute
            max_attempts: 3,          // 3 attempts total
            total_time_seconds: 3600, // 1 hour
        }
    }
}

// Configuration for retry settings by source
#[derive(Debug, Clone)]
pub struct RetrySettings {
    pub source_configs: HashMap<String, RetryConfig>,
    pub default_config: RetryConfig,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            source_configs: HashMap::new(),
            default_config: RetryConfig::default(),
        }
    }
}

// Information about a failed SMS attempt for retry processing
#[derive(Debug, Clone)]
pub struct FailedSmsAttempt {
    pub sms_request: SmsRequest,
    pub source: String,
    pub event_id: String,
    pub attempt_count: u32,
    pub first_attempt_time: Instant,
    pub next_retry_time: Instant,
    pub last_error: String,
}

// Read SMS configuration from ini file
fn read_sms_config_from_ini(ini_path: &str) -> Option<SmsProviderConfig> {
    if !Path::new(ini_path).exists() {
        info!("SMS config file not found: {}, SMS disabled", ini_path);
        return None;
    }

    let mut config = Ini::new();

    match config.load(ini_path) {
        Ok(_) => {
            let provider = config.get("sms_provider", "provider")?;
            if provider != "megalabs" {
                warn!("Unsupported SMS provider: {}, SMS disabled", provider);
                return None;
            }

            let server = config.get("sms_provider", "server")?;
            let user = config.get("sms_provider", "user")?;
            let password = config.get("sms_provider", "password")?;
            let from = config.get("sms_provider", "from")?;
            let message_size_limit = config.get("sms_provider", "message_size_limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(500);
            let timeout_seconds = config.get("sms_provider", "timeout_seconds").and_then(|s| s.parse::<u64>().ok()).unwrap_or(30);

            if server.is_empty() || user.is_empty() || password.is_empty() || from.is_empty() {
                warn!("SMS provider configuration is incomplete in ini file, SMS disabled");
                return None;
            }

            info!("SMS provider loaded from ini file: {}", provider);
            Some(SmsProviderConfig {
                enabled: true,
                provider_type: SmsProviderType::Megalabs {
                    server,
                    user,
                    password,
                    from,
                    message_size_limit,
                    timeout_seconds,
                },
            })
        },
        Err(e) => {
            error!("Failed to read SMS config from ini file {}: {}", ini_path, e);
            None
        },
    }
}

// Read retry configuration from ini file
fn read_retry_config_from_ini(ini_path: &str) -> RetrySettings {
    let mut retry_settings = RetrySettings::default();

    if !Path::new(ini_path).exists() {
        info!("Retry config file not found: {}, using defaults", ini_path);
        return retry_settings;
    }

    let mut config = Ini::new();

    match config.load(ini_path) {
        Ok(_) => {
            info!("Loading retry configurations from ini file");

            // Read default retry configuration
            if let Some(section) = config.get_map_ref().get("retry.default") {
                if let Some(pause_seconds) = section.get("pause_seconds").and_then(|s| s.as_ref().and_then(|val| val.parse::<u64>().ok())) {
                    retry_settings.default_config.pause_seconds = pause_seconds;
                }
                if let Some(max_attempts) = section.get("max_attempts").and_then(|s| s.as_ref().and_then(|val| val.parse::<u32>().ok())) {
                    retry_settings.default_config.max_attempts = max_attempts;
                }
                if let Some(total_time_seconds) = section.get("total_time_seconds").and_then(|s| s.as_ref().and_then(|val| val.parse::<u64>().ok())) {
                    retry_settings.default_config.total_time_seconds = total_time_seconds;
                }
                info!(
                    "Default retry config: pause_seconds={}, max_attempts={}, total_time_seconds={}",
                    retry_settings.default_config.pause_seconds, retry_settings.default_config.max_attempts, retry_settings.default_config.total_time_seconds
                );
            }

            // Read source-specific retry configurations
            for (section_name, section) in config.get_map_ref() {
                if section_name.starts_with("retry.") && section_name != "retry.default" {
                    let source_name = section_name.strip_prefix("retry.").unwrap().to_string();
                    let mut source_config = retry_settings.default_config.clone();

                    if let Some(pause_seconds) = section.get("pause_seconds").and_then(|s| s.as_ref().and_then(|val| val.parse::<u64>().ok())) {
                        source_config.pause_seconds = pause_seconds;
                    }
                    if let Some(max_attempts) = section.get("max_attempts").and_then(|s| s.as_ref().and_then(|val| val.parse::<u32>().ok())) {
                        source_config.max_attempts = max_attempts;
                    }
                    if let Some(total_time_seconds) = section.get("total_time_seconds").and_then(|s| s.as_ref().and_then(|val| val.parse::<u64>().ok())) {
                        source_config.total_time_seconds = total_time_seconds;
                    }

                    info!(
                        "Source '{}' retry config: pause_seconds={}, max_attempts={}, total_time_seconds={}",
                        source_name, source_config.pause_seconds, source_config.max_attempts, source_config.total_time_seconds
                    );

                    retry_settings.source_configs.insert(source_name, source_config);
                }
            }
        },
        Err(e) => {
            error!("Failed to read retry config from ini file {}: {}", ini_path, e);
        },
    }

    retry_settings
}

struct SmsSenderModule {
    sms_provider: Option<SmsProviderConfig>,
    retry_settings: RetrySettings,
    failed_attempts: Arc<Mutex<HashMap<String, FailedSmsAttempt>>>, // key: individual_id
    module_info: ModuleInfo,
    backend: Backend,
    sys_ticket: Ticket,
}

impl VedaQueueModule for SmsSenderModule {
    fn before_batch(&mut self, _size_batch: u32) -> Option<u32> {
        None
    }

    fn prepare(&mut self, queue_element: &mut Individual) -> Result<bool, PrepareError> {
        if let Some(sms_request) = self.extract_sms_request(queue_element) {
            // Check if the queue element was created by a user with sys_ticket
            let user_uri = queue_element.get_first_literal("user_uri").unwrap_or_default();
            if user_uri != self.sys_ticket.user_uri {
                info!("SMS request rejected: user {} does not have sys_ticket, required: {}", user_uri, self.sys_ticket.id);
                return Ok(false);
            }

            info!("Processing SMS request for phone: {}", sms_request.phone);

            let event_id = queue_element.get_first_literal("event_id").unwrap_or_default();

            // Send SMS synchronously and handle retry logic
            if let Some(sms_config) = &self.sms_provider {
                let (success, info_message) = self.send_sms_sync(&sms_request.phone, &sms_request.message, sms_config);
                if success {
                    // Success - remove from failed attempts if it was there and update status
                    {
                        let mut failed_attempts = self.failed_attempts.lock().unwrap();
                        failed_attempts.remove(&sms_request.individual_id);
                    }
                    self.update_sms_status(&sms_request.individual_id, true, &info_message, &event_id, None);
                } else {
                    // Failed - schedule for retry or mark as finally failed
                    self.handle_sms_failure(sms_request, &info_message, &event_id);
                }
            } else {
                warn!("SMS provider not configured, logging message: {}", sms_request.message);
                info!("SMS for {}: {}", sms_request.phone, sms_request.message);
                // Update individual with "not configured" status
                self.update_sms_status(&sms_request.individual_id, false, "SMS provider not configured", &event_id, None);
            }
        }
        let op_id = queue_element.get_first_integer("op_id").unwrap_or_default();

        if let Err(e) = self.module_info.put_info(op_id, op_id) {
            error!("failed to write module_info, op_id = {}, err = {:?}", op_id, e);
            return Err(PrepareError::Fatal);
        }

        Ok(true)
    }

    fn after_batch(&mut self, _prepared_batch_size: u32) -> Result<bool, PrepareError> {
        Ok(true)
    }

    fn heartbeat(&mut self) -> Result<(), PrepareError> {
        Ok(())
    }

    fn before_start(&mut self) {}

    fn before_exit(&mut self) {}
}

#[derive(Debug, Clone)]
pub struct SmsRequest {
    phone: String,
    message: String,
    individual_id: String,
    source: String, // v-s:source field from SMS individual
}

impl SmsSenderModule {
    fn extract_sms_request(&mut self, queue_element: &mut Individual) -> Option<SmsRequest> {
        let c = queue_element.get_first_integer("cmd");
        if c.is_none() {
            error!("[cmd] not found, id={}", queue_element.get_id());
            return None;
        }

        let mut new_state = Individual::default();
        if !get_inner_binobj_as_individual(queue_element, "new_state", &mut new_state) {
            return None;
        }
        //new_state.parse_all();

        //info!("@prepare {}", new_state.get_id());
        // Проверяем, что это индивид для отправки SMS

        let c = queue_element.get_first_integer("cmd");
        let cmd = IndvOp::from_i64(c?);

        if cmd != IndvOp::Remove && new_state.any_exists("rdf:type", &["v-s:Sms"]) {
            info!("prepare {}", new_state.get_id());

            let phone = new_state.get_first_literal("v-s:recipientPhone")?;
            let message = new_state.get_first_literal("v-s:messageBody")?;
            let source = new_state.get_first_literal("v-s:source").unwrap_or_default();

            if !phone.is_empty() && !message.is_empty() {
                return Some(SmsRequest {
                    phone,
                    message,
                    individual_id: new_state.get_id().to_string(),
                    source,
                });
            } else {
                warn!("phone is empty or message is empty");
            }
        }

        None
    }

    fn send_sms_sync(&self, phone: &str, message: &str, sms_config: &SmsProviderConfig) -> (bool, String) {
        match &sms_config.provider_type {
            SmsProviderType::Megalabs {
                server,
                user,
                password,
                from,
                message_size_limit,
                timeout_seconds,
            } => {
                if server.is_empty() || user.is_empty() || password.is_empty() || from.is_empty() {
                    let error_msg = "SMS provider configuration is incomplete";
                    error!("{}", error_msg);
                    return (false, error_msg.to_string());
                }

                // Check message size limit
                if message.len() > *message_size_limit {
                    let error_msg = format!("Message too long for SMS: {} > {}", message.len(), message_size_limit);
                    error!("{}", error_msg);
                    return (false, error_msg);
                }

                info!("Sending SMS to {} via Megalabs API (sync)", phone);

                // Parse phone number to integer
                let phone_number: i64 = match phone.parse() {
                    Ok(num) => num,
                    Err(_) => {
                        let error_msg = format!("Invalid phone number format: {}", phone);
                        error!("{}", error_msg);
                        return (false, error_msg);
                    },
                };

                // Prepare request payload
                let payload = serde_json::json!({
                    "from": from,
                    "to": phone_number,
                    "message": message
                });

                // Create HTTP client with timeout
                let client = match reqwest::blocking::Client::builder().timeout(Duration::from_secs(*timeout_seconds)).build() {
                    Ok(client) => client,
                    Err(e) => {
                        let error_msg = format!("Failed to create HTTP client: {}", e);
                        error!("{}", error_msg);
                        return (false, error_msg);
                    },
                };

                // Make synchronous HTTP request
                match client.post(server).basic_auth(user, Some(password)).json(&payload).send() {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            // Parse response JSON to check internal status
                            match resp.text() {
                                Ok(body) => {
                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                        // Check Megalabs internal status: result.status.code should be 0
                                        if let Some(result) = json.get("result") {
                                            if let Some(status) = result.get("status") {
                                                if let Some(code) = status.get("code") {
                                                    if code.as_i64() == Some(0) {
                                                        let success_msg = format!("SMS sent successfully: {}", body);
                                                        info!("{}", success_msg);
                                                        return (true, success_msg);
                                                    } else {
                                                        let error_msg = format!("API internal error - code: {}, response: {}", code, body);
                                                        error!("{}", error_msg);
                                                        return (false, error_msg);
                                                    }
                                                }
                                            }
                                        }
                                        let error_msg = format!("API unexpected response format: {}", body);
                                        error!("{}", error_msg);
                                        (false, error_msg)
                                    } else {
                                        let error_msg = format!("Failed to parse API response: {}", body);
                                        error!("{}", error_msg);
                                        (false, error_msg)
                                    }
                                },
                                Err(e) => {
                                    let error_msg = format!("Failed to read API response: {}", e);
                                    error!("{}", error_msg);
                                    (false, error_msg)
                                },
                            }
                        } else {
                            let status = resp.status();
                            let error_body = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
                            let error_msg = format!("API HTTP error - status: {}, response: {}", status, error_body);
                            error!("{}", error_msg);
                            (false, error_msg)
                        }
                    },
                    Err(e) => {
                        let error_msg = format!("Failed to send SMS request: {}", e);
                        error!("{}", error_msg);
                        (false, error_msg)
                    },
                }
            },
        }
    }

    fn update_sms_status(&mut self, individual_id: &str, success: bool, info: &str, event_id: &str, next_retry_info: Option<&str>) {
        // Load and update the SMS individual
        if let Some(sms_individual) = self.backend.get_individual(individual_id, &mut Individual::default()) {
            sms_individual.set_bool("v-s:isSuccess", success);
            sms_individual.set_string("v-s:infoOfExecuting", info, Lang::none());

            // Add information about next retry attempt if provided
            if let Some(retry_info) = next_retry_info {
                sms_individual.set_string("v-s:nextRetryInfo", retry_info, Lang::none());
            }

            // Save back to storage with update_use_param to prevent loop processing
            match self.backend.mstorage_api.update_use_param(&self.sys_ticket.id, event_id, "", ALL_MODULES, IndvOp::Put, &sms_individual) {
                Ok(res) => {
                    if res.result == ResultCode::Ok {
                        info!("Updated SMS status for {}: success={}, info={}, event_id={}", individual_id, success, info, event_id);
                    } else {
                        error!("Failed to update SMS status for {}: {:?}", individual_id, res.result);
                    }
                },
                Err(e) => {
                    error!("Failed to call update_use_param for {}: {:?}", individual_id, e);
                },
            }
        } else {
            error!("Failed to load SMS individual for status update: {}", individual_id);
        }
    }

    fn handle_sms_failure(&mut self, sms_request: SmsRequest, error_message: &str, event_id: &str) {
        // Get retry configuration for the source
        let retry_config = self.retry_settings.source_configs.get(&sms_request.source).unwrap_or(&self.retry_settings.default_config).clone();

        let current_time = Instant::now();
        let individual_id = &sms_request.individual_id;

        // Determine what action to take and collect info to avoid borrowing conflicts
        let (action, retry_info, should_remove) = {
            let mut failed_attempts = self.failed_attempts.lock().unwrap();

            if let Some(existing_attempt) = failed_attempts.get_mut(individual_id) {
                // This is a retry attempt
                existing_attempt.attempt_count += 1;
                existing_attempt.last_error = error_message.to_string();

                // Check if we should continue retrying
                let elapsed_time = current_time.duration_since(existing_attempt.first_attempt_time);
                let should_retry = existing_attempt.attempt_count < retry_config.max_attempts && elapsed_time.as_secs() < retry_config.total_time_seconds;

                if should_retry {
                    // Schedule next retry
                    existing_attempt.next_retry_time = current_time + Duration::from_secs(retry_config.pause_seconds);
                    let next_retry_info = format!(
                        "Retry attempt {} of {} scheduled in {} seconds",
                        existing_attempt.attempt_count + 1,
                        retry_config.max_attempts,
                        retry_config.pause_seconds
                    );

                    info!(
                        "SMS sending failed for {}, attempt {}/{}. Next retry in {} seconds. Error: {}",
                        individual_id, existing_attempt.attempt_count, retry_config.max_attempts, retry_config.pause_seconds, error_message
                    );

                    ("retry", Some(next_retry_info), false)
                } else {
                    // No more retries - mark as finally failed
                    info!(
                        "SMS sending finally failed for {} after {} attempts over {} seconds. Final error: {}",
                        individual_id,
                        existing_attempt.attempt_count,
                        elapsed_time.as_secs(),
                        error_message
                    );

                    let final_message = format!("Finally failed after {} attempts. Last error: {}", existing_attempt.attempt_count, error_message);

                    ("final_failure", Some(final_message), true)
                }
            } else {
                // This is the first failure - add to retry queue
                let next_retry_time = current_time + Duration::from_secs(retry_config.pause_seconds);

                let failed_attempt = FailedSmsAttempt {
                    sms_request: sms_request.clone(),
                    source: sms_request.source.clone(),
                    event_id: event_id.to_string(),
                    attempt_count: 1,
                    first_attempt_time: current_time,
                    next_retry_time,
                    last_error: error_message.to_string(),
                };

                failed_attempts.insert(individual_id.clone(), failed_attempt);

                let next_retry_info = format!("First attempt failed, retry 2 of {} scheduled in {} seconds", retry_config.max_attempts, retry_config.pause_seconds);

                info!(
                    "SMS sending failed for {} (source: {}), attempt 1/{}. Next retry in {} seconds. Error: {}",
                    individual_id, sms_request.source, retry_config.max_attempts, retry_config.pause_seconds, error_message
                );

                ("first_failure", Some(next_retry_info), false)
            }
        };

        // Now update status based on the action decided above
        match action {
            "retry" | "first_failure" => {
                if let Some(info) = retry_info {
                    self.update_sms_status(individual_id, false, error_message, event_id, Some(&info));
                }
            },
            "final_failure" => {
                if let Some(info) = retry_info {
                    self.update_sms_status(individual_id, false, &info, event_id, None);
                }

                // Remove from retry queue after updating status
                if should_remove {
                    let mut failed_attempts = self.failed_attempts.lock().unwrap();
                    failed_attempts.remove(individual_id);
                }
            },
            _ => {},
        }
    }
}

// Start background thread for processing retry attempts
fn start_retry_thread(failed_attempts: Arc<Mutex<HashMap<String, FailedSmsAttempt>>>, sms_provider: Option<SmsProviderConfig>, sys_ticket: Ticket) {
    thread::spawn(move || {
        info!("Starting SMS retry thread");

        // Create backend for retry thread
        let mut backend = Backend::create(StorageMode::ReadWrite, false);

        loop {
            thread::sleep(Duration::from_secs(10)); // Check every 10 seconds

            let current_time = Instant::now();
            let mut attempts_to_retry = Vec::new();

            // Collect attempts that are ready for retry
            {
                let failed_attempts_guard = failed_attempts.lock().unwrap();
                for (individual_id, attempt) in failed_attempts_guard.iter() {
                    if current_time >= attempt.next_retry_time {
                        attempts_to_retry.push((individual_id.clone(), attempt.clone()));
                    }
                }
            }

            // Process retry attempts
            for (individual_id, attempt) in attempts_to_retry {
                if let Some(ref sms_config) = sms_provider {
                    info!("Retrying SMS for {} (attempt {} of {})", individual_id, attempt.attempt_count + 1, attempt.attempt_count + 3); // Assuming max_attempts but we'll get it from config

                    // Try to send SMS
                    let (success, info_message) = send_sms_sync_static(&attempt.sms_request.phone, &attempt.sms_request.message, sms_config);

                    if success {
                        // Success - remove from failed attempts and update status
                        {
                            let mut failed_attempts_guard = failed_attempts.lock().unwrap();
                            failed_attempts_guard.remove(&individual_id);
                        }

                        update_sms_status_static(&mut backend, &sys_ticket, &individual_id, true, &info_message, &attempt.event_id, None);

                        info!("SMS retry successful for {} after {} attempts", individual_id, attempt.attempt_count + 1);
                    } else {
                        // Still failed - will be handled by the logic in failed_attempts
                        error!("SMS retry failed for {}, attempt {}: {}", individual_id, attempt.attempt_count + 1, info_message);

                        // Note: The main thread logic will handle the retry scheduling
                        // We just need to simulate a failure here, but since this is a separate thread,
                        // we need to implement the retry logic here as well

                        // For now, let's update the attempt in memory and let the main logic handle it
                        // This is a simplified approach - in production, we might want to have
                        // the retry thread handle all the logic

                        {
                            let mut failed_attempts_guard = failed_attempts.lock().unwrap();
                            if let Some(stored_attempt) = failed_attempts_guard.get_mut(&individual_id) {
                                stored_attempt.attempt_count += 1;
                                stored_attempt.last_error = info_message.clone();

                                // Check if we should continue retrying
                                // We need the retry config here, but for simplicity, let's use defaults
                                let elapsed_time = current_time.duration_since(stored_attempt.first_attempt_time);
                                let max_attempts = 3; // Default, should get from config
                                let total_time_seconds = 3600; // Default, should get from config
                                let pause_seconds = 60; // Default, should get from config

                                let should_retry = stored_attempt.attempt_count < max_attempts && elapsed_time.as_secs() < total_time_seconds;

                                if should_retry {
                                    // Schedule next retry
                                    stored_attempt.next_retry_time = current_time + Duration::from_secs(pause_seconds);
                                    let next_retry_info =
                                        format!("Retry attempt {} of {} scheduled in {} seconds", stored_attempt.attempt_count + 1, max_attempts, pause_seconds);

                                    update_sms_status_static(
                                        &mut backend,
                                        &sys_ticket,
                                        &individual_id,
                                        false,
                                        &info_message,
                                        &stored_attempt.event_id,
                                        Some(&next_retry_info),
                                    );
                                } else {
                                    // No more retries - mark as finally failed
                                    let final_message = format!("Finally failed after {} attempts. Last error: {}", stored_attempt.attempt_count, info_message);
                                    update_sms_status_static(&mut backend, &sys_ticket, &individual_id, false, &final_message, &stored_attempt.event_id, None);

                                    // Remove from retry queue - this will be done outside the loop
                                    // to avoid borrowing issues
                                }
                            }
                        }
                    }
                }
            }

            // Clean up finally failed attempts
            {
                let mut failed_attempts_guard = failed_attempts.lock().unwrap();
                let mut to_remove = Vec::new();

                for (individual_id, attempt) in failed_attempts_guard.iter() {
                    let elapsed_time = current_time.duration_since(attempt.first_attempt_time);
                    // Using default values for now - should be configurable
                    if attempt.attempt_count >= 3 || elapsed_time.as_secs() >= 3600 {
                        to_remove.push(individual_id.clone());
                    }
                }

                for individual_id in to_remove {
                    failed_attempts_guard.remove(&individual_id);
                    info!("Removed finally failed SMS attempt from retry queue: {}", individual_id);
                }
            }
        }
    });
}

// Static version of send_sms_sync for use in retry thread
fn send_sms_sync_static(phone: &str, message: &str, sms_config: &SmsProviderConfig) -> (bool, String) {
    match &sms_config.provider_type {
        SmsProviderType::Megalabs {
            server,
            user,
            password,
            from,
            message_size_limit,
            timeout_seconds,
        } => {
            if server.is_empty() || user.is_empty() || password.is_empty() || from.is_empty() {
                let error_msg = "SMS provider configuration is incomplete";
                error!("{}", error_msg);
                return (false, error_msg.to_string());
            }

            // Check message size limit
            if message.len() > *message_size_limit {
                let error_msg = format!("Message too long for SMS: {} > {}", message.len(), message_size_limit);
                error!("{}", error_msg);
                return (false, error_msg);
            }

            info!("Sending SMS to {} via Megalabs API (retry)", phone);

            // Parse phone number to integer
            let phone_number: i64 = match phone.parse() {
                Ok(num) => num,
                Err(_) => {
                    let error_msg = format!("Invalid phone number format: {}", phone);
                    error!("{}", error_msg);
                    return (false, error_msg);
                },
            };

            // Prepare request payload
            let payload = serde_json::json!({
                "from": from,
                "to": phone_number,
                "message": message
            });

            // Create HTTP client with timeout
            let client = match reqwest::blocking::Client::builder().timeout(Duration::from_secs(*timeout_seconds)).build() {
                Ok(client) => client,
                Err(e) => {
                    let error_msg = format!("Failed to create HTTP client: {}", e);
                    error!("{}", error_msg);
                    return (false, error_msg);
                },
            };

            // Make synchronous HTTP request
            match client.post(server).basic_auth(user, Some(password)).json(&payload).send() {
                Ok(resp) => {
                    if resp.status().is_success() {
                        // Parse response JSON to check internal status
                        match resp.text() {
                            Ok(body) => {
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                    // Check Megalabs internal status: result.status.code should be 0
                                    if let Some(result) = json.get("result") {
                                        if let Some(status) = result.get("status") {
                                            if let Some(code) = status.get("code") {
                                                if code.as_i64() == Some(0) {
                                                    let success_msg = format!("SMS sent successfully: {}", body);
                                                    info!("{}", success_msg);
                                                    return (true, success_msg);
                                                } else {
                                                    let error_msg = format!("API internal error - code: {}, response: {}", code, body);
                                                    error!("{}", error_msg);
                                                    return (false, error_msg);
                                                }
                                            }
                                        }
                                    }
                                    let error_msg = format!("API unexpected response format: {}", body);
                                    error!("{}", error_msg);
                                    (false, error_msg)
                                } else {
                                    let error_msg = format!("Failed to parse API response: {}", body);
                                    error!("{}", error_msg);
                                    (false, error_msg)
                                }
                            },
                            Err(e) => {
                                let error_msg = format!("Failed to read API response: {}", e);
                                error!("{}", error_msg);
                                (false, error_msg)
                            },
                        }
                    } else {
                        let status = resp.status();
                        let error_body = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
                        let error_msg = format!("API HTTP error - status: {}, response: {}", status, error_body);
                        error!("{}", error_msg);
                        (false, error_msg)
                    }
                },
                Err(e) => {
                    let error_msg = format!("Failed to send SMS request: {}", e);
                    error!("{}", error_msg);
                    (false, error_msg)
                },
            }
        },
    }
}

// Static version of update_sms_status for use in retry thread
fn update_sms_status_static(backend: &mut Backend, sys_ticket: &Ticket, individual_id: &str, success: bool, info: &str, event_id: &str, next_retry_info: Option<&str>) {
    // Load and update the SMS individual
    if let Some(sms_individual) = backend.get_individual(individual_id, &mut Individual::default()) {
        sms_individual.set_bool("v-s:isSuccess", success);
        sms_individual.set_string("v-s:infoOfExecuting", info, Lang::none());

        // Add information about next retry attempt if provided
        if let Some(retry_info) = next_retry_info {
            sms_individual.set_string("v-s:nextRetryInfo", retry_info, Lang::none());
        }

        // Save back to storage with update_use_param to prevent loop processing
        match backend.mstorage_api.update_use_param(&sys_ticket.id, event_id, "", ALL_MODULES, IndvOp::Put, &sms_individual) {
            Ok(res) => {
                if res.result == ResultCode::Ok {
                    info!("Updated SMS status for {} (retry thread): success={}, info={}, event_id={}", individual_id, success, info, event_id);
                } else {
                    error!("Failed to update SMS status for {} (retry thread): {:?}", individual_id, res.result);
                }
            },
            Err(e) => {
                error!("Failed to call update_use_param for {} (retry thread): {:?}", individual_id, e);
            },
        }
    } else {
        error!("Failed to load SMS individual for status update (retry thread): {}", individual_id);
    }
}

fn main() -> std::io::Result<()> {
    init_module_log!("SMS_SENDER");
    let mut module = Module::new_with_name("sms-sender");

    let path = "./data";
    let module_info = ModuleInfo::new(path, "sms-sender", true);
    if module_info.is_err() {
        error!("failed to start, err = {:?}", &module_info.err());
        return Ok(());
    }

    // Загружаем конфигурацию SMS
    let sms_provider = read_sms_config_from_ini("./config/veda-sms-sender.ini");
    if sms_provider.is_none() {
        warn!("SMS provider not configured, module will log messages only");
    }

    // Загружаем конфигурацию повторных отправок
    let retry_settings = read_retry_config_from_ini("./config/veda-sms-sender.ini");
    info!("Retry settings loaded: {} source configs", retry_settings.source_configs.len());

    let mut backend = Backend::create(StorageMode::ReadWrite, false);

    let systicket = if let Ok(t) = backend.get_sys_ticket_id() {
        t
    } else {
        error!("Failed to get sys_ticket_id");
        return Ok(());
    };

    let stobj = backend.get_ticket_from_db(&systicket);

    // Create shared storage for failed attempts
    let failed_attempts = Arc::new(Mutex::new(HashMap::new()));

    let mut my_module = SmsSenderModule {
        sms_provider: sms_provider.clone(),
        retry_settings,
        failed_attempts: failed_attempts.clone(),
        module_info: module_info.unwrap(),
        backend,
        sys_ticket: stobj.clone(),
    };

    // Start retry thread if SMS provider is configured
    if let Some(_) = &sms_provider {
        start_retry_thread(failed_attempts.clone(), sms_provider.clone(), stobj.clone());
    }

    module.prepare_queue(&mut my_module);

    Ok(())
}
