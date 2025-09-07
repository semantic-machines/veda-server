#[macro_use]
extern crate log;

use std::path::Path;
use configparser::ini::Ini;
use v_common::init_module_log;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{get_inner_binobj_as_individual, init_log, Module, PrepareError};
use v_common::module::ticket::Ticket;
use v_common::module::veda_backend::Backend;
use v_common::module::veda_module::VedaQueueModule;
use v_common::onto::individual::Individual;
use v_common::onto::datatype::Lang;
use v_common::onto::parser::parse_raw;
use v_common::storage::common::StorageMode;
use v_common::v_api::api_client::{IndvOp, ALL_MODULES};
use v_common::v_api::obj::ResultCode;

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
            },
        }
    }
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
            let message_size_limit = config.get("sms_provider", "message_size_limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(500);

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
                },
            })
        }
        Err(e) => {
            error!("Failed to read SMS config from ini file {}: {}", ini_path, e);
            None
        }
    }
}

struct SmsSenderModule {
    sms_provider: Option<SmsProviderConfig>,
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
            let event_id = queue_element.get_first_literal("event_id").unwrap_or_default();

            // Check if the queue element was created by a user with sys_ticket
            let user_uri = queue_element.get_first_literal("user_uri").unwrap_or_default();
            if user_uri != self.sys_ticket.user_uri {
                info!("SMS request rejected: user {} does not have sys_ticket, required: {}", user_uri, self.sys_ticket.id);
                return Ok(false);
            }

            info!("Processing SMS request for phone: {}", sms_request.phone);
            
            // Send SMS synchronously and update status immediately
            if let Some(sms_config) = &self.sms_provider {
                let (success, info_message) = self.send_sms_sync(&sms_request.phone, &sms_request.message, sms_config);
                self.update_sms_status(&sms_request.individual_id, success, &info_message, &event_id);
            } else {
                warn!("SMS provider not configured, logging message: {}", sms_request.message);
                info!("SMS for {}: {}", sms_request.phone, sms_request.message);
                // Update individual with "not configured" status
                self.update_sms_status(&sms_request.individual_id, false, "SMS provider not configured", &event_id);
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

#[derive(Debug)]
struct SmsRequest {
    phone: String,
    message: String,
    individual_id: String,
}

impl SmsSenderModule {
    fn extract_sms_request(&mut self, queue_element: &mut Individual) -> Option<SmsRequest> {
        if parse_raw(queue_element).is_ok() {
            let cmd = IndvOp::from_i64(queue_element.get_first_integer("cmd")?);

            let mut new_state = Individual::default();
            if !get_inner_binobj_as_individual(queue_element, "new_state", &mut new_state){
                return None;
            }

            // Проверяем, что это индивид для отправки SMS
            if cmd != IndvOp::Remove && new_state.any_exists("rdf:type", &["v-s:Sms"]) {
                let phone = new_state.get_first_literal("v-s:recipientPhone")?;
                let message = new_state.get_first_literal("v-s:messageBody")?;
                
                if !phone.is_empty() && !message.is_empty() {
                    return Some(SmsRequest { 
                        phone, 
                        message,
                        individual_id: new_state.get_id().to_string()
                    });
                }
            }
        }

        None
    }

    fn send_sms_sync(&self, phone: &str, message: &str, sms_config: &SmsProviderConfig) -> (bool, String) {
        match &sms_config.provider_type {
            SmsProviderType::Megalabs { server, user, password, from, message_size_limit } => {
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
                    }
                };

                // Prepare request payload
                let payload = serde_json::json!({
                    "from": from,
                    "to": phone_number,
                    "message": message
                });

                // Create HTTP client with blocking client
                let client = reqwest::blocking::Client::new();

                // Make synchronous HTTP request
                match client
                    .post(server)
                    .basic_auth(user, Some(password))
                    .json(&payload)
                    .send()
                {
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
                                }
                                Err(e) => {
                                    let error_msg = format!("Failed to read API response: {}", e);
                                    error!("{}", error_msg);
                                    (false, error_msg)
                                }
                            }
                        } else {
                            let status = resp.status();
                            let error_body = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
                            let error_msg = format!("API HTTP error - status: {}, response: {}", status, error_body);
                            error!("{}", error_msg);
                            (false, error_msg)
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to send SMS request: {}", e);
                        error!("{}", error_msg);
                        (false, error_msg)
                    }
                }
            }
        }
    }

    fn update_sms_status(&mut self, individual_id: &str, success: bool, info: &str, event_id: &str) {
        // Load and update the SMS individual
        let mut sms_individual = Individual::default();
        if self.backend.storage.get_individual(individual_id, &mut sms_individual) == ResultCode::Ok {
            sms_individual.set_bool("v-s:isSuccess", success);
            sms_individual.set_string("v-s:infoOfExecuting", info, Lang::none());
            
            // Save back to storage with update_use_param to prevent loop processing
            match self.backend.mstorage_api.update_use_param(&self.sys_ticket.id, event_id, "", ALL_MODULES, IndvOp::Put, &sms_individual) {
                Ok(res) => {
                    if res.result == ResultCode::Ok {
                        info!("Updated SMS status for {}: success={}, info={}, event_id={}", individual_id, success, info, event_id);
                    } else {
                        error!("Failed to update SMS status for {}: {:?}", individual_id, res.result);
                    }
                }
                Err(e) => {
                    error!("Failed to call update_use_param for {}: {:?}", individual_id, e);
                }
            }
        } else {
            error!("Failed to load SMS individual for status update: {}", individual_id);
        }
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

    let mut backend = Backend::create(StorageMode::ReadWrite, false);

    let systicket = if let Ok(t) = backend.get_sys_ticket_id() {
        t
    } else {
        error!("Failed to get sys_ticket_id");
        return Ok(());
    };

    let stobj = backend.get_ticket_from_db(&systicket);

    let mut my_module = SmsSenderModule {
        sms_provider,
        module_info: module_info.unwrap(),
        backend,
        sys_ticket: stobj,
    };

    module.prepare_queue(&mut my_module);

    Ok(())
}
