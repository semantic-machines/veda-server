use log::{error, info, warn};
use std::path::Path;
use configparser::ini::Ini;
use v_individual_model::onto::individual::Individual;
use v_common::v_api::common_type::ResultCode;

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

// SMS provider trait and implementation
pub trait SmsProvider: Send + Sync {
    fn send_sms(&self, phone: &str, message: &str) -> Result<(), SmsError>;
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum SmsError {
    InvalidPhone(String),
    InvalidInput(String),
    NetworkError(String),
    ProviderError(String),
}

pub struct MegalabsProvider {
    server: String,
    user: String,
    password: String,
    from: String,
    message_size_limit: usize,
    client: reqwest::Client,
}

impl MegalabsProvider {
    pub fn new(server: String, user: String, password: String, from: String, message_size_limit: usize) -> Self {
        Self {
            server,
            user,
            password,
            from,
            message_size_limit,
            client: reqwest::Client::new(),
        }
    }
}

impl SmsProvider for MegalabsProvider {
    fn send_sms(&self, phone: &str, message: &str) -> Result<(), SmsError> {
        // Check message size limit
        if message.len() > self.message_size_limit {
            return Err(SmsError::InvalidInput("Message too long".to_string()));
        }

        info!("Sending SMS to {} via Megalabs API", phone);
        
        // Parse phone number to integer (as per Megalabs API requirement)
        let phone_number: i64 = phone.parse().map_err(|_| {
            SmsError::InvalidInput("Invalid phone number format".to_string())
        })?;

        // Prepare request payload
        let payload = serde_json::json!({
            "from": self.from,
            "to": phone_number,
            "message": message
        });

        // Make HTTP request to Megalabs API
        let rt = tokio::runtime::Runtime::new().map_err(|e| {
            SmsError::NetworkError(format!("Failed to create runtime: {}", e))
        })?;

        let response = rt.block_on(async {
            self.client
                .post(&self.server)
                .basic_auth(&self.user, Some(&self.password))
                .json(&payload)
                .send()
                .await
        });

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    // Parse response JSON to check internal status
                    let response_body = rt.block_on(async {
                        resp.text().await
                    });
                    
                    match response_body {
                        Ok(body) => {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                // Check Megalabs internal status: result.status.code should be 0
                                if let Some(result) = json.get("result") {
                                    if let Some(status) = result.get("status") {
                                        if let Some(code) = status.get("code") {
                                            if code.as_i64() == Some(0) {
                                                info!("SMS sent successfully to {}: {}", phone, body);
                                                return Ok(());
                                            } else {
                                                error!("Megalabs API internal error - code: {}, response: {}", code, body);
                                                return Err(SmsError::ProviderError(format!("SMS service internal error: {}", body)));
                                            }
                                        }
                                    }
                                }
                                error!("Megalabs API unexpected response format: {}", body);
                                Err(SmsError::ProviderError(format!("Unexpected API response: {}", body)))
                            } else {
                                error!("Failed to parse Megalabs API response: {}", body);
                                Err(SmsError::ProviderError(format!("Invalid API response: {}", body)))
                            }
                        }
                        Err(e) => {
                            error!("Failed to read Megalabs API response: {}", e);
                            Err(SmsError::NetworkError("Failed to read API response".to_string()))
                        }
                    }
                } else {
                    let status = resp.status();
                    let error_body = rt.block_on(async {
                        resp.text().await.unwrap_or_else(|_| "Unknown error".to_string())
                    });
                    error!("Megalabs API HTTP error - status: {}, response: {}", status, error_body);
                    Err(SmsError::NetworkError(format!("SMS service HTTP request error. Status: {}, response: {}", status, error_body)))
                }
            }
            Err(e) => {
                error!("Failed to send SMS request: {}", e);
                Err(SmsError::NetworkError(format!("Network error: {}", e)))
            }
        }
    }
}

// Structure for reading SMS configuration from ini file (unused, kept for reference)
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct SmsIniConfig {
    pub provider: String,
    pub server: String,
    pub user: String,
    pub password: String,
    pub from: String,
    pub message_size_limit: usize,
}

// Read SMS configuration from ini file
pub fn read_sms_config_from_ini(ini_path: &str) -> Option<SmsProviderConfig> {
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

// Helper function to create SMS provider from configuration
pub fn create_sms_provider(config: &SmsProviderConfig) -> Option<Box<dyn SmsProvider>> {
    if !config.enabled {
        return None;
    }

    match &config.provider_type {
        SmsProviderType::Megalabs { server, user, password, from, message_size_limit } => {
            if server.is_empty() || user.is_empty() || password.is_empty() || from.is_empty() {
                warn!("SMS provider configuration is incomplete, SMS disabled");
                return None;
            }
            Some(Box::new(MegalabsProvider::new(
                server.clone(),
                user.clone(),
                password.clone(),
                from.clone(),
                *message_size_limit,
            )))
        }
    }
}

// Mobile authentication helper functions
pub struct MobileAuth;

impl MobileAuth {
    // Check if login is a valid phone number (with or without + prefix)
    fn is_valid_phone_number(login: &str) -> bool {
        // Count digits in the login
        let digit_count = login.chars().filter(|c| c.is_numeric()).count();

        // Check if format is valid
        let valid_format = if login.starts_with('+') {
            // After + should be only digits
            login.chars().skip(1).all(|c| c.is_numeric()) && digit_count >= 10
        } else {
            // Should be only digits
            login.chars().all(|c| c.is_numeric()) && digit_count >= 10
        };

        valid_format
    }

    // Check if this is a valid SMS authentication request
    pub fn is_sms_request(login: &str, password: &str) -> bool {
        // Check if login is phone number
        let login_is_phone = Self::is_valid_phone_number(login);

        // Check if password is empty
        let password_empty = password.is_empty() || password == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        login_is_phone && password_empty
    }

    // Check if this is a mobile authentication request
    pub fn is_sms_authentication(login: &str, password: &str, secret: &str, account: &mut Individual) -> bool {
        // Check if account has mobile auth origin
        let auth_origin = account.get_first_literal("v-s:authOrigin").unwrap_or_default();
        if auth_origin.to_uppercase() != "MOBILE" {
            return false;
        }

        // Check if login is a valid phone number
        let login_is_valid_phone = Self::is_valid_phone_number(login);
        if !login_is_valid_phone {
            return false;
        }

        // Check if password is empty and secret is filled
        let password_empty = password.is_empty() || password == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let secret_filled = !secret.is_empty() && secret.len() >= 4 && secret.chars().all(|c| c.is_numeric());

        password_empty && secret_filled
    }

    // Normalize phone number for SMS sending
    pub fn normalize_phone_number(phone: &str) -> String {
        // Remove '+' and any non-digit characters
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        
        // Handle Russian phone number formats
        match digits.len() {
            11 if digits.starts_with('7') => digits,
            11 if digits.starts_with('8') => format!("7{}", &digits[1..]),
            10 => format!("7{}", digits),
            _ => digits, // Return as-is for other formats
        }
    }

    // Send SMS code using configured provider
    pub fn send_sms_code(phone: &str, code: &str, sms_provider: Option<&SmsProviderConfig>) -> ResultCode {
        // Normalize phone number
        let normalized_phone = Self::normalize_phone_number(phone);
        
        // Create SMS message
        let message = format!("Ваш код для входа: {}. Никому его не сообщайте.", code);
        
        info!("Sending SMS to {}: {}", normalized_phone, message);
        
        // Check if SMS provider is configured
        if let Some(sms_config) = sms_provider {
            if let Some(provider) = create_sms_provider(sms_config) {
                match provider.send_sms(&normalized_phone, &message) {
                    Ok(()) => {
                        info!("SMS successfully sent to {}", normalized_phone);
                        ResultCode::Ok
                    }
                    Err(e) => {
                        error!("Failed to send SMS to {}: {:?}", normalized_phone, e);
                        ResultCode::InternalServerError
                    }
                }
            } else {
                error!("SMS provider not properly configured");
                ResultCode::InternalServerError
            }
        } else {
            // SMS not configured, log the code for debugging
            warn!("SMS provider not configured, logging code: {}", code);
            info!("SMS code for {}: {}", normalized_phone, code);
            ResultCode::Ok
        }
    }
}
