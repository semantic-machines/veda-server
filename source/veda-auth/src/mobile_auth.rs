use log::{error, info, warn};
use std::path::Path;
use configparser::ini::Ini;
use v_individual_model::onto::individual::Individual;
use v_common::v_api::common_type::ResultCode;
use lazy_static::lazy_static;

// Shared tokio runtime for SMS operations (fallback for non-tokio environments)
lazy_static! {
    static ref SMS_RUNTIME: tokio::runtime::Runtime = {
        tokio::runtime::Runtime::new()
            .expect("Failed to create SMS runtime")
    };
}

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

    // Check if this is a request to send SMS code (first step: phone + empty password + empty secret)
    pub fn is_sms_code_request(login: &str, password: &str, secret: &str) -> bool {
        // Check if login is phone number
        let login_is_phone = Self::is_valid_phone_number(login);

        // Check if password is empty
        let password_empty = password.is_empty() || password == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // Check if secret is empty (this is the key difference from verification step)
        let secret_empty = secret.is_empty();

        login_is_phone && password_empty && secret_empty
    }

    // Check if this is SMS code verification request
    pub fn is_sms_code_verification(login: &str, password: &str, secret: &str, account: &mut Individual) -> bool {
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


    // Send SMS code asynchronously (non-blocking)
    pub fn send_sms_code(phone: &str, code: &str, sms_provider: Option<SmsProviderConfig>) -> ResultCode {
        // Normalize phone number
        let normalized_phone = Self::normalize_phone_number(phone);
        
        // Create SMS message
        let message = format!("Ваш код для входа: {}. Никому его не сообщайте.", code);
        
        info!("Scheduling SMS to {} using current runtime", normalized_phone);
        
        // Check if SMS provider is configured and enabled
        if let Some(sms_config) = sms_provider.filter(|config| config.enabled) {
            // Clone data for background task
            let phone_clone = normalized_phone.clone();
            let message_clone = message.clone();
            
            // Try to use current runtime handle (most efficient)
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    // We're already in a tokio runtime - use current handle
                    handle.spawn(async move {
                        Self::send_sms_pure_async(&phone_clone, &message_clone, &sms_config).await;
                    });
                    info!("SMS task spawned on current runtime for {}", normalized_phone);
                }
                Err(_) => {
                    // No current runtime - use our fallback runtime
                    SMS_RUNTIME.spawn(async move {
                        Self::send_sms_pure_async(&phone_clone, &message_clone, &sms_config).await;
                    });
                    info!("SMS task spawned on fallback runtime for {}", normalized_phone);
                }
            }
            
            ResultCode::Ok
        } else {
            // SMS not configured, log the code for debugging
            warn!("SMS provider not configured, logging code: {}", code);
            info!("SMS code for {}: {}", normalized_phone, code);
            ResultCode::Ok
        }
    }


    // Pure async SMS sending without any blocking operations
    async fn send_sms_pure_async(phone: &str, message: &str, sms_config: &SmsProviderConfig) {
        match &sms_config.provider_type {
            SmsProviderType::Megalabs { server, user, password, from, message_size_limit } => {
                if server.is_empty() || user.is_empty() || password.is_empty() || from.is_empty() {
                    error!("SMS provider configuration is incomplete (async)");
                    return;
                }

                // Check message size limit
                if message.len() > *message_size_limit {
                    error!("Message too long for SMS (async): {} > {}", message.len(), message_size_limit);
                    return;
                }

                info!("Sending SMS to {} via Megalabs API (pure async)", phone);
                
                // Parse phone number to integer
                let phone_number: i64 = match phone.parse() {
                    Ok(num) => num,
                    Err(_) => {
                        error!("Invalid phone number format (async): {}", phone);
                        return;
                    }
                };

                // Prepare request payload
                let payload = serde_json::json!({
                    "from": from,
                    "to": phone_number,
                    "message": message
                });

                // Create HTTP client
                let client = reqwest::Client::new();

                // Make PURE async HTTP request (no block_on anywhere!)
                match client
                    .post(server)
                    .basic_auth(user, Some(password))
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            // Parse response JSON to check internal status
                            match resp.text().await {
                                Ok(body) => {
                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                        // Check Megalabs internal status: result.status.code should be 0
                                        if let Some(result) = json.get("result") {
                                            if let Some(status) = result.get("status") {
                                                if let Some(code) = status.get("code") {
                                                    if code.as_i64() == Some(0) {
                                                        info!("SMS sent successfully to {} (pure async): {}", phone, body);
                                                        return;
                                                    } else {
                                                        error!("Megalabs API internal error (async) - code: {}, response: {}", code, body);
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                        error!("Megalabs API unexpected response format (async): {}", body);
                                    } else {
                                        error!("Failed to parse Megalabs API response (async): {}", body);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read Megalabs API response (async): {}", e);
                                }
                            }
                        } else {
                            let status = resp.status();
                            let error_body = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                            error!("Megalabs API HTTP error (async) - status: {}, response: {}", status, error_body);
                        }
                    }
                    Err(e) => {
                        error!("Failed to send SMS request (async): {}", e);
                    }
                }
            }
        }
    }
}

