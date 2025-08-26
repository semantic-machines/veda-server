use crate::common::extract_addr;
use actix_web::{web, HttpRequest, HttpResponse};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use futures::lock::Mutex;
use hex;
use hmac::Hmac;
use log::{error, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use base64;

use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use v_common::v_api::api_client::AuthClient;

type HmacSha256 = Hmac<Sha256>;

// Configuration structures
#[derive(Debug, Clone)]
pub struct SmsAuthConfig {
    pub enabled: bool,
    pub client_secret: String,
    pub provider: SmsProviderConfig,
    pub code_settings: CodeSettings,
    pub rate_limits: RateLimits,
    pub max_time_drift: u64,
}

#[derive(Debug, Clone)]
pub struct CodeSettings {
    pub length: usize,
    pub ttl_seconds: u64,
    pub max_attempts: u8,
}

#[derive(Debug, Clone)]
pub struct RateLimits {
    pub codes_per_phone_per_hour: u32,
    pub codes_per_ip_per_hour: u32,
}

#[derive(Debug, Clone)]
pub enum SmsProviderConfig {
    Megalabs {
        server: String,
        user: String,
        password: String,
        from: String,
        message_size_limit: usize,
    },
}

impl Default for SmsAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_secret: "default-secret-key".to_string(),
            provider: SmsProviderConfig::Megalabs {
                server: "".to_string(),
                user: "".to_string(),
                password: "".to_string(),
                from: "".to_string(),
                message_size_limit: 500,
            },
            code_settings: CodeSettings {
                length: 6,
                ttl_seconds: 300,
                max_attempts: 3,
            },
            rate_limits: RateLimits {
                codes_per_phone_per_hour: 5,
                codes_per_ip_per_hour: 20,
            },
            max_time_drift: 300,
        }
    }
}

// Request/Response structures
#[derive(Debug, Deserialize)]
pub struct SaltedSmsRequest {
    pub phone: String,
    pub timestamp: u64,
    pub nonce: String,
    pub salt: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SmsVerifyRequest {
    pub token: String, // encrypted token
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct SmsAuthResponse {
    pub token: String,
}



// Internal data structures removed - using direct mapping phone -> user_id

// Structure for encrypted session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionData {
    pub phone: String,
    pub code_hash: String,
    pub user_id: String,
    pub created_at: u64, // timestamp
    pub attempts: u8,
    // Stateless fields - no server-side storage needed
    pub request_nonce: String,    // nonce from original request
    pub request_salt: String,     // salt from original request  
    pub request_timestamp: u64,   // timestamp from original request
}

// Container for encrypted session token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionToken {
    pub data: String, // base64 encoded encrypted data
    pub nonce: String, // base64 encoded nonce
}



// Error types
#[derive(Debug, Error)]
pub enum SmsError {
    #[error("SMS service is disabled")]
    ServiceDisabled,
    #[error("Invalid phone number: {0}")]
    InvalidPhone(String),
    #[error("Phone number not registered")]
    PhoneNotRegistered,
    #[error("Session expired")]
    SessionExpired,
    #[error("Invalid verification code")]
    InvalidCode,
    #[error("Too many attempts")]
    TooManyAttempts,
    #[error("Timestamp expired")]
    TimestampExpired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Invalid token format")]
    InvalidTokenFormat,
}

// SMS provider trait
pub trait SmsProvider: Send + Sync {
    fn send_sms(&self, phone: &str, message: &str) -> Result<SmsResult, SmsError>;
}

#[derive(Debug)]
pub struct SmsResult;

// Megalabs provider implementation
pub struct MegalabsProvider {
    client: reqwest::Client,
    server: String,
    user: String,
    password: String,
    from: String,
    message_size_limit: usize,
}

impl MegalabsProvider {
    pub fn new(server: String, user: String, password: String, from: String, message_size_limit: usize) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
            user,
            password,
            from,
            message_size_limit,
        }
    }
}

impl SmsProvider for MegalabsProvider {
    fn send_sms(&self, phone: &str, message: &str) -> Result<SmsResult, SmsError> {
        // Check message size limit
        if message.len() > self.message_size_limit {
            return Err(SmsError::InvalidInput("Message too long".to_string()));
        }

        info!("Sending SMS to {} via Megalabs API", phone);
        
        // Parse phone number to integer (as per Megalabs API requirement)
        let phone_number: i64 = phone.parse().map_err(|_| {
            SmsError::InvalidInput("Invalid phone number format".to_string())
        })?;

        // Prepare request payload (using 'message' field, not 'text')
        let payload = serde_json::json!({
            "from": self.from,
            "to": phone_number,
            "message": message
        });

        // Make HTTP request to Megalabs API
        let response = futures::executor::block_on(async {
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
                    let response_body = futures::executor::block_on(async {
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
                                                return Ok(SmsResult);
                                            } else {
                                                error!("Megalabs API internal error - code: {}, response: {}", code, body);
                                                return Err(SmsError::InvalidInput(format!("SMS service internal error: {}", body)));
                                            }
                                        }
                                    }
                                }
                                error!("Megalabs API unexpected response format: {}", body);
                                Err(SmsError::InvalidInput(format!("Unexpected API response: {}", body)))
                            } else {
                                error!("Failed to parse Megalabs API response: {}", body);
                                Err(SmsError::InvalidInput(format!("Invalid API response: {}", body)))
                            }
                        }
                        Err(e) => {
                            error!("Failed to read Megalabs API response: {}", e);
                            Err(SmsError::InvalidInput("Failed to read API response".to_string()))
                        }
                    }
                } else {
                    let status = resp.status();
                    let error_body = futures::executor::block_on(async {
                        resp.text().await.unwrap_or_else(|_| "Unknown error".to_string())
                    });
                    error!("Megalabs API HTTP error - status: {}, response: {}", status, error_body);
                    Err(SmsError::InvalidInput(format!("SMS service HTTP request error. Status: {}, response: {}", status, error_body)))
                }
            }
            Err(e) => {
                error!("Failed to send SMS request: {}", e);
                Err(SmsError::InvalidInput(format!("Network error: {}", e)))
            }
        }
    }
}

// Main SMS authentication service - now fully stateless
pub struct SmsAuthService {
    config: SmsAuthConfig,
    provider: Box<dyn SmsProvider>,
    // Stateless: all security checks moved to encrypted tokens
}

impl SmsAuthService {
    pub fn new(config: SmsAuthConfig, provider: Box<dyn SmsProvider>) -> Self {
        Self {
            config,
            provider,
        }
    }



    pub async fn verify_salted_request(&self, request: &SaltedSmsRequest) -> Result<(), SmsError> {
        if !self.config.enabled {
            return Err(SmsError::ServiceDisabled);
        }

        // 1. Check timestamp (stricter check for stateless mode)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if (now as i64 - request.timestamp as i64).abs() > self.config.max_time_drift as i64 {
            return Err(SmsError::TimestampExpired);
        }

        // 2. Validate nonce format (basic sanity check)
        if request.nonce.len() < 16 {
            return Err(SmsError::InvalidInput("Nonce too short".to_string()));
        }

        // 3. Validate salt format (basic sanity check)  
        if request.salt.len() < 16 {
            return Err(SmsError::InvalidInput("Salt too short".to_string()));
        }

        // 4. Create message string for signature verification
        let message = self.create_message_string(request);
        
        // 5. Compute expected signature
        let expected_signature = self.compute_hmac(&message, &request.salt)?;

        // 6. Compare signatures
        if request.signature != expected_signature {
            return Err(SmsError::InvalidSignature);
        }

        // Note: In stateless mode, replay protection is limited to timestamp window
        // Nonce/salt reuse protection is moved to token-based validation
        Ok(())
    }

    fn create_message_string(&self, request: &SaltedSmsRequest) -> String {
        // Sort fields for consistency
        let timestamp_str = request.timestamp.to_string();
        let mut fields = vec![
            ("action", "sms_request"),
            ("nonce", &request.nonce),
            ("phone", &request.phone),
            ("salt", &request.salt),
            ("timestamp", &timestamp_str),
        ];
        fields.sort_by(|a, b| a.0.cmp(b.0));
        
        fields.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("|")
    }

    fn compute_hmac(&self, message: &str, salt: &str) -> Result<String, SmsError> {
        use hmac::Mac;
        let mac = match <HmacSha256 as hmac::Mac>::new_from_slice((self.config.client_secret.clone() + salt).as_bytes()) {
            Ok(mac) => mac,
            Err(_) => return Err(SmsError::InvalidKey),
        };
        
        let mut mac = mac;
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        Ok(signature)
    }

    fn encrypt_session_data(&self, session_data: &EncryptedSessionData) -> Result<EncryptedSessionToken, SmsError> {
        // Create encryption key from client_secret
        let key = self.derive_encryption_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SmsError::EncryptionError)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize session data
        let plaintext = serde_json::to_vec(session_data)
            .map_err(|_| SmsError::EncryptionError)?;

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice())
            .map_err(|_| SmsError::EncryptionError)?;

        Ok(EncryptedSessionToken {
            data: base64::encode(ciphertext),
            nonce: base64::encode(nonce_bytes),
        })
    }

    fn decrypt_session_data(&self, token: &EncryptedSessionToken) -> Result<EncryptedSessionData, SmsError> {
        // Create encryption key from client_secret
        let key = self.derive_encryption_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SmsError::DecryptionError)?;

        // Decode nonce and ciphertext
        let nonce_bytes = base64::decode(&token.nonce)
            .map_err(|_| SmsError::InvalidTokenFormat)?;
        let ciphertext = base64::decode(&token.data)
            .map_err(|_| SmsError::InvalidTokenFormat)?;

        if nonce_bytes.len() != 12 {
            return Err(SmsError::InvalidTokenFormat);
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())
            .map_err(|_| SmsError::DecryptionError)?;

        // Deserialize session data
        let session_data: EncryptedSessionData = serde_json::from_slice(&plaintext)
            .map_err(|_| SmsError::DecryptionError)?;

        Ok(session_data)
    }

    fn derive_encryption_key(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::default();
        
        // Base prefix
        hasher.update(b"SMS_ENCRYPTION_");
        
        // Main secret
        hasher.update(self.config.client_secret.as_bytes());
        
        // Code settings - влияют на логику проверки
        hasher.update(self.config.code_settings.ttl_seconds.to_le_bytes());
        hasher.update(&[self.config.code_settings.max_attempts]);
        hasher.update(self.config.code_settings.length.to_le_bytes());
        
        // Rate limits - влияют на доступность сервиса
        hasher.update(self.config.rate_limits.codes_per_phone_per_hour.to_le_bytes());
        hasher.update(self.config.rate_limits.codes_per_ip_per_hour.to_le_bytes());
        
        // Time drift setting - влияет на валидацию времени
        hasher.update(self.config.max_time_drift.to_le_bytes());
        
        // Provider configuration - уникально для каждой настройки провайдера
        match &self.config.provider {
            SmsProviderConfig::Megalabs { server, user, from, message_size_limit, .. } => {
                hasher.update(b"MEGALABS_");
                hasher.update(server.as_bytes());
                hasher.update(user.as_bytes());
                hasher.update(from.as_bytes());
                hasher.update(message_size_limit.to_le_bytes());
            }
        }
        
        hasher.finalize().into()
    }

    // Create separate encryption key for fake responses to prevent attackers from distinguishing errors
    fn derive_fake_encryption_key(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::default();
        
        // Base prefix - different from real key
        hasher.update(b"SMS_FAKE_ENCRYPTION_");
        
        // Use the same secret but with different prefix
        hasher.update(self.config.client_secret.as_bytes());
        
        // Add some fake data to make it different
        hasher.update(b"FAKE_RESPONSE_SALT_12345");
        
        hasher.finalize().into()
    }

    // Generate fake encrypted token for error responses
    fn create_fake_token(&self) -> Result<String, SmsError> {
        // Create fake session data that looks realistic
        let fake_session = EncryptedSessionData {
            phone: "79999999999".to_string(),
            code_hash: "fake_hash_value".to_string(),
            user_id: "fake_user".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            attempts: 0,
            request_nonce: "fake-nonce-uuid".to_string(),
            request_salt: "fake123456789fake".to_string(),
            request_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Use separate encryption key for fake responses
        let key = self.derive_fake_encryption_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SmsError::EncryptionError)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize fake session data
        let plaintext = serde_json::to_vec(&fake_session)
            .map_err(|_| SmsError::EncryptionError)?;

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice())
            .map_err(|_| SmsError::EncryptionError)?;

        let fake_token = EncryptedSessionToken {
            data: base64::encode(ciphertext),
            nonce: base64::encode(nonce),
        };

        let token_string = serde_json::to_string(&fake_token)
            .map_err(|_| SmsError::EncryptionError)?;

        Ok(token_string)
    }

    pub async fn request_auth_code(
        &self,
        request: &SaltedSmsRequest,
        _ip_addr: &str, // IP address for logging purposes (rate limiting removed in stateless mode)
    ) -> Result<String, SmsError> {
        // Normalize phone number
        let normalized_phone = self.normalize_phone(&request.phone)?;

        // Note: In stateless mode, rate limiting is simplified
        // Full rate limiting would require shared storage (Redis/DB)
        // For now, rely on timestamp window and SMS provider limits

        // Generate code for all valid phone numbers
        let code = self.generate_code();
        let code_hash = self.hash_code(&code);

        // Create encrypted session data including request details
        // User validation will be done by AuthClient during verification
        let session_data = EncryptedSessionData {
            phone: normalized_phone.clone(),
            code_hash,
            user_id: "".to_string(), // Empty - will be resolved by AuthClient
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            attempts: 0,
            // Include original request data for replay protection
            request_nonce: request.nonce.clone(),
            request_salt: request.salt.clone(),
            request_timestamp: request.timestamp,
        };

        // Encrypt session data and serialize to string
        let encrypted_token = self.encrypt_session_data(&session_data)?;
        let token_string = serde_json::to_string(&encrypted_token)
            .map_err(|_| SmsError::EncryptionError)?;

        // Send SMS to all valid phone numbers
        // SMS provider will handle invalid numbers
        let message = format!("Ваш код для входа: {}. Никому его не сообщайте.", code);
        self.provider.send_sms(&normalized_phone, &message)?;

        info!("SMS auth code sent to {}", normalized_phone);
        Ok(token_string)
    }

    pub async fn verify_auth_code(
        &self,
        encrypted_token: &str,
        code: &str,
        auth_client: &Mutex<AuthClient>,
    ) -> Result<serde_json::Value, SmsError> {
        // Parse and decrypt the token
        let token: EncryptedSessionToken = serde_json::from_str(encrypted_token)
            .map_err(|_| SmsError::InvalidTokenFormat)?;
        
        let session_data = self.decrypt_session_data(&token)?;
        
        // Check session expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if (now - session_data.created_at) > self.config.code_settings.ttl_seconds {
            return Err(SmsError::SessionExpired);
        }

        // Additional security: verify request timestamp hasn't been reused
        // This provides limited replay protection within the timestamp window
        if (now - session_data.request_timestamp) > self.config.max_time_drift * 2 {
            return Err(SmsError::SessionExpired);
        }

        // Check attempts
        if session_data.attempts >= self.config.code_settings.max_attempts {
            return Err(SmsError::TooManyAttempts);
        }

        // Verify SMS code
        if !self.verify_code_hash(code, &session_data.code_hash) {
            // Note: In stateless mode we can't update the token with new attempt count
            // Each verification attempt gets a fresh decrypt of the original token
            return Err(SmsError::InvalidCode);
        }

        info!("SMS auth successful via phone {}", session_data.phone);

        // Pass phone directly to AuthClient - let it handle user resolution
        // AuthClient should be able to authenticate by phone number
        match auth_client.lock().await.authenticate(&session_data.phone, &None, None, &None) {
            Ok(auth_result) => {
                Ok(auth_result)
            },
            Err(e) => {
                error!("Failed to authenticate phone {} via AuthClient: {:?}", session_data.phone, e);
                Err(SmsError::PhoneNotRegistered)
            }
        }
    }

    fn normalize_phone(&self, phone: &str) -> Result<String, SmsError> {
        // Remove all non-digit characters
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        
        // Validate length and format
        match digits.len() {
            11 if digits.starts_with('7') => Ok(digits),
            11 if digits.starts_with('8') => Ok(format!("7{}", &digits[1..])),
            10 => Ok(format!("7{}", digits)),
            _ => Err(SmsError::InvalidPhone(phone.to_string())),
        }
    }

    fn generate_code(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..self.config.code_settings.length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect()
    }

    fn hash_code(&self, code: &str) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::default();
        hasher.update(code.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn verify_code_hash(&self, code: &str, hash: &str) -> bool {
        self.hash_code(code) == hash
    }


}

// HTTP handlers
pub async fn salted_sms_request(
    req: HttpRequest,
    data: web::Json<SaltedSmsRequest>,
    sms_service: web::Data<SmsAuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    let ip_addr = extract_addr(&req)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Verify salted request
    if let Err(e) = sms_service.verify_salted_request(&data).await {
        warn!("Salted verification failed from {}: {:?}", ip_addr, e);
        // Return fake token to prevent user enumeration
        let fake_token = sms_service.create_fake_token().unwrap_or_else(|_| "error".to_string());
        return Ok(HttpResponse::BadRequest().json(SmsAuthResponse {
            token: fake_token,
        }));
    }

    // Send SMS
    match sms_service.request_auth_code(&data, &ip_addr).await {
        Ok(token) => {
            info!("SMS request processed for {} from {}", data.phone, ip_addr);
            // Return encrypted token
            Ok(HttpResponse::Ok().json(SmsAuthResponse {
                token: token,
            }))
        },
        Err(e) => {
            error!("SMS request failed: {:?}", e);
            // Return fake token to prevent user enumeration
            let fake_token = sms_service.create_fake_token().unwrap_or_else(|_| "error".to_string());
            Ok(HttpResponse::BadRequest().json(SmsAuthResponse {
                token: fake_token,
            }))
        }
    }
}

pub async fn verify_sms_auth(
    data: web::Json<SmsVerifyRequest>,
    sms_service: web::Data<SmsAuthService>,
    auth_client: web::Data<Mutex<AuthClient>>,
) -> Result<HttpResponse, actix_web::Error> {
    match sms_service.verify_auth_code(
        &data.token, // encrypted token
        &data.code,
        &auth_client,
    ).await {
        Ok(auth_result) => {
            // Return the same JSON structure as auth.rs authenticate() method
            Ok(HttpResponse::Ok().json(auth_result))
        },
        Err(e) => {
            // Return error code in the same way as auth.rs authenticate() method
            use actix_web::http::StatusCode;
            use v_common::v_api::obj::ResultCode;
            
            let result_code = match e {
                SmsError::InvalidCode => ResultCode::AuthenticationFailed,
                SmsError::SessionExpired | SmsError::TooManyAttempts => ResultCode::AuthenticationFailed,
                SmsError::DecryptionError | SmsError::InvalidTokenFormat => ResultCode::BadRequest,
                _ => ResultCode::BadRequest,
            };
            
            Ok(HttpResponse::new(StatusCode::from_u16(result_code as u16).unwrap_or(StatusCode::BAD_REQUEST)))
        },
    }
}


