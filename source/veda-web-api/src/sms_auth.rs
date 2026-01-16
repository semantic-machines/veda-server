use crate::common::{extract_addr, extract_initiator};
use actix_web::{web, HttpRequest, HttpResponse};
use futures::lock::Mutex;
use hex;
use hmac::Hmac;
use log::{error, info, warn};
use rand::Rng;
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, pkcs8::{DecodePrivateKey, EncodePublicKey}, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use base64;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use v_common::v_api::api_client::AuthClient;

type HmacSha256 = Hmac<Sha256>;

// Configuration structure - simplified for veda-auth integration
#[derive(Debug, Clone)]
pub struct SmsAuthConfig {
    pub enabled: bool,
    pub client_secret: String,
    pub max_time_drift: u64,
    pub rsa_key_path: Option<String>,  // Optional path to RSA private key file
}

impl Default for SmsAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_secret: "default-secret-key".to_string(),
            max_time_drift: 300,
            rsa_key_path: None,
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

// Structure for encrypted session data - simplified for veda-auth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionData {
    pub phone: String,
    pub created_at: u64, // server timestamp when session was created
    // Stateless fields - no server-side storage needed
    pub request_nonce: String,    // nonce from original request
    pub request_salt: String,     // salt from original request  
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
    #[error("Invalid verification code")]
    InvalidCode,
    #[error("Timestamp expired")]
    TimestampExpired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Session expired")]
    SessionExpired,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Invalid token format")]
    InvalidTokenFormat,
}



// Main SMS authentication service - using veda-auth API
pub struct SmsAuthService {
    config: SmsAuthConfig,
    rsa_private_key: RsaPrivateKey,
    rsa_public_key: RsaPublicKey,
}

impl SmsAuthService {
    pub fn new(config: SmsAuthConfig) -> Result<Self, SmsError> {
        // Load or generate RSA keys
        let (private_key, public_key) = if let Some(key_path) = &config.rsa_key_path {
            Self::load_rsa_keys(key_path)?
        } else {
            Self::generate_rsa_keys()?
        };
        
        Ok(Self {
            config,
            rsa_private_key: private_key,
            rsa_public_key: public_key,
        })
    }
    
    fn generate_rsa_keys() -> Result<(RsaPrivateKey, RsaPublicKey), SmsError> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|_| SmsError::EncryptionError)?;
        let public_key = RsaPublicKey::from(&private_key);
        
        info!("Generated new RSA-2048 keys for SMS session encryption");
        Ok((private_key, public_key))
    }
    
    fn load_rsa_keys(key_path: &str) -> Result<(RsaPrivateKey, RsaPublicKey), SmsError> {
        let key_data = std::fs::read_to_string(key_path)
            .map_err(|_| SmsError::InvalidKey)?;
        
        let private_key = RsaPrivateKey::from_pkcs8_pem(&key_data)
            .map_err(|_| SmsError::InvalidKey)?;
        let public_key = RsaPublicKey::from(&private_key);
        
        info!("Loaded RSA keys from {}", key_path);
        Ok((private_key, public_key))
    }



    pub async fn verify_salted_request(&self, request: &SaltedSmsRequest) -> Result<(), SmsError> {
        if !self.config.enabled {
            return Err(SmsError::ServiceDisabled);
        }

        // Check timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if (now as i64 - request.timestamp as i64).abs() > self.config.max_time_drift as i64 {
            return Err(SmsError::TimestampExpired);
        }

        // Validate nonce format
        if request.nonce.len() < 16 {
            return Err(SmsError::InvalidInput("Nonce too short".to_string()));
        }

        // Validate salt format
        if request.salt.len() < 16 {
            return Err(SmsError::InvalidInput("Salt too short".to_string()));
        }

        // Create message string for signature verification
        let message = self.create_message_string(request);
        
        // Compute expected signature
        let expected_signature = self.compute_hmac(&message, &request.salt)?;

        // Compare signatures
        if request.signature != expected_signature {
            return Err(SmsError::InvalidSignature);
        }

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
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha256>();
        
        info!("🔐 Starting encryption for session data...");
        let encryption_fingerprint = self.get_public_key_fingerprint();
        info!("🔑 Encryption RSA key fingerprint: {}", encryption_fingerprint);
        info!("Session data: {:?}", session_data);
        
        // Serialize session data
        let plaintext = serde_json::to_vec(session_data)
            .map_err(|e| {
                error!("❌ Failed to serialize session data: {:?}", e);
                SmsError::EncryptionError
            })?;
        info!("✅ Serialized to plaintext, length: {}", plaintext.len());

        // Encrypt with RSA public key
        let ciphertext = self.rsa_public_key.encrypt(&mut rng, padding, &plaintext)
            .map_err(|e| {
                error!("❌ RSA encryption failed: {:?}", e);
                error!("Plaintext length: {}", plaintext.len());
                error!("RSA key size: {} bits", self.rsa_public_key.size() * 8);
                SmsError::EncryptionError
            })?;
        info!("✅ RSA encryption successful, ciphertext length: {}", ciphertext.len());

        // Generate random nonce for additional security (not used for encryption but for token uniqueness)
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut nonce_bytes);

        let token = EncryptedSessionToken {
            data: base64::encode(&ciphertext),
            nonce: base64::encode(nonce_bytes),
        };
        
        info!("✅ Created encrypted token - data length: {}, nonce length: {}", 
              token.data.len(), token.nonce.len());

        Ok(token)
    }

    fn decrypt_session_data(&self, token: &EncryptedSessionToken, request_id: &str) -> Result<EncryptedSessionData, SmsError> {
        let padding = Oaep::new::<Sha256>();
        
        // Decode ciphertext
        let ciphertext = base64::decode(&token.data)
            .map_err(|e| {
                error!("[{}] DEBUG: base64 decode failed: {:?}", request_id, e);
                SmsError::InvalidTokenFormat
            })?;

        // Decrypt with RSA private key
        let plaintext = self.rsa_private_key.decrypt(padding, &ciphertext)
            .map_err(|e| {
                error!("[{}] DEBUG: RSA decryption failed: {:?}", request_id, e);
                SmsError::DecryptionError
            })?;

        // Deserialize session data
        let session_data: EncryptedSessionData = serde_json::from_slice(&plaintext)
            .map_err(|e| {
                error!("[{}] DEBUG: JSON deserialization failed: {:?}", request_id, e);
                SmsError::DecryptionError
            })?;

        Ok(session_data)
    }

    // RSA keys provide cryptographic security, no need for additional key derivation
    // Keys are either loaded from file or generated at startup
    pub fn get_public_key_fingerprint(&self) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::default();
        
        // Create fingerprint from public key for logging/debugging
        if let Ok(der) = self.rsa_public_key.to_public_key_der() {
            hasher.update(der.as_bytes());
            hex::encode(&hasher.finalize()[..8])  // First 8 bytes as hex
        } else {
            "unknown".to_string()
        }
    }

    // Generate fake encrypted token for error responses
    fn create_fake_token(&self) -> Result<String, SmsError> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Generate realistic random fake data
        let fake_phone = format!("799{:08}", rng.gen_range(10000000..99999999));
        let fake_nonce = format!("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}", 
            rng.gen::<u32>(), rng.gen::<u16>(), rng.gen::<u16>(), 
            rng.gen::<u16>(), rng.gen::<u64>() & 0xffffffffffff);
        let fake_salt = format!("{:032x}", rng.gen::<u128>());
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fake_session = EncryptedSessionData {
            phone: fake_phone,
            created_at: current_time,
            request_nonce: fake_nonce,
            request_salt: fake_salt,
        };

        // Encrypt fake session data with RSA
        let encrypted_token = self.encrypt_session_data(&fake_session)?;
        let token_string = serde_json::to_string(&encrypted_token)
            .map_err(|_| SmsError::EncryptionError)?;

        Ok(token_string)
    }


    pub async fn request_auth_code(
        &self,
        request: &SaltedSmsRequest,
        ip_addr: Option<std::net::IpAddr>,
        auth_client: &Mutex<AuthClient>,
        initiator: Option<&str>,
    ) -> Result<String, SmsError> {
        // Normalize phone number
        let normalized_phone = self.normalize_phone(&request.phone)?;

        // Call veda-auth API to request SMS code
        match auth_client.lock().await.authenticate(&normalized_phone, &None, ip_addr, &None, Some("veda"), initiator, None) {
            Ok(_) => {
                info!("SMS auth code requested for {}", normalized_phone);
                
                // Create encrypted session data
                let server_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let session_data = EncryptedSessionData {
                    phone: normalized_phone.clone(),
                    created_at: server_now,
                    // Include original request data for replay protection
                    request_nonce: request.nonce.clone(),
                    request_salt: request.salt.clone(),
                };

                // Encrypt session data and serialize to string
                let encrypted_token = self.encrypt_session_data(&session_data)?;
                let token_string = serde_json::to_string(&encrypted_token)
                    .map_err(|e| {
                        error!("❌ Failed to serialize encrypted token: {:?}", e);
                        SmsError::EncryptionError
                    })?;

                info!("🎯 Final token for client: '{}'", token_string);
                Ok(token_string)
            },
            Err(e) => {
                error!("Failed to request SMS code for {} via veda-auth: {:?}", normalized_phone, e);
                Err(SmsError::AuthenticationFailed)
            }
        }
    }

    pub async fn verify_auth_code(
        &self,
        encrypted_token: &str,
        code: &str,
        ip_addr: Option<std::net::IpAddr>,
        auth_client: &Mutex<AuthClient>,
        request_id: &str,
        initiator: Option<&str>,
    ) -> Result<serde_json::Value, SmsError> {
        info!("[{}] DEBUG: verify_auth_code - token_len: {}, code: '{}', ip: {:?}", 
              request_id, encrypted_token.len(), code, ip_addr);
        
        // Parse the encrypted token
        info!("[{}] DEBUG: parsing token...", request_id);
        let token: EncryptedSessionToken = serde_json::from_str(encrypted_token)
            .map_err(|e| {
                error!("[{}] DEBUG: failed to parse token: {:?}", request_id, e);
                SmsError::InvalidTokenFormat
            })?;
            
        // Decrypt session data
        info!("[{}] DEBUG: decrypting session...", request_id);
        let session_data = self.decrypt_session_data(&token, request_id)?;
        info!("[{}] DEBUG: decrypted phone: '{}'", request_id, session_data.phone);
        
        // Check session expiry
        info!("[{}] DEBUG: checking expiry...", request_id);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let session_age = now - session_data.created_at;
        if session_age > 300 { // 5 minutes
            let now_datetime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now);
            let created_datetime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(session_data.created_at);
            
            error!("[{}] DEBUG: session expired: {} seconds", request_id, session_age);
            error!("[{}] DEBUG: now: {:?} ({})", request_id, now_datetime, now);
            error!("[{}] DEBUG: created_at: {:?} ({})", request_id, created_datetime, session_data.created_at);
            return Err(SmsError::SessionExpired);
        }

        // Verify SMS code via veda-auth
        info!("[{}] DEBUG: calling veda-auth for phone: '{}'", request_id, session_data.phone);
        match auth_client.lock().await.authenticate(&session_data.phone, &None, ip_addr, &Some(code.to_string()), Some("veda"), initiator, None) {
            Ok(auth_result) => {
                info!("[{}] DEBUG: auth successful", request_id);
                Ok(auth_result)
            },
            Err(e) => {
                error!("[{}] DEBUG: auth failed: {:?}", request_id, e);
                Err(SmsError::InvalidCode)
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




}

// HTTP handlers
pub async fn salted_sms_request(
    req: HttpRequest,
    data: web::Json<SaltedSmsRequest>,
    sms_service: web::Data<SmsAuthService>,
    auth_client: web::Data<Mutex<AuthClient>>,
) -> Result<HttpResponse, actix_web::Error> {
    let ip_addr = extract_addr(&req);
    let initiator = extract_initiator(&req);

    // Verify salted request
    if let Err(e) = sms_service.verify_salted_request(&data).await {
        warn!("Salted verification failed from {:?}: {:?}", ip_addr, e);
        // Return fake token to prevent user enumeration
        let fake_token = sms_service.create_fake_token().unwrap_or_else(|_| "error".to_string());
        return Ok(HttpResponse::Ok().json(SmsAuthResponse {
            token: fake_token,
        }));
    }

    // Request SMS code via veda-auth
    match sms_service.request_auth_code(&data, ip_addr, &auth_client, initiator.as_deref()).await {
        Ok(token) => {
            info!("✅ SMS request processed for {} from {:?}", data.phone, ip_addr);
            info!("📤 Sending token to client: '{}'", token);
            Ok(HttpResponse::Ok().json(SmsAuthResponse {
                token,
            }))
        },
        Err(e) => {
            error!("SMS request failed: {:?}", e);
            // Return fake token to prevent user enumeration
            let fake_token = sms_service.create_fake_token().unwrap_or_else(|_| "error".to_string());
            Ok(HttpResponse::Ok().json(SmsAuthResponse {
                token: fake_token,
            }))
        }
    }
}

pub async fn verify_sms_auth(
    req: HttpRequest,
    data: web::Json<SmsVerifyRequest>,
    sms_service: web::Data<SmsAuthService>,
    auth_client: web::Data<Mutex<AuthClient>>,
) -> Result<HttpResponse, actix_web::Error> {
    let ip_addr = extract_addr(&req);
    let initiator = extract_initiator(&req);
    
    // Generate unique request ID for tracing
    let request_id = format!("{:08x}", rand::random::<u32>());
    
    info!("[{}] DEBUG: verify_sms_auth from {:?}, token_len: {}, code: '{}'", 
          request_id, ip_addr, data.token.len(), data.code);

    match sms_service.verify_auth_code(
        &data.token,
        &data.code,
        ip_addr,
        &auth_client,
        &request_id,
        initiator.as_deref(),
    ).await {
        Ok(auth_result) => {
            info!("[{}] DEBUG: verify_sms_auth success", request_id);
            Ok(HttpResponse::Ok().json(auth_result))
        },
        Err(e) => {
            error!("[{}] DEBUG: verify_sms_auth failed: {:?}", request_id, e);
            
            use actix_web::http::StatusCode;
            use v_common::v_api::common_type::ResultCode;
            
            let result_code = match e {
                SmsError::InvalidCode => ResultCode::AuthenticationFailed,
                SmsError::AuthenticationFailed => ResultCode::AuthenticationFailed,
                SmsError::SessionExpired => ResultCode::AuthenticationFailed,
                SmsError::DecryptionError | SmsError::InvalidTokenFormat => ResultCode::BadRequest,
                _ => ResultCode::BadRequest,
            };
            
            let status_code = StatusCode::from_u16(result_code as u16).unwrap_or(StatusCode::BAD_REQUEST);
            
            Ok(HttpResponse::new(status_code))
        },
    }
}


