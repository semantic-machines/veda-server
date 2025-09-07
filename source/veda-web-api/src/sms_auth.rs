use crate::common::extract_addr;
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
    pub created_at: u64, // timestamp
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

    fn decrypt_session_data(&self, token: &EncryptedSessionToken) -> Result<EncryptedSessionData, SmsError> {
        let padding = Oaep::new::<Sha256>();
        
        info!("🔍 Decrypting token - data: '{}', nonce: '{}'", token.data, token.nonce);
        
        // Decode ciphertext
        info!("📥 Step 1: Decoding base64 data...");
        let ciphertext = base64::decode(&token.data)
            .map_err(|e| {
                error!("❌ Base64 decode failed: {:?}", e);
                error!("Data that failed to decode: '{}'", token.data);
                SmsError::InvalidTokenFormat
            })?;
        info!("✅ Base64 decoded successfully, ciphertext length: {}", ciphertext.len());

        // Decrypt with RSA private key
        info!("🔐 Step 2: RSA decryption...");
        let current_fingerprint = self.get_public_key_fingerprint();
        info!("RSA key fingerprint: {}", current_fingerprint);
        warn!("⚠️  ВАЖНО: Убедитесь что этот fingerprint такой же как при создании токена!");
        let plaintext = self.rsa_private_key.decrypt(padding, &ciphertext)
            .map_err(|e| {
                error!("❌ RSA decryption failed: {:?}", e);
                error!("Ciphertext length: {}", ciphertext.len());
                error!("Expected RSA key size: {} bits", self.rsa_private_key.size() * 8);
                SmsError::DecryptionError
            })?;
        info!("✅ RSA decryption successful, plaintext length: {}", plaintext.len());

        // Deserialize session data
        info!("📄 Step 3: JSON deserialization...");
        let plaintext_str = String::from_utf8_lossy(&plaintext);
        info!("Plaintext content: {}", plaintext_str);
        
        let session_data: EncryptedSessionData = serde_json::from_slice(&plaintext)
            .map_err(|e| {
                error!("❌ JSON deserialization failed: {:?}", e);
                error!("Plaintext that failed: '{}'", plaintext_str);
                SmsError::DecryptionError
            })?;
        info!("✅ JSON deserialization successful");

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
        let fake_timestamp = current_time - rng.gen_range(0..300); // Random time within last 5 minutes
        
        let fake_session = EncryptedSessionData {
            phone: fake_phone,
            created_at: current_time,
            request_nonce: fake_nonce,
            request_salt: fake_salt,
            request_timestamp: fake_timestamp,
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
    ) -> Result<String, SmsError> {
        // Normalize phone number
        let normalized_phone = self.normalize_phone(&request.phone)?;

        // Call veda-auth API to request SMS code
        match auth_client.lock().await.authenticate(&normalized_phone, &None, ip_addr, &None) {
            Ok(_) => {
                info!("SMS auth code requested for {}", normalized_phone);
                
                // Create encrypted session data
                let session_data = EncryptedSessionData {
                    phone: normalized_phone.clone(),
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    // Include original request data for replay protection
                    request_nonce: request.nonce.clone(),
                    request_salt: request.salt.clone(),
                    request_timestamp: request.timestamp,
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
    ) -> Result<serde_json::Value, SmsError> {
        info!("=== DEBUG: Starting verify_auth_code ===");
        info!("Token length: {}", encrypted_token.len());
        info!("Token content: {}", encrypted_token);
        info!("Code: {}", code);
        
        // Parse the encrypted token - handle both direct object and JSON string
        let token: EncryptedSessionToken = serde_json::from_str(encrypted_token)
            .map_err(|e| {
                error!("❌ Failed to parse encrypted token as JSON: {:?}", e);
                error!("Token content that failed: {}", encrypted_token);
                SmsError::InvalidTokenFormat
            })?;
            
        info!("✅ Successfully parsed token - data length: {}, nonce length: {}", 
              token.data.len(), token.nonce.len());
        
        info!("🔓 Starting decryption process...");
        let session_data = self.decrypt_session_data(&token)?;
        info!("✅ Successfully decrypted session data for phone: {}", session_data.phone);
        
        // Check session expiry (5 minutes default)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if (now - session_data.created_at) > 300 { // 5 minutes
            return Err(SmsError::SessionExpired);
        }

        // Additional security: verify request timestamp hasn't been reused
        if (now - session_data.request_timestamp) > self.config.max_time_drift * 2 {
            return Err(SmsError::SessionExpired);
        }

        // Call veda-auth API to verify SMS code
        // Use empty password and the code in secret field
        match auth_client.lock().await.authenticate(&session_data.phone, &None, ip_addr, &Some(code.to_string())) {
            Ok(auth_result) => {
                info!("SMS auth successful for {}", session_data.phone);
                Ok(auth_result)
            },
            Err(e) => {
                error!("Failed to verify SMS code for {} via veda-auth: {:?}", session_data.phone, e);
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
    match sms_service.request_auth_code(&data, ip_addr, &auth_client).await {
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
    
    info!("🌐 HTTP verify_sms_auth called from {:?}", ip_addr);
    info!("📋 Request data: token length = {}, code = '{}'", 
          data.token.len(), data.code);
    info!("📝 Full token received: '{}'", data.token);

    match sms_service.verify_auth_code(
        &data.token,
        &data.code,
        ip_addr,
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
                SmsError::AuthenticationFailed => ResultCode::AuthenticationFailed,
                SmsError::SessionExpired => ResultCode::AuthenticationFailed,
                SmsError::DecryptionError | SmsError::InvalidTokenFormat => ResultCode::BadRequest,
                _ => ResultCode::BadRequest,
            };
            
            Ok(HttpResponse::new(StatusCode::from_u16(result_code as u16).unwrap_or(StatusCode::BAD_REQUEST)))
        },
    }
}


