use crate::common::{extract_addr, extract_initiator};
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use futures::lock::Mutex;
use log::{error, info, warn};
use serde::Deserialize;
use thiserror::Error;
use v_common::v_api::api_client::AuthClient;
use v_common::v_api::common_type::ResultCode;

// Configuration structure
#[derive(Debug, Clone)]
pub struct SbisAuthConfig {
    pub enabled: bool,
    pub base_url: String,
    pub user_info_endpoint: String,
}

impl Default for SbisAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://online.sbis.ru".to_string(),
            user_info_endpoint: "/service/user_info".to_string(),
        }
    }
}

// Request structure from client
#[derive(Debug, Deserialize)]
pub struct SbisAuthRequest {
    pub access_token: String,
}

// SBIS user info response structure
#[derive(Debug, Deserialize)]
pub struct SbisUserInfo {
    #[serde(rename = "МобильныйТелефонПользователя")]
    pub mobile_phone: Option<String>,
    #[serde(rename = "Телефон")]
    pub phone: Option<String>,
}

// Error types
#[derive(Debug, Error)]
pub enum SbisError {
    #[error("SBIS service is disabled")]
    ServiceDisabled,
    #[error("Invalid SBIS token")]
    InvalidToken,
    #[error("Phone number not found in SBIS response")]
    PhoneNotFound,
    #[error("Failed to get user info from SBIS: {0}")]
    SbisApiError(String),
    #[error("Invalid phone format: {0}")]
    InvalidPhone(String),
}

// Main SBIS authentication service
pub struct SbisAuthService {
    config: SbisAuthConfig,
    http_client: reqwest::Client,
}

impl SbisAuthService {
    pub fn new(config: SbisAuthConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    // Verify SBIS token and get user phone number
    pub async fn verify_token_and_get_phone(&self, access_token: &str) -> Result<String, SbisError> {
        if !self.config.enabled {
            return Err(SbisError::ServiceDisabled);
        }

        let url = format!("{}{}", self.config.base_url, self.config.user_info_endpoint);
        
        info!("Requesting user info from SBIS: {}", url);
        
        let response = self.http_client
            .get(&url)
            .header("X-SBISAccessToken", access_token)
            .send()
            .await
            .map_err(|e| SbisError::SbisApiError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("SBIS API returned error: status={}, body={}", status, body);
            return Err(SbisError::InvalidToken);
        }

        let user_info: SbisUserInfo = response
            .json()
            .await
            .map_err(|e| SbisError::SbisApiError(format!("Failed to parse SBIS response: {}", e)))?;

        // Extract phone number (prefer mobile phone)
        let phone = user_info.mobile_phone
            .or(user_info.phone)
            .ok_or(SbisError::PhoneNotFound)?;

        let normalized_phone = self.normalize_phone(&phone)?;
        
        info!("SBIS token verified, user phone: {}", normalized_phone);
        Ok(normalized_phone)
    }

    fn normalize_phone(&self, phone: &str) -> Result<String, SbisError> {
        // Remove all non-digit characters
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        
        // Validate length and format
        match digits.len() {
            11 if digits.starts_with('7') => Ok(digits),
            11 if digits.starts_with('8') => Ok(format!("7{}", &digits[1..])),
            10 => Ok(format!("7{}", digits)),
            _ => Err(SbisError::InvalidPhone(phone.to_string())),
        }
    }
}

// HTTP handler for SBIS authentication
pub async fn sbis_authenticate(
    req: HttpRequest,
    data: web::Json<SbisAuthRequest>,
    sbis_service: web::Data<SbisAuthService>,
    auth_client: web::Data<Mutex<AuthClient>>,
) -> Result<HttpResponse, actix_web::Error> {
    let ip_addr = extract_addr(&req);
    let initiator = extract_initiator(&req);

    info!("SBIS authentication request from {:?}", ip_addr);

    // Step 1: Verify SBIS token and get phone number
    let phone = match sbis_service.verify_token_and_get_phone(&data.access_token).await {
        Ok(phone) => phone,
        Err(e) => {
            warn!("SBIS token verification failed: {:?}", e);
            return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::AuthenticationFailed as u16).unwrap_or(StatusCode::UNAUTHORIZED)));
        }
    };

    // Step 2-3: Authenticate via veda-auth with provider="sbis"
    // This will find user by phone and create ticket without password verification
    match auth_client.lock().await.authenticate(
        &phone,
        &None,
        ip_addr,
        &None,
        Some("veda"),
        initiator.as_deref(),
        Some("sbis"),
    ) {
        Ok(auth_result) => {
            info!("SBIS authentication successful for phone: {}", phone);
            Ok(HttpResponse::Ok().json(auth_result))
        },
        Err(e) => {
            error!("SBIS authentication failed for phone {}: {:?}", phone, e);
            Ok(HttpResponse::new(StatusCode::from_u16(e.result as u16).unwrap_or(StatusCode::BAD_REQUEST)))
        }
    }
}
