use crate::common::{check_external_enter, extract_addr, extract_initiator, log, UserContextCache, UserInfo};
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use futures::lock::Mutex;
use log::{error, info, warn};
use serde::Deserialize;
use std::io;
use std::time::Instant;
use thiserror::Error;
use v_common::module::ticket::Ticket;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::api_client::AuthClient;
use v_common::v_api::common_type::ResultCode;

// Configuration structure
#[derive(Debug, Clone)]
pub struct SbisAuthConfig {
    pub enabled: bool,
    pub base_url: String,
    pub user_info_endpoint: String,
    // Field name in SBIS response to link with Veda account (e.g. "МобильныйТелефонПользователя", "ЛогинПользователя")
    pub user_link_field: String,
}

impl Default for SbisAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://online.sbis.ru".to_string(),
            user_info_endpoint: "/service/user_info".to_string(),
            user_link_field: "МобильныйТелефонПользователя".to_string(),
        }
    }
}

// Request structure from client
#[derive(Debug, Deserialize)]
pub struct SbisAuthRequest {
    pub access_token: String,
}

// Error types
#[derive(Debug, Error)]
pub enum SbisError {
    #[error("SBIS service is disabled")]
    ServiceDisabled,
    #[error("Invalid SBIS token")]
    InvalidToken,
    #[error("Link field not found in SBIS response: {0}")]
    LinkFieldNotFound(String),
    #[error("Failed to get user info from SBIS: {0}")]
    SbisApiError(String),
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

    // Verify SBIS token and get user link value (configurable field from SBIS response)
    pub async fn verify_token_and_get_link_value(&self, access_token: &str) -> Result<String, SbisError> {
        if !self.config.enabled {
            return Err(SbisError::ServiceDisabled);
        }

        let url = format!("{}{}", self.config.base_url, self.config.user_info_endpoint);
        
        info!("SBIS AUTH: Requesting user info from SBIS: {}", url);
        
        let response = self.http_client
            .get(&url)
            .header("X-SBISAccessToken", access_token)
            .send()
            .await
            .map_err(|e| SbisError::SbisApiError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("SBIS AUTH: API returned error: status={}, body={}", status, body);
            return Err(SbisError::InvalidToken);
        }

        let response_text = response.text().await
            .map_err(|e| SbisError::SbisApiError(format!("Failed to read SBIS response: {}", e)))?;
        
        // Parse JSON first to decode unicode escapes for readable logging
        let json_value: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| SbisError::SbisApiError(format!("Failed to parse SBIS response: {}", e)))?;
        info!("SBIS AUTH: user_info response: {}", json_value);
        
        // Extract link value from configured field
        let link_value = self.extract_link_value(&json_value)?;
        
        info!("SBIS AUTH: token verified, link_value from field '{}': {}", self.config.user_link_field, link_value);
        Ok(link_value)
    }

    // Extract link value from JSON response using configured field name
    fn extract_link_value(&self, json: &serde_json::Value) -> Result<String, SbisError> {
        if let Some(value) = json.get(&self.config.user_link_field) {
            if let Some(s) = value.as_str() {
                if !s.is_empty() {
                    let normalized = Self::normalize_phone_number(s);
                    return Ok(normalized);
                }
            }
        }

        warn!("SBIS AUTH: Link field '{}' not found or empty in response", self.config.user_link_field);
        Err(SbisError::LinkFieldNotFound(self.config.user_link_field.clone()))
    }

    // Normalize phone number: add '+' prefix if starts with '7' and contains only digits
    fn normalize_phone_number(value: &str) -> String {
        let trimmed = value.trim();
        
        // Check if it looks like a Russian phone number (starts with 7, all digits, 11 chars)
        if trimmed.starts_with('7') && trimmed.len() == 11 && trimmed.chars().all(|c| c.is_ascii_digit()) {
            return format!("+{}", trimmed);
        }
        
        trimmed.to_string()
    }
}

// HTTP handler for SBIS authentication
pub async fn sbis_authenticate(
    req: HttpRequest,
    data: web::Json<SbisAuthRequest>,
    sbis_service: web::Data<SbisAuthService>,
    auth_client: web::Data<Mutex<AuthClient>>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();
    let mut uinf = UserInfo {
        ticket: Ticket::default(),
        addr: extract_addr(&req),
    };
    let initiator = extract_initiator(&req);

    info!("SBIS AUTH: request from {:?}", uinf.addr);

    // Step 1: Verify SBIS token and get link value (login/phone/etc from configured field)
    let link_value = match sbis_service.verify_token_and_get_link_value(&data.access_token).await {
        Ok(v) => v,
        Err(e) => {
            warn!("SBIS AUTH: token verification failed: {:?}", e);
            log(Some(&start_time), &uinf, "sbis_authenticate", "token_verification_failed", ResultCode::AuthenticationFailed);
            return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::AuthenticationFailed as u16).unwrap_or(StatusCode::UNAUTHORIZED)));
        }
    };

    // Step 2-3: Authenticate via veda-auth with provider="sbis"
    // This will find user by link_value and create ticket without password verification
    match auth_client.lock().await.authenticate(
        &link_value,
        &None,
        uinf.addr,
        &None,
        Some("veda"),
        initiator.as_deref(),
        Some("sbis"),
    ) {
        Ok(r) => {
            uinf.ticket = Ticket::from(r.clone());
            if ticket_cache.check_external_users {
                if let Err(e) = check_external_enter(&uinf.ticket, &db).await {
                    log(Some(&start_time), &uinf, "sbis_authenticate", &link_value, e);
                    return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap()));
                }
            }

            log(Some(&start_time), &uinf, "sbis_authenticate", &uinf.ticket.user_uri, ResultCode::Ok);
            Ok(HttpResponse::Ok().json(r))
        },
        Err(e) => {
            log(Some(&start_time), &uinf, "sbis_authenticate", &link_value, e.result);
            Ok(HttpResponse::new(StatusCode::from_u16(e.result as u16).unwrap_or(StatusCode::BAD_REQUEST)))
        }
    }
}
