use crate::common::{extract_addr, get_user_info, log_w, UserContextCache, UserId, UserInfo};
use actix_web::cookie::Cookie;
use actix_web::error::ErrorInternalServerError;
use actix_web::http::StatusCode;
use actix_web::web::BytesMut;
use actix_web::HttpResponse;
use actix_web::{web, HttpRequest};
use async_std::fs::File;
use async_std::path::PathBuf;
use async_std::prelude::*;
use base64::encode;
use basen::BASE36;
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use openssl::sha::Sha256;
use rand::rngs::OsRng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use rsa::pkcs8::{FromPrivateKey, FromPublicKey};
use rsa::{PaddingScheme, PublicKey};
use serde::Deserialize;
use serde_json::json;
use std::io;
use std::sync::Arc;
use std::time::Instant;
use v_common::storage::async_storage::AStorage;

#[derive(Debug, Deserialize)]
struct AuthResponse {
    model: AuthModel,
    success: bool,
}

// Struct representing the authentication model
#[derive(Debug, Deserialize)]
struct AuthModel {
    //id: String,
    //identity: String,
    status: String,
    url: String,
}

// Configuration properties for multifactor authentication
#[derive(Default)]
pub struct MultifactorProps {
    pub api_key: String,
    pub api_secret: String,
    pub url: String,
    pub sign_url: String,
    pub audience: String,
    pub callback_scheme: Option<String>,
}

pub async fn multifactor(req: HttpRequest, uinf: &UserInfo, mfp: &MultifactorProps) -> io::Result<HttpResponse> {
    // Check for a valid ticket for the user
    if uinf.ticket.is_none() {
        return Ok(HttpResponse::BadRequest().finish());
    }

    // Encoding API credentials
    let credentials = format!("{}:{}", mfp.api_key, mfp.api_secret);
    let encoded_credentials = base64::encode(credentials);
    let url = format!("{}/access/requests", mfp.url);

    let mut hasher = Sha256::new();
    hasher.update(uinf.user_id.as_bytes());
    let user_identity = format!("{}@optiflow", BASE36.encode_const_len(&hasher.finish()));

    // Encrypt user ticket
    let encrypted_data_base64 = match encrypt(uinf.ticket.as_ref().unwrap()).await {
        Ok(d) => d,
        Err(e) => {
            log::error!("fail encrypt message, error: {:?}", e);
            return Ok(HttpResponse::InternalServerError().finish());
        },
    };

    // Setting up callback scheme and host
    let scheme = if let Some(v) = &mfp.callback_scheme {
        v.to_string()
    } else {
        req.connection_info().scheme().to_string()
    };

    let host = req.connection_info().host().to_string();
    let action_url = format!("{}://{}", scheme, host);

    // Preparing authentication request payload
    let auth_request_data = json!({
        "identity": user_identity,
        "callback": {
            "action": action_url,
            "target": "_self"
        },
        "claims": {
            "id": encrypted_data_base64
        }
    });
    let serialized_data = serde_json::to_string(&auth_request_data)?;

    info!("send request to multifactor, identity={}", user_identity);

    // Creating HTTP client and sending request
    let client = Client::new();
    let mut headers = HeaderMap::new();
    let auth_header_value = HeaderValue::from_str(&format!("Basic {}", encoded_credentials)).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    headers.insert(AUTHORIZATION, auth_header_value);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // Processing the response from multifactor service
    let response = client.post(&url).headers(headers).body(serialized_data).send().await;

    match response {
        Ok(res) if res.status().is_success() => match res.json::<AuthResponse>().await {
            Ok(body) if body.success && body.model.status == "AwaitingAuthentication" => Ok(HttpResponse::SeeOther().content_type("text/plain").body(body.model.url)),
            _ => Ok(HttpResponse::BadRequest().finish()),
        },
        Ok(res) => {
            log::error!("HTTP request unsuccessful: Status: {}, Error: {:?}, url={}", res.status(), res.text().await, url);
            Ok(HttpResponse::InternalServerError().finish())
        },
        Err(e) => {
            log::error!("HTTP request failed: {:?}, url={}", e, url);
            Ok(HttpResponse::InternalServerError().finish())
        },
    }
}

// Struct for JWT claims
#[derive(Debug, Deserialize)]
struct Claims {
    //sub: String,
    //exp: usize,
    //aud: String,
    id: String,
}

// Struct for JSON Web Key Set (JWKS)
#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

// Struct for a single JSON Web Key (JWK)
#[derive(Deserialize)]
struct Jwk {
    //kty: String,
    //r#use: String,
    //kid: String,
    n: String,
    e: String,
    //alg: String,
}

// Function to fetch JWKS from a URL
async fn fetch_jwks(jwks_url: &str) -> Result<Jwks, actix_web::Error> {
    // Sending HTTP GET request to fetch JWKS
    let client = Client::new();

    let res = client.get(jwks_url).send().await.map_err(ErrorInternalServerError)?;
    res.json::<Jwks>().await.map_err(ErrorInternalServerError)
}

// Function to decode a JWT
async fn decode_jwt(jwks: &Jwks, token: &str, audience: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    // Decoding JWT using JWKS and the specified audience
    let key = &jwks.keys[0];

    let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience.to_string()]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

// Encryption function
async fn encrypt(data: &str) -> io::Result<String> {
    // Чтение публичного ключа
    let mut public_key_pem = String::new();
    File::open("./key_storage/public_key.pem").await?.read_to_string(&mut public_key_pem).await?;
    let pem_data = pem::parse(public_key_pem).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to parse PEM"))?;
    let public_key =
        rsa::RsaPublicKey::from_public_key_der(&pem_data.contents).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to create public key from DER"))?;

    // Шифрование
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let encrypted_data = public_key.encrypt(&mut OsRng, padding, data.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encrypt"))?;
    Ok(encode(encrypted_data))
}

// Decryption function
async fn decrypt(data: &str) -> io::Result<String> {
    // Чтение приватного ключа
    let mut private_key_pem = String::new();
    File::open("./key_storage/private_key.pem").await?.read_to_string(&mut private_key_pem).await?;
    let pem_data = pem::parse(private_key_pem).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to parse PEM"))?;

    // Преобразование PEM в DER
    let der_data = pem_data.contents;

    // Создание приватного ключа из DER в формате PKCS#8
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&der_data).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to create private key from DER"))?;

    // Дешифрование
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let decoded_data = base64::decode(data).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to decode base64 data"))?;
    let decrypted_data = private_key.decrypt(padding, &decoded_data).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to decrypt"))?;
    String::from_utf8(decrypted_data).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to convert to String"))
}

// Function to handle a POST request
pub async fn handle_post_request(
    req: HttpRequest,
    mut payload: web::Payload,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    mfp: web::Data<MultifactorProps>,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();

    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        match chunk {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(e) => {
                let io_error = io::Error::new(io::ErrorKind::Other, format!("Payload error: {}", e));
                return Err(io_error);
            },
        }
    }

    let body_str = String::from_utf8_lossy(&body);
    let token = body_str.trim_start_matches("accessToken=");
    let ticket_id = mfa_callback_handler(token, &mfp).await?;

    let uinf = match get_user_info(Some(ticket_id.clone()), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &Some(ticket_id), &extract_addr(&req), "", "get_rights", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let r = json!({
        "id": uinf.ticket,
        "user_uri": uinf.user_id,
        "end_time": uinf.end_time*1000
    });

    let cookie = Cookie::new("auth", format!("{}; SameSite=Strict", encode(r.to_string())));

    let path: PathBuf = "./public/index.html".into();
    match actix_files::NamedFile::open(path) {
        Ok(file) => match file.into_response(&req) {
            Ok(mut response) => {
                response.add_cookie(&cookie).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Cookie error: {}", e)))?;
                Ok(response)
            },
            Err(e) => {
                let io_error = io::Error::new(io::ErrorKind::Other, format!("Response error: {}", e));
                Err(io_error)
            },
        },
        Err(e) => {
            let io_error = io::Error::new(io::ErrorKind::Other, format!("File error: {}", e));
            Err(io_error)
        },
    }
}

async fn mfa_callback_handler(access_token: &str, mfp: &MultifactorProps) -> io::Result<String> {
    let jwks = fetch_jwks(&mfp.sign_url).await.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Ошибка при получении JWKS: {}", e)))?;
    let c = decode_jwt(&jwks, access_token, &mfp.audience).await.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Ошибка при проверке токена: {}", e)))?;
    let ticket = decrypt(&c.id).await.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Ошибка при расшифровке ID: {}", e)))?;

    Ok(ticket)
}
