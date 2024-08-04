use crate::common::{extract_addr, get_user_info, log, log_w, NLPServerConfig, TicketRequest, UserContextCache, UserId};
use actix_multipart::Multipart;
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use async_std::path::Path;
use chrono::Utc;
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use futures::{StreamExt, TryStreamExt};
use regex::RegexBuilder;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::obj::ResultCode;

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

#[derive(Deserialize)]
pub struct AugmentTextRequest {
    text: String,
    #[serde(rename = "type")]
    type_: String,
    property: String,
}

#[derive(Serialize)]
struct LlamaRequest {
    prompt: String,
    n_predict: i32,
}

#[derive(Deserialize)]
struct PhrasesToRemove {
    phrases: Vec<String>,
}

async fn save_file(mut payload: Multipart) -> Result<String, actix_web::Error> {
    while let Ok(Some(mut field)) = payload.try_next().await {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
        let filepath = format!("/tmp/audio_{}.ogg", timestamp);

        let mut f = fs::File::create(&filepath).await?;
        let mut total_size = 0;

        while let Some(chunk) = field.next().await {
            let data = chunk?;
            total_size += data.len();

            if total_size > MAX_FILE_SIZE {
                fs::remove_file(&filepath).await?;
                return Err(actix_web::error::ErrorBadRequest("File too large"));
            }

            f.write_all(&data).await?;
        }

        f.flush().await?;

        if total_size == 0 {
            fs::remove_file(&filepath).await?;
            return Err(actix_web::error::ErrorBadRequest("Empty file"));
        }

        return Ok(filepath);
    }
    Err(actix_web::error::ErrorBadRequest("Could not save file"))
}

async fn convert_audio(input_path: &str, output_path: &str) -> Result<(), actix_web::Error> {
    info!("Starting audio conversion from {} to {}", input_path, output_path);

    let status = Command::new("ffmpeg")
        .arg("-y") // Добавим -y для автоматического подтверждения перезаписи файла
        .arg("-i")
        .arg(input_path)
        .arg("-ar")
        .arg("16000")
        .arg("-ac")
        .arg("1")
        .arg(output_path)
        .status()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to start ffmpeg: {}", e)))?;

    if !status.success() {
        return Err(actix_web::error::ErrorInternalServerError(format!("ffmpeg failed with status: {}", status)));
    }

    info!("Audio conversion completed successfully");

    Ok(())
}

fn clean_text(text: &str, phrases: &[String]) -> String {
    let mut cleaned_text = text.to_string();
    for phrase in phrases {
        let re = RegexBuilder::new(&regex::escape(phrase)).case_insensitive(true).build().unwrap();
        cleaned_text = re.replace_all(&cleaned_text, "").to_string();
    }
    cleaned_text.trim().to_string()
}

async fn transcribe(filepath: String, nlp_config: &NLPServerConfig) -> Result<String, actix_web::Error> {
    let client = reqwest::Client::new();

    // Convert audio to WAV 16kHz
    let output_path = filepath.replace(".ogg", "_converted.wav");
    convert_audio(&filepath, &output_path).await?;

    let file_content = fs::read(&output_path).await.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read converted file: {}", e)))?;

    let file_name = Path::new(&output_path).file_name().and_then(|name| name.to_str()).unwrap_or("audio.wav");

    let part = reqwest::multipart::Part::bytes(file_content)
        .file_name(file_name.to_string())
        .mime_str("audio/wav")
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to create multipart: {}", e)))?;

    let form = reqwest::multipart::Form::new().part("file", part).text("temperature", "0.0").text("temperature_inc", "0.2").text("response_format", "json");

    let response = client
        .post(&format!("{}/inference", nlp_config.whisper_server_url))
        .multipart(form)
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Whisper.cpp server error: {}", e)))?;

    if !response.status().is_success() {
        return Err(actix_web::error::ErrorInternalServerError(format!(
            "Whisper.cpp server returned error status: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )));
    }

    let response_text = response.text().await.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read Whisper.cpp response: {}", e)))?;

    let json: Value = serde_json::from_str(&response_text).map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to parse JSON response: {}", e)))?;

    let transcription = json["text"].as_str().ok_or_else(|| actix_web::error::ErrorInternalServerError("Missing 'text' field in response"))?.to_string();

    // Clean up temporary files
    fs::remove_file(&filepath).await.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to remove original file: {}", e)))?;
    fs::remove_file(&output_path).await.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to remove converted file: {}", e)))?;

    // Загрузка фраз для удаления
    let phrases_text = fs::read_to_string("./nlp_phrases_to_remove.toml")
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read nlp_phrases_to_remove.toml: {}", e)))?;
    let phrases_to_remove: PhrasesToRemove =
        toml::from_str(&phrases_text).map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to parse nlp_phrases_to_remove.toml: {}", e)))?;

    // Очистка транскрипции
    let cleaned_transcription = clean_text(&transcription, &phrases_to_remove.phrases);

    Ok(cleaned_transcription)
}

pub async fn recognize_audio(
    params: web::Query<TicketRequest>,
    ticket_cache: web::Data<UserContextCache>,
    req: HttpRequest,
    payload: Multipart,
    db: web::Data<AStorage>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    nlp_config: web::Data<NLPServerConfig>,
) -> Result<HttpResponse, actix_web::Error> {
    let start_time = Instant::now();

    let uinf = match get_user_info(params.ticket.to_owned(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &params.ticket, &extract_addr(&req), "", "get_individuals", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let filepath = save_file(payload).await?;
    let transcription = transcribe(filepath, &nlp_config).await?;

    log(Some(&start_time), &uinf, "recognize_audio", "success", ResultCode::Ok);

    Ok(HttpResponse::Ok().content_type("text/plain").body(transcription))
}

#[derive(Deserialize)]
pub struct LlamaConfig {
    pub prompt_template: String,
    pub system_prompt: String,
    pub temperature: f32,
    pub n_predict_factor: f32,
    pub stop: Vec<String>,
}

impl Default for LlamaConfig {
    fn default() -> Self {
        LlamaConfig {
            prompt_template: "Исправь следующий текст: {}".to_string(),
            system_prompt: "Ваша задача - проверить и исправить текст, полученный в результате распознавания речи.".to_string(),
            temperature: 0.8,
            n_predict_factor: 1.2,
            stop: vec!["\n".to_string()],
        }
    }
}
fn load_llama_config(config_path: &str) -> Result<LlamaConfig, Box<dyn std::error::Error>> {
    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: LlamaConfig = toml::from_str(&contents)?;
    Ok(config)
}

pub async fn augment_text(
    params: web::Query<TicketRequest>,
    ticket_cache: web::Data<UserContextCache>,
    req: HttpRequest,
    payload: web::Json<AugmentTextRequest>,
    db: web::Data<AStorage>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    nlp_config: web::Data<NLPServerConfig>,
) -> Result<HttpResponse, actix_web::Error> {
    let start_time = Instant::now();

    log::info!("Starting augment_text function");

    let uinf = match get_user_info(params.ticket.to_owned(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &params.ticket, &extract_addr(&req), "", "get_individuals", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    log::info!("User info retrieved successfully");

    let llama_config = match load_llama_config("./llama_config.toml") {
        Ok(config) => config,
        Err(e) => {
            log::error!("Failed to load LLaMA config: {}", e);
            return Err(actix_web::error::ErrorInternalServerError("Failed to load LLaMA configuration"));
        },
    };

    log::info!("LLaMA config loaded successfully");

    let client = reqwest::Client::new();

    let full_prompt = format!("{}\n\nUser: {}\nLlama:", llama_config.system_prompt, payload.text);

    log::debug!("Full prompt: {}", full_prompt);

    let llama_request = json!({
        "stream": true,
        "n_predict": 400,
        "temperature": 0.7,
        "stop": ["</s>","<|end|>","<|eot_id|>","<|end_of_text|>","<|im_end|>","<|EOT|>","<|END_OF_TURN_TOKEN|>","<|end_of_turn|>","<|endoftext|>","Llama","User"],
        "repeat_last_n": 256,
        "repeat_penalty": 1.18,
        "penalize_nl": false,
        "top_k": 40,
        "top_p": 0.95,
        "min_p": 0.05,
        "tfs_z": 1,
        "typical_p": 1,
        "presence_penalty": 0,
        "frequency_penalty": 0,
        "mirostat": 0,
        "mirostat_tau": 5,
        "mirostat_eta": 0.1,
        "grammar": "",
        "n_probs": 0,
        "min_keep": 0,
        "image_data": [],
        "cache_prompt": true,
        "api_key": "",
        "slot_id": -1,
        "prompt": full_prompt
    });

    log::debug!("LLaMA request: {}", serde_json::to_string_pretty(&llama_request).unwrap());

    log::info!("Sending request to LLaMA server at {}", nlp_config.llama_server_url);

    let response = client
        .post(&format!("{}/completion", nlp_config.llama_server_url))
        .json(&llama_request)
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("llama.cpp server error: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        log::error!("LLaMA server returned error status: {} {}", status, error_text);
        return Err(actix_web::error::ErrorInternalServerError(format!("llama.cpp server returned error status: {} {}", status, error_text)));
    }

    log::info!("Received successful response from LLaMA server");

    let mut full_text = String::new();
    let mut stream = response.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error reading stream: {}", e)))?;
        let chunk_str = String::from_utf8_lossy(&chunk);
        for line in chunk_str.lines() {
            if line.starts_with("data: ") {
                let data = &line["data: ".len()..];
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(content) = json["content"].as_str() {
                        full_text.push_str(content);
                    }
                    if json["stop"].as_bool() == Some(true) {
                        break;
                    }
                }
            }
        }
    }

    log::info!("Successfully extracted augmented text");
    log::debug!("Augmented text: {}", full_text);

    log(Some(&start_time), &uinf, "augment_text", "success", ResultCode::Ok);

    log::info!("Augment_text function completed successfully");

    Ok(HttpResponse::Ok().content_type("text/plain").body(full_text))
}
