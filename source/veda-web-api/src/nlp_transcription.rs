use crate::common::{extract_addr, get_user_info, log, log_w, NLPServerConfig, TicketRequest, TranscriptionConfig, UserContextCache, UserId};
use actix_multipart::Multipart;
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use async_std::path::Path;
use chrono::Utc;
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use futures::{StreamExt, TryStreamExt};
use regex::RegexBuilder;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::obj::ResultCode;

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

#[derive(Debug, Deserialize)]
pub struct OpenAIConfig {
    api_key: String,
    model: String,
}

#[derive(Deserialize)]
struct PhrasesToRemove {
    phrases: Vec<String>,
}

async fn save_file(mut payload: Multipart) -> Result<String, actix_web::Error> {
    if let Ok(Some(mut field)) = payload.try_next().await {
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

async fn transcribe_with_openai(filepath: &str, config: &OpenAIConfig) -> Result<String, actix_web::Error> {
    info!("Starting OpenAI transcription for file: {}", filepath);

    let file_content = fs::read(filepath).await.map_err(|e| {
        info!("Failed to read audio file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to read audio file: {}", e))
    })?;

    let file_name = Path::new(filepath).file_name().and_then(|name| name.to_str()).unwrap_or("audio.ogg");

    let part = reqwest::multipart::Part::bytes(file_content).file_name(file_name.to_string()).mime_str("audio/ogg").map_err(|e| {
        info!("Failed to create multipart: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to create multipart: {}", e))
    })?;

    let form = reqwest::multipart::Form::new().part("file", part).text("model", config.model.clone()).text("response_format", "json");

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.openai.com/v1/audio/transcriptions")
        .header("Authorization", format!("Bearer {}", config.api_key))
        .multipart(form)
        .send()
        .await
        .map_err(|e| {
            info!("OpenAI API error: {}", e);
            actix_web::error::ErrorInternalServerError(format!("OpenAI API error: {}", e))
        })?;

    if !response.status().is_success() {
        info!("OpenAI API returned error: {}", response.status());
        return Err(actix_web::error::ErrorInternalServerError(format!(
            "OpenAI API returned error status: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )));
    }

    let response_text = response.text().await.map_err(|e| {
        info!("Failed to read OpenAI response: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to read OpenAI response: {}", e))
    })?;

    let json: Value = serde_json::from_str(&response_text).map_err(|e| {
        info!("Failed to parse JSON response: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to parse JSON response: {}", e))
    })?;

    let transcription = json["text"].as_str().ok_or_else(|| actix_web::error::ErrorInternalServerError("Missing 'text' field in response"))?.to_string();

    info!("OpenAI transcription successful for file: {}", filepath);

    Ok(transcription)
}

async fn transcribe_local(filepath: &str, nlp_config: &NLPServerConfig) -> Result<String, actix_web::Error> {
    info!("Starting transcription for file: {}", filepath);

    let output_path = filepath.to_string();

    let file_content = fs::read(&output_path).await.map_err(|e| {
        info!("Failed to read converted file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to read converted file: {}", e))
    })?;

    let file_name = Path::new(&output_path).file_name().and_then(|name| name.to_str()).unwrap_or("audio.wav");

    info!("Sending file {} to Whisper.cpp for transcription", file_name);

    let part = reqwest::multipart::Part::bytes(file_content).file_name(file_name.to_string()).mime_str("audio/wav").map_err(|e| {
        info!("Failed to create multipart: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to create multipart: {}", e))
    })?;

    let form = reqwest::multipart::Form::new().part("file", part).text("temperature", "0.0").text("temperature_inc", "0.2").text("response_format", "json");

    let response = reqwest::Client::new().post(&format!("{}/inference", nlp_config.whisper_server_url)).multipart(form).send().await.map_err(|e| {
        info!("Whisper.cpp server error: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Whisper.cpp server error: {}", e))
    })?;

    if !response.status().is_success() {
        info!("Whisper.cpp server returned error: {}", response.status());
        return Err(actix_web::error::ErrorInternalServerError(format!(
            "Whisper.cpp server returned error status: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )));
    }

    let response_text = response.text().await.map_err(|e| {
        info!("Failed to read Whisper.cpp response: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to read Whisper.cpp response: {}", e))
    })?;

    let json: Value = serde_json::from_str(&response_text).map_err(|e| {
        info!("Failed to parse JSON response: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to parse JSON response: {}", e))
    })?;

    let transcription = json["text"].as_str().ok_or_else(|| actix_web::error::ErrorInternalServerError("Missing 'text' field in response"))?.to_string();

    info!("Transcription successful for file: {}", filepath);

    fs::remove_file(&output_path).await.map_err(|e| {
        info!("Failed to remove converted file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to remove converted file: {}", e))
    })?;

    Ok(transcription)
}

async fn transcribe(filepath: String, nlp_config: &NLPServerConfig, transcription_config: &TranscriptionConfig) -> Result<String, actix_web::Error> {
    let transcription = if transcription_config.use_local_model {
        transcribe_local(&filepath, nlp_config).await?
    } else {
        transcribe_with_openai(&filepath, &transcription_config.openai).await?
    };

    fs::remove_file(&filepath).await.map_err(|e| {
        info!("Failed to remove original file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to remove original file: {}", e))
    })?;

    let phrases_text = fs::read_to_string("./nlp_phrases_to_remove.toml")
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read nlp_phrases_to_remove.toml: {}", e)))?;

    let phrases_to_remove: PhrasesToRemove =
        toml::from_str(&phrases_text).map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to parse nlp_phrases_to_remove.toml: {}", e)))?;

    Ok(clean_text(&transcription, &phrases_to_remove.phrases))
}

fn clean_text(text: &str, phrases: &[String]) -> String {
    let mut cleaned_text = text.to_string();
    for phrase in phrases {
        let re = RegexBuilder::new(&regex::escape(phrase)).case_insensitive(true).build().unwrap();
        cleaned_text = re.replace_all(&cleaned_text, "").to_string();
    }
    cleaned_text.trim().to_string()
}

pub async fn recognize_audio(
    params: web::Query<TicketRequest>,
    ticket_cache: web::Data<UserContextCache>,
    req: HttpRequest,
    payload: Multipart,
    db: web::Data<AStorage>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    nlp_config: web::Data<NLPServerConfig>,
    transcription_config: web::Data<Option<TranscriptionConfig>>,
) -> Result<HttpResponse, actix_web::Error> {
    let start_time = Instant::now();

    let uinf = match get_user_info(params.ticket.to_owned(), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &params.ticket, &extract_addr(&req), "", "get_individuals", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let config = transcription_config.as_ref().as_ref().ok_or_else(|| {
        let error_msg = "Transcription configuration is not available";
        info!("{}", error_msg);
        actix_web::error::ErrorInternalServerError(error_msg)
    })?;

    let filepath = save_file(payload).await?;
    let transcription = transcribe(filepath, &nlp_config, &config).await?;

    log(Some(&start_time), &uinf, "recognize_audio", "success", ResultCode::Ok);

    Ok(HttpResponse::Ok().content_type("text/plain").body(transcription))
}
