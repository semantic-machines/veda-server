use crate::common::{extract_addr, get_user_info, log, log_w, NLPServerConfig, TicketRequest, UserContextCache, UserId};
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
use tokio::process::Command;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::obj::ResultCode;

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

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
