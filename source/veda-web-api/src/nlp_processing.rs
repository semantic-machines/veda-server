use crate::common::{extract_addr, get_user_info, log, log_w, NLPServerConfig, TicketRequest, UserContextCache, UserId};
use actix_multipart::Multipart;
use actix_web::http::StatusCode;
use actix_web::{web, Error, HttpRequest, HttpResponse};
use async_std::path::Path;
use bytes::Bytes;
use chrono::Utc;
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use futures::task::{Context, Poll};
use futures::{Stream, StreamExt, TryStreamExt};
use futures::stream::{self};
use regex::RegexBuilder;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::pin::Pin;
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
    pub top_k: i32,
    pub top_p: f32,
    pub min_p: f32,
    pub repeat_penalty: f32,
    pub presence_penalty: f32,
    pub frequency_penalty: f32,
    pub mirostat: i32,
    pub mirostat_tau: f32,
    pub mirostat_eta: f32,
    pub stop: Vec<String>,
    pub repeat_last_n: i32,
    pub penalize_nl: bool,
    pub tfs_z: f32,
    pub typical_p: f32,
}
impl Default for LlamaConfig {
    fn default() -> Self {
        LlamaConfig {
            prompt_template: "User: {}\nLlama:".to_string(),
            system_prompt: "You are a helpful assistant.".to_string(),
            temperature: 0.8,
            n_predict_factor: 1.2,
            top_k: 40,
            top_p: 0.95,
            min_p: 0.05,
            repeat_penalty: 1.1,
            presence_penalty: 0.0,
            frequency_penalty: 0.0,
            mirostat: 0,
            mirostat_tau: 5.0,
            mirostat_eta: 0.1,
            stop: vec!["</s>".to_string(), "User:".to_string()],
            repeat_last_n: 0,
            penalize_nl: false,
            tfs_z: 0.0,
            typical_p: 0.0,
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

#[derive(serde::Serialize)]
struct StreamChunk {
    content: String,
    is_end: bool,
}

pub async fn augment_text(
    params: web::Json<AugmentTextRequest>,
    ticket_cache: web::Data<UserContextCache>,
    req: HttpRequest,
    db: web::Data<AStorage>,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    nlp_config: web::Data<NLPServerConfig>,
) -> Result<HttpResponse, Error> {
    info!("Starting augment_text function");

    let ticket_value = req
        .headers()
        .get("Cookie")
        .and_then(|cookie| {
            cookie
                .to_str()
                .ok()
                .and_then(|c| c.split("; ").find(|s| s.starts_with("ticket=")))
                .map(|s| s["ticket=".len()..].to_string())  // Изменила возвращаемое значение с ссылки на строку
        });

    if ticket_value.is_none() {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let uinf = match get_user_info(Some(ticket_value.unwrap()), &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let llama_config = match load_llama_config("./llama_config.toml") {
        Ok(config) => config,
        Err(e) => {
            return Err(actix_web::error::ErrorInternalServerError("Failed to load LLaMA configuration"));
        },
    };

    let client = reqwest::Client::new();
    let full_prompt = format!("{}\n\n{}", llama_config.system_prompt, llama_config.prompt_template.replace("{}", &params.text));
    let input_length = params.text.split_whitespace().count();
    let n_predict = (input_length as f32 * llama_config.n_predict_factor).round() as i32;

    let llama_request = json!({
        "stream": true,
        "n_predict": n_predict,
        "temperature": llama_config.temperature,
        "stop": llama_config.stop,
        "repeat_last_n": llama_config.repeat_last_n,
        "repeat_penalty": llama_config.repeat_penalty,
        "penalize_nl": llama_config.penalize_nl,
        "top_k": llama_config.top_k,
        "top_p": llama_config.top_p,
        "min_p": llama_config.min_p,
        "tfs_z": llama_config.tfs_z,
        "typical_p": llama_config.typical_p,
        "presence_penalty": llama_config.presence_penalty,
        "frequency_penalty": llama_config.frequency_penalty,
        "mirostat": llama_config.mirostat,
        "mirostat_tau": llama_config.mirostat_tau,
        "mirostat_eta": llama_config.mirostat_eta,
        "prompt": full_prompt
    });

    let llama_response = client
        .post(&format!("{}/completion", nlp_config.llama_server_url))
        .json(&llama_request)
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("llama.cpp server error: {}", e)))?;

    if !llama_response.status().is_success() {
        let status = llama_response.status().clone();  // Копируем статус, чтобы избежать перемещения
        let error_text = llama_response.text().await.unwrap_or_default();
        return Err(actix_web::error::ErrorInternalServerError(format!("llama.cpp server returned error status: {} {}", status, error_text)));
    }

    let byte_stream = llama_response.bytes_stream();
    let response_stream = byte_stream.flat_map(|chunk| {
        stream::iter(match chunk {
            Ok(chunk) => {
                let chunk_str = String::from_utf8_lossy(&chunk);
                chunk_str
                    .lines()
                    .filter_map(|line| {
                        if line.starts_with("data: ") {
                            let data = &line["data: ".len()..];
                            let json = serde_json::from_str::<serde_json::Value>(data).ok()?;
                            let content = json.get("content")?.as_str()?.to_string();
                            let stop = json.get("stop")?.as_bool().unwrap_or(false);
                            Some(Ok(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&json!({
                                "content": content,
                                "stop": stop
                            })).unwrap()))))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            },
            Err(e) => vec![Err(actix_web::error::ErrorInternalServerError(format!("Error reading stream: {}", e)))],
        })
    });

    Ok(HttpResponse::Ok()
        .content_type("text/event-stream")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .header("Connection", "keep-alive")
        .streaming(response_stream))
}

// Адаптер для преобразования Stream в тип, который ожидает actix-web 3
struct StreamAdapter<S>(S);

impl<S> Stream for StreamAdapter<S>
where
    S: Stream<Item = Result<String, Error>> + Unpin,
{
    type Item = Result<bytes::Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.0).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(bytes::Bytes::from(item)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}