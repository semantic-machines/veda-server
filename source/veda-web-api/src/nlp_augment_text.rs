use crate::common::{NLPServerConfig, UserContextCache, UserId};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use async_std::prelude::Stream;
use bytes::Bytes;
use futures::channel::mpsc::Sender;
use futures_util::lock::Mutex;
use futures_util::{stream, StreamExt};
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use v_common::storage::async_storage::AStorage;

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
    _ticket_cache: web::Data<UserContextCache>,
    req: HttpRequest,
    _db: web::Data<AStorage>,
    _activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    nlp_config: web::Data<NLPServerConfig>,
) -> Result<HttpResponse, Error> {
    info!("Starting augment_text function");

    let ticket_value = req
        .headers()
        .get("Cookie")
        .and_then(|cookie| cookie.to_str().ok().and_then(|c| c.split("; ").find(|s| s.starts_with("ticket="))).map(|s| s["ticket=".len()..].to_string()));

    if ticket_value.is_none() {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let llama_config = match load_llama_config("./llama_config.toml") {
        Ok(config) => config,
        Err(_e) => {
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
        let status = llama_response.status().clone(); // Копируем статус, чтобы избежать перемещения
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
                        if let Some(data) = line.strip_prefix("data: ") {
                            let json = serde_json::from_str::<serde_json::Value>(data).ok()?;
                            let content = json.get("content")?.as_str()?.to_string();
                            let stop = json.get("stop")?.as_bool().unwrap_or(false);
                            Some(Ok(Bytes::from(format!(
                                "data: {}\n\n",
                                serde_json::to_string(&json!({
                                    "content": content,
                                    "stop": stop
                                }))
                                .unwrap()
                            ))))
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
