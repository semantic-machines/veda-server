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
use async_std::fs::File;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::obj::ResultCode;
use wav::{BitDepth, Header};
use ogg_opus;  // Добавьте эту библиотеку для декодирования Opus
use std::error::Error;
use std::fs::File as StdFile;
use std::io::{Cursor, BufWriter};

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


use async_std::prelude::*;

// Декодирование Opus и запись в файл WAV асинхронно
async fn decode_opus_to_wav(input_path: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    // Открываем Ogg Opus файл асинхронно
    let mut f = File::open(input_path).await?;

    // Читаем весь файл в буфер
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).await?;

    // Декодируем аудио в PCM (i16)
    let (raw, _header) = ogg_opus::decode::<_, 16000>(Cursor::new(buffer))?;

    // Создаем WAV файл с заголовком
    let header = Header {
        audio_format: 1,      // PCM
        channel_count: 1,     // Моноканал
        sampling_rate: 16000, // Частота дискретизации 16kHz
        bytes_per_second: 16000 * 2, // Скорость передачи данных (частота дискретизации * байты на сэмпл)
        bytes_per_sample: 2,  // Размер блока (2 байта на сэмпл)
        bits_per_sample: 16,  // 16 бит на сэмпл
    };

    // Открываем выходной файл синхронно для записи WAV
    let output_file = StdFile::create(output_path)?; // Используем синхронное открытие файла
    let mut writer = BufWriter::new(output_file); // Используем стандартный BufWriter

    // Записываем декодированные данные в WAV файл
    wav::write(header, &BitDepth::Sixteen(raw), &mut writer)?; // Записываем WAV

    Ok(())
}


// Функция транскрипции с использованием WAV файла
async fn transcribe(filepath: String, nlp_config: &NLPServerConfig) -> Result<String, actix_web::Error> {
    let client = reqwest::Client::new();

    // Декодирование Opus в WAV файл
    let output_path = filepath.replace(".ogg", "_converted.wav");
    decode_opus_to_wav(&filepath, &output_path)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Audio decoding failed: {}", e)))?;

    // Чтение содержимого WAV файла
    let file_content = fs::read(&output_path)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to read converted file: {}", e)))?;

    // Генерация имени файла
    let file_name = Path::new(&output_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("audio.wav");

    // Подготовка файла для отправки на сервер
    let part = reqwest::multipart::Part::bytes(file_content)
        .file_name(file_name.to_string())
        .mime_str("audio/wav")
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to create multipart: {}", e)))?;

    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("temperature", "0.0")
        .text("temperature_inc", "0.2")
        .text("response_format", "json");

    // Отправка файла на сервер Whisper для транскрипции
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

    let transcription = json["text"]
        .as_str()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Missing 'text' field in response"))?
        .to_string();

    // Удаление временных файлов
    fs::remove_file(&filepath)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to remove original file: {}", e)))?;
    fs::remove_file(&output_path)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to remove converted file: {}", e)))?;

    Ok(transcription)
}

// Основной обработчик Actix Web
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

// Функция для очистки текста
fn clean_text(text: &str, phrases: &[String]) -> String {
    let mut cleaned_text = text.to_string();
    for phrase in phrases {
        let re = RegexBuilder::new(&regex::escape(phrase))
            .case_insensitive(true)
            .build()
            .unwrap();
        cleaned_text = re.replace_all(&cleaned_text, "").to_string();
    }
    cleaned_text.trim().to_string()
}
