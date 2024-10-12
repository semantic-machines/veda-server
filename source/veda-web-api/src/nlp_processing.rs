use crate::common::{extract_addr, get_user_info, log, log_w, NLPServerConfig, TicketRequest, UserContextCache, UserId};
use actix_multipart::Multipart;
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use async_std::path::Path;
use chrono::Utc;
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use futures::{StreamExt, TryStreamExt};
use hound::{SampleFormat, WavSpec, WavWriter};
use ogg::reading::PacketReader;
use opus::Decoder;
use regex::RegexBuilder;
use rubato::{FftFixedInOut, Resampler};
use serde::Deserialize;
use serde_json::Value;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use v_common::storage::async_storage::AStorage;
use v_common::v_api::obj::ResultCode;

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const INPUT_SAMPLE_RATE: usize = 48000; // Частота дискретизации Opus
const OUTPUT_SAMPLE_RATE: usize = 16000; // Целевая частота дискретизации
const CHANNELS: usize = 2; // Стерео

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

// Декодирование Opus и пересемплирование до 16 кГц, запись в моно WAV
async fn decode_opus_to_wav(input_path: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    // Открываем входной файл Ogg Opus
    let input_file = File::open(input_path)?;
    let reader = BufReader::new(input_file);

    // Инициализируем Ogg PacketReader
    let mut packet_reader = PacketReader::new(reader);

    // Инициализируем Opus-декодер
    let mut decoder = Decoder::new(INPUT_SAMPLE_RATE as u32, opus::Channels::Stereo).expect("Failed to create Opus decoder");

    // Открываем выходной файл для записи в формате WAV
    let output_file = File::create(output_path)?;
    let writer = BufWriter::new(output_file);

    // Указываем спецификации WAV файла (целевые параметры: 16 кГц, моно)
    let spec = WavSpec {
        channels: 1, // Указываем моно (1 канал)
        sample_rate: OUTPUT_SAMPLE_RATE as u32,
        bits_per_sample: 16,
        sample_format: SampleFormat::Int,
    };

    // Создаем WAV writer с выбранными спецификациями
    let mut wav_writer = WavWriter::new(writer, spec).unwrap();

    // Инициализируем ресемплер для изменения частоты с 48 кГц на 16 кГц
    let mut resampler = FftFixedInOut::new(INPUT_SAMPLE_RATE, OUTPUT_SAMPLE_RATE, 960, CHANNELS).unwrap();

    // Буфер для декодированных PCM данных
    let mut pcm_buffer = vec![0; 960 * CHANNELS];

    // Читаем Ogg пакеты и передаем их в Opus-декодер
    while let Ok(Some(packet)) = packet_reader.read_packet() {
        // Пропускаем пакеты с неподходящим размером
        if packet.data.len() < 1 || packet.data.len() > 1275 {
            //eprintln!("Skipping invalid Opus packet with size {}", packet.data.len());
            continue;
        }

        // Декодируем кадр Opus
        match decoder.decode(&packet.data, &mut pcm_buffer, false) {
            Ok(decoded_samples) => {
                // Преобразуем декодированные PCM данные с i16 в f32 для ресемплирования
                let input: Vec<Vec<f32>> =
                    (0..CHANNELS).map(|channel| pcm_buffer.iter().skip(channel).step_by(CHANNELS).take(decoded_samples).map(|&s| s as f32 / 32768.0).collect()).collect();

                // Ресемплируем данные
                let resampled = resampler.process(&input, None).expect("Failed to resample");

                // Преобразуем результат в моно, усредняя левый и правый каналы, затем в i16 и записываем в WAV
                for frame in resampled[0].iter().zip(&resampled[1]) {
                    let mono_sample = ((frame.0 + frame.1) / 2.0 * 32768.0).clamp(-32768.0, 32767.0) as i16;
                    wav_writer.write_sample(mono_sample).unwrap();
                }
            },
            Err(e) => {
                error!("Failed to decode Opus frame: {:?}", e);
                continue; // Пропускаем этот пакет и продолжаем обработку следующих пакетов
            },
        }
    }

    wav_writer.finalize().unwrap();

    info!("Decoding, resampling, and mono conversion completed successfully and saved as {}", output_path);

    Ok(())
}

// Функция транскрипции с использованием WAV файла
async fn transcribe(filepath: String, nlp_config: &NLPServerConfig) -> Result<String, actix_web::Error> {
    info!("Starting transcription for file: {}", filepath);

    let output_path = filepath.replace(".ogg", "_converted.wav");
    decode_opus_to_wav(&filepath, &output_path).await.map_err(|e| {
        info!("Failed to decode audio: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Audio decoding failed: {}", e))
    })?;

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

    fs::remove_file(&filepath).await.map_err(|e| {
        info!("Failed to remove original file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to remove original file: {}", e))
    })?;
    fs::remove_file(&output_path).await.map_err(|e| {
        info!("Failed to remove converted file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to remove converted file: {}", e))
    })?;

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
        let re = RegexBuilder::new(&regex::escape(phrase)).case_insensitive(true).build().unwrap();
        cleaned_text = re.replace_all(&cleaned_text, "").to_string();
    }
    cleaned_text.trim().to_string()
}
