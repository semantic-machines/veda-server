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

#[cfg(feature = "audio_convert")]
use ffmpeg_next as ffmpeg;
#[cfg(feature = "audio_convert")]
use std::path::PathBuf;

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

#[cfg(feature = "audio_convert")]
struct AudioTranscoder {
    stream: usize,
    filter: ffmpeg::filter::Graph,
    decoder: ffmpeg::codec::decoder::Audio,
    encoder: ffmpeg::codec::encoder::Audio,
    in_time_base: ffmpeg::Rational,
    out_time_base: ffmpeg::Rational,
}

#[cfg(feature = "audio_convert")]
impl AudioTranscoder {
    fn new(ictx: &mut ffmpeg::format::context::Input, octx: &mut ffmpeg::format::context::Output, output_path: &PathBuf) -> Result<Self, ffmpeg::Error> {
        let input = ictx.streams().best(ffmpeg::media::Type::Audio).expect("could not find best audio stream");

        let context = ffmpeg::codec::context::Context::from_parameters(input.parameters())?;
        let mut decoder = context.decoder().audio()?;

        let in_time_base = decoder.time_base();
        let in_channels = decoder.channel_layout().channels();

        info!("Input audio: channels={}, layout={:?}", in_channels, decoder.channel_layout());

        let codec = ffmpeg::encoder::find(octx.format().codec(output_path, ffmpeg::media::Type::Audio)).expect("failed to find encoder").audio()?;

        decoder.set_parameters(input.parameters())?;

        let mut output = octx.add_stream(codec)?;
        let context = ffmpeg::codec::context::Context::from_parameters(output.parameters())?;
        let mut encoder = context.encoder().audio()?;

        // Используем такое же количество каналов как во входном потоке
        let channel_layout = if in_channels == 1 {
            ffmpeg::channel_layout::ChannelLayout::MONO
        } else {
            ffmpeg::channel_layout::ChannelLayout::STEREO
        };

        // Настраиваем параметры кодирования
        encoder.set_rate(48000);
        encoder.set_channel_layout(channel_layout);
        encoder.set_channels(channel_layout.channels());
        encoder.set_format(ffmpeg::format::Sample::F32(ffmpeg::format::sample::Type::Planar));

        // Устанавливаем битрейт в зависимости от количества каналов
        let bit_rate = if in_channels == 1 {
            96_000
        } else {
            192_000
        };
        encoder.set_bit_rate(bit_rate);

        let time_base = ffmpeg::Rational(1, 48000);
        encoder.set_time_base(time_base);
        output.set_time_base(time_base);

        let encoder = encoder.open_as(codec)?;
        let out_time_base = output.time_base();
        output.set_parameters(&encoder);

        // Создаем фильтр в зависимости от количества входных каналов
        let filter_spec = if in_channels == 1 {
            "aresample=48000,aformat=sample_fmts=fltp:channel_layouts=mono,asetnsamples=n=64"
        } else {
            "aresample=48000,aformat=sample_fmts=fltp:channel_layouts=stereo,asetnsamples=n=64"
        };

        let filter = Self::create_filter(filter_spec, &decoder, &encoder)?;

        info!("Audio encoder configured: rate=48000Hz, channels={}, bit_rate={}kbps", channel_layout.channels(), bit_rate / 1000);

        Ok(AudioTranscoder {
            stream: input.index(),
            filter,
            decoder,
            encoder,
            in_time_base,
            out_time_base,
        })
    }

    #[cfg(feature = "audio_convert")]
    fn create_filter(spec: &str, decoder: &ffmpeg::codec::decoder::Audio, encoder: &ffmpeg::codec::encoder::Audio) -> Result<ffmpeg::filter::Graph, ffmpeg::Error> {
        let mut filter = ffmpeg::filter::Graph::new();

        let args = format!(
            "time_base={}:sample_rate={}:sample_fmt={}:channel_layout=0x{:x}",
            decoder.time_base(),
            decoder.rate(),
            decoder.format().name(),
            decoder.channel_layout().bits()
        );

        info!("Input filter args: {}", args);

        filter.add(&ffmpeg::filter::find("abuffer").unwrap(), "in", &args)?;
        filter.add(&ffmpeg::filter::find("abuffersink").unwrap(), "out", "")?;

        {
            let mut out = filter.get("out").unwrap();
            out.set_sample_format(encoder.format());
            out.set_channel_layout(encoder.channel_layout());
            out.set_sample_rate(encoder.rate());
        }

        filter.output("in", 0)?.input("out", 0)?.parse(spec)?;
        filter.validate()?;

        info!("Audio filter configured: {}", spec);
        info!("Filter graph dump: {}", filter.dump());

        Ok(filter)
    }

    #[cfg(feature = "audio_convert")]
    async fn transcode(input_path: &str, output_path: &str) -> Result<(), ffmpeg::Error> {
        ffmpeg::init()?;

        info!("Starting transcoding from {} to {}", input_path, output_path);

        let mut ictx = ffmpeg::format::input(&input_path)?;
        let mut octx = ffmpeg::format::output(&output_path)?;

        if let Some(stream) = ictx.streams().best(ffmpeg::media::Type::Audio) {
            let params = stream.parameters();
            info!("Input stream: index={}, time_base={:?}, codec_type={:?}", stream.index(), stream.time_base(), params.medium());
        }

        let output_pathbuf = PathBuf::from(output_path);
        let mut transcoder = Self::new(&mut ictx, &mut octx, &output_pathbuf)?;

        octx.set_metadata(ictx.metadata().to_owned());
        octx.write_header()?;

        let mut total_frames = 0;
        let mut total_packets = 0;

        // Главный цикл обработки
        for (stream, mut packet) in ictx.packets() {
            if stream.index() == transcoder.stream {
                total_packets += 1;
                if total_packets % 100 == 0 {
                    info!("Processing packet {}", total_packets);
                }

                packet.rescale_ts(stream.time_base(), transcoder.in_time_base);
                transcoder.decoder.send_packet(&packet)?;

                let mut decoded = ffmpeg::frame::Audio::empty();
                while transcoder.decoder.receive_frame(&mut decoded).is_ok() {
                    total_frames += 1;

                    transcoder.filter.get("in").unwrap().source().add(&decoded)?;

                    let mut filtered = ffmpeg::frame::Audio::empty();
                    while transcoder.filter.get("out").unwrap().sink().frame(&mut filtered).is_ok() {
                        if let Err(e) = transcoder.encoder.send_frame(&filtered) {
                            info!("Error encoding frame {}: {:?}", total_frames, e);
                            return Err(e);
                        }

                        let mut encoded = ffmpeg::Packet::empty();
                        while transcoder.encoder.receive_packet(&mut encoded).is_ok() {
                            encoded.set_stream(0);
                            encoded.rescale_ts(transcoder.in_time_base, transcoder.out_time_base);
                            if let Err(e) = encoded.write_interleaved(&mut octx) {
                                info!("Error writing packet: {:?}", e);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }

        info!("Processed {} packets, {} frames", total_packets, total_frames);

        // Очищаем декодер
        transcoder.decoder.send_eof()?;
        let mut decoded = ffmpeg::frame::Audio::empty();
        while transcoder.decoder.receive_frame(&mut decoded).is_ok() {
            transcoder.filter.get("in").unwrap().source().add(&decoded)?;
        }

        // Очищаем фильтр
        transcoder.filter.get("in").unwrap().source().flush()?;
        let mut filtered = ffmpeg::frame::Audio::empty();
        while transcoder.filter.get("out").unwrap().sink().frame(&mut filtered).is_ok() {
            transcoder.encoder.send_frame(&filtered)?;

            let mut encoded = ffmpeg::Packet::empty();
            while transcoder.encoder.receive_packet(&mut encoded).is_ok() {
                encoded.set_stream(0);
                encoded.write_interleaved(&mut octx)?;
            }
        }

        // Очищаем энкодер
        transcoder.encoder.send_eof()?;
        let mut encoded = ffmpeg::Packet::empty();
        while transcoder.encoder.receive_packet(&mut encoded).is_ok() {
            encoded.set_stream(0);
            encoded.write_interleaved(&mut octx)?;
        }

        // Записываем трейлер
        if let Err(e) = octx.write_trailer() {
            info!("Error writing trailer: {:?}", e);
            return Err(e);
        }

        info!("Transcoding completed successfully");
        Ok(())
    }
}

#[cfg(feature = "audio_convert")]
pub async fn get_media_format(filepath: &str) -> Result<String, ffmpeg::Error> {
    ffmpeg::init()?;
    let ictx = ffmpeg::format::input(&filepath)?;
    Ok(ictx.format().name().to_string())
}

#[cfg(feature = "audio_convert")]
async fn detect_format_ffmpeg(filepath: &str) -> Result<bool, ffmpeg::Error> {
    let format = get_media_format(filepath).await?;
    let needs_transcoding = format.contains("quicktime") || format.contains("mov");
    info!("Format: {}, needs transcoding: {}", format, needs_transcoding);
    Ok(needs_transcoding)
}

async fn save_file(mut payload: Multipart) -> Result<String, actix_web::Error> {
    if let Ok(Some(mut field)) = payload.try_next().await {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
        let temp_filepath = format!("/tmp/audio_temp_{}", timestamp);
        let final_filepath = format!("/tmp/audio_{}.ogg", timestamp);

        let mut f = fs::File::create(&temp_filepath).await?;
        let mut total_size = 0;

        while let Some(chunk) = field.next().await {
            let data = chunk?;
            total_size += data.len();

            if total_size > MAX_FILE_SIZE {
                fs::remove_file(&temp_filepath).await?;
                return Err(actix_web::error::ErrorBadRequest("File too large"));
            }

            f.write_all(&data).await?;
        }

        f.flush().await?;

        if total_size == 0 {
            fs::remove_file(&temp_filepath).await?;
            return Err(actix_web::error::ErrorBadRequest("Empty file"));
        }

        #[cfg(feature = "audio_convert")]
        {
            match detect_format_ffmpeg(&temp_filepath).await {
                Ok(needs_transcoding) => {
                    if needs_transcoding {
                        info!("QuickTime/MOV format detected, converting to OGG for Whisper compatibility");
                        match AudioTranscoder::transcode(&temp_filepath, &final_filepath).await {
                            Ok(_) => {
                                fs::remove_file(&temp_filepath).await?;
                                Ok(final_filepath)
                            },
                            Err(e) => {
                                fs::remove_file(&temp_filepath).await?;
                                Err(actix_web::error::ErrorInternalServerError(format!("Transcoding failed: {}", e)))
                            },
                        }
                    } else {
                        fs::rename(&temp_filepath, &final_filepath).await?;
                        Ok(final_filepath)
                    }
                },
                Err(e) => {
                    fs::remove_file(&temp_filepath).await?;
                    Err(actix_web::error::ErrorInternalServerError(format!("Failed to detect format: {}", e)))
                },
            }
        }

        #[cfg(not(feature = "audio_convert"))]
        {
            fs::rename(&temp_filepath, &final_filepath).await?;
            Ok(final_filepath)
        }
    } else {
        Err(actix_web::error::ErrorBadRequest("Could not save file"))
    }
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

    let file_content = fs::read(filepath).await.map_err(|e| {
        info!("Failed to read audio file: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to read audio file: {}", e))
    })?;

    let file_name = Path::new(filepath).file_name().and_then(|name| name.to_str()).unwrap_or("audio.ogg");

    info!("Sending file {} to Whisper for transcription", file_name);

    let part = reqwest::multipart::Part::bytes(file_content).file_name(file_name.to_string()).mime_str("audio/ogg").map_err(|e| {
        info!("Failed to create multipart: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to create multipart: {}", e))
    })?;

    let form = reqwest::multipart::Form::new().part("file", part).text("temperature", "0.0").text("temperature_inc", "0.2").text("response_format", "json");

    let response = reqwest::Client::new().post(&format!("{}/inference", nlp_config.whisper_server_url)).multipart(form).send().await.map_err(|e| {
        info!("Whisper server error: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Whisper server error: {}", e))
    })?;

    if !response.status().is_success() {
        info!("Whisper server returned error: {}", response.status());
        return Err(actix_web::error::ErrorInternalServerError(format!(
            "Whisper server returned error status: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )));
    }

    let response_text = response.text().await.map_err(|e| {
        info!("Failed to read Whisper response: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to read Whisper response: {}", e))
    })?;

    let json: Value = serde_json::from_str(&response_text).map_err(|e| {
        info!("Failed to parse JSON response: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to parse JSON response: {}", e))
    })?;

    let transcription = json["text"].as_str().ok_or_else(|| actix_web::error::ErrorInternalServerError("Missing 'text' field in response"))?.to_string();

    info!("Transcription successful for file: {}", filepath);

    fs::remove_file(&filepath).await.map_err(|e| {
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

    #[cfg(feature = "audio_convert")]
    {
        info!("Audio conversion support is enabled (built with FFmpeg)");
    }

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
