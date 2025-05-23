#![allow(clippy::too_many_arguments)]

use crate::common::{extract_addr, get_ticket, get_user_info, log_w, UserContextCache, UserId, UserInfo};
use crate::common::{log, TicketRequest};
use crate::webdav::get_content_type;
use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::http::header::{Charset, DispositionParam};
use actix_web::http::header::{ExtendedValue, HeaderValue};
use actix_web::http::{header, StatusCode};
use actix_web::{get, Result as ActixResult};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use async_std::fs as async_fs;
use async_std::io;
use async_std::path::Path;
use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use filetime::FileTime;
use futures::channel::mpsc::Sender;
use futures::lock::Mutex;
use futures::{AsyncWriteExt, StreamExt, TryStreamExt};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use v_common::az_impl::az_lmdb::LmdbAzContext;
use v_common::storage::async_storage::{get_individual_from_db, AStorage};
use v_common::v_api::api_client::{IndvOp, MStorageClient};
use v_common::v_api::obj::ResultCode;
use v_common::v_authorization::common::{Access, AuthorizationContext};
use v_individual_model::onto::datatype::Lang;
use v_individual_model::onto::individual::Individual;

const FILE_BASE_PATH: &str = "./data/files";
const LOCK_TIMEOUT: i64 = 3600;

#[derive(Debug, Default)]
pub struct Lock {
    pub(crate) id: String,
    //pub(crate) by: String,
    pub(crate) date: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct FileItem {
    id: String,
    path: String,
    mime: Option<mime::Mime>,
    pub(crate) info_id: String,
    pub(crate) size: u64,
    pub(crate) last_modified: DateTime<Utc>,
    pub(crate) original_name: String,
    pub(crate) locked: Option<Lock>,
}

pub async fn to_file_item(uinf: &UserInfo, file_info_id: &str, db: &AStorage, az: &Mutex<LmdbAzContext>) -> Result<FileItem, ResultCode> {
    let file_info_id = if !file_info_id.contains(':') {
        file_info_id.replacen('_', ":", 1)
    } else {
        file_info_id.to_string()
    };

    let (mut file_info, res_code) = get_individual_from_db(&file_info_id, &uinf.user_id, db, Some(az)).await?;

    if res_code != ResultCode::Ok {
        //log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res_code);
        return Err(res_code);
    }

    let mut lock = None;
    let lock_id = file_info.get_first_literal("v-s:lockId");
    let locked_by = file_info.get_first_literal("v-s:lockedBy");
    let locked_date = if let Some(d) = file_info.get_first_datetime("v-s:lockedDateTo") {
        Some(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp_opt(d, 0).ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid timestamp"))?, Utc))
    } else {
        None
    };
    if let (Some(id), Some(_by), Some(date)) = (lock_id, locked_by, locked_date) {
        lock = Some(Lock {
            id,
            //by,
            date,
        });
    }

    let path = file_info.get_first_literal_or_err("v-s:filePath")?;
    let uri = file_info.get_first_literal_or_err("v-s:fileUri")?;
    let full_file_path = format!("{}/{}/{}", FILE_BASE_PATH, path, uri);
    if full_file_path.contains("..") {
        //log(Some(&start_time), &UserInfo::default(), "get_file", &path, ResultCode::BadRequest);
        return Err(ResultCode::BadRequest);
    }

    let original_file_name = file_info.get_first_literal_or_err("v-s:fileName")?;

    let file = NamedFile::open(&full_file_path)?;
    let metadata = file.metadata()?;
    let file_path = Path::new(&original_file_name);
    let file_ext = file_path.extension().unwrap_or_default().to_str().unwrap();
    let file_mime = actix_files::file_extension_to_mime(file_ext);

    let last_modified = DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp_opt(FileTime::from_last_modification_time(&metadata).unix_seconds(), 0)
            .ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid timestamp"))?,
        Utc,
    );
    //.to_rfc2822()
    let size = file_info.get_first_integer("v-s:fileSize").unwrap_or_default() as u64;
    Ok(FileItem {
        info_id: file_info_id,
        id: uri,
        path,
        mime: Some(file_mime),
        size,
        last_modified,
        original_name: original_file_name,
        locked: lock,
    })
}

#[get("/files/{file_id}")]
pub(crate) async fn load_file(
    file_id: web::Path<String>,
    params: web::Query<TicketRequest>,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> io::Result<HttpResponse> {
    get_file(params.ticket.to_owned(), file_id.as_str(), ticket_cache, db, az, req, activity_sender, false, header::DispositionType::Attachment).await
}

pub async fn get_file(
    ticket: Option<String>,
    file_id: &str,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
    only_headers: bool,
    disposition_type: header::DispositionType,
) -> io::Result<HttpResponse> {
    let start_time = Instant::now();

    let uinf = match get_user_info(ticket, &req, &ticket_cache, &db, &activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log(Some(&start_time), &UserInfo::default(), "get_file", file_id, res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    let file_item = match to_file_item(&uinf, file_id, &db, &az).await {
        Ok(file_item) => file_item,
        Err(e) => return Ok(HttpResponse::new(StatusCode::from_u16(e as u16).unwrap())),
    };

    let file_full_name = format!("{}/{}/{}", FILE_BASE_PATH, file_item.path, sanitize_filename::sanitize(&file_item.id));
    let file_ds = NamedFile::open(&file_full_name)?;

    let mut builder = HttpResponse::Ok();

    let etag = format!(r#""{}-{}""#, file_item.last_modified, file_item.size);

    builder.header(header::ETAG, etag).header(header::LAST_MODIFIED, file_item.last_modified.to_rfc2822()).header(header::ACCEPT_RANGES, "bytes").header(
        header::CONTENT_DISPOSITION,
        header::ContentDisposition {
            disposition: disposition_type,
            parameters: vec![DispositionParam::FilenameExt(ExtendedValue {
                charset: Charset::Ext("UTF-8".to_owned()),
                language_tag: None,
                value: file_item.original_name.clone().into_bytes(),
            })],
        },
    );

    builder.set_header(header::CONTENT_LENGTH, HeaderValue::from(file_item.size));

    //builder.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(50));

    log(Some(&start_time), &uinf, "get_file", &format!("{}, size={}", file_id, file_item.size), ResultCode::Ok);
    if !only_headers {
        let ct = HeaderValue::from_str(file_item.mime.unwrap().essence_str()).unwrap();
        builder.content_type(ct);
        if let Ok(mut resp) = file_ds.respond_to(&req).await {
            let http_resp = builder.streaming(resp.take_body());

            return Ok(http_resp);
        }
    } else {
        let ct = HeaderValue::from_str(&get_content_type(&file_full_name, &file_item.mime).await?).unwrap();
        builder.content_type(ct);
        builder.set_header(header::CONTENT_LENGTH, HeaderValue::from(file_item.size));
        let http_resp = builder.finish();
        return Ok(http_resp);
    }

    //log(Some(&start_time), &UserInfo::default(), "get_file", &path, ResultCode::BadRequest);
    Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::BadRequest as u16).unwrap()))
}

async fn check_and_create_file(path: &str, file_name: &str, f: &mut Vec<async_std::fs::File>) -> io::Result<String> {
    let full_path = format!("{path}/{file_name}");

    if full_path.contains("..") {
        return Err(io::Error::new(ErrorKind::InvalidData, ""));
    }

    if !path.is_empty() && f.is_empty() {
        async_std::fs::create_dir_all(&path).await?;
        f.push(async_std::fs::File::create(full_path.clone()).await?);
    }
    Ok(full_path)
}

pub(crate) async fn save_file(
    payload: Multipart,
    ticket_cache: web::Data<UserContextCache>,
    db: web::Data<AStorage>,
    az: web::Data<Mutex<LmdbAzContext>>,
    req: HttpRequest,
    activity_sender: web::Data<Arc<Mutex<Sender<UserId>>>>,
) -> ActixResult<impl Responder> {
    put_file(payload, None, /*bytes,*/ ticket_cache, &db, &az, req, &activity_sender, None, None).await
}

pub(crate) async fn put_file(
    payload: Multipart,
    bytes: Option<web::Bytes>,
    ticket_cache: web::Data<UserContextCache>,
    db: &AStorage,
    az: &Mutex<LmdbAzContext>,
    req: HttpRequest,
    activity_sender: &Arc<Mutex<Sender<UserId>>>,
    ticket: Option<String>,
    in_file_item: Option<FileItem>,
) -> ActixResult<HttpResponse> {
    let start_time = Instant::now();
    let uinf = match get_user_info(ticket, &req, &ticket_cache, db, activity_sender).await {
        Ok(u) => u,
        Err(res) => {
            log_w(Some(&start_time), &get_ticket(&req, &None), &extract_addr(&req), "", "upload_file", "", res);
            return Ok(HttpResponse::new(StatusCode::from_u16(res as u16).unwrap()));
        },
    };

    if az.lock().await.authorize("v-s:File", &uinf.user_id, Access::CanCreate as u8, false).unwrap_or(0) != Access::CanCreate as u8 {
        log(Some(&start_time), &uinf, "upload_file", &format!("user [{}] is not allowed to upload files", uinf.user_id), ResultCode::Ok);
        return Ok(HttpResponse::new(StatusCode::from_u16(ResultCode::NotAuthorized as u16).unwrap()));
    }

    let mut tmp_file: Vec<async_std::fs::File> = Vec::default();
    let tmp_path = "./data/files/tmp";
    if Path::new(&tmp_path).exists().await {
        async_std::fs::create_dir_all(&tmp_path).await.unwrap();
    }
    let upload_tmp_id = format!("veda-upload-{}", &Uuid::new_v4().to_string());

    let (is_encoded_file, fi) = if let Some(v) = store_payload_to_file(payload, tmp_path, &upload_tmp_id, &mut tmp_file).await? {
        v
    } else {
        if let Some(b) = bytes {
            check_and_create_file(tmp_path, &upload_tmp_id, &mut tmp_file).await?;

            if let Some(ff) = tmp_file.get_mut(0) {
                AsyncWriteExt::write_all(ff, &b).await?;
            }

            if let Some(v) = in_file_item {
                (false, v)
            } else {
                return Ok(HttpResponse::InternalServerError().into());
            }
        } else {
            log(Some(&start_time), &uinf, "upload_file", "var bytes is empty", ResultCode::Ok);
            return Ok(HttpResponse::InternalServerError().into());
        }
    };

    ////

    if let Some(ff) = tmp_file.get_mut(0) {
        AsyncWriteExt::flush(ff).await?;
        AsyncWriteExt::close(ff).await?;
    }

    let tmp_file_path = format!("{tmp_path}/{upload_tmp_id}");
    let dest_file_path = &format!("{}/{}", FILE_BASE_PATH, fi.path);
    let file_full_name = format!("{dest_file_path}/{}", sanitize_filename::sanitize(&fi.id));
    if file_full_name.contains("..") {
        log(Some(&start_time), &uinf, "upload_file", &format!("incorrect path [{file_full_name}]"), ResultCode::Ok);
        return Ok(HttpResponse::InternalServerError().into());
    }

    if is_encoded_file {
        let mut f_in = File::open(tmp_file_path.clone())?;
        let mut decoder = base64::read::DecoderReader::new(&mut f_in, base64::STANDARD);
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)?;

        let mut out_file: Vec<async_std::fs::File> = Vec::default();
        check_and_create_file(dest_file_path, sanitize_filename::sanitize(&fi.id).as_str(), &mut out_file).await?;
        if let Some(ff) = out_file.get_mut(0) {
            AsyncWriteExt::write_all(ff, &result).await?;
            AsyncWriteExt::flush(ff).await?;
            AsyncWriteExt::close(ff).await?;
        }
    } else if !fi.path.is_empty() && !fi.id.is_empty() {
        if Path::new(&tmp_file_path).exists().await {
            let _ = async_std::fs::create_dir_all(&dest_file_path).await;
            debug!("ren file {file_full_name} <- {tmp_file_path}");
            if let Err(e) = async_fs::rename(tmp_file_path.clone(), file_full_name.clone()).await {
                warn!("fail rename, use copy, reason={e}");
                if let Err(e) = async_fs::copy(tmp_file_path.clone(), file_full_name.clone()).await {
                    error!("{:?}", e);
                    return Ok(HttpResponse::InternalServerError().into());
                }
                if let Err(e) = async_fs::remove_file(tmp_file_path.clone()).await {
                    warn!("{:?}", e);
                }
            }
        } else {
            warn!("write empty file {file_full_name}");
            async_fs::write(file_full_name.clone(), "").await?;
        }
    }

    log(Some(&start_time), &uinf, "upload_file", &file_full_name, ResultCode::Ok);
    Ok(HttpResponse::Ok().into())
}

async fn store_payload_to_file(mut payload: Multipart, path: &str, file_name: &str, file_buf: &mut Vec<async_std::fs::File>) -> ActixResult<Option<(bool, FileItem)>> {
    let mut is_encoded_file = false;
    let mut fi: FileItem = FileItem::default();

    while let Some(mut field) = payload.try_next().await? {
        let content_type = field.content_disposition().ok_or(actix_web::error::ParseError::Incomplete)?;

        if let Some(name) = content_type.get_name() {
            while let Some(chunk) = field.next().await {
                match name {
                    "path" => {
                        fi.path = std::str::from_utf8(&chunk?)?.to_owned();
                    },
                    "uri" => {
                        fi.id = std::str::from_utf8(&chunk?)?.to_owned();
                    },
                    "file" => {
                        let cur_chunk = &chunk?;
                        check_and_create_file(path, file_name, file_buf).await?;

                        if let Some(ff) = file_buf.get_mut(0) {
                            AsyncWriteExt::write_all(ff, cur_chunk).await?;
                        }
                    },
                    "content" => {
                        is_encoded_file = true;
                        let cur_chunk = &chunk?;

                        if file_buf.is_empty() {
                            let mut pos = 0;
                            for (idx, b) in cur_chunk.iter().enumerate() {
                                if b == &(b',') {
                                    pos = idx + 1;
                                    break;
                                }
                            }

                            if pos > 7 {
                                check_and_create_file(path, file_name, file_buf).await?;
                                if let Some(ff) = file_buf.get_mut(0) {
                                    AsyncWriteExt::write_all(ff, cur_chunk.split_at(pos).1).await?;
                                }
                            }
                        } else {
                            check_and_create_file(path, file_name, file_buf).await?;
                            if let Some(ff) = file_buf.get_mut(0) {
                                AsyncWriteExt::write_all(ff, cur_chunk).await?;
                            }
                        }
                    },
                    _ => {
                        error!("unknown param [{name}]");
                    },
                }
            }
        }
    }

    if !fi.id.is_empty() {
        Ok(Some((is_encoded_file, fi)))
    } else {
        Ok(None)
    }
}

pub fn is_locked(fi: &FileItem) -> bool {
    if let Some(locked) = &fi.locked {
        return Utc::now() <= locked.date;
    }
    false
}

pub async fn update_unlock_info(fi: &FileItem, uinf: UserInfo, mstorage: web::Data<Mutex<MStorageClient>>) -> ResultCode {
    let mut ms = mstorage.lock().await;

    let mut indv = Individual::default();
    indv.set_id(&fi.info_id);
    indv.set_datetime("v-s:lockedDateTo", Utc.timestamp_opt(0, 0).unwrap().timestamp());

    ms.update(&uinf.ticket.unwrap_or_default(), IndvOp::SetIn, &indv).result
}

pub async fn update_lock_info(token: &str, fi: &FileItem, uinf: UserInfo, mstorage: web::Data<Mutex<MStorageClient>>) -> ResultCode {
    if let Some(locked) = &fi.locked {
        if Utc::now() - (locked.date - Duration::seconds(LOCK_TIMEOUT)) < Duration::seconds(300) {
            return ResultCode::Ok;
        }
    }
    let mut ms = mstorage.lock().await;

    let mut indv = Individual::default();
    indv.set_id(&fi.info_id);
    indv.set_datetime("v-s:lockedDateTo", (Utc::now().naive_utc() + Duration::seconds(LOCK_TIMEOUT)).timestamp());
    indv.set_uri("v-s:lockedBy", &uinf.user_id);
    indv.set_string("v-s:lockId", token, Lang::none());

    ms.update(&uinf.ticket.unwrap_or_default(), IndvOp::SetIn, &indv).result
}
