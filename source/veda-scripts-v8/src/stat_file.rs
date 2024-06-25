// Формат файла статистики:
// Каждая строка файла представляет собой последовательность операций,
// начинающуюся с идентификатора операции (op_id), за которым следуют
// количества, разделенные запятыми.
//
// Формат строки: op_id:count1,count2,count3,...
//
// Пример содержимого файла:
// 1000:5,0,3,1,0
// 1001:2,4,0,1
// 1002:0,0,7,2,1,0
//
// Где:
// - Каждая строка начинается с op_id, за которым следует двоеточие
// - После двоеточия идут значения count, разделенные запятыми
// - Значение 0 также записывается и может означать отсутствие данных для данной операции
// - Новая строка начинается, когда суммарная длина текущей строки превышает MAX_LINE_SIZE
// - Новый файл создается, когда количество записей в текущем файле достигает MAX_RECORDS_PER_FILE
//
// Файлы именуются в формате: {consumer_name}_{start_op_id}.stat

use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::fs::{self, read_dir, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use v_v8::v_common::module::module_impl::PrepareError;
use zip::{write::FileOptions, ZipWriter};

const STATS_DIR: &str = "./data/queue_prepare_stat";
const MAX_RECORDS_PER_FILE: usize = 1000000;
const MAX_LINE_SIZE: usize = 4096;
const FLUSH_INTERVAL: Duration = Duration::from_millis(10);

pub struct StatsFile {
    writer: Option<BufWriter<File>>,
    file_path: Option<PathBuf>,
    consumer_name: String,
    current_op_id: Option<i64>,
    count: usize,
    records_in_current_file: usize,
    current_line_size: usize,
    last_flush: Instant,
    has_unflushed_data: bool,
    should_exit: Arc<AtomicBool>,
}

impl StatsFile {
    pub fn new(consumer_name: String) -> Self {
        let should_exit = Arc::new(AtomicBool::new(false));
        let should_exit_clone = should_exit.clone();

        // Setup signal handling
        thread::spawn(move || {
            let mut signals = Signals::new(&[SIGTERM, SIGINT]).unwrap();
            for sig in signals.forever() {
                println!("Received signal {:?}", sig);
                should_exit_clone.store(true, Ordering::Relaxed);
                break;
            }
        });

        StatsFile {
            writer: None,
            file_path: None,
            consumer_name,
            current_op_id: None,
            count: 0,
            records_in_current_file: 0,
            current_line_size: 0,
            last_flush: Instant::now(),
            has_unflushed_data: false,
            should_exit,
        }
    }

    fn open_new_file(&mut self, op_id: i64) -> io::Result<()> {
        let file_name = format!("{}_{}.stat", self.consumer_name, op_id);
        let file_path = Path::new(STATS_DIR).join(&file_name);

        warn!("open_new_file {:?}", file_path);

        fs::create_dir_all(STATS_DIR)?;

        let file = OpenOptions::new().create(true).write(true).read(true).open(&file_path)?;

        self.writer = Some(BufWriter::new(file));
        self.file_path = Some(file_path);
        self.current_op_id = Some(op_id);
        self.records_in_current_file = 0;
        self.current_line_size = 0;
        self.last_flush = Instant::now();
        self.has_unflushed_data = false;

        Ok(())
    }

    pub fn write_count(&mut self, op_id: i64, count: usize) -> io::Result<()> {
        let need_new_file = self.records_in_current_file >= MAX_RECORDS_PER_FILE || self.writer.is_none();
        let is_new_sequence = self.current_op_id.map_or(true, |current_op_id| op_id != current_op_id + 1);

        if need_new_file || is_new_sequence {
            self.flush()?;
            if need_new_file {
                self.open_new_file(op_id)?;
            }
            self.current_line_size = 0;
        }

        let count_str = if count == 0 {
            String::new()
        } else {
            count.to_string()
        };
        let new_entry = format!("{},", count_str);

        if self.current_line_size + new_entry.len() > MAX_LINE_SIZE {
            self.current_line_size = 0;
            if let Some(writer) = &mut self.writer {
                writeln!(writer)?;
            }
        }

        if self.current_line_size == 0 {
            if let Some(writer) = &mut self.writer {
                write!(writer, "{}:", op_id)?;
            }
        }
        if let Some(writer) = &mut self.writer {
            write!(writer, "{}", new_entry)?;
        }
        self.current_line_size += new_entry.len();

        self.count += count;
        self.records_in_current_file += 1;
        self.current_op_id = Some(op_id);
        self.has_unflushed_data = true;

        if self.current_line_size == MAX_LINE_SIZE {
            self.flush()?;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if self.has_unflushed_data {
            if let Some(writer) = &mut self.writer {
                writer.flush()?;
            }
            self.last_flush = Instant::now();
            self.has_unflushed_data = false;
        }
        Ok(())
    }

    pub fn check_flush(&mut self) -> io::Result<()> {
        if self.has_unflushed_data && (self.last_flush.elapsed() >= FLUSH_INTERVAL || self.should_exit.load(Ordering::Relaxed)) {
            self.flush()?;
        }
        Ok(())
    }

    pub fn get_file_name(&self) -> String {
        self.file_path.as_ref().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("unknown").to_string()
    }

    pub fn get_total_count(&self) -> usize {
        self.count
    }

    pub fn should_exit(&self) -> bool {
        self.should_exit.load(Ordering::Relaxed)
    }
}

impl Drop for StatsFile {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            eprintln!("Ошибка при закрытии файла статистики: {:?}", e);
        }
    }
}

// Функция для архивирования старых файлов статистики
fn archive_old_stat_files(consumer_name: &str) -> io::Result<()> {
    let stats_dir = Path::new(STATS_DIR);

    for entry in read_dir(stats_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with(consumer_name) && file_name.ends_with(".stat") {
                    let archive_name = format!("{}.zip", file_name);
                    let archive_path = stats_dir.join(&archive_name);

                    let file = File::create(&archive_path)?;
                    let mut zip = ZipWriter::new(file);
                    let options: FileOptions<'_, ()> = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

                    zip.start_file(file_name, options)?;
                    let mut f = File::open(&path)?;
                    let mut buffer = Vec::new();
                    f.read_to_end(&mut buffer)?;
                    zip.write_all(&buffer)?;

                    zip.finish()?;

                    // Удаляем оригинальный файл после успешного архивирования
                    fs::remove_file(&path)?;
                }
            }
        }
    }

    Ok(())
}

pub fn initialize_stats_file(consumer_name: &str) -> io::Result<StatsFile> {
    fs::create_dir_all(STATS_DIR)?;
    archive_old_stat_files(consumer_name)?;
    Ok(StatsFile::new(consumer_name.to_string()))
}

pub fn write_stats(stats_file: &mut StatsFile, op_id: i64, count: usize) -> Result<(), PrepareError> {
    stats_file.write_count(op_id, count).map_err(|e| {
        error!("Не удалось записать в файл статистики {}: {:?}", stats_file.get_file_name(), e);
        PrepareError::Fatal
    })?;

    stats_file.check_flush().map_err(|e| {
        error!("Не удалось выполнить проверку сброса буфера: {:?}", e);
        PrepareError::Fatal
    })?;

    if stats_file.should_exit() {
        return Err(PrepareError::Fatal);
    }

    Ok(())
}
