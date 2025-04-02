#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate scan_fmt;
#[macro_use]
extern crate version;

use crate::stat_file::{write_stats};
use crate::command_handler::{StatsCollector, handle_nng_commands};
use git_version::git_version;
use std::process::exit;
use std::sync::Mutex;
use std::{env, thread, time};
use v_v8::common::ScriptInfoContext;
use v_v8::scripts_workplace::ScriptsWorkPlace;
use v_v8::v8;
use v_v8::v8::Isolate;
use v_v8::v_common::ft_xapian::xapian_reader::XapianReader;
use v_v8::v_common::module::common::load_onto;
use v_v8::v_common::module::info::ModuleInfo;
use v_v8::v_common::module::module_impl::{get_info_of_module, init_log, wait_load_ontology, wait_module, Module, PrepareError};
use v_v8::v_common::module::remote_indv_r_storage::inproc_storage_manager;
use v_v8::v_common::module::veda_backend::Backend;
use v_v8::v_common::onto::individual::Individual;
use v_v8::v_common::onto::onto_impl::Onto;
use v_v8::v_common::storage::common::StorageMode;
use v_v8::v_common::v_api::api_client::MStorageClient;
use v_v8::v_common::v_queue::consumer::Consumer;
use v_v8::v_common::v_queue::record::Mode;
use std::sync::atomic::Ordering;
use std::sync::Arc;

mod processor;
mod stat_file;
mod command_handler;

const MAX_COUNT_LOOPS: i32 = 100;
const MAIN_QUEUE_CS: &str = "scripts_main0";
const MAX_COUNT_OF_PATH: usize = 128;

lazy_static! {
    static ref INIT_LOCK: Mutex<u32> = Mutex::new(0);
}

#[must_use]
struct SetupGuard {}

impl Drop for SetupGuard {
    fn drop(&mut self) {
        // TODO shutdown process cleanly.
    }
}

fn setup() -> SetupGuard {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        assert!(v8::icu::set_common_data_73(align_data::include_aligned!(align_data::Align16, "third_party/icu/common/icudtl.dat")).is_ok());
        v8::V8::initialize_platform(v8::new_default_platform(0, false).make_shared());
        v8::V8::initialize();
    });
    SetupGuard {}
}

pub struct MyContext<'a> {
    pub api_client: MStorageClient,
    pub xr: XapianReader,
    pub onto: Onto,
    pub workplace: ScriptsWorkPlace<'a, ScriptInfoContext>,
    pub vm_id: String,
    pub sys_ticket: String,
    pub main_queue_cs: Option<Consumer>,
    pub queue_name: String,
    pub count_exec: i64,
    pub module_info: ModuleInfo,
    pub stats_collector: Arc<StatsCollector>,
}

fn main() -> Result<(), i32> {
    let module_name = "SCRIPT_V8";

    init_log(module_name);
    info!("{} {} {}", module_name, version!(), git_version!());
    thread::spawn(move || inproc_storage_manager());

    let _setup_guard = setup();

    let isolate = &mut v8::Isolate::new(Default::default());

    info!("V8 version {}", v8::V8::get_version());

    main0(isolate)
}

fn main0<'a>(isolate: &'a mut Isolate) -> Result<(), i32> {
    if get_info_of_module("input-onto").unwrap_or((0, 0)).0 == 0 {
        wait_module("ontologist", wait_load_ontology());
    }

    let mut backend = Backend::create(StorageMode::ReadOnly, false);

    while !backend.mstorage_api.connect() {
        error!("failed to connect to main module, sleep and repeat");
        thread::sleep(time::Duration::from_millis(1000));
    }

    let mut onto = Onto::default();
    load_onto(&mut backend.storage, &mut onto);

    let w_sys_ticket = backend.get_sys_ticket_id();
    if w_sys_ticket.is_err() {
        error!("failed to get system ticket");
        return Ok(());
    }

    let mut vm_id = "";
    let args: Vec<String> = env::args().collect();
    for el in args.iter() {
        if el == "main" || el.starts_with("lp") {
            vm_id = el;
            break;
        }
    }

    if vm_id.is_empty() {
        error!("failed to start, vm_id is empty");
        return Err(1);
    }

    let process_name = "scripts_".to_owned() + vm_id;
    let consumer_name = format!("{}0", process_name);
    let main_queue_name = "individuals-flow";

    let module_info = ModuleInfo::new("./data", &process_name, true);
    if module_info.is_err() {
        error!("failed to start, err = {:?}", module_info.err());
        return Err(-1);
    }

    if let Some(xr) = XapianReader::new("russian", &mut backend.storage) {
        let stats_collector = Arc::new(StatsCollector::new());
        let stats_collector_clone = Arc::clone(&stats_collector);

        let mut ctx = MyContext {
            api_client: MStorageClient::new(Module::get_property("main_module_url").unwrap_or_default()),
            workplace: ScriptsWorkPlace::new(isolate),
            onto,
            vm_id: "main".to_owned(),
            sys_ticket: w_sys_ticket.unwrap(),
            main_queue_cs: None,
            queue_name: consumer_name,
            count_exec: 0,
            xr,
            module_info: module_info.unwrap(),
            stats_collector,
        };

        let tmp_cn = ctx.queue_name.clone();

        thread::spawn(move || {
            if let Err(e) = handle_nng_commands(stats_collector_clone, tmp_cn) {
                error!("NNG command handler error: {:?}", e);
            }
        });

        if vm_id.starts_with("lp") {
            if let Ok(lp_id) = scan_fmt!(vm_id, "lp{}", i32) {
                ctx.vm_id = format!("V8.LowPriority{}", lp_id);
            } else {
                ctx.vm_id = "V8.LowPriority".to_owned();
            }
        } else {
            ctx.vm_id = "main".to_owned();
        }

        info!("use VM id = {} -> {}", process_name, ctx.vm_id);

        ctx.workplace.load_ext_scripts(&ctx.sys_ticket);
        if let Err(e) = processor::load_event_scripts(&mut ctx.workplace, &mut ctx.xr) {
            error!("fail read event scripts, err={:?}", e);
            exit(-1);
        }

        let mut module = Module::default();

        let mut queue_consumer = Consumer::new("./data/queue", &ctx.queue_name, main_queue_name).expect("!!!!!!!!! FAIL OPEN RW CONSUMER");

        if vm_id.starts_with("lp") {
            loop {
                if let Ok(cs) = Consumer::new_with_mode("./data/queue", MAIN_QUEUE_CS, main_queue_name, Mode::Read) {
                    ctx.main_queue_cs = Some(cs);
                    break;
                }
                warn!("main queue consumer not open, sleep and repeat");
                thread::sleep(time::Duration::from_millis(1000));
            }
        }

        module.listen_queue(
            &mut queue_consumer,
            &mut ctx,
            &mut (before_batch as fn(&mut Backend, &mut MyContext<'a>, batch_size: u32) -> Option<u32>),
            &mut (prepare as fn(&mut Backend, &mut MyContext<'a>, &mut Individual, my_consumer: &Consumer) -> Result<bool, PrepareError>),
            &mut (after_batch as fn(&mut Backend, &mut MyContext<'a>, prepared_batch_size: u32) -> Result<bool, PrepareError>),
            &mut (heartbeat as fn(&mut Backend, &mut MyContext<'a>) -> Result<(), PrepareError>),
            &mut backend,
        );
    } else {
        error!("failed to init ft-query");
    }
    Ok(())
}

fn heartbeat(_module: &mut Backend, ctx: &mut MyContext) -> Result<(), PrepareError> {
    if ctx.stats_collector.collect_stats.load(Ordering::Relaxed) {
        let mut stats_file = ctx.stats_collector.stats_file.lock().unwrap();
        if let Some(file) = stats_file.as_mut() {
            if let Err(e) = file.check_flush() {
                error!("Не удалось завершить запись статистики в файл: {:?}", e);
                return Err(PrepareError::Fatal);
            }
        }
    }
    Ok(())
}

fn before_batch(_module: &mut Backend, _ctx: &mut MyContext, _size_batch: u32) -> Option<u32> {
    None
}

fn after_batch(_module: &mut Backend, _ctx: &mut MyContext, _prepared_batch_size: u32) -> Result<bool, PrepareError> {
    Ok(false)
}

fn prepare(_module: &mut Backend, ctx: &mut MyContext, queue_element: &mut Individual, my_consumer: &Consumer) -> Result<bool, PrepareError> {
    if let Some(main_cs_r) = &mut ctx.main_queue_cs {
        while my_consumer.count_popped > main_cs_r.count_popped && main_cs_r.id == my_consumer.id || my_consumer.id > main_cs_r.id {
            main_cs_r.get_info();

            if my_consumer.count_popped > main_cs_r.count_popped && main_cs_r.id == my_consumer.id || my_consumer.id > main_cs_r.id {
                info!("sleep, scripts_main={}:{}, my={}:{}", main_cs_r.id, main_cs_r.count_popped, my_consumer.id, my_consumer.count_popped);
                thread::sleep(time::Duration::from_millis(1000));
                main_cs_r.open(false);
            }
        }
    }

    let (op_id, new_individuals_count) = match processor::prepare_for_js(ctx, queue_element) {
        Ok((op_id, count)) => {
            if let Err(e) = ctx.module_info.put_info(op_id, op_id) {
                error!("failed to write module_info, op_id = {}, err = {:?}", op_id, e);
                return Err(PrepareError::Fatal);
            }
            (op_id, count)
        },
        Err(e) => {
            return Err(e);
        },
    };

    // Запись статистики
    if ctx.stats_collector.collect_stats.load(Ordering::Relaxed) {
        let mut stats_file = ctx.stats_collector.stats_file.lock().unwrap();
        if let Some(file) = stats_file.as_mut() {
            if let Err(e) = write_stats(file, op_id, new_individuals_count) {
                error!("Не удалось записать статистику: {:?}", e);
                return Err(PrepareError::Fatal);
            }
        }
    }

    Ok(true)
}