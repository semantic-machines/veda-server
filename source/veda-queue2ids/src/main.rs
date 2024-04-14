// Required imports
#[macro_use]
extern crate log;

use bincode::{deserialize_from, serialize_into};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::thread;
use v_common::init_module_log;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{get_cmd, get_inner_binobj_as_individual, init_log, Module, PrepareError};
use v_common::module::veda_backend::Backend;
use v_common::onto::individual::Individual;
use v_common::storage::common::StorageMode;
use v_common::v_api::api_client::IndvOp;
use v_common::v_queue::consumer::Consumer;
use v_common::v_queue::queue::Queue;
use v_common::v_queue::record::{Mode, MsgType};

pub const MSTORAGE_ID: i64 = 1;

// Context struct
struct Context {
    queue_out: Queue,
    map_rdf_types: HashMap<String, u16>,
    base_path: String,
}

fn main() -> Result<(), i32> {
    init_module_log!("QUEUE_2_IDS");
    // Initialize module and backend
    let mut module = Module::default();
    let mut backend = Backend::create(StorageMode::ReadOnly, false);
    while !backend.mstorage_api.connect() {
        info!("waiting for start of main module...");
        thread::sleep(std::time::Duration::from_millis(300));
    }

    // Set base path and initialize module_info
    let base_path = "./data";
    let module_info = ModuleInfo::new(base_path, "queue2ids", true);
    if module_info.is_err() {
        error!("failed to start, err = {:?}", module_info.err());
        return Err(-1);
    }

    // Initialize the output queue for IDs
    let ids_queue_path = format!("{}/ids", base_path);
    let ids_queue_out = Queue::new(&ids_queue_path, "ids", Mode::ReadWrite).expect("!!!!!!!!! FAIL CREATE QUEUE [IDS]");

    // Create a context object
    let mut ctx = Context {
        queue_out: ids_queue_out,
        map_rdf_types: load_map_of_types(&ids_queue_path).unwrap(),
        base_path: base_path.to_string(),
    };

    // Initialize the input queue for individuals
    let mut queue_consumer = Consumer::new(&format!("{}/queue", base_path), "queue2ids", "individuals-flow").expect("!!!!!!!!! FAIL OPEN QUEUE [INDIVIDUALS]");

    // Listen to the queue and process messages
    module.listen_queue(
        &mut queue_consumer,
        &mut ctx,
        &mut (before_batch as fn(&mut Backend, &mut Context, batch_size: u32) -> Option<u32>),
        &mut (prepare as fn(&mut Backend, &mut Context, &mut Individual, my_consumer: &Consumer) -> Result<bool, PrepareError>),
        &mut (after_batch as fn(&mut Backend, &mut Context, prepared_batch_size: u32) -> Result<bool, PrepareError>),
        &mut (heartbeat as fn(&mut Backend, &mut Context) -> Result<(), PrepareError>),
        &mut backend,
    );
    Ok(())
}

// Heartbeat function
fn heartbeat(_module: &mut Backend, _ctx: &mut Context) -> Result<(), PrepareError> {
    Ok(())
}

// Before batch processing function
fn before_batch(_module: &mut Backend, _ctx: &mut Context, _size_batch: u32) -> Option<u32> {
    None
}

// After batch processing function
fn after_batch(_module: &mut Backend, _ctx: &mut Context, _prepared_batch_size: u32) -> Result<bool, PrepareError> {
    Ok(false)
}

fn prepare(_module: &mut Backend, ctx: &mut Context, queue_element: &mut Individual, _my_consumer: &Consumer) -> Result<bool, PrepareError> {
    let ids_queue_path = format!("{}/ids", ctx.base_path);
    let cmd = get_cmd(queue_element);
    if cmd.is_none() {
        error!("skip queue message: cmd is none");
        return Ok(true);
    }
    let cmd = cmd.unwrap();

    // Process only Put commands without "prev_state"
    if cmd == IndvOp::Put && !queue_element.is_exists("prev_state") {
        let mut new_state = Individual::default();
        get_inner_binobj_as_individual(queue_element, "new_state", &mut new_state);

        // Get ID and types as a string and push to the output queue
        match get_id_and_types_as_str(&ids_queue_path, &mut new_state, &mut ctx.map_rdf_types).map_err(|_| PrepareError::Fatal) {
            Ok(id_msg) => {
                if let Err(e) = ctx.queue_out.push(id_msg.as_bytes(), MsgType::String) {
                    error!("fail push {} to queue, error={:?}", id_msg, e);
                    return Err(PrepareError::Fatal);
                }
            },
            Err(e) => {
                error!("fail get id and types as str, error={:?}", e);
                return Err(PrepareError::Fatal);
            },
        }
    }

    Ok(true)
}

fn get_id_and_types_as_str(path: &str, indv: &mut Individual, map_rdf_types: &mut HashMap<String, u16>) -> Result<String, Error> {
    let map_file_name = format!("{}/map-rdf-types.bin", path);
    let mut msg = indv.get_id().to_string();

    // Get RDF types and add them to the message
    if let Some(ts) = indv.get_literals("rdf:type") {
        for t in ts {
            let n = if let Some(n) = map_rdf_types.get(&t) {
                *n
            } else {
                let n = map_rdf_types.len() as u16;
                info!("add to map: {t}->[{n}]");
                map_rdf_types.insert(t, n);

                // Update the RDF types map file
                let mut file = File::create(&map_file_name).map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create file {}: {}", map_file_name, e)))?;
                serialize_into(&mut file, &map_rdf_types).map_err(|e| Error::new(ErrorKind::Other, format!("Failed to serialize data into {}: {}", map_file_name, e)))?;
                n
            };
            msg.push_str(&format!(",{:X}", n));
        }
    }
    Ok(msg)
}

fn load_map_of_types(path: &str) -> Result<HashMap<String, u16>, Error> {
    let map_file_name = format!("{}/map-rdf-types.bin", path);

    if !Path::new(&map_file_name).exists() {
        warn!("map-rdf-types.bin not exists");
        return Ok(HashMap::new());
    }

    // Open the RDF types map file
    let file = File::open(&map_file_name).map_err(|e| Error::new(e.kind(), format!("Не удалось открыть файл {}: {}", map_file_name, e)))?;

    // Deserialize the RDF types map from the file
    let map_rdf_types: HashMap<String, u16> =
        deserialize_from(&file).map_err(|e| Error::new(ErrorKind::InvalidData, format!("Не удалось десериализовать данные из файла {}: {}", map_file_name, e)))?;

    info!("success load map of rdf types, size={}", map_rdf_types.len());

    Ok(map_rdf_types)
}
