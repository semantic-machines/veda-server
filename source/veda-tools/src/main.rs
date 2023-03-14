mod common;
mod exec_js_on_query;
mod queue_tools;
use crate::exec_js_on_query::exec_js_on_query;

#[macro_use]
extern crate log;

use crate::queue_tools::{export_from_query, print_queue, queue_crc, queue_to_veda};
use type_cli::CLI;
use v_v8::v_common::module::module_impl::init_log;

#[derive(CLI)]
#[help = "veda tools"]
enum Tools {
    #[help = "Execute js script on query result"]
    ExecJsOnQuery {
        #[named]
        #[help = "path to query"]
        path_to_query: String,

        #[named]
        #[help = "path to js"]
        path_to_js: String,
    },
    #[help = "Store individuals from queue to storage"]
    QueueToStorage {
        #[named]
        #[help = "path to queue"]
        queue_path: String,

        #[named]
        #[help = "queue part id"]
        #[optional]
        part_id: Option<u32>,

        #[named]
        #[help = "check v-s:updateCounter"]
        #[flag]
        check_counter: bool,
    },
    #[help = "Print individuals from queue"]
    PrintQueue {
        #[named]
        #[help = "path to queue"]
        queue_path: String,

        #[named]
        #[help = "queue part id"]
        #[optional]
        part_id: Option<u32>,

        #[named]
        #[help = "type of out - JSON/TTL"]
        #[optional]
        out_type: Option<String>,
    },
    #[help = "Calculate queue CRC"]
    QueueCrc {
        #[named]
        #[help = "path to queue"]
        queue_path: String,

        #[named]
        #[help = "queue part id"]
        #[optional]
        part_id: Option<u32>,
    },
    #[help = "Build queue from query"]
    QueryToQueue(String),
}

fn main() {
    init_log("VEDA-TOOLS");

    match Tools::process() {
        Tools::ExecJsOnQuery {
            path_to_query,
            path_to_js,
        } => {
            exec_js_on_query(&path_to_query, &path_to_js);
        },
        Tools::QueryToQueue(query) => {
            info!("query={}", query);
            export_from_query(&query).expect("fail create query from queue");
        },
        Tools::QueueToStorage {
            queue_path,
            part_id,
            check_counter,
        } => {
            info!("queue_path={}, part_id={:?}", queue_path, part_id);
            queue_to_veda(queue_path, part_id, check_counter);
        },
        Tools::PrintQueue {
            queue_path,
            part_id,
            out_type,
        } => {
            info!("queue_path={}, part_id={:?}, out_type={:?}", queue_path, part_id, out_type);
            print_queue(queue_path, part_id, out_type);
        },
        Tools::QueueCrc {
            queue_path,
            part_id,
        } => {
            info!("queue_path={}, part_id={:?}", queue_path, part_id);
            queue_crc(queue_path, part_id);
        },
    }
}
