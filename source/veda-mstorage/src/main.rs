#[macro_use]
extern crate log;

mod transaction;

use crate::transaction::{Transaction, TransactionItem};
use chrono::Utc;
use nng::{Message, Protocol, Socket};
use serde_json::json;
use serde_json::value::Value as JSONValue;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str;
use std::thread::sleep;
use std::time::Duration;
use v_common::az_impl::az_lmdb::LmdbAzContext;
use v_common::init_module_log;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{init_log, Module};
use v_common::module::ticket::Ticket;
use v_common::module::veda_backend::{get_storage_use_prop, indv_apply_cmd};
use v_common::onto::individual::{Individual, RawObj};
use v_common::onto::individual2msgpack::to_msgpack;
use v_common::onto::json2individual::parse_json_to_individual;
use v_common::onto::parser::parse_raw;
use v_common::storage::common::{StorageId, StorageMode, VStorage};
use v_common::v_api::api_client::IndvOp;
use v_common::v_api::obj::*;
use v_common::v_authorization::common::{Access, AuthorizationContext};
use v_common::v_queue::queue::Queue;
use v_common::v_queue::record::Mode;

// set MSTORAGE_ID constant to 1
pub const MSTORAGE_ID: i64 = 1;

// define the Context struct
struct Context {
    primary_storage: VStorage,
    queue_out: Queue,
    mstorage_info: ModuleInfo,
    tickets_cache: HashMap<String, Ticket>,
    az: LmdbAzContext,
}

// main function
fn main() -> std::io::Result<()> {
    init_module_log!("MSTORAGE");

    // set the base path to "./data"
    let base_path = "./data";

    // get the primary storage instance in read/write mode
    let mut primary_storage = get_storage_use_prop(StorageMode::ReadWrite);

    // log the total count in the primary storage
    info!("total count: {}", primary_storage.count(StorageId::Individuals));

    // create a new instance of the Queue struct
    let queue_out = Queue::new(&(base_path.to_owned() + "/queue"), "individuals-flow", Mode::ReadWrite).expect("!!!!!!!!! FAIL QUEUE");

    // get the notify_channel_url property for the module
    let notify_channel_url = Module::get_property("notify_channel_url").expect("failed to read property [notify_channel_url]");

    // create a new socket to publish messages to the notify channel
    let notify_soc = Socket::new(Protocol::Pub0).unwrap();

    // try to listen to the notify channel url, log success if connected
    if let Err(e) = notify_soc.listen(&notify_channel_url) {
        error!("failed to connect to {}, err = {}", notify_channel_url, e);
        return Ok(());
    } else {
        info!("bind to notify_channel = {}", notify_channel_url);
    }

    // create a default Ticket struct for the system ticket
    let mut sys_ticket = Ticket::default();

    // loop until a system ticket is found
    while sys_ticket.id.is_empty() {
        // get the system ticket from the primary storage
        if let Ok(ticket_id) = Module::get_sys_ticket_id_from_db(&mut primary_storage) {
            // populate the sys_ticket struct with details from the database
            get_ticket_from_db(&ticket_id, &mut sys_ticket, &mut primary_storage);
            info!("found system ticket");
        } else {
            // if system ticket not found, sleep and repeat
            error!("system ticket not found, sleep and repeat...");
            sleep(Duration::from_secs(1));
        }
    }

    // get the main_module_url property for the module
    let param_name = "main_module_url";
    let main_module_url = Module::get_property(param_name);

    // if main_module_url not found, log error and return
    if main_module_url.is_none() {
        error!("failed to find parameter [{}] in properties file", param_name);
        return Ok(());
    }

    // parse the check_ticket_ip property to a boolean, defaults to true
    let check_ticket_ip = Module::get_property("check_ticket_ip").unwrap_or_default().parse::<bool>().unwrap_or(true);

    // unwrap the main_module_url property
    let main_module_url = main_module_url.unwrap();

    // create a new socket for replication
    let server = Socket::new(Protocol::Rep0)?;

    // try to listen to the main_module_url, log error if failed
    if let Err(e) = server.listen(&main_module_url) {
        error!("failed to listen, err = {:?}", e);
        return Ok(());
    }

    // log that the server has started listening to the main_module_url
    info!("started listening {}", main_module_url);

    // create a new HashMap for tickets cache
    let tickets_cache: HashMap<String, Ticket> = HashMap::new();

    // create a new ModuleInfo object for subject_manager
    let info = ModuleInfo::new(base_path, "subject_manager", true);

    // if an error occurs while creating the ModuleInfo object, log error and return
    if info.is_err() {
        error!("failed to open info file, err = {:?}", info.err());
        return Ok(());
    }

    // initialize op_id variable to 0
    let mut op_id = 0;

    // unwrap the ModuleInfo object and set op_id to committed_op_id if it exists
    let mut mstorage_info = info.unwrap();
    if let Some((_op_id, committed_op_id)) = mstorage_info.read_info() {
        op_id = committed_op_id;
    }

    // log the op_id that the server started with
    info!("started with op_id = {}", op_id);

    let az = LmdbAzContext::new(10000);

    // create a new Context object with the initialized variables
    let mut ctx = Context {
        primary_storage,
        queue_out,
        mstorage_info,
        tickets_cache,
        az,
    };

    // main loop
    loop {
        // if a message is received, prepare a response message
        if let Ok(recv_msg) = server.recv() {
            // create a default JSONValue object
            let mut out_msg = JSONValue::default();

            // set the type of the response message to "OpResult"
            out_msg["type"] = json!("OpResult");

            // prepare the response message
            let resp = request_prepare(&mut ctx, &sys_ticket, &mut op_id, &recv_msg, check_ticket_ip);

            // if the response message is Ok, prepare a JSONValue object with the result code and op_id, and loop through the results to send notifications
            if let Ok(v) = resp {
                for el in v.iter() {
                    if el.res == ResultCode::Ok {
                        // format a message to send to the notify channel
                        let msg_to_modules = format!("#{};{};{}", el.id, el.counter, el.op_id);

                        // try to send the message to the notify channel, log error if failed
                        if notify_soc.send(Message::from(msg_to_modules.as_bytes())).is_err() {
                            error!("failed to notify, id = {}", el.id);
                        }
                    }
                }

                // prepare a JSONValue object with the result code and op_id
                let mut out_el = JSONValue::default();
                out_el["result"] = json!(ResultCode::Ok as u32);
                out_el["op_id"] = json!(op_id);
                out_msg["data"] = json!([out_el]);

                // if the response message is not Ok, prepare a JSONValue object with the error code
            } else if let Some(err_code) = resp.err() {
                out_msg["result"] = json!(err_code as u32);
            }

            // send the prepared response message, log error if failed
            if let Err(e) = server.send(Message::from(out_msg.to_string().as_bytes())) {
                error!("failed to send, err = {:?}", e);
            }
        }
    }
}

// Define a struct Response
struct Response {
    id: String,
    res: ResultCode,
    op_id: i64,
    counter: i64,
}

// Implement a new associated function for the Response struct, which takes four arguments and returns a new Response instance.
impl Response {
    fn new(id: &str, rc: ResultCode, _op_id: i64, _counter: i64) -> Self {
        // Create a new Response instance and return it.
        Response {
            id: id.to_string(),
            res: rc,
            op_id: _op_id,
            counter: _counter,
        }
    }
}

// Define a function request_prepare that takes five arguments and returns either a Vec<Response> or a ResultCode.
fn request_prepare(ctx: &mut Context, sys_ticket: &Ticket, op_id: &mut i64, request: &Message, check_ticket_ip: bool) -> Result<Vec<Response>, ResultCode> {
    // Deserialize the request message into a JSONValue and store it in the variable "v."
    let v: JSONValue = if let Ok(v) = serde_json::from_slice(request.as_slice()) {
        v
    } else {
        JSONValue::Null
    };

    // Extract the ticket field from the JSONValue and return an error if it's not found.
    let fticket = v["ticket"].as_str();
    if fticket.is_none() {
        error!("field [ticket] not found in request");
        return Err(ResultCode::TicketNotFound);
    }
    let ticket_id = fticket.unwrap();
    let mut ticket = Ticket::default();

    // Check if the ticket is already cached in the context, and if not, get it from the database.
    if let Some(cached_ticket) = ctx.tickets_cache.get(ticket_id) {
        ticket = cached_ticket.clone();
    } else {
        get_ticket_from_db(ticket_id, &mut ticket, &mut ctx.primary_storage);
        if ticket.result != ResultCode::Ok {
            error!("ticket [{}] not found in storage", ticket_id);
            return Err(ResultCode::TicketNotFound);
        }
        ctx.tickets_cache.insert(ticket_id.to_string(), ticket.clone());
    }

    // Extract data from the remaining fields in the JSONValue.
    let assigned_subsystems = v["assigned_subsystems"].as_i64();
    let event_id = v["event_id"].as_str();
    let src = v["src"].as_str();

    // Parse the "addr" field as an IP address and store it in the "addr" variable.
    let addr = if let Ok(v) = v["addr"].as_str().unwrap_or_default().parse::<IpAddr>() {
        Some(v)
    } else {
        None
    };

    // Check if the ticket is valid and return an error if it's not.
    if !(ticket.is_ticket_valid(&addr, check_ticket_ip & addr.is_some()) == ResultCode::Ok) {
        error!("ticket [{}] not valid", ticket.id);
        return Err(ResultCode::TicketExpired);
    }

    // Map the "function" field from the JSONValue to an IndvOp enum value.
    let cmd = match v["function"].as_str().unwrap_or_default() {
        "put" => IndvOp::Put,
        "remove" => IndvOp::Remove,
        "add_to" => IndvOp::AddTo,
        "set_in" => IndvOp::SetIn,
        "remove_from" => IndvOp::RemoveFrom,
        _ => {
            error!("unknown command {:?}", v["function"].as_str());
            return Err(ResultCode::BadRequest);
        },
    };

    // If the "individuals" field is an array, start a new transaction and process each individual in the array.
    if let Some(jindividuals) = v["individuals"].as_array() {
        let mut transaction = Transaction {
            sys_ticket: sys_ticket.id.to_owned(),
            id: *op_id,
            event_id,
            src,
            queue: vec![],
            assigned_subsystems,
            ticket,
        };

        let mut res_of_id = vec![];
        for el in jindividuals {
            let mut indv = Individual::default();
            if !parse_json_to_individual(el, &mut indv) {
                error!("failed to parse individual from json");
                return Err(ResultCode::InternalServerError);
            } else {
                // Call the operation_prepare function with the current command, individual, and other parameters.
                let resp = operation_prepare(cmd.clone(), op_id, &mut indv, sys_ticket, &mut transaction, ctx);
                if resp.res != ResultCode::Ok {
                    return Err(resp.res);
                }
                res_of_id.push(resp);
            }
        }

        // Commit the transaction to the primary storage and update the op_id variable.
        if let Ok(res_op_id) = transaction.commit(&mut ctx.primary_storage, &mut ctx.queue_out, &mut ctx.mstorage_info) {
            *op_id = res_op_id;
            return Ok(res_of_id);
        }
    } else {
        error!("field [individuals] is empty");
    }

    // Return an internal server error if the transaction couldn't be committed.
    Err(ResultCode::InternalServerError)
}

// This function prepares an individual operation and returns a response.
// It takes in several parameters such as the command to perform, the ID of the operation,
// a reference to a mutable individual object, a primary storage object, a system ticket object,
// and a reference to a mutable transaction object.
fn operation_prepare(cmd: IndvOp, op_id: &mut i64, new_indv: &mut Individual, sys_ticket: &Ticket, transaction: &mut Transaction, ctx: &mut Context) -> Response {
    // Check if authorization is required
    let is_need_authorize = sys_ticket.user_uri != transaction.ticket.user_uri;

    // Check if the ID of the individual is valid
    if new_indv.get_id().is_empty() || new_indv.get_id().len() < 2 {
        return Response::new(new_indv.get_id(), ResultCode::InvalidIdentifier, -1, -1);
    }

    // Check if the command is not removal and the individual is empty
    if cmd != IndvOp::Remove && new_indv.is_empty() {
        return Response::new(new_indv.get_id(), ResultCode::NoContent, -1, -1);
    }

    debug!("cmd={:?}, new_indv.id={}", cmd, new_indv.get_id());

    // Get the previous state and individual information
    let mut prev_indv = Individual::default();
    let prev_state = ctx.primary_storage.get_raw_value(StorageId::Individuals, new_indv.get_id());

    // If a previous state exists, parse and retrieve it
    if !prev_state.is_empty() {
        prev_indv = Individual::new_raw(RawObj::new(prev_state.clone()));
        if parse_raw(&mut prev_indv).is_ok() {
            prev_indv.parse_all();
        } else {
            error!("failed to parse individual prev states, cmd = {:?}, uri = {}", cmd, new_indv.get_id());
            return Response::new(new_indv.get_id(), ResultCode::FailStore, -1, -1);
        }
    }

    // Check if the previous individual object is empty and the command is removal
    if prev_indv.is_empty() && cmd == IndvOp::Remove {
        warn!("remove not exists, uri = {}", new_indv.get_id());
        return Response::new(new_indv.get_id(), ResultCode::Ok, -1, -1);
    }

    // Check if the previous individual object is empty and certain commands like AddTo, SetIn, and RemoveFrom are called
    if prev_indv.is_empty() && (cmd == IndvOp::AddTo || cmd == IndvOp::SetIn || cmd == IndvOp::RemoveFrom) {
        error!("failed to update, cmd = {:?}, no prev_state, uri = {}", cmd, new_indv.get_id());
        return Response::new(new_indv.get_id(), ResultCode::FailStore, -1, -1);
    }

    // If authorization is required, check if the user has permission to perform the command
    if is_need_authorize {
        // Check if the command is to remove an individual
        if cmd == IndvOp::Remove {
            // Check if the user has authorization to delete the individual
            if ctx.az.authorize(new_indv.get_id(), &transaction.ticket.user_uri, Access::CanDelete as u8, true).unwrap_or(0) != Access::CanDelete as u8 {
                // If not authorized, return response with error
                error!("operation [Remove], Not Authorized, user = {}, request [can delete], uri = {} ", transaction.ticket.user_uri, new_indv.get_id());
                return Response::new(new_indv.get_id(), ResultCode::NotAuthorized, -1, -1);
            }
        } else {
            // Check if the previous state is not empty
            if !prev_state.is_empty() {
                // Check if the new individual is marked as deleted and the previous state is not
                if let Some(new_is_deleted) = new_indv.get_first_bool("v-s:deleted") {
                    if let Some(prev_is_deleted) = prev_indv.get_first_bool("v-s:deleted") {
                        if !prev_is_deleted
                            && new_is_deleted
                            && ctx.az.authorize(new_indv.get_id(), &transaction.ticket.user_uri, Access::CanDelete as u8, true).unwrap_or(0) != Access::CanDelete as u8
                        {
                            // If not authorized to delete, return response with error
                            let types = new_indv.get_literals("rdf:type").unwrap_or_default();
                            error!(
                                "failed to update, Not Authorized, user = {}, request [can delete], uri = {}, types = {:?}",
                                transaction.ticket.user_uri,
                                &new_indv.get_id(),
                                types
                            );
                            return Response::new(new_indv.get_id(), ResultCode::NotAuthorized, -1, -1);
                        }
                    }
                }
                // Check if the user has authorization to update the individual
                if ctx.az.authorize(new_indv.get_id(), &transaction.ticket.user_uri, Access::CanUpdate as u8, true).unwrap_or(0) != Access::CanUpdate as u8 {
                    let types = new_indv.get_literals("rdf:type").unwrap_or_default();
                    error!(
                        "failed to update, Not Authorized, user = {}, request [can update], uri = {}, types = {:?}",
                        transaction.ticket.user_uri,
                        new_indv.get_id(),
                        types
                    );
                    return Response::new(new_indv.get_id(), ResultCode::NotAuthorized, -1, -1);
                }
            }

            // If the command is not to remove the individual
            if cmd != IndvOp::Remove {
                // Check if the user has access to create new types
                let prev_types = prev_indv.get_literals("rdf:type").unwrap_or_default();
                let new_types = new_indv.get_literals("rdf:type").unwrap_or_default();
                let mut added_types = vec![];

                // Check for new types
                if !new_types.is_empty() {
                    for n_el in new_types.iter() {
                        let mut found = false;
                        for p_el in prev_types.iter() {
                            if p_el == n_el {
                                found = true;
                            }
                        }
                        if !found {
                            added_types.push(n_el);
                        }
                    }
                }
                // If no new type found for Put command, return error
                else if cmd == IndvOp::Put {
                    error!(
                        "failed to update, not found type for new individual, user = {}, id = {}, types = {:?}",
                        transaction.ticket.user_uri,
                        new_indv.get_id(),
                        new_types
                    );
                    return Response::new(new_indv.get_id(), ResultCode::NotAuthorized, -1, -1);
                }

                // Check for user authorization to create new type
                for type_id in added_types.iter() {
                    if ctx.az.authorize(type_id, &transaction.ticket.user_uri, Access::CanCreate as u8, true).unwrap_or(0) != Access::CanCreate as u8 {
                        // If not authorized to create new type, return response with error
                        error!("failed to update, Not Authorized, user = {}, request [can create], type = {}", transaction.ticket.user_uri, type_id);
                        return Response::new(new_indv.get_id(), ResultCode::NotAuthorized, -1, -1);
                    }
                }
            }
        }
        // end authorize
    }

    // Update the counter for the previous individual state
    let upd_counter = prev_indv.get_first_integer("v-s:updateCounter").unwrap_or(0) + 1;

    // If the command is Put and created datetime property is not present,
    // add the datetime property to the new individual object
    if cmd == IndvOp::Put && !new_indv.is_exists("v-s:created") {
        new_indv.add_datetime("v-s:created", Utc::now().naive_utc().timestamp());
    }

    let mut prev_state_c1 = vec![];
    if cmd == IndvOp::Remove {
        prev_indv.set_bool("v-s:deleted", true);
        prev_state_c1 = prev_state.clone();
    }

    // Apply the command to the previous individual state and update the counter
    // and add it to the transaction
    if cmd == IndvOp::AddTo || cmd == IndvOp::SetIn || cmd == IndvOp::RemoveFrom || cmd == IndvOp::Remove {
        if cmd == IndvOp::AddTo || cmd == IndvOp::SetIn || cmd == IndvOp::RemoveFrom {
            indv_apply_cmd(&cmd, &mut prev_indv, new_indv);
        }
        prev_indv.set_integer("v-s:updateCounter", upd_counter);

        if !add_to_transaction(IndvOp::Put, &cmd, &mut prev_indv, prev_state, upd_counter, transaction) {
            error!("failed to commit update to main DB");
            return Response::new(new_indv.get_id(), ResultCode::FailStore, -1, -1);
        }
    } else {
        new_indv.set_integer("v-s:updateCounter", upd_counter);
        if !add_to_transaction(IndvOp::Put, &cmd, new_indv, prev_state, upd_counter, transaction) {
            error!("failed to commit update to main DB");
            return Response::new(new_indv.get_id(), ResultCode::FailStore, -1, -1);
        }
    }

    // If the command is removal, set the update counter and add it to the transaction
    if cmd == IndvOp::Remove {
        new_indv.set_integer("v-s:updateCounter", upd_counter);
        if !add_to_transaction(IndvOp::Remove, &cmd, new_indv, prev_state_c1, upd_counter, transaction) {
            error!("failed to commit update to main DB");
            return Response::new(new_indv.get_id(), ResultCode::FailStore, -1, -1);
        }
    }

    // Return a response
    Response::new(new_indv.get_id(), ResultCode::Ok, *op_id, upd_counter)
}

// This function adds a command to a transaction, which is used for database updates
fn add_to_transaction(cmd: IndvOp, original_cmd: &IndvOp, new_indv: &mut Individual, prev_state: Vec<u8>, update_counter: i64, transaction: &mut Transaction) -> bool {
    // Create a new state vector to store the updated state of the individual
    let mut new_state: Vec<u8> = Vec::new();

    // If the command is "Remove", do nothing
    if cmd == IndvOp::Remove {

        // Otherwise, encode the new individual's state using MessagePack
    } else if to_msgpack(new_indv, &mut new_state).is_err() {
        // If there is an error, log the failure to update the individual and return false
        error!("failed to update individual, id = {}", new_indv.get_id());
        return false;
    }

    // Create a new Transaction Item with the given information
    let ti = TransactionItem {
        indv_id: new_indv.get_id().to_owned(),
        cmd,
        original_cmd: original_cmd.clone(),
        new_state,
        prev_state,
        update_counter,
    };

    // Add the Transaction Item to the Transaction
    transaction.add_item(ti);

    // Return true to indicate success
    true
}

// This function gets a Ticket object from the database using its ID
fn get_ticket_from_db(id: &str, dest: &mut Ticket, storage: &mut VStorage) {
    // Create a default Individual object to store the retrieved data
    let mut indv = Individual::default();

    // Use the VStorage object to retrieve the Individual from the database
    if storage.get_individual_from_db(StorageId::Tickets, id, &mut indv) == ResultCode::Ok {
        // Update the Ticket object using the retrieved data
        dest.update_from_individual(&mut indv);

        // Set the result of the Ticket object to "Ok"
        dest.result = ResultCode::Ok;
    }
}
