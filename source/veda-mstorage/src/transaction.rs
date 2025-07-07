// Import necessary modules
use chrono::Utc;
use v_common::module::info::ModuleInfo;
use v_common::module::ticket::Ticket;
use v_individual_model::onto::datatype::Lang;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::individual2msgpack::to_msgpack;
use v_storage::common::{StorageId, StorageResult};
use v_common::v_api::api_client::IndvOp;
use v_common::v_api::common_type::ResultCode;
use v_common::v_queue::queue::Queue;
use v_common::v_queue::record::MsgType;
use v_storage::VStorage;

// Structure definition of TransactionItem
pub struct TransactionItem {
    pub indv_id: String,      // individual id
    pub cmd: IndvOp,          // command to be performed
    pub original_cmd: IndvOp, // original command
    pub new_state: Vec<u8>,   // new state of the individual
    pub prev_state: Vec<u8>,  // previous state of the individual
    pub update_counter: i64,  // counter for updates
}

// Structure definition of Transaction
pub struct Transaction<'a> {
    pub id: i64,                          // transaction id
    pub event_id: Option<&'a str>,        // event id
    pub assigned_subsystems: Option<i64>, // assigned subsystems
    pub src: Option<&'a str>,             // source
    pub queue: Vec<TransactionItem>,      // vector of TransactionItem
    pub sys_ticket: String,               // system ticket
    pub ticket: Ticket,                   // ticket
}

// Implementation of methods for Transaction
impl<'a> Transaction<'a> {
    // Add item to the transaction queue
    pub(crate) fn add_item(&mut self, item: TransactionItem) {
        self.queue.push(item);
    }

    // Commit the transactions
    pub(crate) fn commit(&mut self, storage: &mut VStorage, queue_out: &mut Queue, mstorage_info: &mut ModuleInfo) -> Result<i64, ResultCode> {
        let mut op_id = self.id;

        for el in self.queue.iter() {
            op_id += 1;

            // Skip if individual ID is empty
            if el.indv_id.is_empty() {
                warn!(
                    "SKIP:{}, {} id={}:{}, ticket={}, event_id={}, src={}",
                    op_id,
                    el.original_cmd.as_string(),
                    el.indv_id,
                    el.update_counter,
                    self.ticket.id,
                    self.event_id.unwrap_or_default(),
                    self.src.unwrap_or_default()
                );
                continue;
            }

            // Remove the individual if the command is 'Remove'
            if el.cmd == IndvOp::Remove {
                if let StorageResult::Ok(()) = storage.remove_value(StorageId::Individuals, &el.indv_id) {
                    info!("remove individual, id = {}", el.indv_id);
                } else {
                    error!("failed to remove individual, id = {}", el.indv_id);
                    return Err(ResultCode::InternalServerError);
                }
            } else if let StorageResult::Ok(()) = storage.put_raw_value(StorageId::Individuals, &el.indv_id, el.new_state.clone()) {
                info!(
                    "OK:{}, {} id={}:{}, ticket={}, event_id={}, src={}",
                    op_id,
                    el.original_cmd.as_string(),
                    el.indv_id,
                    el.update_counter,
                    self.ticket.id,
                    self.event_id.unwrap_or_default(),
                    self.src.unwrap_or_default()
                );
            } else {
                error!("failed to update individual, id = {}", el.indv_id);
                return Err(ResultCode::InternalServerError);
            }

            // Add the individual to the queue
            let mut store_to_queue = if let Some(i) = self.assigned_subsystems {
                i != 1
            } else {
                true
            };

            if el.cmd == IndvOp::Remove && el.prev_state.is_empty() {
                store_to_queue = false;
            }

            if store_to_queue {
                let mut queue_element = Individual::default();
                queue_element.set_id(&format!("{}", op_id));
                queue_element.set_integer("cmd", el.cmd.to_i64());
                queue_element.set_uri("uri", &el.indv_id);

                if !self.ticket.user_uri.is_empty() {
                    queue_element.set_uri("user_uri", &self.ticket.user_uri);
                }

                if !el.new_state.is_empty() {
                    queue_element.set_binary("new_state", el.new_state.clone());
                }

                if !el.prev_state.is_empty() {
                    queue_element.set_binary("prev_state", el.prev_state.clone());
                }

                if let Some(v) = self.event_id {
                    queue_element.set_string("event_id", v, Lang::none());
                }

                queue_element.set_integer("tnx_id", op_id);

                let src = if let Some(v) = self.src {
                    if v.is_empty() {
                        "?"
                    } else {
                        v
                    }
                } else {
                    "?"
                };
                queue_element.set_string("src", src, Lang::none());
                queue_element.add_datetime("date", Utc::now().naive_utc().and_utc().timestamp());
                queue_element.add_integer("op_id", op_id);
                queue_element.add_integer("u_count", el.update_counter);

                // Add assigned subsystems, if available
                if let Some(i) = self.assigned_subsystems {
                    queue_element.add_integer("assigned_subsystems", i);
                }

                debug!("add to queue: uri={}", el.indv_id);

                // Serialize and add individual to the queue
                let mut raw1: Vec<u8> = Vec::new();
                if let Err(e) = to_msgpack(&queue_element, &mut raw1) {
                    error!("failed to serialize, err = {:?}", e);
                    return Err(ResultCode::InternalServerError);
                }
                if let Err(e) = queue_out.push(&raw1, MsgType::String) {
                    error!("failed to push message to queue, err = {:?}", e);
                    return Err(ResultCode::InternalServerError);
                }
            }
        }

        // Store transaction information in the module information storage
        if let Err(e) = mstorage_info.put_info(op_id, op_id) {
            error!("failed to put info, err = {:?}", e);
            return Err(ResultCode::InternalServerError);
        }

        Ok(op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v_common::module::ticket::Ticket;

    fn create_test_ticket() -> Ticket {
        let mut ticket = Ticket::default();
        ticket.id = "test_ticket_123".to_string();
        ticket.user_uri = "d:test_user".to_string();
        ticket.result = ResultCode::Ok;
        ticket
    }

    #[test]
    fn test_transaction_item_creation() {
        let indv_id = "d:test_001";
        let cmd = IndvOp::Put;
        let original_cmd = IndvOp::Put;
        let new_state = vec![1, 2, 3, 4];
        let prev_state = vec![5, 6, 7, 8];
        let update_counter = 42;

        let item = TransactionItem {
            indv_id: indv_id.to_string(),
            cmd: cmd.clone(),
            original_cmd: original_cmd.clone(),
            new_state: new_state.clone(),
            prev_state: prev_state.clone(),
            update_counter,
        };

        assert_eq!(item.indv_id, indv_id);
        assert_eq!(item.cmd, cmd);
        assert_eq!(item.original_cmd, original_cmd);
        assert_eq!(item.new_state, new_state);
        assert_eq!(item.prev_state, prev_state);
        assert_eq!(item.update_counter, update_counter);
    }

    #[test]
    fn test_transaction_add_item() {
        let mut transaction = Transaction {
            id: 1,
            event_id: Some("test_event"),
            assigned_subsystems: Some(1),
            src: Some("test_src"),
            queue: vec![],
            sys_ticket: "sys_ticket_123".to_string(),
            ticket: create_test_ticket(),
        };

        let item = TransactionItem {
            indv_id: "d:test_001".to_string(),
            cmd: IndvOp::Put,
            original_cmd: IndvOp::Put,
            new_state: vec![1, 2, 3],
            prev_state: vec![],
            update_counter: 1,
        };

        assert_eq!(transaction.queue.len(), 0);
        
        transaction.add_item(item);
        
        assert_eq!(transaction.queue.len(), 1);
        assert_eq!(transaction.queue[0].indv_id, "d:test_001");
        assert_eq!(transaction.queue[0].cmd, IndvOp::Put);
    }

    #[test]
    fn test_transaction_multiple_items() {
        let mut transaction = Transaction {
            id: 1,
            event_id: None,
            assigned_subsystems: None,
            src: None,
            queue: vec![],
            sys_ticket: "sys_ticket_123".to_string(),
            ticket: create_test_ticket(),
        };

        // Add multiple items
        for i in 1..=3 {
            let item = TransactionItem {
                indv_id: format!("d:test_{:03}", i),
                cmd: IndvOp::Put,
                original_cmd: IndvOp::Put,
                new_state: vec![i as u8],
                prev_state: vec![],
                update_counter: i,
            };
            transaction.add_item(item);
        }

        assert_eq!(transaction.queue.len(), 3);
        
        for (index, item) in transaction.queue.iter().enumerate() {
            let expected_id = format!("d:test_{:03}", index + 1);
            assert_eq!(item.indv_id, expected_id);
            assert_eq!(item.update_counter, (index + 1) as i64);
        }
    }

    #[test]
    fn test_transaction_different_operations() {
        let mut transaction = Transaction {
            id: 1,
            event_id: None,
            assigned_subsystems: None,
            src: None,
            queue: vec![],
            sys_ticket: "sys_ticket_123".to_string(),
            ticket: create_test_ticket(),
        };

        let operations = vec![
            IndvOp::Put,
            IndvOp::Remove,
            IndvOp::AddTo,
            IndvOp::SetIn,
            IndvOp::RemoveFrom,
            IndvOp::RemovePredicates,
        ];

        for (i, op) in operations.iter().enumerate() {
            let item = TransactionItem {
                indv_id: format!("d:test_{}", i),
                cmd: op.clone(),
                original_cmd: op.clone(),
                new_state: vec![i as u8],
                prev_state: vec![],
                update_counter: i as i64,
            };
            transaction.add_item(item);
        }

        assert_eq!(transaction.queue.len(), operations.len());
        
        for (index, item) in transaction.queue.iter().enumerate() {
            assert_eq!(item.cmd, operations[index]);
            assert_eq!(item.original_cmd, operations[index]);
        }
    }

    #[test]
    fn test_transaction_with_metadata() {
        let event_id = "important_event_123";
        let src = "integration_test";
        let assigned_subsystems = 42;

        let transaction = Transaction {
            id: 999,
            event_id: Some(event_id),
            assigned_subsystems: Some(assigned_subsystems),
            src: Some(src),
            queue: vec![],
            sys_ticket: "sys_ticket_456".to_string(),
            ticket: create_test_ticket(),
        };

        assert_eq!(transaction.id, 999);
        assert_eq!(transaction.event_id, Some(event_id));
        assert_eq!(transaction.assigned_subsystems, Some(assigned_subsystems));
        assert_eq!(transaction.src, Some(src));
        assert_eq!(transaction.sys_ticket, "sys_ticket_456");
    }

    #[test]
    fn test_remove_operation_item() {
        let item = TransactionItem {
            indv_id: "d:to_be_removed".to_string(),
            cmd: IndvOp::Remove,
            original_cmd: IndvOp::Remove,
            new_state: vec![], // Remove operations should have empty new_state
            prev_state: vec![1, 2, 3, 4], // Previous state stored in prev_state
            update_counter: 5,
        };

        assert_eq!(item.cmd, IndvOp::Remove);
        assert!(item.new_state.is_empty());
        assert!(!item.prev_state.is_empty());
    }

    // Integration test with actual storage (if available in test environment)
    #[test]
    fn test_transaction_lifecycle() {
        // This test only validates transaction structure without real storage
        let mut transaction = Transaction {
            id: 1,
            event_id: Some("integration_test"),
            assigned_subsystems: Some(1),
            src: Some("unit_test"),
            queue: vec![],
            sys_ticket: "test_sys_ticket".to_string(),
            ticket: create_test_ticket(),
        };

        // Add test item
        let item = TransactionItem {
            indv_id: "d:integration_test_001".to_string(),
            cmd: IndvOp::Put,
            original_cmd: IndvOp::Put,
            new_state: b"test_individual_data".to_vec(),
            prev_state: vec![],
            update_counter: 1,
        };

        transaction.add_item(item);

        // Test that transaction has the item
        assert_eq!(transaction.queue.len(), 1);
        assert_eq!(transaction.queue[0].indv_id, "d:integration_test_001");
        assert_eq!(transaction.queue[0].cmd, IndvOp::Put);
        assert_eq!(transaction.queue[0].update_counter, 1);

        // This test validates the transaction structure and item management
        // without requiring real storage components
    }
}
