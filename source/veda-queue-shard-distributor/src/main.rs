#[macro_use]
extern crate log;

mod config;
mod nng_client;
mod worker_manager;

use config::{read_config_from_ini, DispatcherConfig};
use nng_client::NngClient;
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use worker_manager::WorkerManager;

use v_common::init_module_log;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{get_inner_binobj_as_individual, init_log, Module, PrepareError};
use v_common::module::veda_module::VedaQueueModule;
use v_individual_model::onto::individual::Individual;

// Main dispatcher module
pub struct QueueShardDistributor {
    config: DispatcherConfig,
    worker_manager: Arc<TokioMutex<WorkerManager>>,
    nng_client: Arc<NngClient>,
    module_info: ModuleInfo,
}

impl QueueShardDistributor {
    pub fn new(config: DispatcherConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let module_info = ModuleInfo::new(&config.base_path, "queue-shard-distributor", true)?;
        let nng_client = Arc::new(NngClient::new());
        let worker_manager = Arc::new(TokioMutex::new(WorkerManager::new(config.clone(), Arc::clone(&nng_client))));

        // Ensure worker base directory exists
        fs::create_dir_all(&config.worker_base_path)?;

        Ok(Self {
            config,
            worker_manager,
            nng_client,
            module_info,
        })
    }
}

impl VedaQueueModule for QueueShardDistributor {
    fn before_batch(&mut self, _size_batch: u32) -> Option<u32> {
        None
    }

    fn prepare(&mut self, queue_element: &mut Individual) -> Result<bool, PrepareError> {
        let op_id = queue_element.get_first_integer("op_id").unwrap_or_default();

        // Extract binary data from queue element to get individual ID for logging
        let mut new_state = Individual::default();
        let individual_id = if get_inner_binobj_as_individual(queue_element, "new_state", &mut new_state) {
            new_state.get_id().to_string()
        } else {
            "unknown".to_string()
        };

        // Get the original raw binary data from queue_element
        let serialized_data = queue_element.get_raw_data();

        if serialized_data.is_empty() {
            error!("Queue element has empty raw data, op_id = {}", op_id);
            // Skip this message but continue processing
            return Ok(false);
        }

        // Use block_in_place to run async code in sync context without nested runtime
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
            // Infinite retry loop - keep trying until message is sent successfully
            loop {
                // Wait for available worker (infinite loop until we find one)
                let target_worker = loop {
                    if let Some(worker_id) = self.worker_manager.lock().await.get_free_worker().await {
                        break worker_id;
                    } else {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };

                // Get worker info
                let (nng_address, worker_count) = {
                    let manager = self.worker_manager.lock().await;
                    let worker_info = manager.get_worker(&target_worker)?;
                    let nng_address = worker_info.nng_address.clone();
                    let worker_count = manager.get_worker_ids().len();
                    Some((nng_address, worker_count))
                }?;

                info!(
                    "Distributing message (op_id={}) to worker {} at {} (of {} workers), individual: {}",
                    op_id, target_worker, nng_address, worker_count, individual_id
                );

                // Try to send message to worker via NNG (single attempt)
                match self.nng_client.send_message_to_worker(&target_worker, &nng_address, serialized_data, Arc::clone(&self.worker_manager)).await {
                    Ok(_) => {
                        info!("Successfully sent message op_id={} to worker {}", op_id, target_worker);
                        return Some(());
                    },
                    Err(e) => {
                        error!("Failed to send message to worker {}: {}", target_worker, e);

                        // Mark worker as temporarily unavailable (could be busy, crashed, or network issue)
                        {
                            let manager = self.worker_manager.lock().await;
                            let unavailable_duration = std::time::Duration::from_secs(self.config.worker_unavailable_duration_sec as u64);
                            manager.mark_worker_unavailable(&target_worker, unavailable_duration).await;
                        }

                        // Continue to find another worker - no delay needed
                        continue;
                    },
                }
            }
            })
        });

        match result {
            Some(_) => {
                // Only update module_info after successful send to worker
                // This acts as "commit" for the main queue message
                if let Err(e) = self.module_info.put_info(op_id, op_id) {
                    error!("Failed to write module_info, op_id = {}, err = {:?}", op_id, e);
                    return Err(PrepareError::Fatal);
                }
                Ok(true)
            },
            None => {
                // Failed to send message, skip this message but continue processing
                Ok(false)
            },
        }
    }

    fn after_batch(&mut self, _prepared_batch_size: u32) -> Result<bool, PrepareError> {
        Ok(true)
    }

    fn heartbeat(&mut self) -> Result<(), PrepareError> {
        // Use block_in_place to run async code in sync context without nested runtime
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Clean up dead workers and ensure minimum workers are running during heartbeat
                {
                    let mut manager = self.worker_manager.lock().await;
                    manager.cleanup_dead_workers();
                    manager.ensure_minimum_workers().await;
                }
            })
        });

        info!("Heartbeat completed - worker management updated");
        Ok(())
    }

    fn before_start(&mut self) {
        info!("NNG Queue Shard Distributor starting with config: {:?}", self.config);

        // Use block_in_place to run async code in sync context without nested runtime
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Ensure minimum workers at startup (this creates workers first)
                {
                    let mut manager = self.worker_manager.lock().await;
                    manager.ensure_minimum_workers().await;
                }

                info!("Started {} NNG workers", self.config.min_workers);
            })
        });

        /*
        TODO: Test worker connectivity by sending a test message to each worker
        and verifying they respond correctly before marking them as active.
        This ensures workers are properly started and listening on their NNG addresses.
        */
    }

    fn before_exit(&mut self) {
        info!("Queue Shard Distributor shutting down");
    }
}

fn main() -> std::io::Result<()> {
    init_module_log!("QUEUE_SHARD_DISTRIBUTOR");

    // Create Tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // Run everything inside the runtime context
    rt.block_on(async {
        // Load configuration from INI file
        let config = read_config_from_ini("./config/veda-queue-shard-distributor.ini");
        info!("Starting Queue Shard Distributor with config: {:?}", config);

        let mut dispatcher = match QueueShardDistributor::new(config) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to create dispatcher: {}", e);
                return;
            },
        };

        let mut module = Module::new_with_name("queue-shard-distributor");
        module.prepare_queue(&mut dispatcher);
    });

    Ok(())
}
