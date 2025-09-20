#[macro_use]
extern crate log;

mod config;
mod load_balancer;
mod worker_manager;

use std::collections::HashMap;
use std::fs;
use config::{DispatcherConfig, read_config_from_ini};
use load_balancer::LoadBalancer;
use worker_manager::WorkerManager;

use v_common::init_module_log;
use v_common::module::info::ModuleInfo;
use v_common::module::module_impl::{get_inner_binobj_as_individual, init_log, Module, PrepareError};
use v_common::module::veda_module::VedaQueueModule;
use v_common::v_queue::queue::Queue;
use v_common::v_queue::record::{Mode, MsgType};
use v_individual_model::onto::individual::Individual;

// Main dispatcher module
pub struct QueueShardDistributor {
    config: DispatcherConfig,
    worker_manager: WorkerManager, 
    load_balancer: LoadBalancer,
    sub_queue_cache: HashMap<String, Queue>,
    module_info: ModuleInfo,
}

impl QueueShardDistributor {
    pub fn new(config: DispatcherConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let module_info = ModuleInfo::new(&config.base_path, "queue-shard-distributor", true)?;
        let worker_manager = WorkerManager::new(config.clone());
        let load_balancer = LoadBalancer::new();

        // Ensure worker base directory exists
        fs::create_dir_all(&config.worker_base_path)?;

        Ok(Self {
            config,
            worker_manager,
            load_balancer,
            sub_queue_cache: HashMap::new(),
            module_info,
        })
    }

    fn get_or_create_sub_queue(&mut self, worker_id: &str) -> Result<&mut Queue, Box<dyn std::error::Error>> {
        if !self.sub_queue_cache.contains_key(worker_id) {
            let sub_queue_name = format!("{}-{}", self.config.sub_queue_prefix, worker_id);
            
            info!("Creating sub-queue: {} in {}", sub_queue_name, self.config.worker_base_path);
            
            let queue = Queue::new(&self.config.worker_base_path, &sub_queue_name, Mode::ReadWrite)
                .map_err(|e| format!("Failed to create sub-queue {}: {:?}", sub_queue_name, e))?;
            
            self.sub_queue_cache.insert(worker_id.to_string(), queue);
        }
        
        Ok(self.sub_queue_cache.get_mut(worker_id).unwrap())
    }

    fn ensure_sub_queues_exist_for_active_workers(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let active_workers = self.worker_manager.get_active_workers();
        info!("Ensuring sub-queues exist for {} active workers", active_workers.len());
        
        for (worker_id, sub_queue_name) in active_workers {
            if !self.sub_queue_cache.contains_key(&worker_id) {
                info!("Pre-creating sub-queue: {} in {}", sub_queue_name, self.config.worker_base_path);
                
                let queue = Queue::new(&self.config.worker_base_path, &sub_queue_name, Mode::ReadWrite)
                    .map_err(|e| format!("Failed to pre-create sub-queue {}: {:?}", sub_queue_name, e))?;
                
                self.sub_queue_cache.insert(worker_id, queue);
            }
        }
        
        info!("Successfully ensured sub-queues exist for active workers");
        Ok(())
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

        // Get current workers and select target worker
        let worker_ids = self.worker_manager.get_worker_ids();
        let worker_count = worker_ids.len();
        let target_worker = loop {
            match self.load_balancer.get_next_worker(&worker_ids) {
                Some(worker) => break worker,
                None => {
                    error!("No healthy workers available for message distribution (op_id={}), waiting 30 seconds before retry", op_id);
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    // Update worker consumers to check for new healthy workers
                    let active_workers = self.worker_manager.get_active_workers();
                    self.load_balancer.update_worker_consumers(&active_workers, &self.config.worker_base_path);
                    continue;
                }
            }
        };
        
        info!("Distributing message (op_id={}) to worker {} (of {} workers), individual: {}", 
              op_id, target_worker, worker_count, individual_id);

        // Get or create target sub-queue
        let target_queue = match self.get_or_create_sub_queue(&target_worker) {
            Ok(queue) => queue,
            Err(e) => {
                error!("Failed to get sub-queue for worker {}: {}", target_worker, e);
                // Return Ok(false) to skip this message but continue processing
                return Ok(false);
            }
        };

        // Get the original raw binary data from queue_element
        let serialized_data = queue_element.get_raw_data();
        
        if serialized_data.is_empty() {
            error!("Queue element has empty raw data, op_id = {}", op_id);
            // Skip this message but continue processing
            return Ok(false);
        }

        // Push message to sub-queue (transactional - only succeeds if write is successful)
        if let Err(e) = target_queue.push(serialized_data, MsgType::Object) {
            error!("Failed to push message to sub-queue worker {}, op_id = {}: {:?}", 
                   target_worker, op_id, e);
            // Skip this message but continue processing
            return Ok(false);
        }

        // Only update module_info after successful push to sub-queue
        // This acts as "commit" for the main queue message
        if let Err(e) = self.module_info.put_info(op_id, op_id) {
            error!("Failed to write module_info, op_id = {}, err = {:?}", op_id, e);
            return Err(PrepareError::Fatal);
        }

        info!("Successfully distributed message op_id={} to worker {}", op_id, target_worker);
        Ok(true)
    }

    fn after_batch(&mut self, _prepared_batch_size: u32) -> Result<bool, PrepareError> {
        Ok(true)
    }

    fn heartbeat(&mut self) -> Result<(), PrepareError> {
        // Clean up dead workers and ensure minimum workers are running during heartbeat
        self.worker_manager.cleanup_dead_workers();
        self.worker_manager.ensure_minimum_workers();
        
        // Ensure sub-queues exist for all active workers
        if let Err(e) = self.ensure_sub_queues_exist_for_active_workers() {
            warn!("Failed to ensure sub-queues exist during heartbeat: {}", e);
            // Don't return error, just log warning - continue with heartbeat
        }
        
        // Update load balancer consumers to match active workers
        let active_workers = self.worker_manager.get_active_workers();
        self.load_balancer.update_worker_consumers(&active_workers, &self.config.worker_base_path);
        
        Ok(())
    }

    fn before_start(&mut self) {
        info!("Queue Shard Distributor starting with config: {:?}", self.config);
        
        // Ensure minimum workers at startup (this creates workers first)
        self.worker_manager.ensure_minimum_workers();
        
        // Create sub-queues for active workers after workers are created
        if let Err(e) = self.ensure_sub_queues_exist_for_active_workers() {
            error!("Failed to ensure sub-queues exist: {}", e);
            // Don't panic, but log the error - workers might still work if queues already exist
        }
        
        // Initialize load balancer consumers for active workers
        let active_workers = self.worker_manager.get_active_workers();
        self.load_balancer.update_worker_consumers(&active_workers, &self.config.worker_base_path);
    }

    fn before_exit(&mut self) {
        info!("Queue Shard Distributor shutting down");
    }
}

fn main() -> std::io::Result<()> {
    init_module_log!("QUEUE_SHARD_DISTRIBUTOR");
    
    // Load configuration from INI file
    let config = read_config_from_ini("./config/veda-queue-shard-distributor.ini");
    info!("Starting Queue Shard Distributor with config: {:?}", config);
    
    let mut dispatcher = match QueueShardDistributor::new(config) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to create dispatcher: {}", e);
            return Ok(());
        }
    };

    let mut module = Module::new_with_name("queue-shard-distributor");
    module.prepare_queue(&mut dispatcher);

    Ok(())
}
