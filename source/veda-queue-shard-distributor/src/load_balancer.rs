use std::collections::HashMap;
use v_common::v_queue::consumer::Consumer;
use v_common::v_queue::record::Mode;

// Load balancer with worker load tracking
pub struct LoadBalancer {
    current_index: usize,
    worker_consumers: HashMap<String, Consumer>,
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self {
            current_index: 0,
            worker_consumers: HashMap::new(),
        }
    }

    pub fn get_next_worker(&mut self, worker_ids: &[String]) -> Option<String> {
        if worker_ids.is_empty() {
            return None;
        }

        if worker_ids.len() == 1 {
            return Some(worker_ids[0].clone());
        }

        // Find first available worker starting from last used index
        let start_index = self.current_index % worker_ids.len();
        let mut fallback_to_round_robin = false;
        let mut first_available_worker = None;

        // Check all workers starting from last used index
        for i in 0..worker_ids.len() {
            let worker_index = (start_index + i) % worker_ids.len();
            let worker_id = &worker_ids[worker_index];

            if let Some(consumer) = self.worker_consumers.get_mut(worker_id) {
                // Try to get fresh queue info
                if !consumer.queue.get_info_queue() {
                    warn!("Failed to get queue info for worker {}, falling back to round-robin", worker_id);
                    fallback_to_round_robin = true;
                    break;
                }

                let queue_size = consumer.queue.count_pushed;
                let processed_count = consumer.count_popped;
                let current_load = if queue_size >= processed_count {
                    queue_size - processed_count
                } else {
                    0  // Consumer ahead of queue (shouldn't happen normally)
                };

                debug!("Worker {} load: queue_pushed={}, count_popped={}, load={}",
                       worker_id, queue_size, processed_count, current_load);

                // Remember first available worker if we haven't found one yet
                if first_available_worker.is_none() {
                    first_available_worker = Some(worker_id.clone());
                }

                // If this worker is free (no load), use it immediately
                if current_load == 0 {
                    self.current_index = worker_index + 1;
                    info!("Selected free worker {}", worker_id);
                    return Some(worker_id.clone());
                }
            } else {
                // No consumer for this worker - skip it as defective
                warn!("Skipping worker {} - no consumer found (defective worker)", worker_id);
                continue;
            }
        }

        if fallback_to_round_robin {
            // Fallback to round-robin if load tracking fails
            warn!("Falling back to round-robin distribution");
            let worker_index = self.current_index % worker_ids.len();
            self.current_index = (self.current_index + 1) % worker_ids.len();
            return Some(worker_ids[worker_index].clone());
        }

        // No free worker found, use first available
        if let Some(selected_worker) = first_available_worker {
            // Update index for next round-robin
            if let Some(pos) = worker_ids.iter().position(|w| w == &selected_worker) {
                self.current_index = pos + 1;
            }
            info!("No free worker found, selected first available worker {}", selected_worker);
            Some(selected_worker)
        } else {
            // All workers are defective (no consumers), cannot distribute
            error!("All workers are defective (no consumers found), cannot distribute message");
            None
        }
    }

    pub fn update_worker_consumers(&mut self, active_workers: &[(String, String)], worker_base_path: &str) {
        // Get current worker IDs
        let current_worker_ids: std::collections::HashSet<String> = active_workers.iter().map(|(worker_id, _)| worker_id.clone()).collect();
        
        // Clean up consumers for workers that no longer exist
        let mut to_remove = Vec::new();
        for worker_id in self.worker_consumers.keys() {
            if !current_worker_ids.contains(worker_id) {
                to_remove.push(worker_id.clone());
            }
        }
        for worker_id in to_remove {
            self.worker_consumers.remove(&worker_id);
            info!("Removed consumer for worker {} (no longer active)", worker_id);
        }

        // Create consumers for active workers
        for (worker_id, queue_name) in active_workers {
            if !self.worker_consumers.contains_key(worker_id) {
                let consumer_name = format!("load-balancer-{}", worker_id);

                match Consumer::new_with_mode(worker_base_path, &consumer_name, queue_name, Mode::Read) {
                    Ok(consumer) => {
                        info!("Created readonly consumer for worker {}: {}", worker_id, queue_name);
                        self.worker_consumers.insert(worker_id.clone(), consumer);
                    },
                    Err(e) => {
                        warn!("Failed to create consumer for worker {} ({}): {:?}", worker_id, queue_name, e);
                    }
                }
            }
        }
    }
}
