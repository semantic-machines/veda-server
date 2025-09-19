use std::collections::HashMap;
use v_common::v_queue::consumer::Consumer;
use v_common::v_queue::record::Mode;

// Load balancer with worker load tracking
pub struct LoadBalancer {
    current_index: u32,
    worker_consumers: HashMap<u32, Consumer>,
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self {
            current_index: 0,
            worker_consumers: HashMap::new(),
        }
    }

    pub fn get_next_shard(&mut self, total_shards: u32) -> Option<u32> {
        if total_shards == 0 {
            return None;
        }

        if total_shards == 1 {
            return Some(0);
        }

        // Find first available shard starting from last used index
        let start_index = self.current_index % total_shards;
        let mut fallback_to_round_robin = false;
        let mut first_available_shard = None;

        // Check all shards starting from last used index
        for i in 0..total_shards {
            let shard_id = (start_index + i) % total_shards;

            if let Some(consumer) = self.worker_consumers.get_mut(&shard_id) {
                // Try to get fresh queue info
                if !consumer.queue.get_info_queue() {
                    warn!("Failed to get queue info for shard {}, falling back to round-robin", shard_id);
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

                debug!("Shard {} load: queue_pushed={}, count_popped={}, load={}",
                       shard_id, queue_size, processed_count, current_load);

                // Remember first available shard if we haven't found one yet
                if first_available_shard.is_none() {
                    first_available_shard = Some(shard_id);
                }

                // If this shard is free (no load), use it immediately
                if current_load == 0 {
                    self.current_index = shard_id + 1;
                    info!("Selected free shard {}", shard_id);
                    return Some(shard_id);
                }
            } else {
                // No consumer for this shard - skip it as defective
                warn!("Skipping shard {} - no consumer found (defective shard)", shard_id);
                continue;
            }
        }

        if fallback_to_round_robin {
            // Fallback to round-robin if load tracking fails
            warn!("Falling back to round-robin distribution");
            let shard = self.current_index % total_shards;
            self.current_index = (self.current_index + 1) % total_shards;
            return Some(shard);
        }

        // No free shard found, use first available
        if let Some(selected_shard) = first_available_shard {
            self.current_index = selected_shard + 1;
            info!("No free shard found, selected first available shard {}", selected_shard);
            Some(selected_shard)
        } else {
            // All shards are defective (no consumers), cannot distribute
            error!("All shards are defective (no consumers found), cannot distribute message");
            None
        }
    }

    pub fn update_worker_consumers(&mut self, total_shards: u32, worker_base_path: &str, sub_queue_prefix: &str) {
        // Clean up consumers for shards that no longer exist
        let mut to_remove = Vec::new();
        for &shard_id in self.worker_consumers.keys() {
            if shard_id >= total_shards {
                to_remove.push(shard_id);
            }
        }
        for shard_id in to_remove {
            self.worker_consumers.remove(&shard_id);
            info!("Removed consumer for shard {} (worker no longer active)", shard_id);
        }

        // Create consumers for new shards
        for shard_id in 0..total_shards {
            if !self.worker_consumers.contains_key(&shard_id) {
                let sub_queue_name = format!("{}-{}", sub_queue_prefix, shard_id);
                let consumer_name = format!("load-balancer-{}", shard_id);

                match Consumer::new_with_mode(worker_base_path, &consumer_name, &sub_queue_name, Mode::Read) {
                    Ok(consumer) => {
                        info!("Created readonly consumer for shard {}: {}", shard_id, sub_queue_name);
                        self.worker_consumers.insert(shard_id, consumer);
                    },
                    Err(e) => {
                        warn!("Failed to create consumer for shard {} ({}): {:?}", shard_id, sub_queue_name, e);
                    }
                }
            }
        }
    }
}
