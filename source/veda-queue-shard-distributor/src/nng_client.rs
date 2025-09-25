use nng::{Protocol, Socket};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::worker_manager::WorkerManager;

#[derive(Debug)]
pub struct NngClient {
    sockets: Arc<Mutex<HashMap<String, Socket>>>, // worker_id -> Socket
}

impl NngClient {
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create socket connection to worker
    async fn get_or_create_socket(&self, worker_id: &str, nng_address: &str) -> Result<Socket, String> {
        let mut sockets = self.sockets.lock().await;

        if let Some(socket) = sockets.get(worker_id) {
            // Check if socket is still connected
            return Ok(socket.clone());
        }

        // Create new socket
        match Socket::new(Protocol::Req0) {
            Ok(socket) => match socket.dial(nng_address) {
                Ok(_) => {
                    info!("Connected to NNG worker {} at {}", worker_id, nng_address);
                    sockets.insert(worker_id.to_string(), socket.clone());
                    Ok(socket)
                },
                Err(e) => {
                    error!("Failed to connect to worker {} at {}: {:?}", worker_id, nng_address, e);
                    Err(format!("Failed to connect to worker: {:?}", e))
                },
            },
            Err(e) => {
                error!("Failed to create NNG socket: {:?}", e);
                Err(format!("Failed to create socket: {:?}", e))
            },
        }
    }

    /// Send message to worker and wait for response
    pub async fn send_message_to_worker(
        &self,
        worker_id: &str,
        nng_address: &str,
        message_data: &[u8],
        worker_manager: Arc<tokio::sync::Mutex<WorkerManager>>,
    ) -> Result<(), String> {
        // Mark worker as busy
        {
            let manager = worker_manager.lock().await;
            manager.mark_worker_busy(worker_id).await;
        }

        let socket = self.get_or_create_socket(worker_id, nng_address).await?;

        // Send message
        info!("Sending message to worker {} at {}", worker_id, nng_address);

        match socket.send(message_data) {
            Ok(_) => {
                info!("Message sent to worker {}, waiting for response", worker_id);

                // Clone necessary data for async task
                let worker_id_clone = worker_id.to_string();
                let socket_clone = socket.clone();
                let worker_manager_clone = Arc::clone(&worker_manager);

                // Spawn async task to wait for response
                tokio::spawn(async move {
                    match socket_clone.recv() {
                        Ok(response_data) => match std::str::from_utf8(&response_data) {
                            Ok(response_str) => match serde_json::from_str::<Value>(response_str) {
                                Ok(response_json) => {
                                    if let Some(success) = response_json.get("success").and_then(|v| v.as_bool()) {
                                        if success {
                                            info!("Worker {} completed task successfully", worker_id_clone);
                                        } else {
                                            warn!("Worker {} reported task failure: {:?}", worker_id_clone, response_json.get("error"));
                                        }
                                    } else {
                                        warn!("Invalid response format from worker {}: {}", worker_id_clone, response_str);
                                    }
                                },
                                Err(e) => {
                                    error!("Failed to parse JSON response from worker {}: {:?}", worker_id_clone, e);
                                },
                            },
                            Err(e) => {
                                error!("Invalid UTF-8 response from worker {}: {:?}", worker_id_clone, e);
                            },
                        },
                        Err(e) => {
                            error!("Failed to receive response from worker {}: {:?}", worker_id_clone, e);
                        },
                    }

                    // Mark worker as free after processing (regardless of success/failure)
                    let manager = worker_manager_clone.lock().await;
                    manager.mark_worker_free(&worker_id_clone).await;
                    info!("Worker {} marked as free", worker_id_clone);
                });

                Ok(())
            },
            Err(e) => {
                error!("Failed to send message to worker {}: {:?}", worker_id, e);

                // Mark worker as free since we failed to send
                let manager = worker_manager.lock().await;
                manager.mark_worker_free(worker_id).await;

                Err(format!("Failed to send message: {:?}", e))
            },
        }
    }

    /// Clean up socket connection to worker
    pub async fn cleanup_worker_socket(&self, worker_id: &str) {
        let mut sockets = self.sockets.lock().await;
        if let Some(socket) = sockets.remove(worker_id) {
            // Close socket
            let _ = socket.close();
            info!("Cleaned up socket connection to worker {}", worker_id);
        }
    }

    /// Get count of active socket connections
    pub async fn get_active_connections_count(&self) -> usize {
        let sockets = self.sockets.lock().await;
        sockets.len()
    }
}

impl Drop for NngClient {
    fn drop(&mut self) {
        // Clean up all sockets when NngClient is dropped
        info!("Cleaning up NngClient and closing all socket connections");
    }
}
