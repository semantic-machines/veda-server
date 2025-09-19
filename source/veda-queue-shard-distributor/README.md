# Veda Queue Shard Distributor

Queue fan-out dispatcher module for Veda platform - distributes messages from main queue to multiple worker queues with automatic worker process management.

## Architecture

This module implements a hybrid architecture described in `worker/queue_fanout_dispatcher_docs.md`:

- **Main Dispatcher (Rust)**: Reads from main queue, distributes messages to worker queues based on shard load, and manages worker processes.
- **Worker Processes (Python)**: Independent processes consuming from dedicated worker queues.

## Key Features

- **VedaQueueModule Integration**: Uses `v_common` framework for main queue consumption.
- **Load Balancing**: Distributes messages to the first available worker queue with zero load. If all workers are busy, it falls back to a round-robin strategy.
- **Worker Process Management**: Automatic spawning, monitoring, and restarting of Python workers.
- **PID-based Process Tracking**: Uses PID files for worker discovery and lifecycle management.
- **Configuration System**: INI-based configuration with sensible defaults and environment variable substitution.
- **Transactional Semantics**: Messages are committed from the main queue only after a successful write to a worker queue.
- **Structured Logging**: Integration with `v_common` logging system.

## Configuration

Configuration is loaded from `./config/veda-queue-shard-distributor.ini`:

```ini
[dispatcher]
# Base path for main queue (source queue for reading)
base_path = ./data/queue-main

# Name of the main queue to read from
main_queue_name = individuals-flow

# Minimum number of worker processes to maintain
min_workers = 4

[worker]
# Base path for worker sub-queues and service files
worker_base_path = ./data/queue-workers

# Prefix for sub-queue names (will be appended with -0, -1, -2, etc.)
sub_queue_prefix = individuals-flow-shard

# Sleep time in seconds when a worker queue is empty
sleep_empty_sec = 0.5

# Command to execute for spawning a worker
worker_module = "python3 -m worker.queue_worker"

# Template for worker arguments.
# Available placeholders: {worker_base_path}, {sub_queue_name}, {sleep_empty_sec}
worker_args_template = "--base {worker_base_path} --sub {sub_queue_name} --src queue-shard-distributor --sleep-empty {sleep_empty_sec}"
```

## Components

### `DispatcherConfig`
Configuration structure with INI file loading support.

### `WorkerManager`
- Spawns Python worker processes using the command specified in `worker_module`.
- Monitors process health via PID files in a `worker_pids/` directory within `worker_base_path`.
- Automatically restarts failed workers.
- Ensures the minimum number of workers is always running.

### `LoadBalancer`
- Tracks the load of each worker queue by monitoring the difference between pushed and popped messages.
- Selects the next available shard for message distribution, prioritizing shards with no current load.
- Falls back to round-robin if load information cannot be determined.

### `QueueShardDistributor`
Main module implementing the `VedaQueueModule` trait:
- Consumes messages from the main queue.
- Distributes messages to worker queues using the load balancer.
- Manages worker processes via a heartbeat mechanism, cleaning up dead workers and ensuring minimum counts.

## Build

```bash
cargo build --release
```

## Usage

```bash
# Run with default configuration
veda-queue-shard-distributor
```
The configuration file will be loaded from `./config/veda-queue-shard-distributor.ini`. If it doesn't exist, it will be created with default values.

## Dependencies

- `v_common`: Veda platform integration (queue module, logging).
- `v-individual-model`: Individual data structures.
- `configparser`: INI configuration file parsing.
- Python workers: An existing implementation compatible with the `worker_args_template`.
