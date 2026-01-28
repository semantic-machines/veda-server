# Veda Authorization Indexer

A Rust-based authorization indexer for the Veda semantic platform that processes and indexes access control lists (ACL), memberships, and permission filters.

## Overview

`veda-az-indexer` is a core component of the Veda platform responsible for:
- Processing permission statements and memberships
- Maintaining ACL indexes for efficient authorization queries
- Caching frequently accessed authorization data
- Supporting incremental updates through queue-based processing
- Optional parallel indexing to Tarantool for high-performance authorization

## Features

- **Permission Statement Processing**: Handles `v-s:PermissionStatement` objects with create, read, update, and delete permissions
- **Membership Management**: Processes `v-s:Membership` relationships between users and groups
- **Permission Filters**: Supports `v-s:PermissionFilter` objects for advanced authorization logic
- **Account Indexing**: Maintains login-to-account mappings for efficient lookups
- **ACL Caching**: Intelligent caching system with configurable expiration and cleanup
- **Queue-based Processing**: Processes authorization changes through message queues
- **Tarantool Integration**: Optional parallel indexing to Tarantool for in-memory authorization checks

## Configuration

The indexer reads configuration from `veda.properties` file. Key configuration sections:

### Authorization Cache
```ini
[authorization_cache]
write=true
expiration=30d
cleanup_time=02:00:00
cleanup_batch_time_limit=100ms
cleanup_continue_interval=10s
min_identifier_count_threshold=100
stat_processing_time_limit=5s
stat_processing_interval=10m
```

### Configuration Options

- `write`: Enable/disable cache writing
- `expiration`: Cache entry expiration time (default: 30 days)
- `cleanup_time`: Daily cleanup start time (default: 02:00:00)
- `cleanup_batch_time_limit`: Maximum time per cleanup batch (default: 100ms)
- `cleanup_continue_interval`: Interval between cleanup batches (default: 10s)
- `min_identifier_count_threshold`: Minimum usage count for cache inclusion (default: 100)
- `stat_processing_time_limit`: Maximum time for statistics processing (default: 5s)
- `stat_processing_interval`: Statistics processing interval (default: 10m)

### Indexer Configuration File

To use extended configuration, create a config file in `./config/` directory:

```ini
[indexer]
# Consumer name suffix (optional)
# If set, consumer name will be "az-indexer-{suffix}"
consumer_suffix =

[tarantool]
enabled = true
host = 127.0.0.1
port = 3301
user = veda
password = veda_password
space_id = 514
connect_timeout = 5
request_timeout = 10
```

### Indexer Configuration Options

- `consumer_suffix`: Suffix for queue consumer name. If set, consumer name becomes "az-indexer-{suffix}". Useful for running multiple indexer instances (default: empty)

### Tarantool Configuration Options

- `enabled`: Enable/disable Tarantool indexing (default: false)
- `host`: Tarantool server address (default: 127.0.0.1)
- `port`: Tarantool server port (default: 3301)
- `user`: Authentication username (default: veda)
- `password`: Authentication password
- `space_id`: Tarantool space ID for ACL indexes (default: 514, corresponds to AZ space)
- `connect_timeout`: Connection timeout in seconds (default: 5)
- `request_timeout`: Request timeout in seconds (default: 10)

## Usage

### Basic Usage
```bash
# Run with default settings (LMDB only)
./veda-az-indexer

# Use index format v1
./veda-az-indexer --use_index_format_v1

# Enable Tarantool indexing
./veda-az-indexer --config tarantool.ini

# Combine options
./veda-az-indexer --config tarantool.ini --use_index_format_v1
```

The `--config` argument specifies the config file name. The file is loaded from `./config/` directory.

### Data Directories
The indexer uses several data directories:
- `./data/acl-indexes`: Main ACL index storage
- `./data/acl-cache-indexes`: Cache storage
- `./data/queue`: Message queue data
- `./data/stat`: Statistics files for cache optimization

## Architecture

### Core Components

1. **Main Processing Loop**: Listens to the message queue and processes authorization changes
2. **Permission Statement Handler**: Processes permission grants and denials
3. **Membership Handler**: Manages user-group relationships
4. **ACL Cache**: Provides fast access to frequently used authorization data
5. **Statistics Processor**: Analyzes usage patterns to optimize cache performance
6. **Tarantool Indexer**: Optional component for parallel indexing to Tarantool

### Processing Flow

1. **Queue Processing**: Listens to `individuals-flow` queue for authorization changes
2. **Object Classification**: Determines if the change affects permissions, memberships, or filters
3. **Index Updates**: Updates LMDB-based indexes with new authorization data
4. **Tarantool Sync**: If enabled, writes changes to Tarantool in parallel
5. **Cache Management**: Updates cache entries and performs cleanup operations
6. **Statistics Collection**: Tracks usage patterns for cache optimization

### Storage Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    veda-az-indexer                          │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌────────────────┐  │
│  │   LMDB      │    │  ACL Cache  │    │   Tarantool    │  │
│  │  (primary)  │    │  (optional) │    │   (optional)   │  │
│  └─────────────┘    └─────────────┘    └────────────────┘  │
│        │                  │                    │            │
│        └──────────────────┴────────────────────┘            │
│                           │                                 │
│                    ┌──────┴──────┐                          │
│                    │  Storage    │                          │
│                    │   Trait     │                          │
│                    └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

## Build and Development

### Prerequisites
- Rust 1.70+
- Veda platform dependencies

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
```

### Development Build
```bash
cargo build
```

## Troubleshooting

### Common Issues

1. **Queue Connection Failures**: Ensure the main Veda module is running
2. **Storage Access Errors**: Check file permissions on data directories
3. **Cache Performance**: Adjust cache thresholds based on system memory
4. **Index Corruption**: Verify LMDB database integrity
5. **Tarantool Connection Failures**: Verify Tarantool server is running and credentials are correct
6. **Tarantool Space Not Found**: Ensure space with specified `space_id` exists (default: 514 for AZ space)

### Debug Information

Enable debug logging to see detailed processing information:
```bash
RUST_LOG=debug ./veda-az-indexer
```

## License

This project is part of the Veda platform. Please refer to the main Veda project for licensing information.
