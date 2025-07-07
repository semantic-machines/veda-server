# Veda Auth

Authentication system for Veda platform, written in Rust.

## Features

- **Secure authentication** with PBKDF2 password hashing
- **Protection against brute force attacks** with automatic user blocking
- **Password reset** through secret codes with email notifications
- **Trusted authentication** for system operations
- **Ticket lifecycle management** with time control
- **Support for different authentication sources** (VEDA, AD)
- **Configurable security policies**

## Architecture

The system consists of:
- **Authentication server** (main.rs) - handles requests through NNG protocol
- **Authentication library** (lib.rs) - main authentication logic
- **User management modules** (common.rs) - helper functions
- **Authentication handler** (auth.rs) - main AuthWorkPlace logic

## Quick Start

### 1. Install dependencies
```bash
cargo build
```

### 2. Run server
```bash
cargo run
```

### 3. Basic usage
```rust
use veda_auth::*;
use v_storage::VStorage;
use v_common::module::ticket::Ticket;

// Create storage
let storage_box = VStorage::builder().memory().build()?;
let mut storage = VStorage::new(storage_box);

// Create system ticket
let sys_ticket = create_sys_ticket(&mut storage);

// Create user credentials
let mut credential = Individual::default();
set_password(&mut credential, "secure_password");

// Create user ticket
let mut ticket = Ticket::default();
create_new_ticket("user1", "user:123", "127.0.0.1", 3600, &mut ticket, &mut storage);
```

## Usage Examples

The `examples/` folder contains detailed usage examples:

### 📚 Basic examples

- **`quick_start.rs`** - Minimal code to get started
- **`basic_usage.rs`** - Main system features
- **`configuration_example.rs`** - Configuration for different environments

### 🔧 Advanced examples

- **`simple_client.rs`** - Client for connecting to server
- **`integration_example.rs`** - Integration with other systems
- **`testing_example.rs`** - Testing functionality

### Run examples

```bash
# Quick start
cargo run --example quick_start

# Basic usage
cargo run --example basic_usage

# Configuration setup
cargo run --example configuration_example

# Client-server (requires running server)
cargo run --example simple_client

# System integration
cargo run --example integration_example

# Testing
cargo run --example testing_example
```

## API

### Main functions

```rust
// Set password
set_password(&mut credential, "password");

// Create ticket
create_new_ticket(login, user_id, ip, lifetime, &mut ticket, &mut storage);

// Create system ticket
create_sys_ticket(&mut storage);

// Find users
get_candidate_users_of_login(login, backend, xr, auth_data);
```

### Structures

```rust
// Authentication configuration
pub struct AuthConf {
    pub failed_auth_attempts: i32,
    pub ticket_lifetime: i64,
    pub pass_lifetime: i64,
    // ... other settings
}

// User statistics
pub struct UserStat {
    pub wrong_count_login: i32,
    pub last_wrong_login_date: i64,
    // ... other fields
}

// Authentication workplace
pub struct AuthWorkPlace<'a> {
    pub login: &'a str,
    pub password: &'a str,
    pub ip: &'a str,
    // ... other fields
}
```

## Configuration

### Default settings

```rust
let config = AuthConf {
    failed_auth_attempts: 2,           // Maximum failed attempts
    ticket_lifetime: 10 * 60 * 60,    // Ticket lifetime (10 hours)
    pass_lifetime: 90 * 24 * 60 * 60, // Password lifetime (90 days)
    check_ticket_ip: true,             // Check IP for tickets
    // ... other settings
};
```

### Production configuration

```rust
let prod_config = AuthConf {
    failed_auth_attempts: 3,
    failed_auth_lock_period: 15 * 60,  // Lock for 15 minutes
    ticket_lifetime: 8 * 60 * 60,      // Ticket for 8 hours
    secret_lifetime: 6 * 60 * 60,      // Secret for 6 hours
    check_ticket_ip: true,
    // ... email notifications
};
```

## Security

### Password hashing
- Uses PBKDF2 with SHA-512
- 100,000 iterations for attack protection
- Unique salt for each password

### Attack protection
- Automatic blocking after failed attempts
- Ticket lifetime limits
- IP address checking for tickets
- Password change frequency limits

### Notifications
- Email notifications for password changes
- Warnings about blocked operations
- Configurable notification templates

## Testing

```bash
# Run all tests
cargo test

# Run example tests
cargo test --example basic_usage
cargo test --example testing_example

# Run with detailed output
cargo test -- --nocapture
```

## Performance

- Asynchronous request processing
- In-memory caching for fast access
- Optimized data structures
- Configurable timeouts for network operations

## Integration

### Connect to server

```rust
use nng::{Protocol, Socket};

let socket = Socket::new(Protocol::Req0)?;
socket.dial("tcp://localhost:8080")?;
```

### Send requests

```rust
let request = json!({
    "function": "authenticate",
    "login": "user1",
    "password": "password_hash",
    "addr": "127.0.0.1"
});
```

## Supported protocols

- **NNG (nanomsg)** - main protocol for client-server communication
- **JSON** - data exchange format
- **TCP** - transport protocol

## Logging

The system supports detailed logging:

```bash
# Set logging level
export RUST_LOG=info

# Run with logging
cargo run
```

## Monitoring

Metrics for monitoring:
- Number of successful/failed authentications
- Request processing time
- Number of blocked users
- Resource usage

## Deployment

### Docker

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
COPY --from=builder /app/target/release/veda-auth /usr/local/bin/
CMD ["veda-auth"]
```

### Systemd

```ini
[Unit]
Description=Veda Auth Service
After=network.target

[Service]
Type=simple
User=veda
ExecStart=/usr/local/bin/veda-auth
Restart=always

[Install]
WantedBy=multi-user.target
```

## License

The project is distributed under a license compatible with the Veda project.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Make sure all tests pass
5. Create a Pull Request

## Support

For support:
- Check examples in the `examples/` folder
- Review existing tests
- Create an Issue with problem description
- Refer to Veda documentation 