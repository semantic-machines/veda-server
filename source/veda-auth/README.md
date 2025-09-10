# Veda Auth

Authentication system for Veda platform, written in Rust.

## Features

- **Secure authentication** with PBKDF2 password hashing
- **Protection against brute force attacks** with automatic user blocking
- **Password reset** through secret codes with email notifications
- **SMS authentication** with two-step verification process
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

The authentication configuration is split between two files for better organization:

### Configuration Files

1. **`veda.properties`** - Main system settings and authentication parameters
2. **`config/sms_authentication.ini`** - SMS-specific authentication settings

### SMS Configuration (config/sms_authentication.ini)

```ini
# SMS Authentication Configuration
# Настройки SMS аутентификации для Veda Auth

[sms]
# Настройки SMS аутентификации
sms_rate_limit_period = 20s
sms_daily_limit = 24
sms_code_min = 100000
sms_code_max = 999999
```

### Authentication Settings (veda.properties)

```ini
# Authentication configuration
# Security settings
failed_auth_attempts = 3
failed_change_pass_attempts = 2
failed_auth_lock_period = 15m
failed_pass_change_lock_period = 30m
success_pass_change_lock_period = 24h

# Lifetimes
user_password_lifetime = 90d
user_ticket_lifetime = 8h
secret_lifetime = 6h

# Email notification templates (subject|body format)
expired_pass_notification_template = "Password Expired - {{app_name}}|..."
denied_password_expired_notification_template = "Password Change Denied - {{app_name}}|..."
```

### Configuration Parameters

#### Authentication Parameters (from veda.properties)
| Parameter | Description | Default |
|-----------|-------------|---------|
| `failed_auth_attempts` | Max failed login attempts before lock | 3 |
| `failed_change_pass_attempts` | Max failed password change attempts | 2 |
| `failed_auth_lock_period` | Lock duration after failed attempts | 15m |
| `failed_pass_change_lock_period` | Lock duration after failed password changes | 30m |
| `success_pass_change_lock_period` | Minimum time between password changes | 24h |
| `user_ticket_lifetime` | Authentication ticket lifetime | 8h |
| `user_password_lifetime` | Password validity period | 90d |
| `secret_lifetime` | Secret code lifetime for password reset | 6h |
| `check_ticket_ip` | Enable IP checking for tickets | true |

#### SMS Parameters (from config/sms_authentication.ini)
| Parameter | Description | Default |
|-----------|-------------|---------|
| `sms_daily_limit` | Daily SMS limit per user | 24 |
| `sms_rate_limit_period` | Minimum time between SMS | 20s |
| `sms_code_min` | Minimum SMS code value | 100000 |
| `sms_code_max` | Maximum SMS code value | 999999 |

#### Email Templates (from veda.properties)
| Parameter | Description | Default |
|-----------|-------------|---------|
| `expired_pass_notification_template` | Email template for expired passwords | Built-in template |
| `denied_password_expired_notification_template` | Email template for denied password changes | Built-in template |

## SMS Authentication Process

SMS authentication in Veda Auth uses a two-step verification process:

### Step 1: Request SMS Code

**Request parameters:**
- `login`: Valid phone number (with or without + prefix)
- `password`: Empty or SHA256 hash of empty string
- `secret`: Empty

**Process:**
1. System validates phone number format (minimum 10 digits)
2. Checks rate limiting (default: 20 seconds between requests)
3. Checks daily SMS limit (default: 24 per day)
4. Generates random SMS code (6 digits, 100000-999999 range)
5. Stores code as secret in user credential
6. Sends SMS via backend queue system
7. Returns `ResultCode::Ok` on success

**Phone number formats supported:**
- `+79123456789` - international format
- `79123456789` - national format with country code
- `89123456789` - converted to 7-prefixed format
- `9123456789` - 10-digit format, adds country code

### Step 2: Verify SMS Code

**Request parameters:**
- `login`: Same phone number as in step 1  
- `password`: Empty or SHA256 hash of empty string
- `secret`: SMS code received (4+ digit numeric string)

**Process:**
1. System checks account has `v-s:authOrigin = "MOBILE"`
2. Validates phone number format
3. Compares provided code with stored secret
4. Checks secret expiration (default: 6 hours lifetime)
5. Creates authentication ticket on success
6. Clears used secret for security
7. Resets failed login attempts counter

**Security features:**
- SMS codes expire after configured lifetime
- Rate limiting prevents spam requests  
- Daily limits prevent abuse
- Used secrets are immediately cleared
- Failed attempts are tracked and limited

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