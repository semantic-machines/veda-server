# Veda Auth Examples

This directory contains examples demonstrating how to use the veda-auth authentication system.

## Examples Overview

### 1. Basic Usage (`basic_usage.rs`)
Demonstrates the core functionality of the authentication system:
- Creating credentials and setting passwords
- Creating tickets (system and user)
- Working with authentication configuration
- User statistics and locking logic
- Password handling for different input types

**How to run:**
```bash
cargo run --example basic_usage
```

### 2. Simple Client (`simple_client.rs`)
Shows how to create a client that connects to the authentication server:
- Connecting to the auth server via NNG protocol
- Basic authentication with username/password
- **SMS authentication** with phone number and verification codes
- Authentication with secret codes (password reset)
- Requesting password reset
- Getting trusted tickets
- Checking user existence
- Logout functionality

**How to run:**
```bash
# Start the auth server first
cargo run

# Then in another terminal
cargo run --example simple_client
```

### 3. Configuration Example (`configuration_example.rs`)
Demonstrates various configuration scenarios:
- Default configuration
- Production environment setup
- Development environment setup
- High-security environment setup
- Test environment setup
- User statistics management

**How to run:**
```bash
cargo run --example configuration_example
```



## Prerequisites

Before running the examples, make sure you have:

1. **Rust** installed (version 1.70 or later)
2. **Dependencies** installed:
   ```bash
   cargo build
   ```

## Authentication Server Setup

To run examples that require the authentication server:

1. **Start the server:**
   ```bash
   cargo run
   ```
   This starts the server on `tcp://localhost:8080` by default.

2. **Configure the server** by setting environment variables or creating a configuration file:
   ```bash
   export VEDA_AUTH_URL="tcp://localhost:8080"
   ```

## Example Workflows

### Basic Authentication Flow
1. Start with `basic_usage.rs` to understand core concepts
2. Run `simple_client.rs` to see client-server interaction
3. Explore `configuration_example.rs` for different environments

### Password Reset Flow
1. User requests password reset via `simple_client.rs`
2. System generates secret code and sends notification
3. User authenticates with secret code and new password

### SMS Authentication Flow
1. User sends authentication request with phone number (empty password)
2. System generates and sends SMS code to the mobile phone
3. User authenticates with phone number and received SMS code
4. System validates code and returns authentication ticket

### User Management Flow
1. Check if user exists before creating accounts
2. Create user accounts using the authentication system
3. Manage user lifecycle (enable/disable)
4. Monitor user statistics and handle locking



## Configuration

### Environment Variables
- `VEDA_AUTH_URL`: Authentication server URL (default: `tcp://localhost:8080`)
- `VEDA_AUTH_DATA_PATH`: Path to authentication data storage (default: `./data`)

### Configuration Files
The system looks for configuration in:
- `veda.properties` file
- Environment variables
- Default values

## Security Notes

### Production Use
- Always use secure passwords (demonstrated in examples)
- Configure appropriate timeouts and retry limits
- Enable IP checking for tickets
- Set up proper email notifications for security events
- **Configure SMS provider** properly for SMS authentication
- **Set appropriate SMS rate limits** to prevent abuse
- **Monitor SMS usage** to control costs and prevent spam

### Development Use
- Use relaxed settings for development (shown in config example)
- Disable IP checking for easier testing
- Use longer ticket lifetimes for debugging

## Testing

Run all tests including example tests:
```bash
cargo test
```

Run specific example tests:
```bash
cargo test --example basic_usage
cargo test --example configuration_example
```

## Common Issues

### Connection Issues
- Ensure the auth server is running
- Check the URL configuration
- Verify network connectivity

### Authentication Failures
- Check user credentials
- Verify user account is not disabled
- Check for account lockout due to failed attempts

### Password Issues
- Ensure passwords meet complexity requirements
- Check for password expiration
- Verify proper encoding for non-ASCII passwords

## API Reference

### Core Functions
- `set_password()`: Set password for a credential
- `create_new_ticket()`: Create authentication ticket
- `create_sys_ticket()`: Create system-level ticket
- `get_candidate_users_of_login()`: Find users by login


### Structures
- `AuthConf`: Authentication configuration
- `UserStat`: User statistics tracking
- `AuthWorkPlace`: Main authentication handler
- `Ticket`: Authentication ticket

### Result Codes
- `ResultCode::Ok`: Success
- `ResultCode::AuthenticationFailed`: Invalid credentials
- `ResultCode::TooManyRequests`: Account locked (including SMS rate limits)
- `ResultCode::PasswordExpired`: Password needs reset
- `ResultCode::InvalidSecret`: Invalid secret code (including SMS codes)
- SMS specific errors (handled through existing result codes)
- SMS provider errors (logged but use existing authentication failure codes)

## Contributing

To add new examples:
1. Create a new `.rs` file in the `examples/` directory
2. Follow the existing pattern with documentation and tests
3. Add entry to this README
4. Test thoroughly with different scenarios

## License

These examples are part of the veda-auth project and follow the same license terms. 