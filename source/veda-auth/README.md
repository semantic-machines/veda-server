# veda-auth

Authentication module for Veda system. It provides API for user management and authentication tickets using nanomsg protocol.

## Description

`veda-auth` is a high-performance authentication service that provides:
- User authentication by login and password
- Session management through tickets
- Trusted authentication between services
- Password change with email confirmation
- Protection against brute force attacks

## Architecture

### How it works

1. **Transport**: Uses nanomsg protocol (via `nng` library) with REP/REQ pattern
2. **Data format**: JSON for requests and responses
3. **Storage**: LMDB for tickets and authentication data
4. **Search**: Xapian for user search
5. **Authorization**: LmdbAzContext for access rights checking

### Components

- `main.rs` - main nanomsg server
- `auth.rs` - authentication and password change logic
- `common.rs` - common functions and configuration

## API

Server accepts JSON requests and returns JSON responses via nanomsg. All requests must contain `function` field that defines operation type.

### 1. User Authentication

**Request:**
```json
{
  "function": "authenticate",
  "login": "user_login",
  "password": "sha256_hash_of_password", 
  "secret": "secret_code_for_password_reset",
  "addr": "client_ip_address"
}
```

**Response:**
```json
{
  "type": "ticket",
  "id": "ticket_id",
  "user_uri": "user_uri",
  "user_login": "user_login", 
  "result": 200,
  "end_time": 1640995200000,
  "auth_origin": "VEDA"
}
```

**Description:**
- `login` - user login
- `password` - SHA256 hash of password (or special constant for empty password)
- `secret` - secret code for password reset (optional):
  - Empty string for normal authentication
  - "?" to request password reset
  - 6+ characters to confirm new password
- `addr` - client IP address for ticket binding

### 2. Get Trusted Ticket

**Request:**
```json
{
  "function": "get_ticket_trusted",
  "ticket": "existing_ticket_id",
  "login": "target_user_login",
  "addr": "client_ip_address"
}
```

**Response:**
```json
{
  "type": "ticket", 
  "id": "new_ticket_id",
  "user_uri": "user_uri",
  "user_login": "user_login",
  "result": 200,
  "end_time": 1640995200000
}
```

**Description:**
Allows getting ticket for another user with proper rights. Requires:
- Valid ticket of user with permissions
- Membership in `cfg:TrustedAuthenticationUserGroup` group or authentication as same user

### 3. Logout

**Request:**
```json
{
  "function": "logout",
  "ticket": "ticket_id",
  "addr": "client_ip_address" 
}
```

**Response:**
```json
{
  "type": "ticket",
  "id": "ticket_id", 
  "result": 200,
  "end_time": 1640995200000
}
```

**Description:**
Deactivates specified ticket by setting end time to current moment.

## Result Codes

- `200` (Ok) - Success
- `201` (Created) - New object created
- `400` (BadRequest) - Invalid request
- `401` (Unauthorized) - Authentication error
- `403` (Forbidden) - Access denied
- `404` (NotFound) - User not found
- `422` (UnprocessableEntity) - Invalid data
- `429` (TooManyRequests) - Too many attempts
- `451` (UnavailableForLegalReasons) - Password expired
- `500` (InternalServerError) - Internal error

## Configuration

Configuration is read from `cfg:standart_node` object in database:

### Security Parameters
- `cfg:failed_auth_attempts` - max failed login attempts (default: 2)
- `cfg:failed_auth_lock_period` - lock time after limit exceeded (default: 30 minutes)
- `cfg:failed_change_pass_attempts` - max password change attempts (default: 2)
- `cfg:failed_pass_change_lock_period` - password change lock time (default: 30 minutes)
- `cfg:success_pass_change_lock_period` - min interval between password changes (default: 24 hours)

### Lifetime Parameters
- `cfg:user_ticket_lifetime` - ticket lifetime (default: 10 hours)
- `cfg:secret_lifetime` - secret code lifetime (default: 12 hours)
- `cfg:user_password_lifetime` - max password age (default: 90 days)

### Notifications
- `cfg:expired_pass_notification_template` - expired password notification template
- `cfg:denied_password_expired_notification_template` - password change denial notification template

## Security

### Password Storage
- Passwords are hashed using PBKDF2-HMAC-SHA512
- Random salt is used for each password
- 100,000 iterations to slow down attacks (constant `N_ITER` in `src/common.rs`)

**What 100,000 iterations means:**
PBKDF2 (Password-Based Key Derivation Function 2) applies hash function many times to password and salt. Large number of iterations makes hash computation slow (~0.1-0.2 seconds). This:
- Is barely noticeable for normal user login
- Significantly slows down brute force attacks
- Makes dictionary attacks impossible in reasonable time
- Meets modern security standards (OWASP recommends 100,000+ iterations for PBKDF2-SHA256)

### Attack Protection
- Limit on login attempts
- Temporary blocking after limit exceeded
- Ticket binding to IP addresses (optional)
- Password change frequency control

### Password Reset
- One-time secret code generation
- Code delivery via email
- Limited code lifetime
- Protection against reuse

## Running

```bash
# Build dependencies
cargo build --release

# Run (requires veda.properties config file)
./target/release/veda-auth
```

### Environment Variables
- `auth_url` - URL for nanomsg listening (from veda.properties)
- `check_ticket_ip` - check IP when validating tickets (default: true)

## Data Structure

### Ticket
```json
{
  "id": "uuid",
  "user_uri": "d:user_123", 
  "user_login": "username",
  "start_time": 1640995200000,
  "end_time": 1640998800000,
  "result": 200
}
```

### Credential
- Password hash (PBKDF2)
- Salt for hashing
- Creation date
- Secret code (for reset)
- Permanent flag

## Dependencies

- `nng` - nanomsg library for Rust
- `chrono` - date and time handling
- `serde_json` - JSON serialization
- `ring` - cryptographic functions
- `uuid` - unique identifier generation
- `v_common` - common Veda system components

## Monitoring

Service logs detailed information about all authentication operations:
- Successful and failed login attempts
- Ticket creation and deactivation
- Password change requests
- Configuration and database errors

Logs contain user information, IP addresses and timestamps for security audit. 