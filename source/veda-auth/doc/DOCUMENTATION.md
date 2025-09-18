# veda-auth

Authentication server for Veda platform.

## Overview

veda-auth provides centralized authentication system with the following features:

- **User authentication** with login and password
- **Password reset** via secret codes sent by email
- **SMS authentication** with verification codes sent to mobile phones
- **Session management** through ticket system
- **Brute force protection** with automatic account locking
- **Trusted authentication** for system processes
- **User existence checking**

Server accepts JSON requests over NNG protocol.

## API

### Main Functions

#### `authenticate`
User authentication with login and password.

**Request:**
```json
{
    "function": "authenticate",
    "login": "user_login",
    "password": "password_hash", 
    "secret": "",
    "addr": "client_ip"
}
```

**Response:**
```json
{
    "type": "ticket",
    "id": "ticket_id",
    "user_uri": "user:uri",
    "user_login": "user_login",
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "password",
    "domain": "veda",
    "initiator": "authenticate"
}
```

#### `get_ticket_trusted`
Get trusted ticket for another user (requires special permissions).

**Request:**
```json
{
    "function": "get_ticket_trusted",
    "ticket": "current_ticket_id",
    "login": "target_user_login",
    "addr": "client_ip"
}
```

**Response:**
```json
{
    "type": "ticket",
    "id": "new_ticket_id",
    "user_uri": "target_user_uri",
    "user_login": "target_user_login",
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "trusted",
    "domain": "veda",
    "initiator": "get_ticket_trusted"
}
```

#### `logout`
End session and invalidate ticket.

**Request:**
```json
{
    "function": "logout",
    "ticket": "ticket_id",
    "addr": "client_ip"
}
```



### SMS Authentication

#### SMS Authentication Flow
1. **Request SMS code**: Send authentication request with phone number
2. **Receive SMS code**: Code is sent to the provided mobile phone
3. **Authenticate with code**: Use the received code to complete authentication

#### SMS Request (Phone + Empty Password)
```json
{
    "function": "authenticate",
    "login": "+7xxxxxxxxxx",
    "password": "",
    "secret": "",
    "addr": "127.0.0.1"
}
```

#### SMS Authentication (Phone + Code)
```json
{
    "function": "authenticate", 
    "login": "+7xxxxxxxxxx",
    "password": "",
    "secret": "123456",
    "addr": "127.0.0.1"
}
```

**Response (Success):**
```json
{
    "type": "ticket",
    "id": "ticket-uuid-123",
    "user_uri": "user:id",
    "user_login": "+7xxxxxxxxxx",
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "sms",
    "domain": "veda",
    "initiator": "authenticate"
}
```

### Password Management

#### Regular authentication
```json
{
    "function": "authenticate",
    "login": "admin",
    "password": "sha256_hash_of_password",
    "secret": "",
    "addr": "127.0.0.1"
}
```

#### Password reset request
```json
{
    "function": "authenticate", 
    "login": "admin",
    "password": "",
    "secret": "?",
    "addr": "127.0.0.1"
}
```

#### Set new password with secret code
```json
{
    "function": "authenticate",
    "login": "admin", 
    "password": "new_password_hash",
    "secret": "123456",
    "addr": "127.0.0.1"
}
```

### Connection Format

Server runs on address specified in configuration (default `tcp://localhost:8080`).

All requests are sent in JSON format over NNG REQ/REP sockets.

### Response Fields

All successful authentication responses include these fields:

#### Standard Fields
- `type` - Always "ticket" for authentication responses
- `id` - Unique ticket identifier
- `user_uri` - User URI from database  
- `user_login` - User login name
- `result` - Result code (0 for success, error code for failures)
- `end_time` - Ticket expiration timestamp in milliseconds
- `auth_origin` - Authentication origin type, taken from user's `v-s:authOrigin` field:
  - `"VEDA"` - Standard Veda platform users (default)
  - `"AD"` - Active Directory users  
  - `"MOBILE"` - Mobile-only users

#### Authentication Context Fields
- `auth_method` - Authentication method used:
  - `"password"` - Standard login/password authentication
  - `"secret"` - Authentication with secret code (password reset)
  - `"sms"` - SMS code authentication
  - `"trusted"` - Trusted ticket generation
- `domain` - Authentication domain (default: "veda")
- `initiator` - Operation that initiated authentication:
  - `"authenticate"` - Standard authentication request
  - `"get_ticket_trusted"` - Trusted ticket request

### Result Codes

- `0` - `Ok` - Successful operation
- `1` - `AuthenticationFailed` - Invalid credentials
- `470` - `TooManyRequests` - Account locked due to too many failed attempts
- `471` - `PasswordExpired` - Password expired, reset required
- `472` - `InvalidSecret` - Invalid secret code
- `473` - `SecretExpired` - Secret code expired
- `474` - `EmptyPassword` - Empty password
- `475` - `NewPasswordIsEqualToOld` - New password equals old password
- `476` - `Locked` - Operation locked
- `477` - `TooManyRequestsChangePassword` - Too many password change requests
- `478` - `ChangePasswordForbidden` - Password change forbidden

### Security Policies

- Automatic account locking after multiple failed attempts
- Limited lifetime for tickets and secret codes  
- Optional IP address verification
- Secure password storage

### Configuration

Main parameters:
- **Server address**: default `tcp://localhost:8080`
- **Ticket lifetime**: 10 hours (configurable)
- **Max failed attempts**: 2 (configurable)
- **Lock period**: 30 minutes (configurable)
- **IP checking**: enabled by default

#### SMS Configuration
- **SMS rate limit**: 60 seconds between requests (configurable via `cfg:sms_rate_limit_period`)
- **Daily SMS limit**: 5 SMS per day per user (configurable via `cfg:sms_daily_limit`)
- **SMS code range**: 100,000 - 999,999 (configurable via `cfg:sms_code_min`, `cfg:sms_code_max`)
- **SMS code lifetime**: matches secret lifetime configuration
- **SMS provider**: Megalabs integration (configurable in SMS service)
- **SMS tracking**: Each SMS individual is marked with `v-s:source` field set to "veda-auth" for tracking purposes

### Usage Examples

#### Server Connection
```bash
# Start server
./veda-auth

# Server listens on tcp://localhost:8080
```

#### Client Authentication
```json
// Send request:
{
    "function": "authenticate",
    "login": "admin",
    "password": "hashed_password",
    "secret": "",
    "addr": "127.0.0.1"
}

// Receive response:
{
    "type": "ticket",
    "id": "ticket-uuid-123",
    "user_uri": "user:admin", 
    "user_login": "admin",
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "password",
    "domain": "veda",
    "initiator": "authenticate"
}
```

#### Password Reset
```json
// 1. Request reset:
{
    "function": "authenticate",
    "login": "admin",
    "password": "",
    "secret": "?",
    "addr": "127.0.0.1"
}

// 2. Use code from email:
{
    "function": "authenticate", 
    "login": "admin",
    "password": "new_hashed_password",
    "secret": "123456",
    "addr": "127.0.0.1"
}
```

#### SMS Authentication
```json
// 1. Request SMS code:
{
    "function": "authenticate",
    "login": "+79xxxxxxxxx",
    "password": "",
    "secret": "",
    "addr": "127.0.0.1"
}

// 2. Authenticate with SMS code:
{
    "function": "authenticate",
    "login": "+79xxxxxxxxx", 
    "password": "",
    "secret": "654321",
    "addr": "127.0.0.1"
}

// Response on success:
{
    "type": "ticket",
    "id": "ticket-uuid-456",
    "user_uri": "user:mobile_user",
    "user_login": "+79xxxxxxxxx",
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "sms",
    "domain": "veda",
    "initiator": "authenticate"
}
```

### System Requirements

- Veda platform for user and data management
- Configured email server for sending password reset codes
- **SMS provider** for sending SMS authentication codes (Megalabs supported)
- Access to user database
