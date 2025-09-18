# veda-auth API Reference

## Overview

The veda-auth service provides authentication functionality via NNG (nanomsg) protocol. This document describes the available API functions and their usage.

## Supported Functions

The API currently supports three main functions:

### 1. `authenticate`

User authentication with various methods including regular login/password, SMS authentication, and secret codes.

#### Standard Authentication

**Request:**
```json
{
    "function": "authenticate",
    "login": "username", 
    "password": "password_hash",
    "secret": "",
    "addr": "client_ip"
}
```

#### SMS Authentication - Request Code

For phone number authentication, send empty password to request SMS code:

**Request:**
```json
{
    "function": "authenticate",
    "login": "+7xxxxxxxxxx",
    "password": "",
    "secret": "",
    "addr": "client_ip"
}
```

#### SMS Authentication - Verify Code

Use received SMS code for authentication:

**Request:**
```json
{
    "function": "authenticate", 
    "login": "+7xxxxxxxxxx",
    "password": "",
    "secret": "123456",
    "addr": "client_ip"
}
```

#### Password Reset with Secret

**Request:**
```json
{
    "function": "authenticate",
    "login": "username",
    "password": "new_password_hash", 
    "secret": "secret_code",
    "addr": "client_ip"
}
```

#### Response

**Success:**
```json
{
    "type": "ticket",
    "id": "ticket_id",
    "user_uri": "user_uri",
    "user_login": "username", 
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "password",
    "domain": "veda",
    "initiator": "authenticate"
}
```

**Error:**
```json
{
    "type": "ticket",
    "id": "",
    "user_uri": "",
    "user_login": "",
    "result": 422,  // Error code
    "end_time": 0,
    "auth_origin": "VEDA"
}
```

### 2. `get_ticket_trusted`

Get a trusted ticket for impersonation (requires appropriate permissions).

**Request:**
```json
{
    "function": "get_ticket_trusted",
    "ticket": "admin_ticket_id",
    "login": "target_username",
    "addr": "client_ip"
}
```

**Response:**
```json
{
    "type": "ticket",
    "id": "new_ticket_id",
    "user_uri": "target_user_uri",
    "user_login": "target_username",
    "result": 0,
    "end_time": 1640995200000,
    "auth_origin": "VEDA",
    "auth_method": "trusted",
    "domain": "veda",
    "initiator": "get_ticket_trusted"
}
```

### 3. `logout`

Invalidate an authentication ticket.

**Request:**
```json
{
    "function": "logout",
    "ticket": "ticket_id",
    "addr": "client_ip"
}
```

**Response:**
```json
{
    "type": "ticket",
    "id": "ticket_id",
    "result": 0,
    "end_time": 1640995200000
}
```

## Response Fields

All authentication responses include these fields:

### Standard Fields
- `type` - Always "ticket" for authentication responses
- `id` - Unique ticket identifier (empty string on error)
- `user_uri` - User URI from database (empty string on error)
- `user_login` - User login name (empty string on error)
- `result` - Result code (0 for success, error code for failures)
- `end_time` - Ticket expiration timestamp in milliseconds
- `auth_origin` - Authentication origin type, taken from user's `v-s:authOrigin` field:
  - `"VEDA"` - Standard Veda platform users (default)
  - `"AD"` - Active Directory users  
  - `"MOBILE"` - Mobile-only users

### Authentication Context Fields
- `auth_method` - Authentication method used:
  - `"password"` - Standard login/password authentication
  - `"secret"` - Authentication with secret code (password reset)
  - `"sms"` - SMS code authentication
  - `"trusted"` - Trusted ticket generation
- `domain` - Authentication domain (default: "veda")
- `initiator` - Operation that initiated authentication:
  - `"authenticate"` - Standard authentication request
  - `"get_ticket_trusted"` - Trusted ticket request

**Note:** The `auth_method`, `domain`, and `initiator` fields are only present in successful authentication responses, not in error responses.

## Result Codes

Common result codes returned in the `result` field:

- `0` - Success (OK)
- `422` - Authentication Failed
- `423` - Too Many Requests
- `424` - Password Expired
- `425` - Invalid Secret
- `426` - Secret Expired
- `427` - Empty Password
- `500` - Internal Server Error

## SMS Authentication Configuration

SMS authentication can be configured via ini file. See `SMS_CONFIG.md` for details.

### SMS Settings in Database

Configure these parameters in `cfg:standart_node`:

- `cfg:sms_rate_limit_period` - Rate limit between SMS requests
- `cfg:sms_daily_limit` - Maximum SMS per day per user  
- `cfg:sms_code_min` - Minimum SMS code value
- `cfg:sms_code_max` - Maximum SMS code value
- `cfg:sms_config_file` - Path to SMS configuration file

### SMS Individual Creation

When SMS authentication is requested, the system creates a `v-s:Sms` individual with the following properties:

- `rdf:type` - "v-s:Sms"
- `v-s:recipientPhone` - Normalized phone number
- `v-s:messageBody` - SMS message text with authentication code
- `v-s:created` - Timestamp when SMS was created
- `v-s:source` - Source module that created the SMS (set to "veda-auth" for authentication module)
- `v-s:isSuccess` - Delivery status (initially false)
- `v-s:infoOfExecuting` - Execution information (initially empty)

## Connection

The service uses NNG (nanomsg) protocol. Default connection:
- URL: `tcp://localhost:8080` (configurable via `auth_url` property)
- Protocol: Request-Reply (REP0)
- Timeout: 30 seconds receive, 60 seconds send

## Security Notes

1. **Password Hashing**: Passwords should be pre-hashed before sending
2. **IP Validation**: Client IP is validated if `check_ticket_ip` is enabled
3. **Rate Limiting**: Failed authentication attempts trigger temporary locks
4. **SMS Security**: SMS codes expire and have limited attempts
5. **Ticket Lifetime**: Authentication tickets have configurable expiration

## Examples

See `examples/` directory for implementation examples in Rust.
