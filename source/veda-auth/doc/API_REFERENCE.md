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
    "auth_origin": "VEDA"
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
    "end_time": 1640995200000
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
