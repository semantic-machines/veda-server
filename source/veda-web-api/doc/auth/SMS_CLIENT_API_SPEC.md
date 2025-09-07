# SMS Authentication API Specification

API specification for client-side developers.

For server developers: See `SMS_AUTH_README.md`

## Overview

SMS authentication works in 2 stages:
1. Request SMS code - client sends signed request with phone number
2. Verify code - client sends received SMS code to get auth token

Flow diagram: See `SMS_FLOW_DIAGRAM.md`

## Architecture

The SMS module acts as a lightweight wrapper:
- **Validates HMAC signatures** on client requests
- **Creates encrypted session tokens** for stateless operation
- **Delegates SMS handling** to veda-auth API
- **Returns compatible auth tickets** for the main system

## Request Format

### Request Signing
All requests to `/auth/sms/request` must include HMAC-SHA256 signature:

```
message = "action=sms_request|nonce={uuid}|phone={phone}|salt={hex}|timestamp={unix_timestamp}"
signature = HMAC-SHA256(message, client_secret + salt)
```

### Required Headers
```
Content-Type: application/json
```

## API Endpoints

SMS authentication uses only 2 endpoints:

### 1. Request SMS Code

**POST** `/auth/sms/request`

**Request Body:**
```json
{
    "phone": "79991234567",
    "timestamp": 1703123456,
    "nonce": "550e8400-e29b-41d4-a716-446655440000", 
    "salt": "abcdef1234567890abcdef1234567890",
    "signature": "computed_hmac_sha256_hex"
}
```

**Response (Success):**
```json
{
    "token": "eyJkYXRhIjoiYmFzZTY0ZW5jcnlwdGVkZGF0YSIsIm5vbmNlIjoiYmFzZTY0bm9uY2UifQ=="
}
```

`token` contains encrypted session information as a JSON token with `data` (RSA encrypted data) and `nonce` (random nonce) fields.

**Response (Error):**
```json
{
    "token": "eyJkYXRhIjoiZmFrZWVuY3J5cHRlZGRhdGEiLCJub25jZSI6ImZha2Vub25jZSJ9"
}
```

To prevent user enumeration attacks, a token is always returned, even on errors.

**HTTP Status Codes:**
- `200` - Request always processed (SMS sent if valid request and phone registered)

Note: Always returns HTTP 200 to prevent user enumeration attacks, even for invalid requests.

### 2. Verify SMS Code

**POST** `/auth/sms/verify`

**Request Body:**
```json
{
    "token": "eyJkYXRhIjoiYmFzZTY0ZW5jcnlwdGVkZGF0YSIsIm5vbmNlIjoiYmFzZTY0bm9uY2UifQ==",
    "code": "123456"
}
```

**Response (Success):**
```json
{
    "id": "auth-ticket-string",
    "user_uri": "cfg:Administrator", 
    "end_time": 1703209856
}
```

On successful verification, an authentication ticket is returned.

**HTTP Status Codes:**
- `200` - Authentication successful  
- `400` - Bad request (invalid token format, malformed request)
- `473` - Authentication failed (invalid code, session expired, user not found)

## Client Implementation Requirements

### 1. HMAC Signature Generation

```
1. Generate random salt (16 bytes, hex encoded)
2. Get current timestamp (Unix seconds)
3. Generate UUID v4 for nonce
4. Create message string with sorted fields:
   "action=sms_request|nonce={nonce}|phone={phone}|salt={salt}|timestamp={timestamp}"
5. Compute HMAC-SHA256(message, client_secret + salt)
6. Encode signature as hex string
```

### 2. Phone Number Format

- Accept: `+7 (999) 123-45-67`, `8 999 123 45 67`, `79991234567`
- Normalize to: `79991234567` (11 digits starting with 7)

### 3. Error Handling

Handle these error scenarios:
- Invalid signature → Show generic message "Code sent if number registered"
- Network errors → Allow retry with exponential backoff
- Authentication failures → Allow retry up to 3 times per session

Note: Rate limiting is handled by veda-auth and does not return specific error codes to prevent enumeration attacks.

## Configuration

The client needs access to:
- `client_secret` - for HMAC signing (same as in config/veda-web-api.ini)
- `api_base_url` - server base URL

## Rate Limits

Rate limiting is handled by veda-auth and does not return specific HTTP error codes to prevent user enumeration. Configure limits in veda-auth:
- SMS per phone per hour
- SMS per IP per hour  
- Maximum verification attempts per session

## Testing

For testing, use phone numbers registered in veda-auth.

SMS codes are handled by veda-auth - check veda-auth logs for development codes.

## Integration with Existing Auth

SMS auth is fully compatible with the main authentication system:
- Returns the same JSON format as `auth.rs -> authenticate()`
- Uses veda-auth to create valid tickets
- Phone-based authentication is handled by veda-auth
- Can be used **standalone** or in combination with other methods

## Dependencies

### veda-auth Requirements

veda-auth configuration:
- veda-auth instance running and accessible from web API server
- Phone number to user mappings in veda-auth user database
- SMS provider configured (supported providers)
- Rate limiting policies defined in veda-auth
- `auth_url` property set in web API configuration

### Client Dependencies

Required libraries:
- HMAC-SHA256 implementation (`crypto` module in Node.js, `crypto-js` in browser)
- UUID generation library
- Base64 encoding/decoding
- HTTP client (fetch, axios, etc.)

**Browser Example:**
```html
<script src="https://cdn.example.com/crypto-js/4.1.1/crypto-js.min.js"></script>
<script>
    function computeHmac(message, key) {
        return CryptoJS.HmacSHA256(message, key).toString(CryptoJS.enc.Hex);
    }
</script>
```

**Node.js Example:**
```javascript
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

function computeHmac(message, key) {
    return crypto.createHmac('sha256', key).update(message).digest('hex');
}
```

## Security Considerations

Security requirements:
1. `client_secret`: Use strong secret (32+ random characters)
2. HTTPS only: Never use SMS auth over unencrypted HTTP connections
3. Timestamp validation: Ensure client and server clocks are synchronized
4. Token handling: Treat tokens as sensitive data, never log or expose
5. Rate limiting: Implement client-side rate limiting to prevent abuse

Example configuration:
```javascript
const SMS_CONFIG = {
    client_secret: process.env.SMS_CLIENT_SECRET, // From environment
    api_base_url: 'https://api.example.com', // HTTPS only
    max_retries: 3,
    timeout: 30000
};
```

Best practices:
- Never hardcode `client_secret` in source code
- Validate all user inputs (phone numbers, codes)
- Implement proper error handling without information leakage
- Use storage for authentication tokens
- Implement session timeout and cleanup
