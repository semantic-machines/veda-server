# SMS Authentication Implementation

SMS authentication module with RSA encryption, HMAC request signing and veda-auth integration.

## Documentation

- **Client API**: `SMS_CLIENT_API_SPEC.md` - API specification for client developers
- **Flow Diagram**: `SMS_FLOW_DIAGRAM.md` - detailed interaction flow and testing

## Features

- Stateless operation with RSA-2048 session encryption
- HMAC-SHA256 request signatures with salt-based replay protection  
- Complete delegation to veda-auth for SMS sending and user management
- Privacy protection using fake tokens for invalid requests
- Compatible with existing authorization system

## Setup

### Configuration config/veda-web-api.ini

```ini
[sms]
enabled = true
client_secret = your-secret-key-here
max_time_drift = 300
# rsa_key_path = /etc/veda/rsa_private_key.pem  # optional
```

- `enabled` - enable/disable SMS authentication
- `client_secret` - HMAC signing secret (must match client)
- `max_time_drift` - timestamp tolerance in seconds
- `rsa_key_path` - optional path to RSA private key file

### RSA Key Management

**Development**: Keys auto-generated at startup
```bash
cargo run
# Output: "Generated new RSA-2048 keys for SMS session encryption"
```

**Production**: Use persistent key file
```bash
# Generate RSA private key
openssl genpkey -algorithm RSA -out /etc/veda/rsa_private_key.pem -pkcs8
chmod 600 /etc/veda/rsa_private_key.pem

# Configure in config/veda-web-api.ini
rsa_key_path = /etc/veda/rsa_private_key.pem
```

**Cluster Requirements**: All nodes must use identical RSA private key for token compatibility.

### veda-auth Setup

SMS module delegates all SMS operations to veda-auth. Required:
- SMS provider configured in veda-auth
- Phone number → user ID mappings in veda-auth database  
- Rate limiting policies in veda-auth
- Phone-based authentication support in veda-auth

## Production Notes

For production deployment:
1. Generate strong `client_secret` (32+ characters)
2. Use persistent RSA key for clusters: `rsa_key_path = /path/to/key.pem`
3. Use HTTPS for all SMS endpoints
4. Configure SMS provider in veda-auth

## Troubleshooting

Enable debug logging: `RUST_LOG=veda_web_api=debug cargo run`

Common issues:
- HTTP 200 with fake token → Check `client_secret` and system clocks
- HTTP 400 on verification → Verify RSA key consistency and session timing
- HTTP 473 on verification → Check veda-auth logs and user registration
- HTTP 500 errors → Verify veda-auth connectivity
