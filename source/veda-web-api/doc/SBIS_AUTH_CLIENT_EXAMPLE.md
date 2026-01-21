# SBIS OAuth Authentication - Client Example

## Request

```http
POST /auth/sbis/authenticate HTTP/1.1
Host: your-veda-server.com
Content-Type: application/json

{
    "access_token": "SBIS_ACCESS_TOKEN"
}
```

## cURL

```bash
curl -X POST "https://your-veda-server.com/auth/sbis/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"access_token": "your_sbis_access_token_here"}'
```

## JavaScript

```javascript
async function authenticateViaSbis(sbisAccessToken) {
  const response = await fetch('/auth/sbis/authenticate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      access_token: sbisAccessToken
    })
  });

  if (!response.ok) {
    throw new Error(`Authentication failed: ${response.status}`);
  }

  return await response.json();
}

// Usage
const ticket = await authenticateViaSbis('sbis_token_here');
console.log('Ticket ID:', ticket.id);
console.log('User:', ticket.user_uri);
```

## Response

### Success (HTTP 200)

```json
{
  "type": "ticket",
  "id": "abc123-ticket-id-xyz",
  "user_uri": "d:person_12345",
  "user_login": "+79001234567",
  "result": 200,
  "end_time": 1737100800,
  "auth_origin": "VEDA",
  "auth_method": "sbis",
  "domain": "veda",
  "initiator": "authenticate"
}
```

Note: Phone numbers are automatically normalized (e.g. `79001234567` becomes `+79001234567`).

### Error

| HTTP Status | Description |
|-------------|-------------|
| 472 | Authentication failed (invalid SBIS token, user not found, or link field not found in SBIS response) |
| 400 | Bad request |

No response body on error.

## Complete Flow

```
1. User clicks "Login via SBIS"
2. Redirect to SBIS OAuth page
3. User authorizes in SBIS
4. SBIS redirects back with access_token
5. Client sends access_token to POST /auth/sbis/authenticate
6. Server verifies token with SBIS API (GET /service/user_info with X-SBISAccessToken header)
7. Server extracts link value from configured field (e.g. phone number)
8. Server finds user in Veda by link value
9. Server returns veda ticket
10. Client uses ticket.id for subsequent API requests
```

## Using the Ticket

```javascript
// After authentication, use ticket.id for API requests
const ticketId = ticket.id;

// Example: get individual
const response = await fetch(`/get_individual?ticket=${ticketId}&uri=d:some_uri`);
const data = await response.json();
```
