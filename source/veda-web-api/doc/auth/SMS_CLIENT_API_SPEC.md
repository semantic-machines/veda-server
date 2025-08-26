# SMS Authentication API Specification

Спецификация API для разработчика клиентской части.

🔧 **Для серверных разработчиков**: См. `SMS_AUTH_README.md`  
📋 **Этот файл**: Спецификация API для клиентских разработчиков

## Overview

SMS аутентификация работает в 2 этапа:
1. **Запрос SMS кода** - клиент отправляет подписанный запрос с номером телефона
2. **Проверка кода** - клиент отправляет полученный SMS код для получения токена

📊 **Диаграмма потока**: См. `SMS_FLOW_DIAGRAM.md` - визуализация взаимодействия

## Request Format

### Request Signing
Все запросы к `/auth/sms/request` должны быть подписаны HMAC-SHA256:

```
message = "action=sms_request|nonce={uuid}|phone={phone}|salt={hex}|timestamp={unix_timestamp}"
signature = HMAC-SHA256(message, client_secret + salt)
```

### Required Headers
```
Content-Type: application/json
X-Client-Type: web-app
```

## API Endpoints

SMS аутентификация использует только 2 endpoint'а:

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

**Security Note:** `token` содержит зашифрованную информацию о сессии в виде JSON токена с полями `data` (зашифрованные данные) и `nonce` (для AES-GCM). Выше показан пример формата - реальный токен будет содержать актуальные зашифрованные данные. SMS отправляется на все валидные номера телефонов, проверка существования пользователя происходит только при верификации кода через AuthClient.

**Response (Error):**
```json
{
    "token": "eyJkYXRhIjoiZmFrZWVuY3J5cHRlZGRhdGEiLCJub25jZSI6ImZha2Vub25jZSJ9"
}
```

**Security Note:** Для предотвращения атак перебора пользователей, токен всегда возвращается в ответе, даже при ошибках. В случае ошибок возвращается зашифрованный фейковый токен с отдельным ключом шифрования, что делает невозможным различение валидных и невалидных запросов.

**HTTP Status Codes:**
- `200` - Request processed (SMS sent if phone registered)
- `400` - Invalid request/signature
- `429` - Rate limited

**Security Note:** SMS отправляется на валидные номера телефонов. Проверка существования пользователя в системе происходит только при верификации кода для предотвращения атак перебора номеров телефонов.

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

**Security Note:** При успешной верификации возвращается валидный тикет аутентификации. Если пользователь с указанным номером телефона не найден в системе, возвращается ошибка аутентификации.

**HTTP Status Codes:**
- `200` - Authentication successful
- `401` - Authentication failed (invalid code/session)
- `400` - Bad request

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
- Invalid signature → Show generic error, don't retry
- Rate limited → Show retry timer with countdown
- Network errors → Allow retry with exponential backoff

**Security Note:** Для защиты приватности пользователей рекомендуется показывать общее сообщение типа "Если номер зарегистрирован, код отправлен". После получения успешного ответа с `token` переходите к экрану ввода кода.

## Configuration

The client needs access to:
- `client_secret` - for HMAC signing (same as in sms_auth.ini)
- `api_base_url` - server base URL

## Rate Limits

Default limits (configurable on server):
- 5 SMS per phone per hour
- 20 SMS per IP per hour

## Testing

Для тестирования используйте номера телефонов, зарегистрированные в системе через AuthClient.

SMS codes visible in server logs when testing.

## Integration with Existing Auth

SMS auth полностью совместим с основной системой аутентификации:
- Возвращает тот же JSON формат, что и `auth.rs -> authenticate()`
- Использует `AuthClient` для создания валидных tickets
- Аутентификация происходит по номеру телефона через AuthClient
- Можно использовать как **standalone** или в комбинации с другими методами
