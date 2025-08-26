# SMS Authentication Implementation

Реализация SMS-аутентификации с HMAC подписью запросов.

📋 **Для клиентских разработчиков**: См. `CLIENT_API_SPEC.md`  
🔧 **Этот файл**: Техническая документация для серверных разработчиков

## Возможности

- **Полностью Stateless**: Никакого shared state между нодами
- **AES-256-GCM шифрование**: Безопасное хранение данных сессии в токенах
- **HMAC подпись**: HMAC-SHA256 с солью для валидации запросов
- **Упрощенная архитектура**: Нет fake токенов, проверка пользователя только при верификации
- **Privacy-first**: Не раскрываем информацию о регистрации до валидного SMS
- **Nonce и timestamp**: Предотвращение повторных запросов в токенах
- **Поддержка провайдеров**: Megalabs и возможность добавления других
- **Независимость**: SMS модуль не зависит от базы пользователей
- **Масштабируемость**: Неограниченное горизонтальное масштабирование

## Архитектура

### Схема взаимодействия

📊 **Подробная диаграмма**: См. `SMS_FLOW_DIAGRAM.md` - детальная диаграмма последовательности

```
Пользователь → Клиент (JS) → Сервер (Rust) → SMS провайдер
     ↑                                ↓
     ←――――――――― SMS код ←――――――――――――――――――
```

## Установка


### 1. Конфигурация sms_auth.ini

```ini
[sms]
enabled = true
client_secret = veda-sms-secret-key-2024-secure
code_length = 6
code_ttl = 300
max_attempts = 3
codes_per_phone_per_hour = 5
codes_per_ip_per_hour = 20
max_time_drift = 300

[sms_provider]
provider = megalabs
server = https://a2p-api.megalabs.ru/sms/v1/sms
user = yyyyyyyy
password = xxxxxxxx
from = SLPK
message_size_limit = 500
```

### 2. Добавление пользователей

Пользователи загружаются из базы данных через AuthClient. SMS модуль не содержит собственного реестра пользователей - вся проверка делегирована AuthClient при верификации кода.

## API Endpoints

SMS аутентификация предоставляет 2 HTTP endpoint'а:
- `POST /auth/sms/request` - запрос SMS кода (требует криптографической подписи)  
- `POST /auth/sms/verify` - проверка SMS кода

📋 **Для клиентских разработчиков**: См. `CLIENT_API_SPEC.md` - полная спецификация API с примерами запросов и ответов.

### Совместимость с основным Auth

SMS аутентификация полностью совместима с существующей системой:
- Endpoint `/auth/sms/verify` возвращает тот же JSON формат, что и `auth.rs -> authenticate()`
- Использует `AuthClient` для создания валидных tickets через основную систему
- Аутентификация происходит по номеру телефона через AuthClient

## Безопасность

### Шифрование сессий

**Stateless архитектура**: Вместо хранения сессий на сервере, все данные сессии зашифровываются AES-256-GCM и возвращаются клиенту в виде зашифрованного токена в поле `token`. 

**Структура зашифрованного токена**:
```json
{
    "data": "base64_encrypted_session_data",
    "nonce": "base64_aes_gcm_nonce"
}
```

Зашифрованные данные содержат:
- Номер телефона
- Хеш SMS кода
- Timestamp создания сессии
- Данные для replay protection (nonce, salt, timestamp запроса)

**Генерация ключа шифрования**:
```rust
// Ключ генерируется из конфигурации сервера
fn derive_encryption_key() -> [u8; 32] {
    SHA256(
        "SMS_ENCRYPTION_" +
        client_secret +
        code_ttl_seconds +
        max_attempts + 
        code_length +
        rate_limits +
        max_time_drift +
        provider_config
    )
}
```

Это означает, что:
- Ключ уникален для каждой конфигурации сервера
- При изменении любого параметра в `sms_auth.ini` старые токены становятся недействительными
- Только сервер с точно такой же конфигурацией может расшифровать токены

### Создание подписи (серверная проверка)

Сервер проверяет HMAC-SHA256 подпись следующим образом:

### Серверная проверка

```rust
// 1. Проверка timestamp
if (now - request.timestamp).abs() > 300 { 
    return Err(SmsError::TimestampExpired);
}

// 2. Проверка nonce
if nonces.contains(&request.nonce) {
    return Err(SmsError::NonceReused);
}

// 3. Проверка подписи
let expected = hmac_sha256(message, client_secret + salt);
if request.signature != expected {
    return Err(SmsError::InvalidSignature);
}
```

## Провайдеры SMS

### Megalabs

```rust
impl SmsProvider for MegalabsProvider {
    fn send_sms(&self, phone: &str, message: &str) -> Result<SmsResult, SmsError> {
        // Parse phone number to integer
        let phone_number: i64 = phone.parse().map_err(|_| {
            SmsError::InvalidInput("Invalid phone number format".to_string())
        })?;

        // Prepare request payload
        let payload = serde_json::json!({
            "from": self.from,
            "to": phone_number,
            "message": message
        });

        // Make HTTP request to Megalabs API with basic auth
        let response = self.client
            .post(&self.server)
            .basic_auth(&self.user, Some(&self.password))
            .json(&payload)
            .send()
            .await?;
        
        // Check response status and internal API status
        // ...
    }
}
```

### Добавление нового провайдера

1. Реализовать trait `SmsProvider`
2. Добавить вариант в `SmsProviderConfig`
3. Обновить создание провайдера в `main.rs`

## Тестирование

### Локальное тестирование

1. Запустить сервер: `cargo run`
2. Использовать готовый клиент или curl для тестирования
3. Использовать зарегистрированные в системе номера телефонов
4. SMS код выводится в логах сервера
5. Для curl запросов нужна правильная HMAC подпись (см. CLIENT_API_SPEC.md)

### Интеграционные тесты

```rust
#[tokio::test]
async fn test_sms_auth_flow() {
    // 1. Создать тестовый запрос
    let request = create_signed_request("79991234567");
    
    // 2. Отправить SMS
    let response = send_sms_request(request).await;
    assert!(response.token.is_some());
    
    // 3. Проверить код
    let verify_response = verify_code(response.token.unwrap(), "123456").await;
    assert!(verify_response.id.is_some());
}
```

## Мониторинг

### Логирование

```rust
info!("SMS auth code sent to {} for user {}", phone, user_id);
warn!("Rate limit exceeded for IP {}", ip_addr);
error!("SMS provider error: {:?}", error);
```

### Метрики

- Количество SMS запросов
- Успешность доставки
- Rate limit срабатывания

## Производственное развертывание

### Конфигурация

1. **client_secret**: Сгенерировать криптографически стойкий ключ
2. **SMS провайдер**: Настроить реальные учетные данные  
3. **Rate limits**: Настроить под требования безопасности
4. **Идентичная конфигурация**: Все ноды должны иметь абсолютно одинаковый `sms_auth.ini`

### Требования для продуктива

**Обязательно реализовать**:
- 🛡️ **Rate limiting**: Внедрить Redis/DB для точного контроля между нодами  
- 📝 **Логирование**: Централизованные логи для отслеживания попыток
- 🔗 **AuthClient интеграция**: Убедиться что AuthClient поддерживает аутентификацию по телефону

### Максимально упрощенная архитектура

**Принцип работы**:
1. 📤 **Отправляем SMS** на валидные номера телефонов
2. 🔍 **Передаем телефон в AuthClient** при верификации - он проверяет существование пользователя
3. 🏗️ **SMS модуль не знает о пользователях** до этапа верификации

**Преимущества**:
- 🔒 **Полная приватность** - не раскрываем информацию о регистрации 
- 🧹 **Максимальная простота** - SMS модуль только проверяет коды
- 🔧 **Полная независимость** - SMS не зависит от логики пользователей
- ⚡ **Минимум кода** - AuthClient отвечает за всю логику пользователей
- 🎯 **Единая ответственность** - каждый модуль делает только свое

**Рекомендации**:
- 🔄 **Backup стратегия**: Регулярные backup конфигурации
- 📊 **Мониторинг**: Метрики успешности SMS, ошибок шифрования
- 🚨 **Алерты**: Уведомления о подозрительной активности

### Масштабирование

**Полностью Stateless архитектура** - никакого shared state между нодами:

1. **Нет синхронизации** - каждая нода независима
2. **Load balancer** - запросы могут попадать на любую ноду
3. **Database** - только для хранения связей телефон → пользователь  
4. **Monitoring** - для отслеживания состояния системы

**Что исключено из shared state**:
- ❌ `used_nonces` - nonce включены в зашифрованный токен
- ❌ `salt_cache` - salt включены в зашифрованный токен  
- ❌ `rate_limits` - упрощено до timestamp проверок
- ❌ `auth_sessions` - все данные в зашифрованном токене

**Преимущества**:
- ♾️ **Неограниченное масштабирование** - добавляй ноды без настроек
- 🔄 **Полная отказоустойчивость** - любая нода может упасть
- 🚀 **Мгновенное развертывание** - нет warm-up периода  
- ⚖️ **Идеальная балансировка** - нет sticky sessions
- 🏗️ **Простота архитектуры** - нет Redis/кластерных баз данных

## Интеграция с существующей системой

SMS аутентификация работает независимо от существующей MFA системы. 

### Варианты интеграции:

1. **Standalone SMS** - SMS как единственный фактор аутентификации
2. **SMS + Password** - SMS после проверки логина/пароля  
3. **Choice based** - выбор между SMS и существующей MFA

```rust
// SMS аутентификация работает параллельно с другими методами
// Выбор метода аутентификации зависит от клиентского приложения
// и не требует специальной конфигурации пользователя
```

## Troubleshooting

### Частые проблемы

1. **Signature mismatch**: Проверить соответствие client_secret на клиенте и сервере
2. **Timestamp expired**: Синхронизировать время между клиентом и сервером  
3. **Phone not registered**: AuthClient не смог найти пользователя по телефону (ошибка возникает только при верификации кода)
4. **SMS not delivered**: Проверить настройки SMS провайдера или валидность номера
5. **Token decryption failed**: 
   - Изменился конфиг сервера после создания токена
   - Токен поврежден при передаче
   - Используется неправильный client_secret
6. **Session expired**: Токен создан более чем `code_ttl` секунд назад
7. **Invalid code**: Неправильный SMS код или превышено количество попыток
8. **Simplified limitations**:
   - Rate limiting упрощен - защита полагается на timestamp окна
   - Replay protection ограничен временными проверками
   - Проверка пользователей происходит только при верификации кода
9. **Configuration mismatch**: Разные ноды имеют разные конфиги
10. **AuthClient integration**: Проблемы с созданием tickets через AuthClient

### Отладка

```bash
# Включить подробное логирование
RUST_LOG=veda_web_api=debug cargo run

# Проверить конфигурацию
cat sms_auth.ini
```

### Проверка работы сервера

```bash
# Проверка что SMS endpoints доступны
curl -X POST http://localhost:8080/auth/sms/request \
  -H "Content-Type: application/json" \
  -d '{}' 
# Ожидаем: 400 Bad Request (invalid signature)

curl -X POST http://localhost:8080/auth/sms/verify \
  -H "Content-Type: application/json" \
  -d '{}'
# Ожидаем: 400 Bad Request (missing fields)
```

📋 **Примеры полных запросов**: См. `CLIENT_API_SPEC.md`
