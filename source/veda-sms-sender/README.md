# veda-sms-sender

Модуль для отправки SMS сообщений в системе Veda.

## Описание

Этот модуль обрабатывает индивиды типа `v-s:Sms` из очереди и отправляет соответствующие SMS сообщения через настроенного провайдера.

## Принцип работы

1. Модуль слушает очередь `individuals-flow`
2. Когда в очереди появляется индивид типа `v-s:Sms`, модуль его обрабатывает  
3. **Проверка авторизации**: Модуль проверяет, что запрос создан пользователем с системным тикетом (`sys_ticket`)
4. Из индивида извлекаются номер телефона (`v-s:recipientPhone`) и сообщение (`v-s:messageBody`)
5. SMS отправляется через настроенного провайдера (в данный момент поддерживается Megalabs)
6. Статус отправки обновляется в индивиде с защитой от зацикливания через `event_id`

## Безопасность и защита

### Проверка системного тикета
Модуль обрабатывает только запросы от пользователей с системным тикетом (`sys_ticket`). Если пользователь не имеет соответствующих прав, запрос отклоняется с сообщением в логе.

## Структура индивида v-s:Sms

По аналогии с `v-s:Email`, SMS наследуется от `v-s:Deliverable`:

```json
{
  "@": "d:sms_1234567890",
  "rdf:type": [{"type": "Uri", "data": "v-s:Sms"}],
  "v-s:recipientPhone": [{"type": "String", "data": "79001234567"}],
  "v-s:messageBody": [{"type": "String", "data": "Ваш код для входа: 1234"}],
  "v-s:created": [{"type": "Datetime", "data": 1234567890}],
  "v-s:isSuccess": [{"type": "Boolean", "data": false}],
  "v-s:infoOfExecuting": [{"type": "String", "data": ""}]
}
```

## Конфигурация

Модуль использует файл `sms.ini` для настройки SMS провайдера:

```ini
[sms_provider]
provider=your_sms_provider
server=https://your-provider.com/api/v1/sms
user=your_api_username
password=your_api_password
from=YOUR_SENDER_NAME
message_size_limit=500
```

## Запуск

```bash
./veda-sms-sender
```

## Логи

Модуль записывает подробные логи:
- Успешная отправка SMS
- Ошибки при отправке  
- Проблемы с конфигурацией
- Обработанные индивиды
- **Отклонённые запросы** от пользователей без системного тикета
- **Обновления статуса** с указанием `event_id` для отслеживания защиты от зацикливания
- **Ошибки получения системного тикета** при запуске модуля

## Требования к системе

- Модуль требует права на чтение и запись в хранилище (`StorageMode::ReadWrite`) для получения системного тикета
- Пользователи должны иметь системный тикет для создания запросов на отправку SMS

## Примеры логов

### Успешная отправка
```
INFO Processing SMS request for phone: 79001234567
INFO SMS sent successfully: {"result":{"status":{"code":0}}}
INFO Updated SMS status for d:sms_1234567890: success=true, info=SMS sent successfully, event_id=12345
```

### Отклонённый запрос
```
INFO SMS request rejected: user cfg:Guest does not have sys_ticket, required: cfg:VedaSystem
```

### Защита от зацикливания
```
INFO Updated SMS status for d:sms_1234567890: success=true, info=SMS sent successfully, event_id=12345
```

## Интеграция

Для создания запроса на отправку SMS используйте метод `MobileAuth::send_sms_code_with_backend()` в модуле veda-auth. Убедитесь, что пользователь имеет системный тикет для успешной отправки.
