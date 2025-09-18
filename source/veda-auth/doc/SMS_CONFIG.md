# SMS Configuration

## Overview

SMS authentication can be configured using an INI file. By default, the system looks for `sms.ini` in the current directory.

## Configuration File Location

The SMS configuration file path can be specified in the database configuration:
- Parameter: `cfg:sms_config_file` 
- Default value: `"sms.ini"`

## INI File Format

Create a file named `sms.ini` (or the path specified in configuration) with the following content:

```ini
[sms_provider]
# SMS provider type (replace with your provider)
provider = your_provider_name

# Provider API settings
server = https://your-sms-provider.com/api/v1/sms
user = your_api_username
password = your_api_password
from = YOUR_SENDER_NAME
message_size_limit = 500
```

## Configuration Parameters

### Required Parameters
- `provider` - SMS provider type (replace with your actual provider)
- `server` - SMS provider API server URL
- `user` - Username for SMS provider API
- `password` - Password for SMS provider API
- `from` - Sender name/number

### Optional Parameters
- `message_size_limit` - Maximum SMS message length (default: 500)

## Database Configuration

Additional SMS settings can be configured in the database (`cfg:standart_node`):

```
cfg:sms_rate_limit_period: "60s"     # Rate limit between SMS requests
cfg:sms_daily_limit: 5               # Maximum SMS per day per user
cfg:sms_code_min: 100000             # Minimum SMS code value
cfg:sms_code_max: 999999             # Maximum SMS code value
```

## How It Works

1. When a user requests SMS authentication with phone number and empty password
2. The system generates a random code between `sms_code_min` and `sms_code_max`
3. The code is saved as `v-s:secret` in the user's credential
4. A `v-s:Sms` individual is created with the message and tracking information
5. SMS is sent using the configured provider
6. User enters the received code to authenticate

## SMS Individual Properties

When an SMS is created for authentication, the following properties are set:

- `rdf:type`: "v-s:Sms"
- `v-s:recipientPhone`: Normalized phone number (Russian format with +7 prefix)
- `v-s:messageBody`: SMS message with authentication code
- `v-s:created`: Creation timestamp
- `v-s:source`: Source module ("veda-auth" for authentication requests)
- `v-s:isSuccess`: Delivery status (initially false)
- `v-s:infoOfExecuting`: Execution information (initially empty)

## Security Notes

- SMS codes expire based on `cfg:secret_lifetime` setting
- Rate limiting prevents abuse
- Failed attempts are tracked and may result in temporary locks
- Phone numbers are normalized to Russian format (+7)

## Troubleshooting

If SMS is not working:
1. Check if the INI file exists and is readable
2. Verify all required parameters are set
3. Check application logs for SMS provider errors
4. Ensure the SMS provider API credentials are correct
