# RSA Key Management for SMS Authentication

Guide for RSA-2048 key setup and management.

## Key Generation

### Production
```bash
# Create key directory
sudo mkdir -p /etc/veda
sudo chmod 755 /etc/veda

# Generate RSA-2048 private key with password protection
sudo openssl genpkey \
    -algorithm RSA \
    -out /etc/veda/rsa_private_key.pem \
    -pkcs8 \
    -aes256

# Set permissions
sudo chmod 600 /etc/veda/rsa_private_key.pem
sudo chown veda-service:veda-service /etc/veda/rsa_private_key.pem

# Configure
echo "rsa_key_path = /etc/veda/rsa_private_key.pem" >> sms_auth.ini
```

### Development
```bash
# Generate unprotected key for development
openssl genpkey \
    -algorithm RSA \
    -out ./dev_rsa_key.pem \
    -pkcs8

# Configure
echo "rsa_key_path = ./dev_rsa_key.pem" >> sms_auth.ini
```

## Troubleshooting

Permission denied:
```bash
sudo chmod 600 /etc/veda/rsa_private_key.pem
sudo chown veda-service:veda-service /etc/veda/rsa_private_key.pem
```

Key not found:
```bash
ls -la /etc/veda/rsa_private_key.pem
grep rsa_key_path sms_auth.ini
```

Invalid key format:
```bash
openssl rsa -in /etc/veda/rsa_private_key.pem -text -noout
```
