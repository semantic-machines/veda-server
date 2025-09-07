#!/bin/bash

# Скрипт генерации RSA ключей для SMS аутентификации

set -e

KEY_DIR="/etc/veda"
KEY_FILE="$KEY_DIR/rsa_private_key.pem"
USER="veda-service"
GROUP="veda-service"

echo "🔑 Генерация RSA ключей для SMS аутентификации..."

# Создание директории
if [ ! -d "$KEY_DIR" ]; then
    echo "📁 Создание директории $KEY_DIR"
    sudo mkdir -p "$KEY_DIR"
fi

# Генерация RSA ключа с парольной защитой
echo "🔐 Генерация RSA-2048 ключа..."
sudo openssl genpkey \
    -algorithm RSA \
    -out "$KEY_FILE" \
    -pkcs8 \
    -aes256 \
    -pass stdin <<< "veda-sms-key-$(date +%s)"

# Установка безопасных прав доступа
echo "🛡️ Установка прав доступа..."
sudo chmod 600 "$KEY_FILE"

# Создание пользователя/группы если не существуют
if ! id "$USER" &>/dev/null; then
    echo "👤 Создание пользователя $USER"
    sudo useradd -r -s /bin/false "$USER"
fi

sudo chown "$USER:$GROUP" "$KEY_FILE" 2>/dev/null || sudo chown "root:root" "$KEY_FILE"

echo "✅ RSA ключ создан: $KEY_FILE"
echo ""
echo "🔧 Обновите конфигурацию:"
echo "echo 'rsa_key_path = $KEY_FILE' >> config/veda-web-api.ini"
echo ""
echo "⚠️  Важно:"
echo "   - Сохраните пароль ключа в безопасном месте"
echo "   - Сделайте резервную копию ключа"
echo "   - Скопируйте ключ на все ноды кластера"
