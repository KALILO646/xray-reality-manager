# Xray Reality Manager

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Xray](https://img.shields.io/badge/Xray-Reality-orange.svg)](https://github.com/XTLS/Xray-core)

Автоматизированная система управления VPN серверами с поддержкой протокола Xray Reality. Включает автоматическое обнаружение конфигурации, управление пользователями, генерацию VLESS ссылок и создание QR-кодов.

## Основные возможности

- **Автоматическое обнаружение конфигурации** - парсинг настроек Xray с сервера
- **Определение геолокации** - автоматическое определение страны сервера
- **Управление пользователями** - создание, удаление, получение информации
- **Генерация VLESS ссылок** - создание ссылок для Reality протокола
- **QR-коды** - автоматическое создание QR-кодов для быстрого подключения
- **Health check** - мониторинг состояния всех нод

## Требования

Для использования у Вас должен быть настроен [Xray Reality VPN server](https://github.com/XTLS/Xray-core). Данный модуль не настраивает сервер, он предназначен для управления учетными записями.

### Установка зависимостей

```bash
pip install paramiko requests qrcode python-dotenv
```
# Установка зависимостей
```bash
pip install -r requirements.txt
```

## Настройка

Скопируйте файл конфигурации и настройте `.env`:

```bash
cp env.example .env
```

Настройте `.env` файл:

```env
# ===========================================
# ОСНОВНЫЕ НАСТРОЙКИ
# ===========================================

# Название базы данных SQLite
DATABASE_NAME=vpn_users.db

# Директория для файлов пользователей
USER_FILES_DIR=user_files

# Директория для QR-кодов
QR_CODES_DIR=qr_codes

# ===========================================
# НАСТРОЙКИ ЛОГИРОВАНИЯ
# ===========================================

# Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL=INFO

# Формат логов (можно настроить под свои нужды)
LOG_FORMAT=%(asctime)s - %(name)s - %(levelname)s - %(message)s

# Файл для сохранения логов
LOG_FILE=vpn_module.log


```

### Инициализация модуля

```python
from api_server import initialize_vpn_module

# Инициализация базы данных и модуля
initialize_vpn_module()
```

### Добавление VPN сервера

```python
from api_server import add_node_with_auto_discovery

# Добавление сервера с автоматическим обнаружением конфигурации
add_node_with_auto_discovery(
    node_id="server1",
    server_ip="91.108.249.114",
    server_domain="vpn.example.com",
    username="root",
    password="your_password"
)
```

**Что происходит автоматически:**
- Поиск конфигурации Xray на сервере
- Извлечение настроек Reality протокола
- Определение страны сервера по IP

### Создание пользователя

```python
from api_server import add_user_fast, VpnUser

# Создание пользователя
user = VpnUser(uid_tg="123456789", username="john_doe")
result = add_user_fast(user)

print(f"UUID: {result['uuid']}")
print(f"VLESS: {result['vless_link']}")
print(f"QR-код: {result['qr_file']}")
```

## API Reference

### Управление нодами

#### `add_node_with_auto_discovery(node_id, server_ip, server_domain, username, password)`
Добавляет новую ноду с автоматическим обнаружением конфигурации.

**Параметры:**
- `node_id` (str) - уникальный идентификатор ноды
- `server_ip` (str) - IP адрес сервера
- `server_domain` (str) - домен сервера
- `username` (str) - SSH пользователь
- `password` (str) - SSH пароль

**Возвращает:** `VpnNode` объект

#### `get_all_nodes()`
Получает список всех нод.

**Возвращает:** список `VpnNode` объектов

#### `get_node_by_id(node_id)`
Получает ноду по ID.

**Параметры:**
- `node_id` (str) - идентификатор ноды

**Возвращает:** `VpnNode` объект или `None`

#### `health_check()`
Проверяет состояние всех нод.

**Возвращает:** словарь со статусом системы

### Управление пользователями

#### `add_user_fast(user_data, node_id=None, country_code=None)`
Быстрое создание пользователя (рекомендуется).

**Параметры:**
- `user_data` (VpnUser) - данные пользователя
- `node_id` (str, optional) - конкретная нода
- `country_code` (str, optional) - выбор по стране

**Возвращает:** словарь с результатом

#### `add_user(user_data, node_id=None, country_code=None)`
Полное создание пользователя с дополнительными проверками.

#### `get_user_info(uuid)`
Получает информацию о пользователе.

**Параметры:**
- `uuid` (str) - UUID пользователя

**Возвращает:** словарь с информацией

#### `delete_user(uuid)`
Удаляет пользователя.

**Параметры:**
- `uuid` (str) - UUID пользователя

**Возвращает:** `True` при успехе

### Геолокация

#### `get_available_countries()`
Получает список доступных стран.

**Возвращает:** список кодов стран

#### `get_nodes_by_country(country_code)`
Получает ноды в определенной стране.

**Параметры:**
- `country_code` (str) - код страны

**Возвращает:** список `VpnNode` объектов

## Структуры данных

### VpnNode
```python
class VpnNode:
    node_id: str              # Уникальный ID ноды
    server_ip: str           # IP адрес сервера
    server_domain: str       # Домен сервера
    server_username: str     # SSH пользователь
    xray_config_path: str    # Путь к конфигурации Xray
    xray_port: str          # Порт Xray
    reality_public_key: str  # Публичный ключ Reality
    reality_short_id: str    # Short ID Reality
    reality_sni: str        # SNI для Reality
    country: str            # Страна сервера
    country_code: str       # Код страны
    city: str              # Город
    region: str            # Регион
    is_active: bool        # Активна ли нода
```

### VpnUser
```python
class VpnUser:
    uid_tg: str            # Telegram User ID
    username: str          # Telegram username
    node_id: str          # ID ноды (опционально)
```

## Примеры использования

### Создание пользователя на конкретной ноде
```python
user = VpnUser(uid_tg="123456789", username="john_doe")
result = add_user_fast(user, node_id="server1")
```

### Создание пользователя в определенной стране
```python
user = VpnUser(uid_tg="123456789", username="john_doe")
result = add_user_fast(user, country_code="US")
```

### Получение информации о пользователе
```python
info = get_user_info("550e8400-e29b-41d4-a716-446655440000")
print(f"User: {info['username']}")
print(f"Node: {info['node_info']['node_id']}")
print(f"Country: {info['node_info']['country']}")
```

### Проверка состояния системы
```python
status = health_check()
print(f"Status: {status['status']}")
print(f"Nodes: {len(status['node_statuses'])}")
```

## Вклад в проект

Мы приветствуем вклад в развитие проекта! Пожалуйста, ознакомьтесь с [руководством по вкладу](CONTRIBUTING.md) перед отправкой pull request.

## Поддержка

Если у вас есть вопросы или проблемы:

- [Создайте issue](https://github.com/your-username/xray-reality-manager/issues)
- [Обсуждения](https://github.com/your-username/xray-reality-manager/discussions)

## Лицензия

Этот проект лицензирован под [MIT License](LICENSE) - см. файл LICENSE для деталей.

## Связанные проекты

- [Xray-core](https://github.com/XTLS/Xray-core) - Основной проект Xray
- [v2ray-agent](https://github.com/mack-a/v2ray-agent) - Скрипт установки Xray
