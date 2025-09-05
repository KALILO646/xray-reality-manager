import json
import uuid
import secrets
import requests
import tempfile
import os
import paramiko
import sqlite3
import hashlib
import logging
import re
import base64
from datetime import datetime
from dotenv import load_dotenv
import time
import ipaddress
from functools import lru_cache
from contextlib import contextmanager

load_dotenv()

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
log_format = os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_file = os.getenv("LOG_FILE", "vpn_module.log")

log_level_map = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}

logging.basicConfig(
    level=log_level_map.get(log_level, logging.INFO),
    format=log_format,
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "30"))
SSH_MAX_RETRIES = int(os.getenv("SSH_MAX_RETRIES", "3"))
OPERATION_DELAY = int(os.getenv("OPERATION_DELAY", "1"))
XRAY_RESTART_DELAY = int(os.getenv("XRAY_RESTART_DELAY", "2"))

@contextmanager
def ssh_connection(server_ip, username, password):
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(
            hostname=server_ip,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT
        )
        yield ssh
    except Exception as e:
        logger.error(f"SSH connection error to {server_ip}: {e}")
        raise
    finally:
        if ssh:
            ssh.close()
        
@contextmanager
def db_connection():
    conn = None
    try:
        database_name = os.getenv("DATABASE_NAME")
        conn = sqlite3.connect(database_name)
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def encrypt_password(password):
    return base64.b64encode(password.encode()).decode()

def decrypt_password(encrypted_password):
    try:
        return base64.b64decode(encrypted_password.encode()).decode()
    except Exception:
        return encrypted_password

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_node_id(node_id):
    if not node_id or not isinstance(node_id, str):
        raise ValueError("node_id должен быть непустой строкой")
    if not re.match(r'^[a-zA-Z0-9._-]+$', node_id):
        raise ValueError("node_id может содержать только буквы, цифры, точки, подчеркивания и дефисы")
    if len(node_id) > 50:
        raise ValueError("node_id слишком длинный (максимум 50 символов)")
    return True

def validate_uuid(uuid_str):
    if not uuid_str or not isinstance(uuid_str, str):
        raise ValueError("UUID должен быть непустой строкой")
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        raise ValueError("Неверный формат UUID")

def validate_env():
    required_vars = [
        "DATABASE_NAME", "QR_CODES_DIR", "USER_FILES_DIR"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    if not os.getenv("QR_API_URL"):
        os.environ["QR_API_URL"] = "https://api.qrserver.com/v1/create-qr-code/"
    
    if not os.getenv("QR_SIZE"):
        os.environ["QR_SIZE"] = "300x300"
    
    if not os.getenv("SSH_TIMEOUT"):
        os.environ["SSH_TIMEOUT"] = "30"
    
    if not os.getenv("SSH_MAX_RETRIES"):
        os.environ["SSH_MAX_RETRIES"] = "3"
    
    if not os.getenv("OPERATION_DELAY"):
        os.environ["OPERATION_DELAY"] = "1"
    
    if not os.getenv("XRAY_RESTART_DELAY"):
        os.environ["XRAY_RESTART_DELAY"] = "2"


def generate_uuid():
    return str(uuid.uuid4())

def generate_short_id():
    return secrets.token_hex(4)

def generate_path():
    return f"/{secrets.token_hex(8)}"

@lru_cache(maxsize=128)
def get_country_by_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country = data.get('country', 'Unknown')
                country_code = data.get('countryCode', 'XX')
                print(f"🌍 Страна для IP {ip_address}: {country} ({country_code})")
                return {
                    'country': country,
                    'country_code': country_code,
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown')
                }
        
        print(f"⚠️ Не удалось определить страну для IP {ip_address}")
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'region': 'Unknown'
        }
        
    except Exception as e:
        print(f"❌ Ошибка определения страны для IP {ip_address}: {e}")
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'region': 'Unknown'
        }

def get_country_by_domain(domain):
    try:
        import socket
        
        ip_address = socket.gethostbyname(domain)
        print(f"🔍 IP адрес домена {domain}: {ip_address}")
        return get_country_by_ip(ip_address)
            
    except Exception as e:
        print(f"❌ Ошибка определения страны для домена {domain}: {e}")
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'region': 'Unknown'
        }

def execute_remote_command(command, server_ip, username, password):
    try:
        with ssh_connection(server_ip, username, password) as ssh:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            if error:
                logger.warning(f"SSH command warning on {server_ip}: {error}")
            
            logger.info(f"SSH command executed on {server_ip}: {command[:50]}...")
            return output
        
    except Exception as e:
        logger.error(f"SSH command failed on {server_ip}: {e}")
        return None

def find_xray_config_path(server_ip, username, password):
    possible_paths = [
        "/etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json",
        "/etc/xray/config.json",
        "/usr/local/etc/xray/config.json",
        "/etc/v2ray/config.json",
        "/usr/local/etc/v2ray/config.json"
    ]
    
    for path in possible_paths:
        result = execute_remote_command(f"test -f {path} && echo 'exists'", server_ip, username, password)
        if result == "exists":
            print(f"✅ Найден конфиг Xray: {path}")
            return path
    
    print("❌ Не найден конфиг Xray на сервере")
    return None

def parse_xray_config_from_server(server_ip, username, password):
    config_path = find_xray_config_path(server_ip, username, password)
    if not config_path:
        return None
    
    config_content = execute_remote_command(f"cat {config_path}", server_ip, username, password)
    if not config_content:
        return None
    
    try:
        config = json.loads(config_content)
        return config, config_path
    except json.JSONDecodeError:
        print("❌ Ошибка парсинга JSON конфигурации Xray")
        return None

def extract_reality_config_from_xray(config):
    try:
        for inbound in config.get('inbounds', []):
            if (inbound.get('protocol') == 'vless' and 
                inbound.get('streamSettings', {}).get('security') == 'reality'):
                
                stream_settings = inbound.get('streamSettings', {})
                reality_settings = stream_settings.get('realitySettings', {})
                
                port = inbound.get('port')
                public_key = reality_settings.get('publicKey')
                
                short_ids = reality_settings.get('shortIds', [])
                short_id = None
                if short_ids:
                    for sid in short_ids:
                        if sid and sid.strip():
                            short_id = sid
                break
        
                server_names = reality_settings.get('serverNames', [])
                sni = None
                if server_names:
                    for sname in server_names:
                        if sname and sname.strip():
                            sni = sname
                            break
                
                if all([port, public_key, short_id, sni]):
                    return {
                        'port': str(port),
                        'public_key': public_key,
                        'short_id': short_id,
                        'sni': sni
                    }
                else:
                    print(f"❌ Неполная Reality конфигурация:")
                    print(f"   Порт: {port}")
                    print(f"   Public Key: {public_key}")
                    print(f"   Short ID: {short_id}")
                    print(f"   SNI: {sni}")
                    print(f"   Short IDs массив: {short_ids}")
                    print(f"   Server Names массив: {server_names}")
        
        print("❌ Не найден Reality inbound в конфигурации")
        return None
    except Exception as e:
        print(f"❌ Ошибка извлечения Reality конфигурации: {e}")
        return None

def auto_discover_server_config(server_ip, server_domain, username, password):
    print(f"🔍 Автоматическое обнаружение конфигурации на сервере {server_domain}...")
    
    config_data = parse_xray_config_from_server(server_ip, username, password)
    if not config_data:
        return None
    
    config, config_path = config_data
    reality_config = extract_reality_config_from_xray(config)
    
    if not reality_config:
        return None
    
    print(f"✅ Конфигурация обнаружена:")
    print(f"   Порт: {reality_config['port']}")
    print(f"   SNI: {reality_config['sni']}")
    print(f"   Public Key: {reality_config['public_key'][:20]}...")
    print(f"   Short ID: {reality_config['short_id']}")
    print(f"   Config Path: {config_path}")
    
    return {
        'xray_config_path': config_path,
        'xray_port': reality_config['port'],
        'reality_public_key': reality_config['public_key'],
        'reality_short_id': reality_config['short_id'],
        'reality_sni': reality_config['sni']
    }




def generate_vless_link_for_node(uuid_str, short_id, path, node):
    try:
        port = int(node.xray_port)
    except ValueError:
        raise ValueError(f"XRAY_PORT должен быть числом, получено: {node.xray_port}")
    
    print(f"🔧 Генерация VLESS ссылки для UUID: {uuid_str[:8]} на ноде {node.node_id}...")
    print(f"   Сервер: {node.server_domain}:{port}")
    print(f"   SNI: {node.reality_sni}")
    print(f"   Public Key: {node.reality_public_key[:20]}...")
    print(f"   Short ID: {node.reality_short_id}")
    
    vless_link = (
        f"vless://{uuid_str}@{node.server_domain}:{port}"
        f"?encryption=none"
        f"&security=reality"
        f"&pqv="
        f"&type=tcp"
        f"&sni={node.reality_sni}"
        f"&fp=chrome"
        f"&pbk={node.reality_public_key}"
        f"&sid={node.reality_short_id}"
        f"&flow=xtls-rprx-vision"
        f"#HiddenPathVPN-{node.node_id}"
    )
    
    print(f"✅ VLESS ссылка сгенерирована успешно для ноды {node.node_id}")
    return vless_link

def generate_qr_code(vless_link, uuid_str):
    try:
        qr_api_url = os.getenv("QR_API_URL")
        qr_size = os.getenv("QR_SIZE")
        qr_codes_dir = os.getenv("QR_CODES_DIR")
        
        params = {
            'size': qr_size,
            'data': vless_link
        }
        
        response = requests.get(qr_api_url, params=params)
        if response.status_code == 200:
            qr_filename = f"{qr_codes_dir}/qr_{uuid_str[:8]}.png"
            os.makedirs(qr_codes_dir, exist_ok=True)
            with open(qr_filename, 'wb') as f:
                f.write(response.content)
            print(f"✅ QR-код сохранен как {qr_filename}")
            return qr_filename
        else:
            print(f"❌ Ошибка API QR-кода: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Ошибка при генерации QR-кода: {e}")
        return None



class VpnNode:
    def __init__(self, node_id: str, server_ip: str, server_domain: str, 
                 server_username: str, server_password: str, xray_config_path: str,
                 xray_port: str, reality_public_key: str, reality_short_id: str, 
                 reality_sni: str, country: str = None, country_code: str = None,
                 city: str = None, region: str = None, is_active: bool = True):
        validate_node_id(node_id)
        self.node_id = node_id
        self.server_ip = server_ip
        self.server_domain = server_domain
        self.server_username = server_username
        self.server_password = server_password
        self.xray_config_path = xray_config_path
        self.xray_port = xray_port
        self.reality_public_key = reality_public_key
        self.reality_short_id = reality_short_id
        self.reality_sni = reality_sni
        self.country = country or 'Unknown'
        self.country_code = country_code or 'XX'
        self.city = city or 'Unknown'
        self.region = region or 'Unknown'
        self.is_active = is_active

class VpnUser:
    def __init__(self, uid_tg: str, username: str, node_id: str = None):
        self.uid_tg = uid_tg
        self.username = username
        self.node_id = node_id

def init_database():
    try:
        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise ValueError("DATABASE_NAME не установлен")
        
        with db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT UNIQUE NOT NULL,
                    server_ip TEXT NOT NULL,
                    server_domain TEXT NOT NULL,
                    server_username TEXT NOT NULL,
                    server_password_hash TEXT NOT NULL,
                    xray_config_path TEXT NOT NULL,
                    xray_port TEXT NOT NULL,
                    reality_public_key TEXT NOT NULL,
                    reality_short_id TEXT NOT NULL,
                    reality_sni TEXT NOT NULL,
                    country TEXT DEFAULT 'Unknown',
                    country_code TEXT DEFAULT 'XX',
                    city TEXT DEFAULT 'Unknown',
                    region TEXT DEFAULT 'Unknown',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT UNIQUE NOT NULL,
                    short_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    vless_link TEXT NOT NULL,
                    qr_code_path TEXT NOT NULL,
                    uid_tg TEXT,
                    username TEXT,
                    node_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (node_id) REFERENCES nodes (node_id) ON DELETE CASCADE
                )
            ''')
        
            migration_columns = [
                ("country", "TEXT DEFAULT 'Unknown'"),
                ("country_code", "TEXT DEFAULT 'XX'"),
                ("city", "TEXT DEFAULT 'Unknown'"),
                ("region", "TEXT DEFAULT 'Unknown'")
            ]
            
            for column_name, column_def in migration_columns:
                try:
                    cursor.execute(f"ALTER TABLE nodes ADD COLUMN {column_name} {column_def}")
                    logger.info(f"Added column {column_name} to nodes table")
                except sqlite3.OperationalError:
                    pass
        
            try:
                cursor.execute("ALTER TABLE nodes RENAME COLUMN server_password TO server_password_hash")
                logger.info("Migrated server_password to server_password_hash")
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
            logger.info("Database initialized successfully")
        print("✅ База данных инициализирована")
            
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        print(f"❌ Ошибка инициализации БД: {e}")
        raise

def save_account_to_db(uuid_str, short_id, path, vless_link, qr_code_path, uid_tg=None, username=None, node_id=None):
    try:
        validate_uuid(uuid_str)
        
        with db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT uuid FROM accounts WHERE uuid = ?', (uuid_str,))
            if cursor.fetchone():
                raise ValueError(f"Пользователь с UUID {uuid_str} уже существует")
            
            if node_id:
                cursor.execute('SELECT node_id FROM nodes WHERE node_id = ?', (node_id,))
                if not cursor.fetchone():
                    raise ValueError(f"Нода с ID {node_id} не найдена")
            
            cursor.execute('''
                INSERT INTO accounts (uuid, short_id, path, vless_link, qr_code_path, uid_tg, username, node_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (uuid_str, short_id, path, vless_link, qr_code_path, uid_tg, username, node_id))
            
            conn.commit()
            logger.info(f"Account {uuid_str} saved to database")
        print(f"✅ Пользователь {uuid_str} сохранен в БД")
        return True
            
    except Exception as e:
        logger.error(f"Error saving account to database: {e}")
        print(f"❌ Ошибка сохранения в БД: {e}")
        raise

def get_user_by_uuid(uuid_str):
    try:
        if not uuid_str or not isinstance(uuid_str, str):
            raise ValueError("UUID должен быть непустой строкой")
        
        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise ValueError("DATABASE_NAME не установлен")
        
        conn = sqlite3.connect(database_name)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM accounts WHERE uuid = ?', (uuid_str,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            print(f"✅ Пользователь {uuid_str} найден в БД")
        else:
            print(f"⚠️ Пользователь {uuid_str} не найден в БД")
        
        return user
    except Exception as e:
        print(f"❌ Ошибка поиска пользователя в БД: {e}")
        if 'conn' in locals():
            conn.close()
        raise

def delete_user_from_db(uuid_str):
    try:
        if not uuid_str or not isinstance(uuid_str, str):
            raise ValueError("UUID должен быть непустой строкой")
        
        with db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT uuid FROM accounts WHERE uuid = ?', (uuid_str,))
            if not cursor.fetchone():
                raise ValueError(f"Пользователь с UUID {uuid_str} не найден в БД")
            
            cursor.execute('DELETE FROM accounts WHERE uuid = ?', (uuid_str,))
            deleted_count = cursor.rowcount
            
            if deleted_count == 0:
                raise ValueError(f"Не удалось удалить пользователя {uuid_str} из БД")
            
            conn.commit()
        print(f"✅ Пользователь {uuid_str} удален из БД")
        return True
    except Exception as e:
        print(f"❌ Ошибка удаления пользователя из БД: {e}")
        raise

def delete_user_files(uuid_str):
    try:
        if not uuid_str or not isinstance(uuid_str, str):
            raise ValueError("UUID должен быть непустой строкой")
        
        deleted_files = []
        
        qr_codes_dir = os.getenv("QR_CODES_DIR")
        if qr_codes_dir:
            qr_file = f"{qr_codes_dir}/qr_{uuid_str[:8]}.png"
            if os.path.exists(qr_file):
                os.remove(qr_file)
                deleted_files.append(qr_file)
                print(f"✅ QR код удален: {qr_file}")
            else:
                print(f"⚠️ QR код не найден: {qr_file}")
        
        user_files_dir = os.getenv("USER_FILES_DIR")
        if user_files_dir:
            info_file = f"{user_files_dir}/user_{uuid_str[:8]}.txt"
            if os.path.exists(info_file):
                os.remove(info_file)
                deleted_files.append(info_file)
                print(f"✅ Текстовый файл удален: {info_file}")
            else:
                print(f"⚠️ Текстовый файл не найден: {info_file}")
        
        print(f"✅ Удалено файлов: {len(deleted_files)}")
        return True
    except Exception as e:
        print(f"❌ Ошибка при удалении файлов: {e}")
        return False

def initialize_vpn_module():
    try:
        validate_env()
        init_database()
        print("✅ VPN модуль инициализирован успешно")
        return True
    except ValueError as e:
        print(f"❌ Ошибка инициализации VPN модуля: {e}")
        return False

def add_user_fast(user_data: VpnUser, node_id: str = None, country_code: str = None):
    try:
        if not user_data.uid_tg or not user_data.uid_tg.strip():
            raise ValueError("UID_TG не может быть пустым")
        
        if not user_data.username or not user_data.username.strip():
            raise ValueError("Username не может быть пустым")
        
        if len(user_data.uid_tg) > 50:
            raise ValueError("UID_TG слишком длинный (максимум 50 символов)")
        
        if len(user_data.username) > 50:
            raise ValueError("Username слишком длинный (максимум 50 символов)")
        
        if node_id:
            node = get_node_by_id(node_id)
            if not node:
                raise ValueError(f"Нода с ID {node_id} не найдена")
        elif country_code:
            nodes_in_country = get_nodes_by_country(country_code)
            if not nodes_in_country:
                raise ValueError(f"Нет доступных нод в стране {country_code}")
            
            best_node = None
            min_users = float('inf')
            
            for node_candidate in nodes_in_country:
                database_name = os.getenv("DATABASE_NAME")
                conn = sqlite3.connect(database_name)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM accounts WHERE node_id = ?', (node_candidate.node_id,))
                user_count = cursor.fetchone()[0]
                conn.close()
                
                if user_count < min_users:
                    min_users = user_count
                    best_node = node_candidate
            
            node = best_node
        else:
            node = get_best_node()
            if not node:
                raise ValueError("Нет доступных нод")
        
        uuid_str = generate_uuid()
        short_id = generate_short_id()
        path = generate_path()
        
        print(f"⚡ Быстрое добавление пользователя {uuid_str} для TG: {user_data.uid_tg} (@{user_data.username}) на ноду {node.node_id}")
        
        config = get_xray_config_from_node(node)
        if not config:
            raise Exception(f"Не удалось получить конфигурацию с ноды {node.node_id}")
        
        if not update_xray_config_on_node(config, uuid_str, short_id, node):
            raise Exception(f"Не удалось обновить конфигурацию на ноде {node.node_id}")
        
        if not restart_xray_on_node(node):
            raise Exception(f"Не удалось перезапустить Xray на ноде {node.node_id}")
        
        vless_link = generate_vless_link_for_node(uuid_str, short_id, path, node)
        print(f"✅ VLESS ссылка сгенерирована: {vless_link[:50]}...")
        
        qr_file = generate_qr_code(vless_link, uuid_str)
        
        user_files_dir = os.getenv("USER_FILES_DIR")
        os.makedirs(user_files_dir, exist_ok=True)
        info_file = f"{user_files_dir}/user_{uuid_str[:8]}.txt"
        with open(info_file, 'w', encoding='utf-8') as f:
            f.write(f"Новый пользователь Xray Reality VPN\n")
            f.write(f"=" * 40 + "\n")
            f.write(f"UUID: {uuid_str}\n")
            f.write(f"ShortID: {short_id}\n")
            f.write(f"Path: {path}\n")
            f.write(f"Node ID: {node.node_id}\n")
            f.write(f"Server: {node.server_domain}\n")
            f.write(f"TG UID: {user_data.uid_tg}\n")
            f.write(f"TG Username: @{user_data.username}\n")
            f.write(f"Дата создания: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"\nVLESS ссылка:\n{vless_link}\n")
            if qr_file:
                f.write(f"\nQR-код: {qr_file}\n")
        
        save_account_to_db(
            uuid_str,
            short_id, 
            path,
            vless_link,
            qr_file,
            user_data.uid_tg,
            user_data.username,
            node.node_id
        )
        
        return {
            "success": True, 
            "vless_link": vless_link, 
            "uuid": uuid_str,
            "qr_file": qr_file,
            "node_id": node.node_id,
            "server_domain": node.server_domain,
            "country": node.country,
            "country_code": node.country_code,
            "city": node.city,
            "region": node.region
        }
        
    except Exception as e:
        print(f"❌ Ошибка при быстром добавлении пользователя: {str(e)}")
        import traceback
        traceback.print_exc()
        raise e

def add_user(user_data: VpnUser, node_id: str = None, country_code: str = None):
    try:
        if not user_data.uid_tg or not user_data.uid_tg.strip():
            raise ValueError("UID_TG не может быть пустым")
        
        if not user_data.username or not user_data.username.strip():
            raise ValueError("Username не может быть пустым")
        
        if len(user_data.uid_tg) > 50:
            raise ValueError("UID_TG слишком длинный (максимум 50 символов)")
        
        if len(user_data.username) > 50:
            raise ValueError("Username слишком длинный (максимум 50 символов)")
        
        if node_id:
            node = get_node_by_id(node_id)
            if not node:
                raise ValueError(f"Нода с ID {node_id} не найдена")
        elif country_code:
            nodes_in_country = get_nodes_by_country(country_code)
            if not nodes_in_country:
                raise ValueError(f"Нет доступных нод в стране {country_code}")
            
            best_node = None
            min_users = float('inf')
            
            for node_candidate in nodes_in_country:
                database_name = os.getenv("DATABASE_NAME")
                conn = sqlite3.connect(database_name)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM accounts WHERE node_id = ?', (node_candidate.node_id,))
                user_count = cursor.fetchone()[0]
                conn.close()
                
                if user_count < min_users:
                    min_users = user_count
                    best_node = node_candidate
            
            node = best_node
        else:
            node = get_best_node()
            if not node:
                raise ValueError("Нет доступных нод")
        
        uuid_str = generate_uuid()
        short_id = generate_short_id()
        path = generate_path()
        
        print(f"Добавление пользователя {uuid_str} для TG: {user_data.uid_tg} (@{user_data.username}) на ноду {node.node_id}")
        
        config = get_xray_config_from_node(node)
        if not config:
            raise Exception(f"Не удалось получить конфигурацию с ноды {node.node_id}")
        
        if not update_xray_config_on_node(config, uuid_str, short_id, node):
            raise Exception(f"Не удалось обновить конфигурацию на ноде {node.node_id}")
        
        if not graceful_reload_xray_on_node(node):
            raise Exception(f"Не удалось перезагрузить конфигурацию Xray на ноде {node.node_id}")
        
        vless_link = generate_vless_link_for_node(uuid_str, short_id, path, node)
        print(f"✅ VLESS ссылка сгенерирована: {vless_link[:50]}...")
        
        qr_file = generate_qr_code(vless_link, uuid_str)
        
        user_files_dir = os.getenv("USER_FILES_DIR")
        os.makedirs(user_files_dir, exist_ok=True)
        info_file = f"{user_files_dir}/user_{uuid_str[:8]}.txt"
        with open(info_file, 'w', encoding='utf-8') as f:
            f.write(f"Новый пользователь Xray Reality VPN\n")
            f.write(f"=" * 40 + "\n")
            f.write(f"UUID: {uuid_str}\n")
            f.write(f"ShortID: {short_id}\n")
            f.write(f"Path: {path}\n")
            f.write(f"Node ID: {node.node_id}\n")
            f.write(f"Server: {node.server_domain}\n")
            f.write(f"TG UID: {user_data.uid_tg}\n")
            f.write(f"TG Username: @{user_data.username}\n")
            f.write(f"Дата создания: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"\nVLESS ссылка:\n{vless_link}\n")
            if qr_file:
                f.write(f"\nQR-код: {qr_file}\n")
        
        save_account_to_db(
            uuid_str,
            short_id, 
            path,
            vless_link,
            qr_file,
            user_data.uid_tg,
            user_data.username,
            node.node_id
        )
        
        return {
            "success": True, 
            "vless_link": vless_link, 
            "uuid": uuid_str,
            "qr_file": qr_file,
            "node_id": node.node_id,
            "server_domain": node.server_domain,
            "country": node.country,
            "country_code": node.country_code,
            "city": node.city,
            "region": node.region
        }
        
    except Exception as e:
        print(f"❌ Ошибка при добавлении пользователя: {str(e)}")
        import traceback
        traceback.print_exc()
        raise e

def delete_user(uuid_param: str):
    try:
        try:
            uuid.UUID(uuid_param)
        except ValueError:
            raise ValueError("Неверный формат UUID")
        
        print(f"Удаление пользователя {uuid_param}")
        
        user = get_user_by_uuid(uuid_param)
        if not user:
            raise ValueError("Пользователь не найден")
        
        node_id = user[8]
        node = get_node_by_id(node_id)
        if not node:
            raise ValueError(f"Нода {node_id} не найдена")
        
        if not remove_user_from_xray_on_node(uuid_param, node):
            raise Exception(f"Не удалось удалить пользователя из конфигурации Xray на ноде {node_id}")
        
        if not restart_xray_on_node(node):
            raise Exception(f"Не удалось перезапустить Xray на ноде {node_id}")
        
        if not delete_user_files(uuid_param):
            print(f"⚠️ Предупреждение: не удалось удалить некоторые файлы пользователя {uuid_param}")
        
        if not delete_user_from_db(uuid_param):
            raise Exception("Не удалось удалить пользователя из БД")
        
        return {
            "success": True, 
            "message": f"Пользователь {uuid_param} успешно удален с ноды {node_id}"
        }
        
    except Exception as e:
        print(f"❌ Ошибка при удалении пользователя: {str(e)}")
        import traceback
        traceback.print_exc()
        raise e

def get_user_info(uuid_param: str):
    try:
        try:
            uuid.UUID(uuid_param)
        except ValueError:
            raise ValueError("Неверный формат UUID")
        
        user = get_user_by_uuid(uuid_param)
        if not user:
            raise ValueError("Пользователь не найден")
        
        node_id = user[8]
        node = get_node_by_id(node_id) if node_id else None
        
        return {
            "uuid": user[1],
            "short_id": user[2],
            "path": user[3],
            "vless_link": user[4],
            "qr_code_path": user[5],
            "uid_tg": user[6],
            "username": user[7],
            "created_at": user[8],
            "node_id": node_id,
            "node_info": {
                "node_id": node.node_id,
                "server_domain": node.server_domain,
                "server_ip": node.server_ip,
                "country": node.country,
                "country_code": node.country_code,
                "city": node.city,
                "region": node.region
            } if node else {
                "node_id": "unknown",
                "server_domain": "unknown",
                "server_ip": "unknown",
                "country": "unknown",
                "country_code": "XX",
                "city": "unknown",
                "region": "unknown"
            }
        }
        
    except Exception as e:
        print(f"❌ Ошибка при получении информации о пользователе: {str(e)}")
        raise e

def add_node(node: VpnNode):
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT node_id FROM nodes WHERE node_id = ?', (node.node_id,))
            if cursor.fetchone():
                raise ValueError(f"Нода с ID {node.node_id} уже существует")
            
            cursor.execute('''
                INSERT INTO nodes (node_id, server_ip, server_domain, server_username, server_password_hash,
                                 xray_config_path, xray_port, reality_public_key, reality_short_id,
                                 reality_sni, country, country_code, city, region, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (node.node_id, node.server_ip, node.server_domain, node.server_username,
                  encrypt_password(node.server_password), node.xray_config_path, node.xray_port,
                  node.reality_public_key, node.reality_short_id, node.reality_sni,
                  node.country, node.country_code, node.city, node.region, node.is_active))
            
            conn.commit()
        print(f"✅ Нода {node.node_id} добавлена в БД")
        return True
    except Exception as e:
        print(f"❌ Ошибка добавления ноды в БД: {e}")
        raise

def add_node_with_auto_discovery(node_id, server_ip, server_domain, username, password):
    try:
        print(f"🔍 Добавление ноды {node_id} с автоматическим обнаружением конфигурации...")
        
        discovered_config = auto_discover_server_config(server_ip, server_domain, username, password)
        if not discovered_config:
            raise ValueError(f"Не удалось обнаружить конфигурацию Xray на сервере {server_domain}")
        
        print(f"🌍 Определение местоположения сервера...")
        country_info = get_country_by_ip(server_ip)
        
        node = VpnNode(
            node_id=node_id,
            server_ip=server_ip,
            server_domain=server_domain,
            server_username=username,
            server_password=password,
            xray_config_path=discovered_config['xray_config_path'],
            xray_port=discovered_config['xray_port'],
            reality_public_key=discovered_config['reality_public_key'],
            reality_short_id=discovered_config['reality_short_id'],
            reality_sni=discovered_config['reality_sni'],
            country=country_info['country'],
            country_code=country_info['country_code'],
            city=country_info['city'],
            region=country_info['region'],
            is_active=True
        )
        
        return add_node(node)
        
    except Exception as e:
        print(f"❌ Ошибка добавления ноды с автообнаружением: {e}")
        raise

def get_node_by_id(node_id: str):
    try:
        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise ValueError("DATABASE_NAME не установлен")
        
        conn = sqlite3.connect(database_name)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM nodes WHERE node_id = ?', (node_id,))
        node_data = cursor.fetchone()
        conn.close()
        
        if node_data:
            return VpnNode(
                node_id=node_data[1],
                server_ip=node_data[2],
                server_domain=node_data[3],
                server_username=node_data[4],
                server_password=decrypt_password(node_data[5]),
                xray_config_path=node_data[6],
                xray_port=node_data[7],
                reality_public_key=node_data[8],
                reality_short_id=node_data[9],
                reality_sni=node_data[10],
                country=node_data[11] if len(node_data) > 11 else 'Unknown',
                country_code=node_data[12] if len(node_data) > 12 else 'XX',
                city=node_data[13] if len(node_data) > 13 else 'Unknown',
                region=node_data[14] if len(node_data) > 14 else 'Unknown',
                is_active=bool(node_data[15] if len(node_data) > 15 else node_data[11])
            )
        return None
    except Exception as e:
        print(f"❌ Ошибка получения ноды из БД: {e}")
        if 'conn' in locals():
            conn.close()
        raise

def get_all_nodes():
    try:
        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise ValueError("DATABASE_NAME не установлен")
        
        conn = sqlite3.connect(database_name)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM nodes WHERE is_active = 1')
        nodes_data = cursor.fetchall()
        conn.close()
        
        nodes = []
        for node_data in nodes_data:
            nodes.append(VpnNode(
                node_id=node_data[1],
                server_ip=node_data[2],
                server_domain=node_data[3],
                server_username=node_data[4],
                server_password=decrypt_password(node_data[5]),
                xray_config_path=node_data[6],
                xray_port=node_data[7],
                reality_public_key=node_data[8],
                reality_short_id=node_data[9],
                reality_sni=node_data[10],
                country=node_data[11] if len(node_data) > 11 else 'Unknown',
                country_code=node_data[12] if len(node_data) > 12 else 'XX',
                city=node_data[13] if len(node_data) > 13 else 'Unknown',
                region=node_data[14] if len(node_data) > 14 else 'Unknown',
                is_active=bool(node_data[15] if len(node_data) > 15 else node_data[11])
            ))
        return nodes
    except Exception as e:
        print(f"❌ Ошибка получения нод из БД: {e}")
        if 'conn' in locals():
            conn.close()
        raise

def update_node_status(node_id: str, is_active: bool):
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('UPDATE nodes SET is_active = ? WHERE node_id = ?', (is_active, node_id))
            if cursor.rowcount == 0:
                raise ValueError(f"Нода с ID {node_id} не найдена")
            
            conn.commit()
        print(f"✅ Статус ноды {node_id} обновлен: {'активна' if is_active else 'неактивна'}")
        return True
    except Exception as e:
        print(f"❌ Ошибка обновления статуса ноды: {e}")
        raise

def delete_node(node_id: str):
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM accounts WHERE node_id = ?', (node_id,))
            user_count = cursor.fetchone()[0]
            if user_count > 0:
                raise ValueError(f"Невозможно удалить ноду {node_id}: на ней зарегистрировано {user_count} пользователей")
            
            cursor.execute('DELETE FROM nodes WHERE node_id = ?', (node_id,))
            if cursor.rowcount == 0:
                raise ValueError(f"Нода с ID {node_id} не найдена")
            
            conn.commit()
        print(f"✅ Нода {node_id} удалена из БД")
        return True
    except Exception as e:
        print(f"❌ Ошибка удаления ноды: {e}")
        raise

def get_best_node():
    try:
        nodes = get_all_nodes()
        if not nodes:
            raise ValueError("Нет доступных нод")
        
        best_node = None
        min_users = float('inf')
        
        for node in nodes:
            database_name = os.getenv("DATABASE_NAME")
            conn = sqlite3.connect(database_name)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM accounts WHERE node_id = ?', (node.node_id,))
            user_count = cursor.fetchone()[0]
            conn.close()
            
            if user_count < min_users:
                min_users = user_count
                best_node = node
        
        return best_node
    except Exception as e:
        print(f"❌ Ошибка выбора лучшей ноды: {e}")
        raise

def get_nodes_by_country(country_code):
    try:
        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise ValueError("DATABASE_NAME не установлен")
        
        conn = sqlite3.connect(database_name)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM nodes WHERE country_code = ? AND is_active = 1', (country_code,))
        nodes_data = cursor.fetchall()
        conn.close()
        
        nodes = []
        for node_data in nodes_data:
            nodes.append(VpnNode(
                node_id=node_data[1],
                server_ip=node_data[2],
                server_domain=node_data[3],
                server_username=node_data[4],
                server_password=decrypt_password(node_data[5]),
                xray_config_path=node_data[6],
                xray_port=node_data[7],
                reality_public_key=node_data[8],
                reality_short_id=node_data[9],
                reality_sni=node_data[10],
                country=node_data[11] if len(node_data) > 11 else 'Unknown',
                country_code=node_data[12] if len(node_data) > 12 else 'XX',
                city=node_data[13] if len(node_data) > 13 else 'Unknown',
                region=node_data[14] if len(node_data) > 14 else 'Unknown',
                is_active=bool(node_data[15] if len(node_data) > 15 else node_data[11])
            ))
        return nodes
    except Exception as e:
        print(f"❌ Ошибка получения нод по стране: {e}")
        if 'conn' in locals():
            conn.close()
        raise

def get_available_countries():
    try:
        database_name = os.getenv("DATABASE_NAME")
        if not database_name:
            raise ValueError("DATABASE_NAME не установлен")
        
        conn = sqlite3.connect(database_name)
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT country, country_code, COUNT(*) as node_count FROM nodes WHERE is_active = 1 GROUP BY country, country_code ORDER BY country')
        countries_data = cursor.fetchall()
        conn.close()
        
        countries = []
        for country_data in countries_data:
            countries.append({
                'country': country_data[0],
                'country_code': country_data[1],
                'node_count': country_data[2]
            })
        return countries
    except Exception as e:
        print(f"❌ Ошибка получения списка стран: {e}")
        if 'conn' in locals():
            conn.close()
        raise

def execute_remote_command_on_node(command, node: VpnNode):
    try:
        with ssh_connection(node.server_ip, node.server_username, node.server_password) as ssh:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            if error:
                logger.warning(f"SSH command warning on node {node.node_id}: {error}")
            
            logger.info(f"SSH command executed on node {node.node_id}: {command[:50]}...")
            return output
        
    except Exception as e:
        logger.error(f"SSH command failed on node {node.node_id}: {e}")
        return None

def get_xray_config_from_node(node: VpnNode):
    reality_config_content = execute_remote_command_on_node(f"cat {node.xray_config_path}", node)
    if reality_config_content:
        try:
            return json.loads(reality_config_content)
        except json.JSONDecodeError:
            print(f"❌ Ошибка парсинга JSON Reality конфигурации на ноде {node.node_id}")
            return None
    return None

def update_xray_config_on_node(config, uuid_str, short_id, node: VpnNode):
    try:
        target_inbound = None
        for inbound in config.get('inbounds', []):
            if (inbound.get('protocol') == 'vless' and 
                inbound.get('streamSettings', {}).get('security') == 'reality'):
                target_inbound = inbound
                break
        
        if not target_inbound:
            print(f"❌ Не найден Reality inbound в конфигурации на ноде {node.node_id}")
            return False
        
        if 'settings' not in target_inbound:
            target_inbound['settings'] = {}
        if 'clients' not in target_inbound['settings']:
            target_inbound['settings']['clients'] = []
        
        existing_user = next((client for client in target_inbound['settings']['clients'] 
                            if client.get('id') == uuid_str), None)
        if existing_user:
            print(f"⚠️ Пользователь с UUID {uuid_str} уже существует на ноде {node.node_id}")
            return True
        
        new_client = {
            "id": uuid_str,
            "email": f"{uuid_str[:8]}-vless_reality_vision",
            "flow": "xtls-rprx-vision"
        }
        
        target_inbound['settings']['clients'].append(new_client)
        
        print(f"⚡ Быстрое обновление конфигурации на ноде {node.node_id}...")
        
        update_command = f'cat > {node.xray_config_path} << \'EOF\'\n{json.dumps(config, indent=2)}\nEOF'
        
        result = execute_remote_command_on_node(update_command, node)
        if result is None:
            raise Exception(f"Не удалось обновить конфигурацию на ноде {node.node_id}")
        
        execute_remote_command_on_node(f'chown root:root {node.xray_config_path} && chmod 644 {node.xray_config_path}', node)
        
        print(f"✅ Пользователь {uuid_str} добавлен в конфигурацию на ноде {node.node_id}")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при обновлении конфигурации Xray на ноде {node.node_id}: {e}")
        return False

def graceful_reload_xray_on_node(node: VpnNode):
    try:
        print(f"⚡ Быстрый reload конфигурации Xray на ноде {node.node_id}...")
        
        reload_result = execute_remote_command_on_node("pkill -HUP xray", node)
        
        if reload_result is not None:
            print(f"✅ Сигнал перезагрузки отправлен на ноду {node.node_id}")
            time.sleep(1)
            return True
        else:
            print(f"⚠️ Не удалось отправить сигнал на ноду {node.node_id}, используем полный перезапуск")
            return restart_xray_on_node(node)
            
    except Exception as e:
        print(f"❌ Ошибка при graceful reload на ноде {node.node_id}: {e}, используем полный перезапуск")
        return restart_xray_on_node(node)

def restart_xray_on_node(node: VpnNode):
    try:
        print(f"⚡ Быстрый перезапуск Xray на ноде {node.node_id}...")
        
        restart_command = "systemctl restart xray"
        restart_result = execute_remote_command_on_node(restart_command, node)
        
        if restart_result is None:
            print(f"❌ Не удалось перезапустить Xray на ноде {node.node_id}")
            return False
        
        time.sleep(2)
        
        status_result = execute_remote_command_on_node("systemctl is-active xray", node)
        if status_result and "active" in status_result:
            print(f"✅ Xray успешно перезапущен на ноде {node.node_id}")
            return True
        else:
            print(f"❌ Xray не активен на ноде {node.node_id} после перезапуска")
            return False
        
    except Exception as e:
        print(f"❌ Ошибка при перезапуске Xray на ноде {node.node_id}: {e}")
        return False

def remove_user_from_xray_on_node(uuid_str, node: VpnNode):
    try:
        config = get_xray_config_from_node(node)
        if not config:
            return False
        
        target_inbound = None
        for inbound in config.get('inbounds', []):
            if (inbound.get('protocol') == 'vless' and 
                inbound.get('streamSettings', {}).get('security') == 'reality'):
                target_inbound = inbound
                break
        
        if not target_inbound:
            return False
        
        if 'clients' in target_inbound['settings']:
            target_inbound['settings']['clients'] = [
                client for client in target_inbound['settings']['clients'] 
                if client.get('id') != uuid_str
            ]
            print(f"✅ Пользователь {uuid_str} удален из конфигурации Xray на ноде {node.node_id}")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f, indent=2)
            temp_file = f.name
        
        try:
            with open(temp_file, 'r') as f:
                config_content = f.read()
            
            update_command = f'cat > {node.xray_config_path} << \'EOF\'\n{config_content}\nEOF'
            
            result = execute_remote_command_on_node(update_command, node)
            if result is None:
                raise Exception(f"Не удалось обновить конфигурацию на ноде {node.node_id}")
            
            execute_remote_command_on_node(f'chown root:root {node.xray_config_path}', node)
            
        except Exception as e:
            print(f"❌ Ошибка при обновлении конфигурации на ноде {node.node_id}: {e}")
            return False
        
        os.unlink(temp_file)
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при удалении пользователя из Xray на ноде {node.node_id}: {e}")
        return False

def health_check():
    try:
        nodes = get_all_nodes()
        if not nodes:
            return {"status": "no_nodes", "timestamp": datetime.now().isoformat()}
        
        healthy_nodes = 0
        node_statuses = {}
        
        for node in nodes:
            try:
                config = get_xray_config_from_node(node)
                if config:
                    node_statuses[node.node_id] = "healthy"
                    healthy_nodes += 1
                else:
                    node_statuses[node.node_id] = "unhealthy"
            except Exception as e:
                node_statuses[node.node_id] = f"error: {str(e)}"
        
        overall_status = "healthy" if healthy_nodes > 0 else "unhealthy"
        
        return {
            "status": overall_status,
            "healthy_nodes": healthy_nodes,
            "total_nodes": len(nodes),
            "node_statuses": node_statuses,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "timestamp": datetime.now().isoformat()}
