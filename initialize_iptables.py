import subprocess
import sqlite3
import logging
import os
from db import init_db

# Настройка логирования
log_dir = "/app/data"
log_file = f"{log_dir}/traffic_filter.log"

# Проверяем, что директория /app/data существует и доступна
try:
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(log_file, "a") as f:
        pass
except Exception as e:
    print(f"Failed to access log directory {log_dir}: {e}")
    exit(1)

logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger()

# Добавляем консольный вывод
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console)

def run_nft_command(command):
    """Запускает команду nft и логирует результат."""
    logger.debug(f"Executing nft command: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        logger.debug(f"Command output: {result.stdout}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(command)}\nError: {e.stderr}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in command {' '.join(command)}: {e}")
        raise

def initialize_iptables():
    """Инициализирует правила с использованием nftables."""
    try:
        logger.info("Initializing iptables with nftables")

        # Инициализируем базу данных
        logger.debug("Initializing database")
        init_db()

        # Проверяем, что таблицы созданы
        conn = sqlite3.connect("/app/data/traffic_filter.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resources'")
        if not cursor.fetchone():
            logger.error("Table 'resources' not found after init_db")
            raise Exception("Database initialization failed")

        # Очищаем существующие правила (используем nft)
        run_nft_command(["nft", "flush", "ruleset"])

        # Загружаем конфигурацию из базы
        logger.debug("Querying resources table")
        cursor.execute("SELECT id, name, ip, ports, chain FROM resources")
        resources = cursor.fetchall()

        if not resources:
            logger.info("No resources found in database, skipping configuration")
        else:
            for resource_id, name, ip, ports, chain in resources:
                logger.info(f"Configuring resource: {name} ({ip}, chain: {chain})")

                # Создаём цепочку в таблице filter
                run_nft_command(["nft", "add", "table", "ip", "filter"])
                run_nft_command(["nft", "add", "chain", "ip", "filter", chain, "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}"])

                # Направляем трафик в цепочку
                if ports:
                    for port in ports.split(","):
                        run_nft_command(["nft", "add", "rule", "ip", "filter", "forward", f"ip daddr {ip} tcp dport {port}", f"jump {chain}"])
                else:
                    run_nft_command(["nft", "add", "rule", "ip", "filter", "forward", f"ip daddr {ip}", f"jump {chain}"])

                # Правила в цепочке
                run_nft_command(["nft", "add", "set", f"ip {chain}_wl", "{", "type", "ipv4_addr", ";", "}"])
                run_nft_command(["nft", "add", "set", f"ip {chain}_bl", "{", "type", "ipv4_addr", ";", "}"])
                run_nft_command(["nft", "add", "set", f"ip {chain}_tbl", "{", "type", "ipv4_addr", ";", "timeout", "1h", ";", "}"])

                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "ip saddr @ {chain}_wl", "accept", "comment", "'WL: Allow trusted IPs'"])
                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "ip saddr @ {chain}_bl", "drop", "comment", "'BL: Block blacklisted IPs'"])
                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "ip saddr @ {chain}_tbl", "drop", "comment", "'TBL: Temp block IPs'"])
                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "accept", "comment", "'Default: Allow remaining traffic'"])

                # Логирование (простая реализация, можно улучшить)
                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "ip saddr @ {chain}_wl", "log", "prefix", f"'WL_PASS_{chain}: '"])
                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "ip saddr @ {chain}_bl", "log", "prefix", f"'BL_DROP_{chain}: '"])
                run_nft_command(["nft", "add", "rule", f"ip filter {chain}", "ip saddr @ {chain}_tbl", "log", "prefix", f"'TBL_DROP_{chain}: '"])

                # Загружаем IP-адреса из базы
                logger.debug(f"Querying lists for resource_id {resource_id}")
                cursor.execute("SELECT list_type, ip FROM lists WHERE resource_id = ?", (resource_id,))
                for list_type, ip_addr in cursor.fetchall():
                    run_nft_command(["nft", "add", "element", f"ip {chain}_{list_type}", "{", ip_addr, "}"])

        conn.close()
        logger.info("nftables rules generated")

    except Exception as e:
        logger.error(f"Failed to initialize nftables: {e}")
        raise

if __name__ == "__main__":
    try:
        initialize_iptables()
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        exit(1)
