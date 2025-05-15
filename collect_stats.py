import sqlite3
import logging
import time
import re
from db import get_db

# Настройка логирования
logging.basicConfig(
    filename="/app/data/traffic_filter.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger()

# Добавляем консольный вывод
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console)

def collect_stats():
    """Собирает статистику трафика из логов iptables."""
    try:
        logger.info("Starting traffic statistics collection")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, chain FROM resources")
            resources = cursor.fetchall()
            chain_map = {chain.lower(): resource_id for resource_id, chain in resources}

            # Инициализируем позиции в файлах логов
            log_positions = {
                "wl": 0,
                "bl": 0,
                "tbl": 0
            }
            log_files = {
                "wl": "/var/log/iptables_wl.log",
                "bl": "/var/log/iptables_bl.log",
                "tbl": "/var/log/iptables_tbl.log"
            }

            update_interval = 60  # Обновляем статистику каждые 60 секунд

            while True:
                for list_type, log_file in log_files.items():
                    try:
                        with open(log_file, "r") as f:
                            f.seek(log_positions[list_type])
                            lines = f.readlines()
                            log_positions[list_type] = f.tell()

                            packets = 0
                            bytes_ = 0

                            for line in lines:
                                # Пример лога: "May 15 14:30:01 debian kernel: WL_PASS IN=eth0 OUT= SRC=192.168.1.1 DST=172.30.30.1 LEN=52"
                                match = re.search(r"SRC=\S+ DST=\S+ LEN=(\d+)", line)
                                if match:
                                    packets += 1
                                    bytes_ += int(match.group(1))

                            if packets > 0 or bytes_ > 0:
                                for chain, resource_id in chain_map.items():
                                    if chain.lower() in line.lower():
                                        cursor.execute(
                                            "INSERT INTO traffic_stats (resource_id, timestamp, rule, packets, bytes) VALUES (?, ?, ?, ?, ?)",
                                            (resource_id, int(time.time()), f"{list_type}_{chain.lower()}", packets, bytes_)
                                        )
                                        logger.info(f"Recorded stats for {chain} ({list_type}): packets={packets}, bytes={bytes_}")

                    except Exception as e:
                        logger.error(f"Error reading {log_file}: {e}")

                conn.commit()
                time.sleep(update_interval)

    except Exception as e:
        logger.error(f"Error collecting stats: {e}")

if __name__ == "__main__":
    collect_stats()
