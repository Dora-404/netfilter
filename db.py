import sqlite3
import logging

# Настройка логирования
logging.basicConfig(
    filename="/app/data/traffic_filter.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger()

def get_db():
    """Подключение к базе данных."""
    conn = sqlite3.connect("/app/data/traffic_filter.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Инициализирует базу данных."""
    logger.info("Initializing database")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                ports TEXT,
                chain TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER,
                list_type TEXT,
                ip TEXT NOT NULL,
                FOREIGN KEY (resource_id) REFERENCES resources(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_stats (
                timestamp INTEGER,
                resource_id INTEGER,
                rule TEXT,
                packets INTEGER,
                bytes INTEGER,
                FOREIGN KEY (resource_id) REFERENCES resources(id)
            )
        """)
        conn.commit()
    logger.info("Database initialized")
