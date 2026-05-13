import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "shieldscan.db"
LEGACY_DATABASE_PATH = BASE_DIR / "manual_monitor.db"


def ensure_data_dir():
    DATA_DIR.mkdir(exist_ok=True)


def migrate_legacy_database():
    ensure_data_dir()
    if LEGACY_DATABASE_PATH.exists() and not DATABASE_PATH.exists():
        DATABASE_PATH.write_bytes(LEGACY_DATABASE_PATH.read_bytes())


def get_connection():
    migrate_legacy_database()
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_column(connection, table_name, column_name, definition):
    columns = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_db():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                phone TEXT DEFAULT '',
                about TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS user_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                risk REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS manual_monitor (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                normalized_url TEXT,
                result TEXT NOT NULL,
                risk REAL NOT NULL,
                trusted INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                manual_result TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )
        ensure_column(connection, "manual_monitor", "user_id", "INTEGER")
        ensure_column(connection, "manual_monitor", "normalized_url", "TEXT")
        ensure_column(connection, "manual_monitor", "status", "TEXT NOT NULL DEFAULT 'pending'")
        ensure_column(connection, "manual_monitor", "manual_result", "TEXT")


def create_user(username, password_hash, display_name, phone="", about=""):
    init_db()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, display_name, phone, about)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, password_hash, display_name, phone, about),
        )


def get_user_by_username(username):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()


def get_user_by_id(user_id):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def update_user_profile(user_id, display_name, phone, about):
    init_db()
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET display_name = ?, phone = ?, about = ?
            WHERE id = ?
            """,
            (display_name, phone, about, user_id),
        )


def create_agent(username, password_hash, display_name):
    init_db()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO agents (username, password_hash, display_name)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, display_name),
        )


def get_agent_by_username(username):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM agents WHERE username = ?",
            (username,),
        ).fetchone()


def get_agent_by_id(agent_id):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM agents WHERE id = ?",
            (agent_id,),
        ).fetchone()


def save_user_scan(user_id, url, result, risk, status):
    init_db()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO user_scans (user_id, url, result, risk, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, url, result, risk, status),
        )


def get_user_scans(user_id, limit=100):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            """
            SELECT id, url, result, risk, status, created_at
            FROM user_scans
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()


def save_manual_monitor_entry(user_id, url, normalized_url, result, risk, trusted):
    init_db()
    with get_connection() as connection:
        existing = connection.execute(
            """
            SELECT id
            FROM manual_monitor
            WHERE (normalized_url = ? OR url = ?) AND status = 'pending'
            ORDER BY id DESC
            LIMIT 1
            """,
            (normalized_url, url),
        ).fetchone()

        if existing:
            connection.execute(
                """
                UPDATE manual_monitor
                SET user_id = ?,
                    url = ?,
                    normalized_url = ?,
                    result = ?,
                    risk = ?,
                    trusted = ?,
                    created_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (user_id, url, normalized_url, result, risk, 1 if trusted else 0, existing["id"]),
            )
            return False

        connection.execute(
            """
            INSERT INTO manual_monitor (user_id, url, normalized_url, result, risk, trusted, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (user_id, url, normalized_url, result, risk, 1 if trusted else 0),
        )
        return True


def get_approved_decision(url, normalized_url):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            """
            SELECT manual_result, risk
            FROM manual_monitor
            WHERE (normalized_url = ? OR url = ?)
              AND status = 'approved'
              AND manual_result IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (normalized_url, url),
        ).fetchone()


def approve_manual_monitor_entry(entry_id, manual_result):
    init_db()
    with get_connection() as connection:
        entry = connection.execute(
            """
            SELECT user_id, url, risk
            FROM manual_monitor
            WHERE id = ?
            """,
            (entry_id,),
        ).fetchone()

        connection.execute(
            """
            UPDATE manual_monitor
            SET status = 'approved', manual_result = ?
            WHERE id = ?
            """,
            (manual_result, entry_id),
        )

        if entry and entry["user_id"]:
            connection.execute(
                """
                UPDATE user_scans
                SET result = ?, risk = ?, status = 'agent_approved'
                WHERE user_id = ?
                  AND url = ?
                  AND status = 'pending_manual_review'
                """,
                (manual_result, entry["risk"], entry["user_id"], entry["url"]),
            )


def get_manual_monitor_entries(limit=100):
    init_db()
    with get_connection() as connection:
        return connection.execute(
            """
            SELECT
                manual_monitor.id,
                manual_monitor.url,
                manual_monitor.result,
                manual_monitor.risk,
                manual_monitor.trusted,
                manual_monitor.status,
                manual_monitor.manual_result,
                manual_monitor.created_at,
                users.display_name,
                users.username,
                users.phone,
                users.about
            FROM manual_monitor
            LEFT JOIN users ON users.id = manual_monitor.user_id
            ORDER BY manual_monitor.created_at DESC, manual_monitor.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
