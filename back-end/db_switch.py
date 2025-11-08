# db_switch.py
import os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# If a managed DB is provided, use it; else fallback to a local SQLite file.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SQLITE_PATH = os.path.join(BASE_DIR, "users.db")

_database_url = os.getenv("DATABASE_URL")
if not _database_url:
    # SQLite (file) for local/dev
    _database_url = f"sqlite+pysqlite:///{DEFAULT_SQLITE_PATH}"

IS_SQLITE = _database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if IS_SQLITE else {}

engine: Engine = create_engine(
    _database_url,
    pool_pre_ping=True,
    connect_args=connect_args,
    future=True,
)

def init_schema() -> None:
    """Create the users table if it doesn't exist (works for both Postgres & SQLite)."""
    ddl = """
    CREATE TABLE IF NOT EXISTS users(
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT,
      email       TEXT UNIQUE,
      password    TEXT,
      google_id   TEXT,
      provider    TEXT,
      credits     INTEGER DEFAULT 2,
      is_verified INTEGER DEFAULT 0,
      otp_hash    TEXT,
      otp_expires_at TEXT
    )
    """
    # In Postgres, INTEGER PRIMARY KEY AUTOINCREMENT is not valid; use SERIAL.
    # We can fix this at runtime by swapping the line when not SQLite.
    if not IS_SQLITE:
        ddl = ddl.replace(
            "id          INTEGER PRIMARY KEY AUTOINCREMENT,",
            "id          SERIAL PRIMARY KEY,"
        )

    with engine.begin() as conn:
        conn.execute(text(ddl))

def read_one(sql: str, params: dict | None = None):
    with engine.connect() as conn:
        return conn.execute(text(sql), params or {}).fetchone()

def read_all(sql: str, params: dict | None = None):
    with engine.connect() as conn:
        return conn.execute(text(sql), params or {}).fetchall()

def exec_write(sql: str, params: dict | None = None):
    """Execute INSERT/UPDATE/DELETE inside a transaction. Returns rowcount."""
    with engine.begin() as conn:
        res = conn.execute(text(sql), params or {})
        # rowcount works for UPDATE/DELETE; for INSERT use RETURNING to fetch ids when needed
        return res.rowcount

def insert_and_get_id(sql_with_returning: str, params: dict | None = None):
    """
    Execute INSERT and return the inserted id.
    - For Postgres, pass a statement with `RETURNING id`.
    - For SQLite, we can emulate by reading back via email, or using last_insert_rowid().
    """
    if IS_SQLITE:
        # Use SQLite-specific last_insert_rowid() by running two statements
        with engine.begin() as conn:
            conn.execute(text(sql_with_returning), params or {})
            row = conn.execute(text("SELECT last_insert_rowid()")).fetchone()
            return row[0] if row else None
    else:
        with engine.begin() as conn:
            row = conn.execute(text(sql_with_returning), params or {}).fetchone()
            return row[0] if row else None
if _database_url.startswith("postgres://"):
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)

init_schema()
