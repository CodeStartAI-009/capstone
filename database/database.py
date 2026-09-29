"""SQLite connection handling, schema creation and migrations (standard library only)."""
import logging
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

from database.models import MIGRATIONS, SCHEMA, SCHEMA_VERSION

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """The history database could not be opened, initialised or queried."""


class Database:
    """One SQLite file. A new connection is opened per operation (safe with Flask's threaded server)."""

    def __init__(self, path, timeout=5.0):
        self.path = Path(path)
        self.timeout = timeout
        self._ready = False
        self._lock = threading.Lock()

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=self.timeout)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self):
        """Create the file, the schema and apply migrations. Safe to call repeatedly."""
        with self._lock:
            if self._ready:
                return
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with closing(self.connect()) as conn:
                    conn.execute("PRAGMA journal_mode = WAL")  # readers do not block the writer
                    version = conn.execute("PRAGMA user_version").fetchone()[0]
                    table_exists = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_history'").fetchone()
                    with conn:
                        if table_exists and version < SCHEMA_VERSION:
                            for target in range(max(version, 1) + 1, SCHEMA_VERSION + 1):
                                for statement in MIGRATIONS.get(target, []):
                                    conn.execute(statement)
                                logger.info("Migrated scan history database to schema version %d", target)
                        conn.executescript(SCHEMA)
                        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            except (sqlite3.Error, OSError) as exc:
                raise DatabaseError("could not initialise the history database") from exc
            self._ready = True

    def run(self, operation):
        """Run ``operation(conn)`` in a transaction; wrap any SQLite error in DatabaseError."""
        self.initialize()
        try:
            with closing(self.connect()) as conn, conn:
                return operation(conn)
        except sqlite3.Error as exc:
            raise DatabaseError("history database operation failed") from exc
