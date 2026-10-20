import sqlite3
import threading


class StorageEngine:
    def __init__(self, db_path="devflow_events.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    type TEXT,
                    connection TEXT,
                    process TEXT,
                    payload TEXT,
                    json_body TEXT,
                    latency REAL,
                    trace_id TEXT,
                    offset_ms REAL,
                    hex_dump TEXT
                )
            """)
            existing_cols = {
                row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()
            }
            for col, col_type in (("trace_id", "TEXT"), ("offset_ms", "REAL"), ("hex_dump", "TEXT")):
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
            conn.commit()
            conn.close()

    def save_event(self, event_dict):
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                conn.execute("""
                    INSERT INTO events (
                        timestamp, type, connection, process, payload,
                        json_body, latency, trace_id, offset_ms, hex_dump
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_dict.get("timestamp"),
                    event_dict.get("type"),
                    event_dict.get("connection"),
                    event_dict.get("process"),
                    event_dict.get("payload"),
                    event_dict.get("json_body"),
                    event_dict.get("latency"),
                    event_dict.get("trace_id"),
                    event_dict.get("offset_ms"),
                    event_dict.get("hex_dump")
                ))
                conn.commit()
                conn.close()
            except sqlite3.Error:
                pass

    def get_recent_events(self, limit=120):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT timestamp, type, connection, process, payload, json_body, "
                "latency, trace_id, offset_ms, hex_dump "
                "FROM events ORDER BY id ASC LIMIT ?",
                (limit,)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]

    def clear_all(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM events")
            conn.commit()
            conn.close()
