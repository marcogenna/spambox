"""Accesso SQLite condiviso tra worker e interfaccia web.

SQLite in modalità WAL per permettere letture concorrenti (webapp) mentre
il worker scrive, come da architettura MVP consigliata.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS protected_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS allowed_forwarder_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analysis_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    processed_at TEXT NOT NULL DEFAULT (datetime('now')),
    message_uid TEXT,
    from_address TEXT,
    reply_to_address TEXT,
    subject TEXT,
    risk_score REAL,
    verdict TEXT,
    reasons_json TEXT,
    lookalike_json TEXT,
    virustotal_json TEXT,
    urlhaus_json TEXT,
    safebrowsing_json TEXT,
    rspamd_json TEXT,
    domain_age_json TEXT,
    brand_impersonation_json TEXT,
    auth_json TEXT,
    response_sent INTEGER DEFAULT 0,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_analysis_log_processed_at ON analysis_log(processed_at);
CREATE INDEX IF NOT EXISTS idx_analysis_log_verdict ON analysis_log(verdict);
CREATE INDEX IF NOT EXISTS idx_analysis_log_from ON analysis_log(from_address);
"""

# Colonne aggiunte dopo la creazione iniziale della tabella: su un database
# già esistente "CREATE TABLE IF NOT EXISTS" non le aggiunge da solo, serve
# una migrazione leggera eseguita a ogni init_db().
_ANALYSIS_LOG_MIGRATIONS: dict[str, str] = {
    "urlhaus_json": "ALTER TABLE analysis_log ADD COLUMN urlhaus_json TEXT",
    "domain_age_json": "ALTER TABLE analysis_log ADD COLUMN domain_age_json TEXT",
    "safebrowsing_json": "ALTER TABLE analysis_log ADD COLUMN safebrowsing_json TEXT",
    "brand_impersonation_json": "ALTER TABLE analysis_log ADD COLUMN brand_impersonation_json TEXT",
}


def _run_migrations(conn: sqlite3.Connection) -> None:
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(analysis_log)")}
    for column, statement in _ANALYSIS_LOG_MIGRATIONS.items():
        if column not in existing_columns:
            conn.execute(statement)


def get_connection(sqlite_path: str) -> sqlite3.Connection:
    Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(sqlite_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(sqlite_path: str) -> None:
    conn = get_connection(sqlite_path)
    try:
        conn.executescript(SCHEMA)
        _run_migrations(conn)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def connect(sqlite_path: str) -> Iterator[sqlite3.Connection]:
    conn = get_connection(sqlite_path)
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Domini protetti
# ---------------------------------------------------------------------------

def list_domains(sqlite_path: str) -> list[sqlite3.Row]:
    with connect(sqlite_path) as conn:
        return conn.execute(
            "SELECT * FROM protected_domains ORDER BY domain ASC"
        ).fetchall()


def add_domain(sqlite_path: str, domain: str, note: str = "") -> None:
    domain = domain.strip().lower()
    with connect(sqlite_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO protected_domains (domain, note) VALUES (?, ?)",
            (domain, note),
        )
        conn.commit()


def update_domain(sqlite_path: str, domain_id: int, domain: str, note: str) -> None:
    with connect(sqlite_path) as conn:
        conn.execute(
            "UPDATE protected_domains SET domain = ?, note = ? WHERE id = ?",
            (domain.strip().lower(), note, domain_id),
        )
        conn.commit()


def delete_domain(sqlite_path: str, domain_id: int) -> None:
    with connect(sqlite_path) as conn:
        conn.execute("DELETE FROM protected_domains WHERE id = ?", (domain_id,))
        conn.commit()


# ---------------------------------------------------------------------------
# Domini autorizzati a inoltrare email a SpamBox (whitelist mittenti)
# ---------------------------------------------------------------------------

def list_allowed_forwarder_domains(sqlite_path: str) -> list[sqlite3.Row]:
    with connect(sqlite_path) as conn:
        return conn.execute(
            "SELECT * FROM allowed_forwarder_domains ORDER BY domain ASC"
        ).fetchall()


def add_allowed_forwarder_domain(sqlite_path: str, domain: str, note: str = "") -> None:
    domain = domain.strip().lower()
    with connect(sqlite_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO allowed_forwarder_domains (domain, note) VALUES (?, ?)",
            (domain, note),
        )
        conn.commit()


def update_allowed_forwarder_domain(sqlite_path: str, domain_id: int, domain: str, note: str) -> None:
    with connect(sqlite_path) as conn:
        conn.execute(
            "UPDATE allowed_forwarder_domains SET domain = ?, note = ? WHERE id = ?",
            (domain.strip().lower(), note, domain_id),
        )
        conn.commit()


def delete_allowed_forwarder_domain(sqlite_path: str, domain_id: int) -> None:
    with connect(sqlite_path) as conn:
        conn.execute("DELETE FROM allowed_forwarder_domains WHERE id = ?", (domain_id,))
        conn.commit()


# ---------------------------------------------------------------------------
# Log analisi
# ---------------------------------------------------------------------------

def insert_analysis_log(sqlite_path: str, entry: dict[str, Any]) -> int:
    with connect(sqlite_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO analysis_log (
                message_uid, from_address, reply_to_address, subject,
                risk_score, verdict, reasons_json, lookalike_json,
                virustotal_json, urlhaus_json, safebrowsing_json, rspamd_json,
                domain_age_json, brand_impersonation_json, auth_json, response_sent, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.get("message_uid"),
                entry.get("from_address"),
                entry.get("reply_to_address"),
                entry.get("subject"),
                entry.get("risk_score"),
                entry.get("verdict"),
                json.dumps(entry.get("reasons", []), ensure_ascii=False),
                json.dumps(entry.get("lookalike", {}), ensure_ascii=False),
                json.dumps(entry.get("virustotal", {}), ensure_ascii=False),
                json.dumps(entry.get("urlhaus", {}), ensure_ascii=False),
                json.dumps(entry.get("safebrowsing", {}), ensure_ascii=False),
                json.dumps(entry.get("rspamd", {}), ensure_ascii=False),
                json.dumps(entry.get("domain_age", {}), ensure_ascii=False),
                json.dumps(entry.get("brand_impersonation", {}), ensure_ascii=False),
                json.dumps(entry.get("auth", {}), ensure_ascii=False),
                int(bool(entry.get("response_sent", False))),
                entry.get("error"),
            ),
        )
        conn.commit()
        return cur.lastrowid


def query_logs(
    sqlite_path: str,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    verdict: Optional[str] = None,
    sender: Optional[str] = None,
    limit: int = 200,
) -> list[sqlite3.Row]:
    query = "SELECT * FROM analysis_log WHERE 1=1"
    params: list[Any] = []
    if date_from:
        query += " AND processed_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND processed_at <= ?"
        params.append(date_to)
    if verdict:
        query += " AND verdict = ?"
        params.append(verdict)
    if sender:
        query += " AND from_address LIKE ?"
        params.append(f"%{sender}%")
    query += " ORDER BY processed_at DESC LIMIT ?"
    params.append(limit)
    with connect(sqlite_path) as conn:
        return conn.execute(query, params).fetchall()
