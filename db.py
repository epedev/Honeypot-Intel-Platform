"""
Postgres access layer for the honeypot pipeline.

Connection string comes from the POSTGRES_CONN_STRING app setting in thAzure Function configuration. Never hardcode it, never commit it.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterable

from dotenv import load_dotenv
load_dotenv()

import psycopg2
from psycopg2.extras import Json

from log_schema import HoneypotEvent

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS honeypot_events (
    id BIGSERIAL PRIMARY KEY,
    event_hash TEXT UNIQUE NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    source_ip TEXT NOT NULL,
    route_hit TEXT NOT NULL,
    attack_category TEXT,
    http_method TEXT,
    resp_status INTEGER,
    src_port TEXT,
    query TEXT,
    user_agent TEXT,
    headers JSONB,
    payload JSONB,
    raw JSONB,
    ingested_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_honeypot_events_timestamp ON honeypot_events (event_timestamp);
CREATE INDEX IF NOT EXISTS idx_honeypot_events_source_ip ON honeypot_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_events_category ON honeypot_events (attack_category);
CREATE INDEX IF NOT EXISTS idx_honeypot_events_resp_status ON honeypot_events (resp_status);

CREATE TABLE IF NOT EXISTS processed_blobs (
    blob_name TEXT PRIMARY KEY,
    processed_at TIMESTAMPTZ DEFAULT now(),
    event_count INTEGER,
    quarantine_count INTEGER
);
"""

INSERT_SQL = """
INSERT INTO honeypot_events
    (event_hash, event_timestamp, source_ip, route_hit, attack_category,
     http_method, resp_status, src_port, query, user_agent, headers, payload, raw)
VALUES
    (%(event_hash)s, %(event_timestamp)s, %(source_ip)s, %(route_hit)s,
     %(attack_category)s, %(http_method)s, %(resp_status)s, %(src_port)s,
     %(query)s, %(user_agent)s, %(headers)s, %(payload)s, %(raw)s)
ON CONFLICT (event_hash) DO NOTHING;
"""


@contextmanager
def get_connection():
    conn_string = os.environ["POSTGRES_CONN_STRING"]
    conn = psycopg2.connect(conn_string)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)


def is_blob_processed(conn, blob_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM processed_blobs WHERE blob_name = %s", (blob_name,))
        return cur.fetchone() is not None


def mark_blob_processed(conn, blob_name: str, event_count: int, quarantine_count: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO processed_blobs (blob_name, event_count, quarantine_count) "
            "VALUES (%s, %s, %s) ON CONFLICT (blob_name) DO NOTHING",
            (blob_name, event_count, quarantine_count),
        )


def insert_events(conn, events: Iterable[HoneypotEvent]) -> int:
    rows = [e.to_db_row() for e in events]
    if not rows:
        return 0
    with conn.cursor() as cur:
        for row in rows:
            row["headers"] = Json(row["headers"])
            row["payload"] = Json(row["payload"])
            row["raw"] = Json(row["raw"])
            cur.execute(INSERT_SQL, row)
    return len(rows)
