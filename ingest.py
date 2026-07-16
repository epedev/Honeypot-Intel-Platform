"""
Pull-based ingester. Runs on the home box via cron. No Azure Function,
no Blob Storage — pulls decoy.log directly from the honeypot VM over SSH
and writes normalized events straight into the local Postgres instance.

Usage (cron, every 5 min):
    */5 * * * * /usr/bin/python3 /home/epedev/honeypot-grafana-pipeline/ingest.py >> /home/epedev/honeypot-grafana-pipeline/ingest.log 2>&1

Requires:
  - SSH key auth from this box to the honeypot VM (no password prompt)
  - rsync installed locally
  - POSTGRES_CONN_STRING env var (or hardcode below for a local-only box —
    still don't commit real credentials to git)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from log_schema import normalize_event, NormalizationError
from db import get_connection, ensure_schema, insert_events

# --- configuration -----------------------------------------------------
SSH_KEY = os.path.expanduser("~/.ssh/azure_honeypot")
REMOTE_USER = os.environ.get("HONEYPOT_SSH_USER", "azureuser")
REMOTE_HOST = os.environ.get("HONEYPOT_VM_IP", "")  # set this
REMOTE_LOG_PATH = "/opt/decoy-system/logs/decoy.log"

LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_LOG_COPY = os.path.join(LOCAL_DIR, "decoy.log")
STATE_FILE = os.path.join(LOCAL_DIR, ".ingest_offset")
QUARANTINE_FILE = os.path.join(LOCAL_DIR, "quarantine.jsonl")


def pull_log() -> None:
    if not REMOTE_HOST:
        print("HONEYPOT_VM_IP not set, aborting.", file=sys.stderr)
        sys.exit(1)

    cmd = [
        "rsync", "-az",
        "-e", f"ssh -i {SSH_KEY} -o StrictHostKeyChecking=accept-new",
        f"{REMOTE_USER}@{REMOTE_HOST}:{REMOTE_LOG_PATH}",
        LOCAL_LOG_COPY,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"rsync failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)


def get_offset() -> int:
    if not os.path.exists(STATE_FILE):
        return 0
    with open(STATE_FILE) as f:
        return int(f.read().strip() or 0)


def set_offset(offset: int) -> None:
    with open(STATE_FILE, "w") as f:
        f.write(str(offset))


def process_new_lines(offset: int) -> tuple[list, list, int]:
    events = []
    quarantine = []

    with open(LOCAL_LOG_COPY, "rb") as f:
        f.seek(offset)
        new_bytes = f.read()
        new_offset = f.tell()

    for line in new_bytes.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_dict = json.loads(line)
        except json.JSONDecodeError as exc:
            quarantine.append({"line": line, "error": f"invalid json: {exc}"})
            continue

        try:
            events.append(normalize_event(raw_dict))
        except NormalizationError as exc:
            quarantine.append({"line": line, "error": str(exc)})

    return events, quarantine, new_offset


def main() -> None:
    pull_log()

    offset = get_offset()
    file_size = os.path.getsize(LOCAL_LOG_COPY)

    if file_size < offset:
        # Log got rotated/truncated on the remote side — start over from 0
        # rather than crash or silently miss everything.
        print("Log file shrank — assuming rotation, resetting offset to 0.")
        offset = 0

    events, quarantine, new_offset = process_new_lines(offset)

    if events:
        with get_connection() as conn:
            ensure_schema(conn)
            inserted = insert_events(conn, events)
            print(f"Inserted {inserted} new event(s).")
    else:
        print("No new events.")

    if quarantine:
        with open(QUARANTINE_FILE, "a") as f:
            for item in quarantine:
                f.write(json.dumps(item) + "\n")
        print(f"Quarantined {len(quarantine)} line(s) — see {QUARANTINE_FILE}")

    set_offset(new_offset)


if __name__ == "__main__":
    main()
