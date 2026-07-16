# Honeypot Intelligence Platform

A self-hosted pipeline that captures, normalizes, categorizes, and visualizes
attacker traffic against a decoy web service — built end to end (bait routes,
ingestion, database, dashboards) with no third-party SaaS in the data path.

## Architecture

```
┌─────────────────────┐       SSH + rsync        ┌──────────────────────┐
│  decoy (Azure VM)   │ ────────────────────────▶ │  homelab (local box)  │
│                      │      (pull, every 5min)   │                        │
│  Flask decoy app     │                            │  ingest.py (cron)     │
│  - bait routes       │                            │  ├─ pull_log()        │
│    /admin, /.env,    │                            │  ├─ normalize_event() │
│    /.git/config,     │                            │  ├─ categorize_route()│
│    IDOR-shaped API   │                            │  └─ insert_events()   │
│  - decoy.log         │                            │                        │
│    (flat JSON,       │                            │  Postgres 16 (Docker)│
│    RotatingFileHandler)│                          │  └─ honeypot_events   │
│                      │                            │                        │
│  Headscale (mesh VPN)│                            │  Grafana              │
└─────────────────────┘                            │  └─ 4 dashboard panels│
                                                     └──────────────────────┘
```

Mesh connectivity between nodes runs over a self-hosted Headscale instance
(100.64.x addressing) rather than a commercial VPN/mesh provider — consistent
with a privacy-first, self-hosted-infrastructure approach.

## Data flow

1. **Capture** — Flask app on `decoy` logs every hit to a bait route as a flat
   JSON line via `RotatingFileHandler`.
2. **Pull** — `ingest.py`, run via cron every 5 minutes on `homelab`, rsyncs
   `decoy.log` over SSH (key-based auth, no interactive prompts).
3. **Normalize** — `log_schema.py::normalize_event()` maps whatever shape the
   Flask app wrote into a canonical `HoneypotEvent` dataclass. Malformed or
   unrecognized lines are quarantined (`quarantine.jsonl`), never silently
   dropped.
4. **Categorize** — `log_schema.py::categorize_route()` assigns an
   `attack_category` per event using a two-stage approach (see below).
5. **Store** — `db.py::insert_events()` writes to Postgres, deduplicated on a
   SHA-256 hash of `(timestamp, source_ip, route, payload)` so re-ingesting
   the same event twice is a no-op.
6. **Visualize** — Grafana reads directly from Postgres across four panels
   (attack category breakdown, source IP frequency, timeline, response
   status).

## Attack categorization

Categorization is intentionally two-stage, not a single flat lookup:

**Stage 1 — exact/substring match against `ROUTE_CATEGORY_MAP`.**
A curated, priority-ordered dict mapping known bait-route substrings and
named CVE fingerprints (GeoServer, Hikvision, Pulse Secure/Ivanti,
ThinkPHP, Symfony profiler LFI, Spring Boot Actuator, CVE-2024-4577, etc.)
to categories. Order matters — the first matching pattern wins, so more
specific/higher-severity patterns are placed ahead of broad prefix rules.

**Stage 2 — keyword-heuristic fallback.**
Anything that doesn't hit an exact pattern is checked against a
credential/secret-flavored keyword list (`credential`, `secret`, `token`,
`tfvars`, `service-account`, etc.) before falling through to `unknown`.
This exists because scanners use inconsistent naming for the same class of
target file (`db.sql` vs `dump.sql` vs `database.yml`) — an exact-match-only
map would require an ever-growing list of literal filenames and still miss
novel variants.

Categories in use: `credential_access`, `sensitive_file_disclosure`,
`info_disclosure`, `rce_attempt`, `known_cve_probe`, `cve_2024_4577_rce`,
`infra_recon`, `idor_probe`, `scanner_fingerprint`, `unknown`.

**Backfill.** `attack_category` is computed once at ingest time and stored,
not recomputed on read — so categorization-logic improvements don't
retroactively apply to historical rows automatically. `backfill_categories.py`
recomputes every row's category from the stored raw JSONB (not from the
possibly-already-wrong `attack_category` column), so repeated backfills don't
compound drift. Always supports `--dry-run` before writing.

## Current dataset snapshot

Run this to regenerate current numbers (the table below should be updated
whenever this README is revisited — don't trust stale figures):

```bash
python3 -c "
from db import get_connection
with get_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(\"SELECT attack_category, COUNT(*) FROM honeypot_events GROUP BY attack_category ORDER BY COUNT(*) DESC;\")
        for cat, count in cur.fetchall():
            print(count, cat)
"
```

| Category | Count |
|---|---|
| _(run query above and fill in)_ | |

## Key engineering decisions

- **Server-side cursor for backfill** — `backfill_categories.py` uses a
  named psycopg2 cursor (`cursor(name=...)`) rather than pulling the full
  table into memory, since the event table can exceed 10k+ rows.
- **Batched writes** — backfill updates are batched via `executemany` in
  groups of 500, not one round-trip per row.
- **Dead-man's-switch alerting** — a Discord webhook fires if ingestion
  goes stale (no new events within the expected cron interval), rather than
  relying on someone noticing an empty dashboard.
- **Credential hygiene, the hard way** — an early version of this pipeline
  had a hardcoded Postgres connection string duplicated across `.zshrc` and
  a systemd-managed `.env`, which caused a 13+ hour silent ingestion failure
  when the two drifted out of sync. Credentials are now `.env`-scoped
  (`chmod 600`), loaded via `python-dotenv`, and the systemd/cron execution
  path is treated as the source of truth — not the interactive shell.

## Setup

```bash
pip install -r requirements.txt --break-system-packages   # no venv yet, see Known limitations
cp .env.example .env   # fill in POSTGRES_CONN_STRING, HONEYPOT_SSH_USER, HONEYPOT_VM_IP
chmod 600 .env
python3 backfill_categories.py --dry-run   # sanity check before first real run
```

Cron (every 5 minutes):
```
*/5 * * * * /usr/bin/python3 /home/epedev/honeypot-grafana-pipeline/ingest.py >> /home/epedev/honeypot-grafana-pipeline/ingest.log 2>&1
```

## Known limitations / open items

Documented deliberately rather than hidden — these are understood gaps, not
undiscovered ones:

- **No venv** — currently runs against system Python with
  `pip install --break-system-packages`. Fragile against system package
  upgrades; wrapping in a venv is the next infra task.
- **No rsync timeout or lockfile** — `ingest.py`'s `pull_log()` has no
  `timeout=` on the rsync subprocess call, and nothing prevents two
  overlapping cron invocations from racing on the offset file if one run
  hangs.
- **`db.py` has unused blob-tracking code** (`processed_blobs`,
  `is_blob_processed`, `mark_blob_processed`) left over from an earlier
  Azure Blob Storage-based design that was replaced by direct SSH pull.
  Not wired into the current pipeline; scheduled for removal.
- **No unit tests on `categorize_route()`** — the single function
  determining every event's classification has no automated test coverage.
  Given a keyword-heuristic fallback exists, this is a real gap: a future
  edit could silently break classification for a whole category with no
  signal until a manual audit catches it.
- **`unknown` residual (~20% of dataset)** — after exact-match and keyword
  heuristic passes, roughly one-fifth of traffic remains uncategorized.
  This is treated as an accepted baseline (genuinely diverse internet scan
  noise) rather than a target to drive to zero — see the categorization
  section above for the tradeoff reasoning.
