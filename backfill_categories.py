"""
Backfill attack_category for all existing rows in honeypot_events.

attack_category is computed once at ingest time and stored — it does NOT
recompute automatically when categorize_route() changes. Every row inserted
before a categorization fix (e.g. the CVE-2024-4577 query-string detection)
keeps its old, possibly-wrong category forever unless this is run.

Safe to re-run any time you change ROUTE_CATEGORY_MAP or categorize_route():
it recomputes from the stored `raw` JSONB (the original ingested event),
not from the possibly-already-wrong attack_category column, so there's no
compounding drift.

Usage:
    python3 backfill_categories.py            # apply changes
    python3 backfill_categories.py --dry-run   # show what would change, no writes
"""
from __future__ import annotations

import sys
from collections import Counter

from db import get_connection
from log_schema import categorize_route

BATCH_SIZE = 500


def backfill(dry_run: bool = False) -> None:
    changed = Counter()  # (old_category -> new_category) counts
    total = 0
    updated = 0

    with get_connection() as conn:
        with conn.cursor(name="backfill_cursor") as read_cur:
            # server-side cursor: table could have 10k+ rows, don't pull it all into memory at once
            read_cur.itersize = BATCH_SIZE
            read_cur.execute(
                "SELECT id, route_hit, attack_category, raw FROM honeypot_events ORDER BY id"
            )

            pending_updates = []

            def flush():
                nonlocal updated
                if not pending_updates:
                    return
                with conn.cursor() as write_cur:
                    write_cur.executemany(
                        "UPDATE honeypot_events SET attack_category = %(new_cat)s WHERE id = %(id)s",
                        pending_updates,
                    )
                updated += len(pending_updates)
                pending_updates.clear()

            for row_id, route_hit, old_category, raw in read_cur:
                total += 1
                query = (raw or {}).get("query") or ""
                new_category = categorize_route(str(route_hit), query)

                if new_category != old_category:
                    changed[f"{old_category} -> {new_category}"] += 1
                    if not dry_run:
                        pending_updates.append({"id": row_id, "new_cat": new_category})
                        if len(pending_updates) >= BATCH_SIZE:
                            flush()

            if not dry_run:
                flush()

    print(f"\nScanned {total} rows.")
    if dry_run:
        print(f"Would update {sum(changed.values())} rows (dry run — no writes made):")
    else:
        print(f"Updated {updated} rows:")
    for transition, count in changed.most_common():
        print(f"  {count:6d}  {transition}")

    if not changed:
        print("  (no category changes needed — everything already matches current logic)")


if __name__ == "__main__":
    backfill(dry_run="--dry-run" in sys.argv)
