"""
app/audit_ledger.py
-------------------
Append-only hash chain (blockchain-like) over analysis runs.

Each entry stores a SHA-256 hash of itself chained with the previous
entry's hash, making any post-hoc tampering detectable.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone


def _db_path(instance_path: str) -> str:
    """Return the absolute path to the SQLite database file."""
    return os.path.join(instance_path, "logguard.db")


def init_ledger(instance_path: str) -> None:
    """Create the ``ledger_entries`` table if it does not exist."""
    os.makedirs(instance_path, exist_ok=True)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger_entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_hash    TEXT    NOT NULL,
                timestamp    TEXT    NOT NULL,
                actor        TEXT    NOT NULL,
                input_hash   TEXT    NOT NULL,
                results_hash TEXT    NOT NULL,
                config_hash  TEXT    NOT NULL,
                entry_hash   TEXT    NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    actor: str,
    input_hash: str,
    results_hash: str,
    config_hash: str,
) -> str:
    """Return the SHA-256 hex-digest of the canonical JSON of the entry fields."""
    payload = json.dumps(
        {
            "prev_hash": prev_hash,
            "timestamp": timestamp,
            "actor": actor,
            "input_hash": input_hash,
            "results_hash": results_hash,
            "config_hash": config_hash,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def append_entry(
    instance_path: str,
    actor: str,
    input_hash: str,
    results_hash: str,
    config_hash: str = "",
) -> None:
    """
    Append a new entry to the ledger.

    The ``entry_hash`` is computed over ``prev_hash + all fields`` so that
    any modification to any earlier entry invalidates the chain.
    """
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        last = conn.execute(
            "SELECT entry_hash FROM ledger_entries ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["entry_hash"] if last else "0" * 64

        ts = datetime.now(timezone.utc).isoformat()
        entry_hash = _compute_entry_hash(
            prev_hash, ts, actor, input_hash, results_hash, config_hash
        )

        conn.execute(
            """
            INSERT INTO ledger_entries
                (prev_hash, timestamp, actor, input_hash, results_hash,
                 config_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (prev_hash, ts, actor, input_hash, results_hash, config_hash, entry_hash),
        )
        conn.commit()
    finally:
        conn.close()


def get_all_entries(instance_path: str) -> list[dict]:
    """Return all ledger entries ordered by insertion order."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM ledger_entries ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def verify_chain(instance_path: str) -> dict:
    """
    Verify the integrity of the entire ledger chain.

    Returns
    -------
    dict
        ``{"valid": bool, "entry_count": int, "error": str | None}``
    """
    entries = get_all_entries(instance_path)
    if not entries:
        return {"valid": True, "entry_count": 0, "error": None}

    for i, entry in enumerate(entries):
        expected_prev = "0" * 64 if i == 0 else entries[i - 1]["entry_hash"]

        if entry["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "entry_count": len(entries),
                "error": (
                    f"Chain broken at entry id={entry['id']}: "
                    "prev_hash mismatch."
                ),
            }

        computed = _compute_entry_hash(
            entry["prev_hash"],
            entry["timestamp"],
            entry["actor"],
            entry["input_hash"],
            entry["results_hash"],
            entry["config_hash"],
        )
        if computed != entry["entry_hash"]:
            return {
                "valid": False,
                "entry_count": len(entries),
                "error": f"Hash mismatch at entry id={entry['id']}.",
            }

    return {"valid": True, "entry_count": len(entries), "error": None}
