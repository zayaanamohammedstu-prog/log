"""
app/run_store.py
----------------
Persistence layer for analysis runs and anomaly results.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone


def _db_path(instance_path: str) -> str:
    """Return the absolute path to the SQLite database file."""
    return os.path.join(instance_path, "logguard.db")


def init_run_store(instance_path: str) -> None:
    """Create analysis run tables if they don't exist yet."""
    os.makedirs(instance_path, exist_ok=True)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                username     TEXT    NOT NULL,
                input_type   TEXT    NOT NULL,
                input_hash   TEXT    NOT NULL,
                filename     TEXT    NOT NULL DEFAULT '',
                summary_json TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id            INTEGER NOT NULL,
                ip_address        TEXT,
                hour_bucket       TEXT,
                features_json     TEXT,
                anomaly_score     REAL,
                is_anomaly        INTEGER,
                ensemble_score    REAL,
                model_scores_json TEXT,
                ensemble_label    TEXT,
                explanations_json TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS attack_chains (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id     INTEGER NOT NULL,
                chain_json TEXT    NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );
            """
        )
        conn.commit()
        # Migrate existing DBs: add new columns if they don't exist yet
        for alter_sql in [
            "ALTER TABLE analysis_runs ADD COLUMN filename TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE analysis_runs ADD COLUMN summary_json TEXT",
        ]:
            try:
                conn.execute(alter_sql)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Column already present
    finally:
        conn.close()


def save_run(
    instance_path: str,
    username: str,
    input_type: str,
    input_hash: str,
    filename: str = "",
    summary_json: str = "",
) -> int:
    """Insert a new analysis run row. Returns the new run_id."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        ts = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO analysis_runs"
            " (timestamp, username, input_type, input_hash, filename, summary_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (ts, username, input_type, input_hash, filename, summary_json or None),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def save_results(
    instance_path: str,
    run_id: int,
    results_records: list[dict],
) -> None:
    """Bulk-insert result rows for a run."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        for rec in results_records:
            conn.execute(
                """
                INSERT INTO analysis_results
                    (run_id, ip_address, hour_bucket, features_json,
                     anomaly_score, is_anomaly, ensemble_score,
                     model_scores_json, ensemble_label, explanations_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    rec.get("ip_address"),
                    rec.get("hour_bucket"),
                    json.dumps(rec.get("features", {})),
                    rec.get("anomaly_score"),
                    int(bool(rec.get("is_anomaly", False))),
                    rec.get("ensemble_score"),
                    json.dumps(rec.get("model_scores", {})),
                    rec.get("ensemble_label"),
                    json.dumps(rec.get("explanations", {})),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def get_run(instance_path: str, run_id: int) -> dict | None:
    """Return run row as dict or None if not found."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM analysis_runs WHERE id = ?", (run_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_runs(instance_path: str, limit: int = 50) -> list[dict]:
    """Return the most recent runs, newest first (summary_json excluded)."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, timestamp, username, input_type, input_hash, filename"
            " FROM analysis_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_run_summary(instance_path: str, run_id: int) -> dict | None:
    """Return the stored summary JSON for a run, or None if not found/missing."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, timestamp, username, input_type, filename, summary_json"
            " FROM analysis_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        raw = row["summary_json"]
        if not raw:
            return None
        summary = json.loads(raw)
        summary["run_id"] = row["id"]
        summary["timestamp"] = row["timestamp"]
        summary["filename"] = row["filename"] or ""
        return summary
    finally:
        conn.close()


def get_run_results(instance_path: str, run_id: int) -> list[dict]:
    """Return all result rows for a run."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM analysis_results WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def save_chains(instance_path: str, run_id: int, chains: list[dict]) -> None:
    """Save a list of chain dicts for a run."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        for chain in chains:
            conn.execute(
                "INSERT INTO attack_chains (run_id, chain_json) VALUES (?, ?)",
                (run_id, json.dumps(chain)),
            )
        conn.commit()
    finally:
        conn.close()


def get_chains(instance_path: str, run_id: int) -> list[dict]:
    """Return all chains for a run, each including its DB id."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, chain_json FROM attack_chains"
            " WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        result = []
        for r in rows:
            chain = json.loads(r["chain_json"])
            chain["id"] = r["id"]
            result.append(chain)
        return result
    finally:
        conn.close()


def get_chain(instance_path: str, run_id: int, chain_id: int) -> dict | None:
    """Return a single chain by its DB id and run_id, or None."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, chain_json FROM attack_chains"
            " WHERE id = ? AND run_id = ?",
            (chain_id, run_id),
        ).fetchone()
        if not row:
            return None
        chain = json.loads(row["chain_json"])
        chain["id"] = row["id"]
        return chain
    finally:
        conn.close()
