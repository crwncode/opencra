"""Local SQLite cache at ~/.opencra/cache.db with WAL mode."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from opencra_cli.paths import opencra_home

OSV_TTL = timedelta(hours=12)


def default_db_path() -> Path:
    override = os.environ.get("OPENCRA_CACHE")
    if override:
        return Path(override).expanduser()
    return opencra_home() / "cache.db"


class Cache:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._init()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Cache:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kev_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                fetched_at TEXT NOT NULL,
                catalog_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS osv_cache (
                purl TEXT PRIMARY KEY,
                fetched_at TEXT NOT NULL,
                vulns_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS osv_vulns (
                vuln_id TEXT PRIMARY KEY,
                fetched_at TEXT NOT NULL,
                vuln_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                serial_number TEXT,
                sbom_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                purl TEXT,
                name TEXT NOT NULL,
                version TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                purl TEXT NOT NULL,
                osv_id TEXT,
                cve_id TEXT,
                severity TEXT,
                in_kev INTEGER NOT NULL DEFAULT 0,
                summary TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        self.conn.commit()

    def get_kev_catalog(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT catalog_json FROM kev_meta WHERE id = 1").fetchone()
        if not row:
            return None
        return json.loads(row["catalog_json"])

    def get_kev_fetched_at(self) -> datetime | None:
        row = self.conn.execute("SELECT fetched_at FROM kev_meta WHERE id = 1").fetchone()
        if not row:
            return None
        return datetime.fromisoformat(row["fetched_at"])

    def save_kev_catalog(self, payload: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO kev_meta (id, fetched_at, catalog_json)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET fetched_at = excluded.fetched_at,
                                          catalog_json = excluded.catalog_json
            """,
            (now, json.dumps(payload)),
        )
        self.conn.commit()

    def get_osv(self, purl: str) -> list[dict[str, Any]] | None:
        row = self.conn.execute(
            "SELECT fetched_at, vulns_json FROM osv_cache WHERE purl = ?",
            (purl,),
        ).fetchone()
        if not row:
            return None
        fetched = datetime.fromisoformat(row["fetched_at"])
        if datetime.now(timezone.utc) - fetched > OSV_TTL:
            return None
        return json.loads(row["vulns_json"])

    def get_osv_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT fetched_at, vuln_json FROM osv_vulns WHERE vuln_id = ?",
            (vuln_id,),
        ).fetchone()
        if not row:
            return None
        fetched = datetime.fromisoformat(row["fetched_at"])
        if datetime.now(timezone.utc) - fetched > OSV_TTL:
            return None
        payload = json.loads(row["vuln_json"])
        return payload if isinstance(payload, dict) else None

    def save_osv_vuln(self, vuln_id: str, vuln: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO osv_vulns (vuln_id, fetched_at, vuln_json)
            VALUES (?, ?, ?)
            ON CONFLICT(vuln_id) DO UPDATE SET fetched_at = excluded.fetched_at,
                                               vuln_json = excluded.vuln_json
            """,
            (vuln_id, now, json.dumps(vuln)),
        )
        self.conn.commit()

    def save_osv(self, purl: str, vulns: list[dict[str, Any]]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO osv_cache (purl, fetched_at, vulns_json)
            VALUES (?, ?, ?)
            ON CONFLICT(purl) DO UPDATE SET fetched_at = excluded.fetched_at,
                                            vulns_json = excluded.vulns_json
            """,
            (purl, now, json.dumps(vulns)),
        )
        self.conn.commit()

    def save_scan(self, target: str, result_json: dict[str, Any], sbom_json: dict[str, Any]) -> int:
        scanned_at = result_json.get("scanned_at") or datetime.now(timezone.utc).isoformat()
        serial = (result_json.get("sbom") or {}).get("serial_number")
        cur = self.conn.execute(
            """
            INSERT INTO scans (target, scanned_at, serial_number, sbom_json, result_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target, scanned_at, serial, json.dumps(sbom_json), json.dumps(result_json)),
        )
        scan_id = int(cur.lastrowid or 0)
        for component in (result_json.get("sbom") or {}).get("components") or []:
            self.conn.execute(
                "INSERT INTO components (scan_id, purl, name, version) VALUES (?, ?, ?, ?)",
                (scan_id, component.get("purl"), component.get("name"), component.get("version")),
            )
        for match in result_json.get("matches") or []:
            self.conn.execute(
                """
                INSERT INTO matches (scan_id, purl, osv_id, cve_id, severity, in_kev, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    match.get("purl"),
                    match.get("osv_id"),
                    match.get("cve_id"),
                    match.get("severity"),
                    1 if match.get("in_kev") else 0,
                    match.get("summary"),
                ),
            )
        self.conn.commit()
        return scan_id

    def last_scan(self) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT result_json FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return json.loads(row["result_json"])
