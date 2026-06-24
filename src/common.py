"""Shared helpers: config loading, privacy-safe redaction, and log writers.

This project NEVER reads or stores e-mail bodies. It only records metadata
(timestamps, sizes, identifiers) needed to prove *where* delivery breaks down.
"""

from __future__ import annotations

import configparser
import csv
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config.ini"
LOG_DIR = PROJECT_ROOT / "logs"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


class ConfigError(Exception):
    """Raised for any user-facing configuration problem (missing/invalid)."""


# Sections/options that must be present and non-blank for the tool to run.
REQUIRED_OPTIONS = {"imap": ["host", "user", "password"]}


def load_config(path: str | os.PathLike | None = None) -> configparser.ConfigParser:
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    if not cfg_path.exists():
        raise ConfigError(
            f"Config not found: {cfg_path}\n"
            f"    Copy config.example.ini to config.ini and fill it in."
        )
    cfg = configparser.ConfigParser()
    try:
        cfg.read(cfg_path, encoding="utf-8")
    except configparser.Error as exc:
        raise ConfigError(f"Could not parse {cfg_path}: {exc}") from exc
    return cfg


def validate_config(cfg: configparser.ConfigParser) -> None:
    """Raise ConfigError listing every missing/blank required field."""
    missing: list[str] = []
    for section, options in REQUIRED_OPTIONS.items():
        if not cfg.has_section(section):
            missing.extend(f"{section}.{opt}" for opt in options)
            continue
        for opt in options:
            if not cfg.has_option(section, opt) or not cfg.get(section, opt).strip():
                missing.append(f"{section}.{opt}")
    if missing:
        raise ConfigError(
            "config.ini is incomplete. Missing/blank required fields: "
            + ", ".join(missing)
            + "\n    See config.example.ini for the expected layout."
        )


def redact(value: str | None, mode: str, salt: str) -> str:
    """Privacy filter for header values.

    mode = "hash" : irreversible short fingerprint (default; safe to share)
    mode = "full" : keep the raw value (only for your own local debugging)
    mode = "none" : drop it entirely
    """
    if value is None:
        return ""
    value = value.strip()
    if not value:
        return ""
    if mode == "full":
        return value
    if mode == "none":
        return ""
    digest = hashlib.sha256((salt + "|" + value).encode("utf-8")).hexdigest()
    return "h:" + digest[:16]


class EventLog:
    """Thread-safe append writer for connection / message events.

    Writes both a machine-readable JSONL stream and a human-readable CSV.
    """

    MESSAGE_FIELDS = [
        "detected_at",
        "vantage",
        "kind",
        "folder",
        "message_id",
        "internaldate",
        "date_header",
        "from",
        "to",
        "subject",
        "size_bytes",
        "server_to_client_delay_sec",
    ]

    CONN_FIELDS = [
        "ts",
        "vantage",
        "event",
        "detail",
        "idle_seconds",
    ]

    def __init__(self, vantage: str):
        LOG_DIR.mkdir(exist_ok=True)
        stamp = now_utc().strftime("%Y%m%d")
        safe_vantage = "".join(c if c.isalnum() or c in "-_" else "_" for c in vantage)
        self._lock = threading.Lock()
        self.msg_csv = LOG_DIR / f"messages_{safe_vantage}_{stamp}.csv"
        self.msg_jsonl = LOG_DIR / f"messages_{safe_vantage}_{stamp}.jsonl"
        self.conn_csv = LOG_DIR / f"connection_{safe_vantage}_{stamp}.csv"
        self.conn_jsonl = LOG_DIR / f"connection_{safe_vantage}_{stamp}.jsonl"
        self._ensure_header(self.msg_csv, self.MESSAGE_FIELDS)
        self._ensure_header(self.conn_csv, self.CONN_FIELDS)

    @staticmethod
    def _ensure_header(path: Path, fields: list[str]) -> None:
        if not path.exists() or path.stat().st_size == 0:
            with path.open("w", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=fields).writeheader()

    def message(self, row: dict) -> None:
        with self._lock:
            self._append(self.msg_csv, self.msg_jsonl, self.MESSAGE_FIELDS, row)

    def connection(self, event: str, detail: str = "", idle_seconds: float | None = None,
                   vantage: str = "") -> None:
        row = {
            "ts": iso(now_utc()),
            "vantage": vantage,
            "event": event,
            "detail": detail,
            "idle_seconds": "" if idle_seconds is None else round(idle_seconds, 1),
        }
        with self._lock:
            self._append(self.conn_csv, self.conn_jsonl, self.CONN_FIELDS, row)
        line = f"[{row['ts']}] {event:18} {detail}"
        if idle_seconds is not None:
            line += f" (idle {idle_seconds:.1f}s)"
        print(line, flush=True)

    @staticmethod
    def _append(csv_path: Path, jsonl_path: Path, fields: list[str], row: dict) -> None:
        clean = {k: row.get(k, "") for k in fields}
        with csv_path.open("a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=fields).writerow(clean)
        with jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(clean, ensure_ascii=False) + "\n")
