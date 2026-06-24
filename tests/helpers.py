"""Shared test helpers: path setup, in-memory Settings, and fake IMAP clients."""

from __future__ import annotations

import configparser
import imaplib
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import common  # noqa: E402
from imap_monitor import Settings  # noqa: E402


def make_settings(**overrides) -> Settings:
    cfg = configparser.ConfigParser()
    cfg["imap"] = {
        "host": overrides.get("host", "imap.example.com"),
        "port": str(overrides.get("port", 993)),
        "ssl": str(overrides.get("ssl", True)),
        "user": overrides.get("user", "user@example.com"),
        "password": overrides.get("password", "SECRET-PW-123"),
        "folder": overrides.get("folder", "INBOX"),
    }
    cfg["monitor"] = {
        "mode": overrides.get("mode", "poll"),
        "poll_seconds": str(overrides.get("poll_seconds", 30)),
        "idle_refresh_seconds": str(overrides.get("idle_refresh_seconds", 60)),
        "vantage": overrides.get("vantage", "test"),
    }
    cfg["privacy"] = {
        "redact": overrides.get("redact", "hash"),
        "salt": overrides.get("salt", "test-salt"),
    }
    return Settings(cfg)


def use_temp_logs(tmp_path: Path) -> None:
    """Redirect EventLog output to a temp dir for the duration of a test."""
    common.LOG_DIR = Path(tmp_path)
    common.LOG_DIR.mkdir(exist_ok=True)


def read_rows(log_dir, glob_pattern: str) -> list:
    """Read all CSV rows matching a glob under log_dir (closes the file)."""
    import csv
    rows = []
    for f in sorted(Path(log_dir).glob(glob_pattern)):
        with f.open(encoding="utf-8") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

class FakeIMAPClient:
    """Stand-in for imapclient.IMAPClient (IDLE mode)."""

    def __init__(self, existing=None, login_exc=None, select_exc=None,
                 noop_exc=None, search_results=None, fetch_data=None):
        self.existing = existing or []
        self.login_exc = login_exc
        self.select_exc = select_exc
        self.noop_exc = noop_exc
        self.search_results = search_results if search_results is not None else []
        self.fetch_data = fetch_data or {}
        self.logged_out = False
        self.fetch_items = None

    def login(self, user, password):
        if self.login_exc:
            raise self.login_exc

    def select_folder(self, folder):
        if self.select_exc:
            raise self.select_exc

    def search(self, criteria):
        if criteria == ["ALL"]:
            return self.existing
        return self.search_results

    def idle(self):
        pass

    def idle_done(self):
        pass

    def noop(self):
        if self.noop_exc:
            raise self.noop_exc
        return b"NOOP completed"

    def fetch(self, uids, items):
        self.fetch_items = items
        return {u: self.fetch_data.get(u, {}) for u in uids}

    def logout(self):
        self.logged_out = True


class FakeIMAP4:
    """Stand-in for imaplib.IMAP4 / IMAP4_SSL (poll mode)."""

    error = imaplib.IMAP4.error
    abort = imaplib.IMAP4.abort

    def __init__(self, mailbox, login_exc=None, select_exc=None):
        # mailbox: list of dicts {uid, internaldate, size, header}
        self.mailbox = mailbox
        self.login_exc = login_exc
        self.select_exc = select_exc
        self.fetch_items = None
        self.logged_out = False

    def login(self, user, password):
        if self.login_exc:
            raise self.login_exc
        return ("OK", [b"LOGIN completed"])

    def select(self, folder, readonly=False):
        if self.select_exc:
            raise self.select_exc
        return ("OK", [str(len(self.mailbox)).encode()])

    def uid(self, command, *args):
        if command == "search":
            ids = b" ".join(str(m["uid"]).encode() for m in self.mailbox)
            return ("OK", [ids])
        if command == "fetch":
            uid = int(args[0])
            self.fetch_items = args[1]
            m = next((x for x in self.mailbox if x["uid"] == uid), None)
            if m is None:
                return ("OK", [None])
            hdr = m["header"]
            meta = (f'{uid} (INTERNALDATE "{m["internaldate"]}" '
                    f'RFC822.SIZE {m["size"]} '
                    f'BODY[HEADER.FIELDS (MESSAGE-ID DATE FROM TO SUBJECT)] '
                    f'{{{len(hdr)}}}')
            return ("OK", [(meta.encode(), hdr), b")"])
        return ("OK", [b""])

    def logout(self):
        self.logged_out = True
        return ("BYE", [b"LOGOUT"])
