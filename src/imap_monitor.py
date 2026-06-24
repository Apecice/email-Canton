"""IMAP delivery & connection monitor.

Goal: produce hard evidence for the question "did the mail reach the server long
before my client noticed it, and is my long-lived connection silently dying?"

For every new message it records:
  - INTERNALDATE  -> when the *server* received it (independent of your client)
  - Date header   -> when the sender claims they sent it
  - detected_at   -> when THIS monitor first saw it on a fresh/idle connection
  -> server_to_client_delay_sec = detected_at - INTERNALDATE  (the smoking gun)

It also logs every connection lifecycle event (connect / login / idle start /
idle wakeups / drops / errors / reconnects) so you can see exactly how long an
idle connection survives across the mainland<->HK border before it goes dead.

Two modes:
  idle  -> uses IMAP IDLE (needs `imapclient`). Best at catching silent drops.
  poll  -> reconnects + searches every N seconds using only the stdlib.
The monitor auto-falls back to poll if imapclient is unavailable.

Privacy: only headers/metadata are fetched, never the body. From/To/Subject are
hashed by default (configurable). See config.ini -> [privacy].
"""

from __future__ import annotations

import argparse
import email
import email.utils
import signal
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

from common import (
    ConfigError, EventLog, iso, load_config, now_utc, redact, validate_config,
)

try:
    from imapclient import IMAPClient  # type: ignore
    from imapclient.exceptions import LoginError as _IMAPClientLoginError  # type: ignore
    HAVE_IMAPCLIENT = True
except Exception:  # pragma: no cover - optional dependency
    HAVE_IMAPCLIENT = False
    _IMAPClientLoginError = ()  # type: ignore

import imaplib

_STOP = False

# How long each idle_check slice waits before we re-check the stop flag. Keeps
# Ctrl-C responsive even when idle_refresh is several minutes.
IDLE_SLICE_SECONDS = 15


class PermanentError(Exception):
    """A non-retryable error (bad credentials, missing folder). Retrying it
    forever is pointless and hides the real problem from the user."""

    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind      # "auth" | "mailbox"
        self.detail = detail


def _is_permanent_error(exc: BaseException) -> bool:
    """Distinguish "give up and tell the user" from "reconnect and retry".

    - imaplib.IMAP4.abort  -> the connection died; reconnect (TRANSIENT).
    - imapclient LoginError / imaplib.IMAP4.error -> server rejected us at the
      protocol level (wrong password, bad mailbox); retrying won't help.
    - OSError / socket timeout -> network blip; reconnect (TRANSIENT).
    """
    if isinstance(exc, imaplib.IMAP4.abort):
        return False
    if HAVE_IMAPCLIENT and isinstance(exc, _IMAPClientLoginError):
        return True
    if isinstance(exc, imaplib.IMAP4.error):
        return True
    return False


def _handle_signal(signum, frame):
    global _STOP
    _STOP = True
    print("\n[*] Stopping after current cycle...", flush=True)


# The ONLY thing we ever fetch from a message. BODY.PEEK = read headers without
# downloading the body and without setting the \Seen flag. We never request
# BODY[], BODY[TEXT] or RFC822.TEXT, so message content never leaves the server.
HEADER_FETCH = "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID DATE FROM TO SUBJECT)]"
FETCH_ITEMS = ["INTERNALDATE", "RFC822.SIZE", HEADER_FETCH]


def _parse_headers(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw)
    return {
        "message_id": (msg.get("Message-ID") or "").strip(),
        "date_header": (msg.get("Date") or "").strip(),
        "from": (msg.get("From") or "").strip(),
        "to": (msg.get("To") or "").strip(),
        "subject": (msg.get("Subject") or "").strip(),
    }


def _date_header_to_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(value)
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class Settings:
    def __init__(self, cfg):
        self.host = cfg.get("imap", "host")
        self.port = cfg.getint("imap", "port", fallback=993)
        self.user = cfg.get("imap", "user")
        self.password = cfg.get("imap", "password")
        self.folder = cfg.get("imap", "folder", fallback="INBOX")
        self.use_ssl = cfg.getboolean("imap", "ssl", fallback=True)
        self.mode = cfg.get("monitor", "mode", fallback="idle").lower()
        self.poll_seconds = cfg.getint("monitor", "poll_seconds", fallback=30)
        self.idle_refresh = cfg.getint("monitor", "idle_refresh_seconds", fallback=300)
        self.vantage = cfg.get("monitor", "vantage", fallback="unknown")
        self.redact_mode = cfg.get("privacy", "redact", fallback="hash").lower()
        self.salt = cfg.get("privacy", "salt", fallback="changeme")


def _record_message(log: EventLog, st: Settings, kind: str, internaldate: datetime | None,
                    size: int | None, headers: dict) -> None:
    detected = now_utc()
    delay = ""
    if internaldate is not None:
        delay = round((detected - internaldate).total_seconds(), 1)
    log.message({
        "detected_at": iso(detected),
        "vantage": st.vantage,
        "kind": kind,
        "folder": st.folder,
        "message_id": redact(headers.get("message_id"), st.redact_mode, st.salt),
        "internaldate": iso(internaldate),
        "date_header": headers.get("date_header", ""),
        "from": redact(headers.get("from"), st.redact_mode, st.salt),
        "to": redact(headers.get("to"), st.redact_mode, st.salt),
        "subject": redact(headers.get("subject"), st.redact_mode, st.salt),
        "size_bytes": "" if size is None else size,
        "server_to_client_delay_sec": delay,
    })
    sj = "" if internaldate is None else f"  server->client delay: {delay}s"
    print(f"  + new message detected ({kind}){sj}", flush=True)


# --------------------------------------------------------------------------- #
# IDLE mode (imapclient)
# --------------------------------------------------------------------------- #

def _default_make_client(st: "Settings"):
    return IMAPClient(st.host, port=st.port, ssl=st.use_ssl, timeout=30)


def _establish_idle(st: "Settings", log: EventLog, make_client) -> "IMAPClient":
    """Connect + login + select. Raises PermanentError for non-retryable
    problems so the caller can stop instead of looping forever."""
    log.connection("connect", f"{st.host}:{st.port} ssl={st.use_ssl}", vantage=st.vantage)
    client = make_client(st)
    try:
        client.login(st.user, st.password)
    except Exception as exc:
        if _is_permanent_error(exc):
            raise PermanentError("auth", f"login rejected: {exc!r}") from exc
        raise
    log.connection("login_ok", st.user, vantage=st.vantage)
    try:
        client.select_folder(st.folder)
    except Exception as exc:
        if _is_permanent_error(exc):
            raise PermanentError("mailbox",
                                 f"cannot select folder {st.folder!r}: {exc!r}") from exc
        raise
    return client


def _idle_wait(client, st: "Settings"):
    """Wait for IDLE activity in small slices so a stop request is honoured
    quickly. Returns (responses, idle_seconds)."""
    start = time.monotonic()
    remaining = st.idle_refresh
    while remaining > 0 and not _STOP:
        chunk = min(IDLE_SLICE_SECONDS, remaining)
        responses = client.idle_check(timeout=chunk)
        if responses:
            return responses, time.monotonic() - start
        remaining -= chunk
    return [], time.monotonic() - start


def _check_alive(client, st: "Settings", log: EventLog) -> bool:
    """NOOP probe. False means the long-lived connection has silently died --
    exactly the failure that forces a client restart to receive mail."""
    try:
        client.noop()
        log.connection("noop_ok", "connection still alive", vantage=st.vantage)
        return True
    except Exception as exc:
        log.connection("noop_fail", f"connection is DEAD: {exc!r}", vantage=st.vantage)
        return False


def _handle_new_idle(client, st: "Settings", log: EventLog, seen_max_uid: int) -> int:
    """After an IDLE wake-up, report genuinely new messages and return the new
    high-water UID. Filters the IMAP "N:*" quirk that can echo the highest
    existing UID even when nothing newer arrived."""
    found = client.search(["UID", f"{seen_max_uid + 1}:*"])
    new_uids = [u for u in found if u > seen_max_uid]
    if not new_uids:
        return seen_max_uid
    return _report_uids(client, st, log, new_uids, "idle")


def run_idle(st: Settings, log: EventLog, make_client=None,
             max_reconnects: int | None = None) -> None:
    make_client = make_client or _default_make_client
    backoff = 2
    seen_max_uid = 0
    reconnects = 0
    while not _STOP:
        client = None
        try:
            client = _establish_idle(st, log, make_client)
            backoff = 2

            # Baseline: highest existing UID so we only report genuinely new mail.
            existing = client.search(["ALL"])
            if existing:
                seen_max_uid = max(seen_max_uid, max(existing))
            log.connection("baseline", f"max_uid={seen_max_uid} count={len(existing)}",
                           vantage=st.vantage)

            while not _STOP:
                client.idle()
                log.connection("idle_start", "", vantage=st.vantage)
                responses, idle_dur = _idle_wait(client, st)
                client.idle_done()

                if responses:
                    log.connection("idle_wake", str(responses)[:200],
                                   idle_seconds=idle_dur, vantage=st.vantage)
                    seen_max_uid = _handle_new_idle(client, st, log, seen_max_uid)
                elif _STOP:
                    break
                else:
                    # No server traffic for the whole window: is the socket alive?
                    log.connection("idle_timeout", f"no activity for {st.idle_refresh}s",
                                   idle_seconds=idle_dur, vantage=st.vantage)
                    if not _check_alive(client, st, log):
                        raise imaplib.IMAP4.abort("NOOP failed - connection dead")

        except PermanentError as exc:
            log.connection(f"{exc.kind}_error", exc.detail, vantage=st.vantage)
            break
        except KeyboardInterrupt:
            break
        except Exception as exc:
            log.connection("drop", repr(exc), vantage=st.vantage)
            if _STOP:
                break
            reconnects += 1
            if max_reconnects is not None and reconnects >= max_reconnects:
                break
            log.connection("reconnect_wait", f"{backoff}s", vantage=st.vantage)
            _sleep_interruptible(backoff)
            backoff = min(backoff * 2, 60)
        finally:
            if client is not None:
                try:
                    client.logout()
                except Exception:
                    pass


def _report_uids(client, st: Settings, log: EventLog, uids: list[int], kind: str) -> int:
    data = client.fetch(uids, FETCH_ITEMS)
    max_uid = max(uids)
    for uid in sorted(uids):
        info = data.get(uid, {})
        internaldate = info.get(b"INTERNALDATE")
        if internaldate is not None and internaldate.tzinfo is None:
            internaldate = internaldate.replace(tzinfo=timezone.utc)
        size = info.get(b"RFC822.SIZE")
        raw = b""
        for k, v in info.items():
            if isinstance(k, bytes) and k.startswith(b"BODY"):
                raw = v
                break
        headers = _parse_headers(raw) if raw else {}
        _record_message(log, st, kind, internaldate, size, headers)
    return max_uid


# --------------------------------------------------------------------------- #
# Poll mode (stdlib imaplib only)
# --------------------------------------------------------------------------- #

def _sleep_interruptible(seconds: float) -> None:
    slept = 0.0
    while slept < seconds and not _STOP:
        step = min(1.0, seconds - slept)
        time.sleep(step)
        slept += step


def _default_connect_imaplib(st: "Settings"):
    if st.use_ssl:
        return imaplib.IMAP4_SSL(st.host, st.port,
                                 ssl_context=ssl.create_default_context(), timeout=30)
    return imaplib.IMAP4(st.host, st.port, timeout=30)


def _establish_poll(st: "Settings", log: EventLog, connect):
    log.connection("connect", f"{st.host}:{st.port} ssl={st.use_ssl}", vantage=st.vantage)
    started = time.monotonic()
    conn = connect(st)
    try:
        conn.login(st.user, st.password)
    except Exception as exc:
        if _is_permanent_error(exc):
            raise PermanentError("auth", f"login rejected: {exc!r}") from exc
        raise
    log.connection("login_ok", st.user, idle_seconds=time.monotonic() - started,
                   vantage=st.vantage)
    try:
        conn.select(st.folder, readonly=True)
    except Exception as exc:
        if _is_permanent_error(exc):
            raise PermanentError("mailbox",
                                 f"cannot select folder {st.folder!r}: {exc!r}") from exc
        raise
    return conn


def run_poll(st: Settings, log: EventLog, connect=None, sleeper=None,
             max_cycles: int | None = None) -> None:
    connect = connect or _default_connect_imaplib
    sleeper = sleeper or _sleep_interruptible
    seen_uids: set[str] = set()
    primed = False
    cycles = 0
    while not _STOP:
        conn = None
        try:
            conn = _establish_poll(st, log, connect)

            typ, data = conn.uid("search", None, "ALL")
            uids = data[0].split() if data and data[0] else []
            uid_strs = [u.decode() for u in uids]

            if not primed:
                seen_uids = set(uid_strs)
                primed = True
                log.connection("baseline", f"count={len(seen_uids)}", vantage=st.vantage)
            else:
                new = [u for u in uid_strs if u not in seen_uids]
                if new:
                    log.connection("poll_new", f"{len(new)} new", vantage=st.vantage)
                    for u in new:
                        _poll_report(conn, st, log, u)
                        seen_uids.add(u)
                else:
                    log.connection("poll_empty", "no new mail", vantage=st.vantage)
        except PermanentError as exc:
            log.connection(f"{exc.kind}_error", exc.detail, vantage=st.vantage)
            break
        except KeyboardInterrupt:
            break
        except Exception as exc:
            log.connection("drop", repr(exc), vantage=st.vantage)
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:
                    pass

        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            break
        if _STOP:
            break
        sleeper(st.poll_seconds if primed else 1)


def _poll_report(conn: imaplib.IMAP4, st: Settings, log: EventLog, uid: str) -> None:
    typ, data = conn.uid("fetch", uid, f"({' '.join(FETCH_ITEMS)})")
    internaldate = None
    size = None
    headers: dict = {}
    for part in data:
        if isinstance(part, tuple):
            meta = part[0].decode("latin-1", "replace")
            internaldate = _imaplib_internaldate(meta)
            size = _imaplib_size(meta)
            headers = _parse_headers(part[1])
    _record_message(log, st, "poll", internaldate, size, headers)


def _imaplib_internaldate(meta: str) -> datetime | None:
    import re
    m = re.search(r'INTERNALDATE "([^"]+)"', meta)
    if not m:
        return None
    parsed = imaplib.Internaldate2tuple(f'INTERNALDATE "{m.group(1)}"'.encode())
    if parsed is None:
        return None
    return datetime.fromtimestamp(time.mktime(parsed), tz=timezone.utc)


def _imaplib_size(meta: str) -> int | None:
    import re
    m = re.search(r"RFC822\.SIZE (\d+)", meta)
    return int(m.group(1)) if m else None


def main() -> int:
    parser = argparse.ArgumentParser(description="IMAP delivery & connection monitor")
    parser.add_argument("-c", "--config", help="path to config.ini")
    parser.add_argument("--mode", choices=["idle", "poll"], help="override config mode")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
        validate_config(cfg)
    except ConfigError as exc:
        print(f"[!] {exc}", flush=True)
        return 2
    st = Settings(cfg)
    if args.mode:
        st.mode = args.mode

    if st.redact_mode == "hash" and st.salt.strip().lower() in (
            "", "changeme", "change-this-to-any-random-string"):
        print("[!] Warning: [privacy] salt is still the default. Set a unique salt "
              "in config.ini so hashed identifiers can't be guessed.", flush=True)

    if st.mode == "idle" and not HAVE_IMAPCLIENT:
        print("[!] 'imapclient' not installed; falling back to poll mode "
              "(pip install imapclient for IDLE).", flush=True)
        st.mode = "poll"

    log = EventLog(st.vantage)
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        signal.signal(signal.SIGTERM, _handle_signal)
    except (ValueError, AttributeError):
        pass

    print(f"[*] Monitoring {st.user} on {st.host}:{st.port} "
          f"folder={st.folder} mode={st.mode} vantage={st.vantage}", flush=True)
    print(f"[*] Logs -> {log.msg_csv.parent}", flush=True)
    log.connection("monitor_start",
                   f"mode={st.mode} host={st.host} folder={st.folder} "
                   f"host_machine={socket.gethostname()}", vantage=st.vantage)

    if st.mode == "idle":
        run_idle(st, log)
    else:
        run_poll(st, log)

    log.connection("monitor_stop", "", vantage=st.vantage)
    print("[*] Stopped.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
