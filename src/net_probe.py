"""Network-layer probe for the mail server.

Repeatedly opens a TCP (and optionally TLS) connection to the mail ports and
records connect latency / TLS-handshake latency / failures. Run this alongside
imap_monitor.py to show that the cross-border path itself is slow or flaky --
the network evidence that backs up the application-level delays.

Output: logs/netprobe_<vantage>_<date>.csv  (one row per probe)
"""

from __future__ import annotations

import argparse
import csv
import socket
import ssl
import sys
import time
from pathlib import Path

from common import LOG_DIR, iso, load_config, now_utc

FIELDS = [
    "ts", "vantage", "host", "port", "tls",
    "tcp_connect_ms", "tls_handshake_ms", "ok", "error",
]


def probe_once(host: str, port: int, use_tls: bool, timeout: float) -> dict:
    row = {"ts": iso(now_utc()), "host": host, "port": port, "tls": use_tls,
           "tcp_connect_ms": "", "tls_handshake_ms": "", "ok": False, "error": ""}
    sock = None
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)
        row["tcp_connect_ms"] = round((time.monotonic() - t0) * 1000, 1)
        if use_tls:
            ctx = ssl.create_default_context()
            t1 = time.monotonic()
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            row["tls_handshake_ms"] = round((time.monotonic() - t1) * 1000, 1)
            ssock.close()
            sock = None
        row["ok"] = True
    except Exception as exc:
        row["error"] = repr(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="Mail server network probe")
    parser.add_argument("-c", "--config", help="path to config.ini")
    parser.add_argument("--interval", type=int, default=60, help="seconds between probes")
    args = parser.parse_args()

    cfg = load_config(args.config)
    host = cfg.get("imap", "host")
    vantage = cfg.get("monitor", "vantage", fallback="unknown")
    # Probe IMAPS plus the submission/SMTPS ports if present.
    targets = [(host, cfg.getint("imap", "port", fallback=993), True)]
    if cfg.has_section("smtp"):
        smtp_host = cfg.get("smtp", "host", fallback=host)
        for p in cfg.get("smtp", "ports", fallback="587,465").split(","):
            p = p.strip()
            if p.isdigit():
                targets.append((smtp_host, int(p), p == "465"))

    LOG_DIR.mkdir(exist_ok=True)
    stamp = now_utc().strftime("%Y%m%d")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in vantage)
    out = LOG_DIR / f"netprobe_{safe}_{stamp}.csv"
    if not out.exists() or out.stat().st_size == 0:
        with out.open("w", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=FIELDS).writeheader()

    print(f"[*] Probing {targets} every {args.interval}s -> {out}", flush=True)
    try:
        while True:
            for host_t, port_t, tls_t in targets:
                row = probe_once(host_t, port_t, tls_t, timeout=15)
                row["vantage"] = vantage
                with out.open("a", newline="", encoding="utf-8") as fh:
                    csv.DictWriter(fh, fieldnames=FIELDS).writerow(
                        {k: row.get(k, "") for k in FIELDS})
                status = "OK " if row["ok"] else "FAIL"
                print(f"[{row['ts']}] {host_t}:{port_t} {status} "
                      f"tcp={row['tcp_connect_ms']}ms tls={row['tls_handshake_ms']}ms "
                      f"{row['error']}", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Stopped.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
