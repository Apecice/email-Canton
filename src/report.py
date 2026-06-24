"""Summarize collected logs into a shareable, redacted report.

Reads the CSV logs produced by imap_monitor.py and net_probe.py and prints (and
writes to reports/) a plain-text summary that contains NO message content -- only
aggregate statistics and connection timelines. This is the artifact you can safely
forward to your e-mail provider / IT as evidence.
"""

from __future__ import annotations

import argparse
import csv
import glob
import statistics
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"


def _read(pattern: str) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(glob.glob(str(LOG_DIR / pattern))):
        with open(path, newline="", encoding="utf-8") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


def _f(value: str):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _pct(values, p):
    if not values:
        return None
    values = sorted(values)
    k = (len(values) - 1) * (p / 100)
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def summarize_messages(lines: list[str]) -> None:
    rows = _read("messages_*.csv")
    lines.append("=" * 70)
    lines.append("MESSAGE DELIVERY DELAY  (detected_at - server INTERNALDATE)")
    lines.append("=" * 70)
    if not rows:
        lines.append("  (no message records found)\n")
        return
    by_vantage: dict[str, list[float]] = {}
    for r in rows:
        d = _f(r.get("server_to_client_delay_sec", ""))
        if d is not None:
            by_vantage.setdefault(r.get("vantage", "?"), []).append(d)
    lines.append(f"  total messages recorded: {len(rows)}\n")
    for vantage, delays in sorted(by_vantage.items()):
        lines.append(f"  vantage: {vantage}   (n={len(delays)})")
        lines.append(f"    min / median / p95 / max delay (s): "
                     f"{min(delays):.1f} / {statistics.median(delays):.1f} / "
                     f"{(_pct(delays, 95) or 0):.1f} / {max(delays):.1f}")
        slow = [d for d in delays if d > 300]
        lines.append(f"    messages delayed > 5 min: {len(slow)} "
                     f"({100 * len(slow) / len(delays):.0f}%)")
        vslow = [d for d in delays if d > 1800]
        lines.append(f"    messages delayed > 30 min: {len(vslow)} "
                     f"({100 * len(vslow) / len(delays):.0f}%)\n")


def summarize_connection(lines: list[str]) -> None:
    rows = _read("connection_*.csv")
    lines.append("=" * 70)
    lines.append("CONNECTION STABILITY  (long-lived IMAP connection health)")
    lines.append("=" * 70)
    if not rows:
        lines.append("  (no connection records found)\n")
        return
    counts: dict[str, int] = {}
    idle_durations: list[float] = []
    drops: list[dict] = []
    noop_fail = 0
    for r in rows:
        ev = r.get("event", "")
        counts[ev] = counts.get(ev, 0) + 1
        if ev in ("idle_timeout", "idle_wake"):
            d = _f(r.get("idle_seconds", ""))
            if d:
                idle_durations.append(d)
        if ev == "drop":
            drops.append(r)
        if ev == "noop_fail":
            noop_fail += 1
    lines.append("  event counts:")
    for ev, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"    {ev:18} {c}")
    lines.append("")
    lines.append(f"  connection drops:        {len(drops)}")
    lines.append(f"  silent-death (noop_fail): {noop_fail}   "
                 f"<- these prove the connection died without notice")
    if idle_durations:
        lines.append(f"  idle window before wake/timeout (s): "
                     f"median={statistics.median(idle_durations):.0f} "
                     f"max={max(idle_durations):.0f}")
    if drops:
        lines.append("\n  recent drop reasons:")
        for r in drops[-8:]:
            lines.append(f"    [{r.get('ts','')}] {r.get('detail','')[:90]}")
    lines.append("")


def summarize_netprobe(lines: list[str]) -> None:
    rows = _read("netprobe_*.csv")
    lines.append("=" * 70)
    lines.append("NETWORK PATH  (TCP/TLS connect latency & failures to mail ports)")
    lines.append("=" * 70)
    if not rows:
        lines.append("  (no network probe records found)\n")
        return
    truthy = ("True", "true", "1")
    groups: dict[tuple, dict] = {}
    for r in rows:
        key = (r.get("vantage", "?"), r.get("host", ""), r.get("port", ""))
        g = groups.setdefault(key, {"tcp": [], "tcp_fail": 0, "tls_fail": 0, "n": 0})
        g["n"] += 1
        # Prefer the explicit tcp_ok signal; fall back to ok for older logs.
        tcp_ok = r.get("tcp_ok", "") in truthy if r.get("tcp_ok", "") != "" \
            else r.get("ok") in truthy
        full_ok = r.get("ok") in truthy
        if tcp_ok:
            t = _f(r.get("tcp_connect_ms", ""))
            if t is not None:
                g["tcp"].append(t)
            if not full_ok:
                g["tls_fail"] += 1  # connected but TLS handshake failed
        else:
            g["tcp_fail"] += 1      # genuine connectivity failure
    for (vantage, host, port), g in sorted(groups.items()):
        tcp = g["tcp"]
        med = f"{statistics.median(tcp):.0f}" if tcp else "n/a"
        p95 = f"{(_pct(tcp, 95) or 0):.0f}" if tcp else "n/a"
        fail_pct = 100 * g["tcp_fail"] / g["n"] if g["n"] else 0
        lines.append(f"  {vantage} -> {host}:{port}  probes={g['n']}  "
                     f"tcp_fail={g['tcp_fail']} ({fail_pct:.0f}%)  "
                     f"tls_fail={g['tls_fail']}  "
                     f"tcp_connect median={med}ms p95={p95}ms")
    lines.append("")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a redacted evidence report")
    parser.parse_args()
    lines: list[str] = []
    lines.append("CANTONSERVICES MAIL DELIVERY DIAGNOSTIC REPORT")
    lines.append(f"generated: {datetime.now().astimezone().isoformat()}")
    lines.append("note: contains metadata/aggregates only -- no message content.\n")
    summarize_messages(lines)
    summarize_connection(lines)
    summarize_netprobe(lines)
    lines.append("=" * 70)
    lines.append("HOW TO READ THIS")
    lines.append("=" * 70)
    lines.append(
        "  * If 'server INTERNALDATE' is much earlier than 'detected_at', the mail\n"
        "    reached the HK server on time but your client could not pull it -> the\n"
        "    problem is the cross-border CONNECTION, not the mail server's delivery.\n"
        "  * 'noop_fail' / 'drop' events show your long-lived IMAP connection dying\n"
        "    silently -- which is exactly why a client restart 'fixes' it.\n"
        "  * Compare two vantages (mainland vs HK/overseas): if HK shows ~0 delay and\n"
        "    no drops while mainland shows large delays/drops, the border path is the\n"
        "    cause.")

    report = "\n".join(lines)
    print(report)
    REPORT_DIR.mkdir(exist_ok=True)
    out = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    out.write_text(report + "\n", encoding="utf-8")
    print(f"\n[*] Saved -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
