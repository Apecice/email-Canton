"""Report aggregation: empty logs, delay stats, and connectivity counting."""

import csv
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (sets sys.path)
import report


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


class TestReport(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.log_dir = Path(self._td.name)
        report.LOG_DIR = self.log_dir

    def tearDown(self):
        self._td.cleanup()

    def test_empty_logs_do_not_crash(self):
        lines = []
        report.summarize_messages(lines)
        report.summarize_connection(lines)
        report.summarize_netprobe(lines)
        text = "\n".join(lines)
        self.assertIn("no message records", text)
        self.assertIn("no connection records", text)

    def test_delay_threshold_counts(self):
        rows = [
            {"detected_at": "x", "vantage": "mainland", "server_to_client_delay_sec": "10"},
            {"detected_at": "x", "vantage": "mainland", "server_to_client_delay_sec": "400"},
            {"detected_at": "x", "vantage": "mainland", "server_to_client_delay_sec": "2000"},
        ]
        _write_csv(self.log_dir / "messages_mainland_1.csv",
                   ["detected_at", "vantage", "server_to_client_delay_sec"], rows)
        lines = []
        report.summarize_messages(lines)
        text = "\n".join(lines)
        self.assertIn("delayed > 5 min: 2", text)   # 400 and 2000
        self.assertIn("delayed > 30 min: 1", text)  # 2000 only

    def test_netprobe_counts_tcp_failures(self):
        rows = [
            {"vantage": "mainland", "host": "h", "port": "993", "ok": "True",
             "tcp_ok": "True", "tcp_connect_ms": "100"},
            {"vantage": "mainland", "host": "h", "port": "993", "ok": "False",
             "tcp_ok": "False", "tcp_connect_ms": "", "error": "timeout"},
            # TLS failed but TCP fine -> should NOT count as a connectivity failure.
            {"vantage": "mainland", "host": "h", "port": "993", "ok": "False",
             "tcp_ok": "True", "tcp_connect_ms": "120", "error": "cert"},
        ]
        _write_csv(self.log_dir / "netprobe_mainland_1.csv",
                   ["vantage", "host", "port", "ok", "tcp_ok", "tcp_connect_ms", "error"],
                   rows)
        lines = []
        report.summarize_netprobe(lines)
        text = "\n".join(lines)
        # Exactly one genuine TCP-connectivity failure of three probes.
        self.assertIn("tcp_fail=1", text)


if __name__ == "__main__":
    unittest.main()
