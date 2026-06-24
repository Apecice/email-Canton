"""Error-handling scenarios -- the bugs this TDD round is meant to expose & fix.

Covers: auth failure, bad-folder, transient network errors, config validation,
and graceful-stop responsiveness.
"""

import configparser
import imaplib
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import FakeIMAP4, FakeIMAPClient, make_settings, use_temp_logs

import common
import imap_monitor as im


def _events(log_dir: Path):
    import csv
    rows = []
    for f in Path(log_dir).glob("connection_*.csv"):
        with f.open(encoding="utf-8") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


class TestPermanentErrorClassification(unittest.TestCase):
    def test_imap_protocol_error_is_permanent(self):
        self.assertTrue(im._is_permanent_error(imaplib.IMAP4.error("NO bad login")))

    def test_abort_is_transient(self):
        # IMAP4.abort means "reconnect", NOT "give up".
        self.assertFalse(im._is_permanent_error(imaplib.IMAP4.abort("bye")))

    def test_network_error_is_transient(self):
        self.assertFalse(im._is_permanent_error(OSError("conn reset")))
        self.assertFalse(im._is_permanent_error(TimeoutError("timed out")))


class TestAuthFailureStopsInsteadOfLooping(unittest.TestCase):
    def test_poll_auth_failure_does_not_retry_forever(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            calls = {"n": 0}

            def connect(s):
                calls["n"] += 1
                return FakeIMAP4([], login_exc=imaplib.IMAP4.error(
                    "b'[AUTHENTICATIONFAILED] Invalid credentials'"))

            # max_cycles high: if it loops forever it would connect many times.
            im.run_poll(st, log, connect=connect, sleeper=lambda s: None,
                        max_cycles=50)
            self.assertEqual(calls["n"], 1, "should stop after first auth rejection")
            evs = [r["event"] for r in _events(td)]
            self.assertIn("auth_error", evs)

    def test_idle_establish_auth_failure_raises_permanent(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            fake = FakeIMAPClient(login_exc=imaplib.IMAP4.error("NO auth failed"))
            with self.assertRaises(im.PermanentError) as ctx:
                im._establish_idle(st, log, lambda s: fake)
            self.assertEqual(ctx.exception.kind, "auth")


class TestBadFolderStops(unittest.TestCase):
    def test_poll_bad_folder_is_permanent(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings(folder="NoSuchBox")
            log = common.EventLog(st.vantage)
            calls = {"n": 0}

            def connect(s):
                calls["n"] += 1
                return FakeIMAP4([], select_exc=imaplib.IMAP4.error(
                    "SELECT failed: no such mailbox"))

            im.run_poll(st, log, connect=connect, sleeper=lambda s: None,
                        max_cycles=50)
            self.assertEqual(calls["n"], 1)
            self.assertIn("mailbox_error", [r["event"] for r in _events(td)])


class TestTransientErrorRetries(unittest.TestCase):
    def test_poll_network_error_retries_then_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            calls = {"n": 0}

            def connect(s):
                calls["n"] += 1
                raise OSError("connection reset by peer")

            # Transient errors SHOULD retry (up to the bound), not stop at 1.
            im.run_poll(st, log, connect=connect, sleeper=lambda s: None,
                        max_cycles=3)
            self.assertEqual(calls["n"], 3, "transient errors should keep retrying")
            self.assertIn("drop", [r["event"] for r in _events(td)])


class TestConfigValidation(unittest.TestCase):
    def test_missing_file_raises_config_error(self):
        with self.assertRaises(common.ConfigError):
            common.load_config("/nonexistent/path/config.ini")

    def test_malformed_file_raises_config_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as fh:
            fh.write("this is not = a valid\n[unclosed section\n")
            path = fh.name
        with self.assertRaises(common.ConfigError):
            common.load_config(path)

    def test_missing_required_option_reported_clearly(self):
        cfg = configparser.ConfigParser()
        cfg["imap"] = {"host": "imap.example.com"}  # missing user + password
        with self.assertRaises(common.ConfigError) as ctx:
            common.validate_config(cfg)
        msg = str(ctx.exception)
        self.assertIn("user", msg)
        self.assertIn("password", msg)

    def test_blank_required_option_is_rejected(self):
        cfg = configparser.ConfigParser()
        cfg["imap"] = {"host": "h", "user": "u", "password": "   "}
        with self.assertRaises(common.ConfigError):
            common.validate_config(cfg)

    def test_valid_config_passes(self):
        cfg = configparser.ConfigParser()
        cfg["imap"] = {"host": "h", "user": "u", "password": "p"}
        common.validate_config(cfg)  # must not raise


class TestGracefulStop(unittest.TestCase):
    def test_idle_wait_returns_promptly_when_stopped(self):
        # With a long idle_refresh, a stop request must not block for the full
        # window: _idle_wait must poll in small slices.
        st = make_settings(idle_refresh_seconds=600)
        fake = FakeIMAPClient()
        im._STOP = True
        try:
            calls = {"max_timeout": 0}
            orig = fake.idle_check if hasattr(fake, "idle_check") else None

            def idle_check(timeout):
                calls["max_timeout"] = max(calls["max_timeout"], timeout)
                return []
            fake.idle_check = idle_check
            responses, dur = im._idle_wait(fake, st)
            self.assertEqual(responses, [])
            # Each slice must be small (<=15s) so Ctrl-C is responsive.
            self.assertLessEqual(calls["max_timeout"], 15)
        finally:
            im._STOP = False


if __name__ == "__main__":
    unittest.main()
