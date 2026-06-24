"""Privacy & data-safety guarantees -- the user's #1 concern.

These tests assert the tool NEVER fetches message bodies and NEVER writes the
password (or raw confidential headers, by default) to disk.
"""

import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import FakeIMAP4, make_settings, use_temp_logs

import common
import imap_monitor as im


class TestNeverFetchesBody(unittest.TestCase):
    def test_fetch_spec_is_header_peek_only(self):
        # The only thing we ever request must be PEEK'd header fields.
        self.assertIn("BODY.PEEK[HEADER.FIELDS", im.HEADER_FETCH)
        self.assertIn("MESSAGE-ID", im.HEADER_FETCH)
        # Must NOT request the full body or a non-peeking body (would mark read).
        self.assertNotIn("BODY[]", im.HEADER_FETCH)
        self.assertNotIn("RFC822.TEXT", im.HEADER_FETCH)
        self.assertNotIn("BODY[TEXT]", im.HEADER_FETCH)

    def test_poll_fetch_request_contains_no_body(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            hdr = b"Message-ID: <a@b>\r\nFrom: x@y.com\r\nSubject: secret\r\n\r\n"
            mailbox = [{"uid": 1, "internaldate": "23-Jun-2026 02:00:00 +0000",
                        "size": 10, "header": hdr}]
            fake = FakeIMAP4(mailbox)
            im.run_poll(st, log, connect=lambda s: fake,
                        sleeper=lambda s: mailbox.append(
                            {"uid": 2, "internaldate": "23-Jun-2026 03:00:00 +0000",
                             "size": 20, "header": hdr}),
                        max_cycles=2)
            self.assertIsNotNone(fake.fetch_items)
            spec = fake.fetch_items
            self.assertIn("BODY.PEEK[HEADER.FIELDS", spec)
            self.assertNotIn("BODY[]", spec)
            self.assertNotIn("RFC822.TEXT", spec)


class TestNeverLeaksSecrets(unittest.TestCase):
    def test_password_never_written_to_logs(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            pw = "TOP-SECRET-PASSWORD-9999"
            st = make_settings(password=pw)
            log = common.EventLog(st.vantage)
            mailbox = [{"uid": 1, "internaldate": "23-Jun-2026 02:00:00 +0000",
                        "size": 10, "header": b"Subject: hi\r\n\r\n"}]
            im.run_poll(st, log, connect=lambda s: FakeIMAP4(mailbox),
                        sleeper=lambda s: None, max_cycles=2)
            for f in Path(td).glob("*"):
                self.assertNotIn(pw, f.read_text(encoding="utf-8"),
                                 f"password leaked into {f.name}")

    def test_subject_and_sender_hashed_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings(redact="hash")
            log = common.EventLog(st.vantage)
            secret_subject = "CONFIDENTIAL-DEAL-MEMO"
            secret_from = "ceo@bigclient.com"
            hdr = (f"Message-ID: <m1@x>\r\nFrom: {secret_from}\r\n"
                   f"Subject: {secret_subject}\r\n\r\n").encode()
            mailbox = [{"uid": 1, "internaldate": "23-Jun-2026 02:00:00 +0000",
                        "size": 10, "header": hdr}]
            im.run_poll(st, log, connect=lambda s: FakeIMAP4(mailbox),
                        sleeper=lambda s: mailbox.append(
                            {"uid": 2, "internaldate": "23-Jun-2026 03:00:00 +0000",
                             "size": 20, "header": hdr}),
                        max_cycles=2)
            blob = "".join(f.read_text(encoding="utf-8") for f in Path(td).glob("messages_*"))
            self.assertNotIn(secret_subject, blob)
            self.assertNotIn(secret_from, blob)
            self.assertIn("h:", blob)  # hashed marker present


class TestRedaction(unittest.TestCase):
    def test_hash_is_deterministic_and_salt_sensitive(self):
        a = common.redact("ceo@x.com", "hash", "salt1")
        b = common.redact("ceo@x.com", "hash", "salt1")
        c = common.redact("ceo@x.com", "hash", "salt2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("h:"))
        self.assertNotIn("ceo@x.com", a)

    def test_full_and_none_modes(self):
        self.assertEqual(common.redact("a@b.com", "full", "s"), "a@b.com")
        self.assertEqual(common.redact("a@b.com", "none", "s"), "")

    def test_empty_and_none_inputs(self):
        self.assertEqual(common.redact(None, "hash", "s"), "")
        self.assertEqual(common.redact("", "hash", "s"), "")
        self.assertEqual(common.redact("   ", "hash", "s"), "")

    def test_unknown_mode_defaults_to_hashing_not_leaking(self):
        # A typo in the config must fail safe (hash), never expose the raw value.
        out = common.redact("secret@x.com", "hashed-typo", "s")
        self.assertNotIn("secret@x.com", out)


if __name__ == "__main__":
    unittest.main()
