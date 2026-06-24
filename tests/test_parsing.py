"""Parsing & detection correctness: INTERNALDATE/timezones, headers, delays,
new-message dedup, and the IDLE helper functions."""

import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import helpers
from helpers import (FakeIMAP4, FakeIMAPClient, make_settings,
                     read_rows, use_temp_logs)

import common
import imap_monitor as im


class TestInternaldate(unittest.TestCase):
    def test_utc_internaldate(self):
        meta = '1 (INTERNALDATE "23-Jun-2026 02:00:00 +0000" RFC822.SIZE 5 BODY[...])'
        dt = im._imaplib_internaldate(meta)
        self.assertEqual(dt, datetime(2026, 6, 23, 2, 0, 0, tzinfo=timezone.utc))

    def test_offset_internaldate_normalized_to_utc(self):
        meta = '1 (INTERNALDATE "23-Jun-2026 10:00:00 +0800" RFC822.SIZE 5 BODY[...])'
        dt = im._imaplib_internaldate(meta)
        self.assertEqual(dt, datetime(2026, 6, 23, 2, 0, 0, tzinfo=timezone.utc))

    @unittest.skipUnless(hasattr(time, "tzset"), "tzset not available (Windows)")
    def test_correct_under_non_utc_local_timezone(self):
        # The user's machine is UTC+8. Parsing must not be affected by local TZ.
        old = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "Asia/Shanghai"
            time.tzset()
            meta = '1 (INTERNALDATE "23-Jun-2026 02:00:00 +0000" RFC822.SIZE 5 BODY[...])'
            dt = im._imaplib_internaldate(meta)
            self.assertEqual(dt, datetime(2026, 6, 23, 2, 0, 0, tzinfo=timezone.utc))
        finally:
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            time.tzset()

    def test_missing_internaldate_returns_none(self):
        self.assertIsNone(im._imaplib_internaldate("1 (RFC822.SIZE 5)"))

    def test_size_parsing(self):
        self.assertEqual(im._imaplib_size("1 (RFC822.SIZE 12345 ...)"), 12345)
        self.assertIsNone(im._imaplib_size("1 (no size here)"))


class TestHeaderParsing(unittest.TestCase):
    def test_basic(self):
        raw = (b"Message-ID: <x@y>\r\nDate: Tue, 23 Jun 2026 10:00:00 +0800\r\n"
               b"From: Bob <b@x.com>\r\nTo: me@z.com\r\nSubject: hi\r\n\r\n")
        h = im._parse_headers(raw)
        self.assertEqual(h["message_id"], "<x@y>")
        self.assertEqual(h["from"], "Bob <b@x.com>")
        self.assertEqual(h["subject"], "hi")

    def test_missing_headers_are_empty(self):
        h = im._parse_headers(b"\r\n")
        self.assertEqual(h["from"], "")
        self.assertEqual(h["subject"], "")
        self.assertEqual(h["message_id"], "")

    def test_non_ascii_subject_does_not_crash(self):
        raw = ("Subject: =?UTF-8?B?5Lit5paH5Li76aKY?=\r\nFrom: a@b.com\r\n\r\n").encode()
        h = im._parse_headers(raw)
        self.assertIsInstance(h["subject"], str)

    def test_empty_bytes(self):
        h = im._parse_headers(b"")
        self.assertEqual(h["from"], "")


class TestDelayComputation(unittest.TestCase):
    def test_positive_delay_when_server_received_earlier(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            past = datetime.now(timezone.utc).replace(microsecond=0)
            past = past.fromtimestamp(past.timestamp() - 600, tz=timezone.utc)
            im._record_message(log, st, "poll", past, 100,
                               {"message_id": "<a@b>", "from": "x@y.com"})
            row = read_rows(td, "messages_*.csv")[0]
            delay = float(row["server_to_client_delay_sec"])
            self.assertGreater(delay, 590)
            self.assertLess(delay, 660)

    def test_no_internaldate_leaves_delay_blank(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            im._record_message(log, st, "poll", None, None, {})
            row = read_rows(td, "messages_*.csv")[0]
            self.assertEqual(row["server_to_client_delay_sec"], "")


class TestPollNewMessageDetection(unittest.TestCase):
    def test_priming_then_single_report_no_duplicates(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            hdr = b"Message-ID: <m1@x>\r\nFrom: a@b.com\r\nSubject: s\r\n\r\n"
            mailbox = [{"uid": 1, "internaldate": "23-Jun-2026 02:00:00 +0000",
                        "size": 10, "header": hdr}]
            added = {"done": False}

            def sleeper(_):
                if not added["done"]:
                    mailbox.append({"uid": 2, "internaldate": "23-Jun-2026 03:00:00 +0000",
                                    "size": 20, "header": hdr})
                    added["done"] = True

            im.run_poll(st, log, connect=lambda s: FakeIMAP4(mailbox),
                        sleeper=sleeper, max_cycles=3)
            msgs = read_rows(td, "messages_*.csv")
            # Only uid 2 is "new" (uid 1 existed at baseline); reported exactly once.
            self.assertEqual(len(msgs), 1, f"expected 1 new message, got {len(msgs)}")


class TestIdleHelpers(unittest.TestCase):
    def test_check_alive_true_on_noop_ok(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            self.assertTrue(im._check_alive(FakeIMAPClient(), st, log))

    def test_check_alive_false_on_noop_failure(self):
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            fake = FakeIMAPClient(noop_exc=OSError("dead socket"))
            self.assertFalse(im._check_alive(fake, st, log))
            evs = [r["event"] for r in read_rows(td, "connection_*.csv")]
            self.assertIn("noop_fail", evs)

    def test_handle_new_idle_filters_uid_quirk(self):
        # IMAP "N:*" can return the highest UID even when it is < N. Those must
        # be filtered so we never re-report an already-seen message.
        with tempfile.TemporaryDirectory() as td:
            use_temp_logs(Path(td))
            st = make_settings()
            log = common.EventLog(st.vantage)
            internal = datetime(2026, 6, 23, 2, 0, 0, tzinfo=timezone.utc)
            raw = b"Message-ID: <n@x>\r\nFrom: a@b.com\r\nSubject: s\r\n\r\n"
            fetch_data = {7: {b"INTERNALDATE": internal, b"RFC822.SIZE": 12,
                              b"BODY[HEADER.FIELDS (MESSAGE-ID DATE FROM TO SUBJECT)]": raw}}
            # search returns 5 (the stale quirk hit) and 7 (genuinely new); seen=5.
            fake = FakeIMAPClient(search_results=[5, 7], fetch_data=fetch_data)
            new_max = im._handle_new_idle(fake, st, log, seen_max_uid=5)
            self.assertEqual(new_max, 7)
            msgs = read_rows(td, "messages_*.csv")
            self.assertEqual(len(msgs), 1)  # only uid 7 reported


if __name__ == "__main__":
    unittest.main()
