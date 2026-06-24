"""Network probe: success, refused, timeout, and TLS-vs-TCP distinction."""

import socket
import threading
import unittest

import helpers  # noqa: F401  (sets sys.path)
import net_probe as np


class TestProbe(unittest.TestCase):
    def test_success_records_tcp_latency_and_tcp_ok(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def accept_and_close():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass
        threading.Thread(target=accept_and_close, daemon=True).start()
        try:
            row = np.probe_once("127.0.0.1", port, use_tls=False, timeout=5)
            self.assertTrue(row["ok"])
            self.assertTrue(row["tcp_ok"])
            self.assertNotEqual(row["tcp_connect_ms"], "")
        finally:
            srv.close()

    def test_connection_refused(self):
        row = np.probe_once("127.0.0.1", 1, use_tls=False, timeout=2)
        self.assertFalse(row["ok"])
        self.assertFalse(row["tcp_ok"])
        self.assertNotEqual(row["error"], "")

    def test_tls_failure_against_plain_socket_still_marks_tcp_ok(self):
        # A TLS/cert problem is NOT a connectivity failure. tcp_ok must stay True
        # so the report doesn't mislabel a cert issue as "can't reach server".
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve():
            try:
                c, _ = srv.accept()
                c.recv(16)
                c.close()
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        try:
            row = np.probe_once("127.0.0.1", port, use_tls=True, timeout=3)
            self.assertTrue(row["tcp_ok"], "TCP connected, so tcp_ok must be True")
            self.assertFalse(row["ok"], "TLS handshake should fail on a plain socket")
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
