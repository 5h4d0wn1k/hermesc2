"""Server core tests: loopback listener, registry, task queue, ctl, sweep."""

from __future__ import annotations

import time

from tests.helpers import HermesTestCase, queue

from hermesc2.gating import ScopeViolation
from hermesc2.labruntime import ensure_passphrase
from hermesc2.crypto import Crypto
from hermesc2.server import CtrlClient, Server
from hermesc2.tasks import make_task
from hermesc2.beacon import SessionTimeout


class ServerBindTest(HermesTestCase):
    def test_server_binds_loopback_and_reports_port(self) -> None:
        s = self.server()
        try:
            self.assertEqual(s.host, "127.0.0.1")
            self.assertGreater(s.port, 0)
            self.assertTrue(s.alive)
        finally:
            s.stop()

    def test_server_refuses_non_loopback_host(self) -> None:
        with self.assertRaises(ScopeViolation):
            Server(self.cfg(), self.crypto(), host="198.51.100.2")

    def test_status_shape(self) -> None:
        s = self.server()
        try:
            st = s.status()
            self.assertEqual(st["host"], "127.0.0.1")
            self.assertTrue(st["alive"])
            self.assertIn("sessions", st)
            self.assertIn("beacons", st)
        finally:
            s.stop()

    def test_server_stop_kills_listener(self) -> None:
        s = self.server()
        s.stop()
        self.assertFalse(s.alive)


class RegistryTest(HermesTestCase):
    def test_hello_registers_session_and_heartbeat(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-srv-01", {"hostname": "lab-box"})
            sess = s.registry.get("lab-srv-01")
            self.assertIsNotNone(sess)
            self.assertEqual(sess.hostname, "lab-box")
            self.assertEqual(len(sess.checkin_times), 0)
            before = sess.last_seen
            time.sleep(0.01)
            s.registry.heartbeat("lab-srv-01", seq=1)
            self.assertGreaterEqual(sess.last_seen, before)
            self.assertEqual(len(sess.checkin_times), 1)
        finally:
            s.stop()

    def test_register_non_lab_id_refused(self) -> None:
        s = self.server()
        try:
            with self.assertRaises(ScopeViolation):
                s.registry.register("server-01", {"hostname": "x"})
        finally:
            s.stop()

    def test_task_queue_pending_dispatch(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-q-01", {})
            task = make_task("info", allowlisted=True)
            s.registry.queue("lab-q-01", task, require_consent=False)
            sess = s.registry.get("lab-q-01")
            self.assertEqual(len(sess.tasks), 1)
            pend = s.registry.pending("lab-q-01")
            self.assertEqual(pend[0]["task_id"], task["task_id"])
            # second call is empty: already dispatched
            self.assertEqual(s.registry.pending("lab-q-01"), [])
        finally:
            s.stop()

    def test_queue_requires_allowlist_for_side_effects(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-consent-01", {})
            task = make_task("exec", {"command": "date"}, allowlisted=False)
            with self.assertRaises(ScopeViolation):
                s.registry.queue("lab-consent-01", task, require_consent=True)
        finally:
            s.stop()

    def test_queue_kill_requires_allowlisted_session(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-kill-01", {})
            task = make_task("KILL", allowlisted=True)
            s.registry.queue("lab-kill-01", task, require_consent=False, consent=True)
            sess = s.registry.get("lab-kill-01")
            self.assertEqual(sess.tasks[0].type, "KILL")
        finally:
            s.stop()

    def test_finish_stores_result_and_rtt(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-fin-01", {})
            task = make_task("info", allowlisted=True)
            s.registry.queue("lab-fin-01", task, require_consent=False)
            tid = task["task_id"]
            s.registry.pending("lab-fin-01")
            res = {"type": "result", "task_id": tid, "status": "ok", "hostname": "h"}
            out = s.registry.finish("lab-fin-01", res)
            self.assertIsNotNone(out)
            self.assertGreaterEqual(out["rtt"], 0)
            sess = s.registry.get("lab-fin-01")
            self.assertEqual(sess.results[0]["hostname"], "h")
        finally:
            s.stop()

    def test_wipe_moves_session_to_ended(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-wipe-01", {})
            s.registry.wipe("lab-wipe-01", reason="test")
            self.assertIsNone(s.registry.get("lab-wipe-01"))
            self.assertIsNotNone(s.registry.get_ended("lab-wipe-01"))
        finally:
            s.stop()

def test_sweep_times_out_stale_sessions(self) -> None:
    s = self.server()
    try:
        s.registry.register("lab-stale-01", {})
        sess = s.registry.get("lab-stale-01")
        sess.last_seen = time.time() - 10  # stale: last beacon long ago
        expired = s.registry.sweep(0.0001)
        self.assertIn("lab-stale-01", expired)
        self.assertIsNone(s.registry.get("lab-stale-01"))
    finally:
        s.stop()


class CtrlClientTest(HermesTestCase):
    def test_ctl_status_roundtrip(self) -> None:
        s = self.server()
        crypto = self.crypto()
        try:
            with CtrlClient(crypto, "127.0.0.1", s.port) as ctl:
                reply = ctl.status()
            self.assertTrue(reply["alive"])
            self.assertEqual(reply["server"]["port"], s.port)
        finally:
            s.stop()

    def test_ctl_queue_then_agent_pull(self) -> None:
        s = self.server()
        crypto = self.crypto()
        try:
            s.registry.register("lab-ctl-01", {})
            with CtrlClient(crypto, "127.0.0.1", s.port) as ctl:
                ack = ctl.queue("lab-ctl-01", make_task("info", allowlisted=True),
                                consent=True)
            self.assertEqual(ack["op"], "queue")
            self.assertTrue(ack["task"])
            sess = s.registry.get("lab-ctl-01")
            self.assertEqual(len(sess.tasks), 1)
        finally:
            s.stop()

    def test_ctl_shutdown_stops_server(self) -> None:
        s = self.server()
        crypto = self.crypto()
        with CtrlClient(crypto, "127.0.0.1", s.port) as ctl:
            ctl.shutdown()
        deadline = time.monotonic() + 3
        while s.alive and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(s.alive)

    def test_ctl_wipe(self) -> None:
        s = self.server()
        crypto = self.crypto()
        try:
            s.registry.register("lab-ctlw-01", {})
            with CtrlClient(crypto, "127.0.0.1", s.port) as ctl:
                ack = ctl.wipe("lab-ctlw-01")
            self.assertEqual(ack["op"], "wipe")
            self.assertIsNone(s.registry.get("lab-ctlw-01"))
        finally:
            s.stop()

    def test_ctl_results(self) -> None:
        s = self.server()
        crypto = self.crypto()
        try:
            s.registry.register("lab-res-01", {})
            task = make_task("info", allowlisted=True)
            s.registry.queue("lab-res-01", task, require_consent=False)
            tid = task["task_id"]
            s.registry.pending("lab-res-01")
            s.registry.finish("lab-res-01",
                              {"type": "result", "task_id": tid, "ok": True})
            with CtrlClient(crypto, "127.0.0.1", s.port) as ctl:
                reply = ctl.results("lab-res-01")
            self.assertEqual(len(reply["results"]), 1)
        finally:
            s.stop()


class QueueTaskApiTest(HermesTestCase):
    def test_queue_task_api_requires_consent(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-api-01", {})
            with self.assertRaises(ScopeViolation):
                queue(s, "lab-api-01", "exec", {"command": "date"})
        finally:
            s.stop()

    def test_queue_task_api_return_task_id(self) -> None:
        s = self.server()
        try:
            s.registry.register("lab-api-02", {})
            tid = queue(s, "lab-api-02", "info", allowlisted=True)
            self.assertTrue(tid.startswith("t-"))
        finally:
            s.stop()


if __name__ == "__main__":
    import unittest

    unittest.main()