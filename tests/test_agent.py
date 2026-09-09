"""Live agent tests: spawn the bundled fixture vs a real loopback server.

These are the real assertions the lab requires: heartbeat arrives, tasks are
executed and answered, killswitch unloads the process, dry-run never executes,
and the loopback gate is enforced end-to-end.
"""

from __future__ import annotations

import socket
import time

from tests.helpers import HermesTestCase, queue

from hermesc2.gating import ScopeViolation
from hermesc2.labruntime import ensure_passphrase
from hermesc2.crypto import Crypto
from hermesc2.server import CtrlClient
from hermesc2.tasks import make_task


class LiveAgentTest(HermesTestCase):
    def _server(self, interval=0.12):
        return self.server(agent_interval=interval)

    def test_beacon_received_and_task_executed(self) -> None:
        s = self._server()
        crypto = self.crypto()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=1)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            sess = s.registry.get("lab-test-01")
            self.assertGreaterEqual(sess.beacon_count, 1)
            tid = queue(s, "lab-test-01", "info")
            res = self.wait_result(s, "lab-test-01", tid)
            self.assertIsNotNone(res)
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["hostname"], socket.gethostname())
            self.assertEqual(res["type"], "result")
        finally:
            s.stop()

    def test_exec_runs_only_allowlisted_demo_command(self) -> None:
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=0, allowlist=True)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            tid = queue(s, "lab-test-01", "exec", {"command": "date"},
                        allowlisted=True, consent=True)
            res = self.wait_result(s, "lab-test-01", tid)
            self.assertIsNotNone(res)
            self.assertEqual(res["status"], "ok")
            self.assertIn("command", res)
        finally:
            s.stop()

    def test_exec_rejects_non_allowlisted_command(self) -> None:
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=0, allowlist=True)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            tid = queue(s, "lab-test-01", "exec", {"command": "not-a-cmd"},
                        allowlisted=True, consent=True)
            res = self.wait_result(s, "lab-test-01", tid)
            self.assertIsNotNone(res)
            self.assertEqual(res["type"], "error")
        finally:
            s.stop()

    def test_dry_run_queue_never_touches_agent(self) -> None:
        """Dry-run agent receives allowlisted exec but returns would-run."""
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=1, allowlist=True)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            tid = queue(s, "lab-test-01", "exec", {"command": "date"},
                        allowlisted=True, consent=True)
            res = self.wait_result(s, "lab-test-01", tid)
            self.assertIsNotNone(res)
            self.assertEqual(res["type"], "would-run")
            self.assertIn("DRY-RUN", res.get("output", ""))
            # the agent must never have executed anything
            sess = s.registry.get("lab-test-01")
            self.assertEqual(sess.results[0].get("type"), "would-run")
        finally:
            s.stop()

    def test_upload_and_download_roundtrip_through_sandbox(self) -> None:
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=0, allowlist=True)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            up = queue(s, "lab-test-01", "upload",
                       {"path": "lab_captures/a.txt",
                        "content_b64": __import__("base64").b64encode(b"hello lab").decode()},
                       allowlisted=True, consent=True)
            up_res = self.wait_result(s, "lab-test-01", up)
            self.assertIsNotNone(up_res)
            self.assertEqual(up_res["status"], "ok")
            # the sandboxed file exists under c2_data/
            from pathlib import Path
            f = Path(s.cfg.sandbox_root) / "lab_captures" / "a.txt"
            self.assertTrue(f.exists())
            self.assertEqual(f.read_bytes(), b"hello lab")
            down = queue(s, "lab-test-01", "download", {"path": "lab_captures/a.txt"})
            down_res = self.wait_result(s, "lab-test-01", down)
            self.assertIsNotNone(down_res)
            import base64
            self.assertEqual(base64.b64decode(down_res["content_b64"]), b"hello lab")
        finally:
            s.stop()

    def test_download_refuses_escape_path(self) -> None:
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=0, allowlist=True)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            tid = queue(s, "lab-test-01", "download", {"path": "../etc/passwd"})
            res = self.wait_result(s, "lab-test-01", tid)
            self.assertIsNotNone(res)
            self.assertEqual(res["type"], "error")  # sandbox violation
        finally:
            s.stop()

    def test_killswitch_terminates_process_and_wipe_session(self) -> None:
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=1, beacons=400)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            tid = queue(s, "lab-test-01", "KILL", allowlisted=True, consent=True)
            rc = p.wait(timeout=30)
            self.assertEqual(rc, 0)
            deadline = time.monotonic() + 5
            while s.registry.get("lab-test-01") is not None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNone(s.registry.get("lab-test-01"))
            self.assertIsNotNone(s.registry.get_ended("lab-test-01"))
        finally:
            s.stop()

    def test_agent_id_must_be_lab_pattern(self) -> None:
        crypto = self.crypto()
        cfg = s = self._server()
        from hermesc2.agent import Agent
        with self.assertRaises(ScopeViolation):
            Agent(s.cfg, crypto, "host-01")

    def test_exit_task_unloads_agent(self) -> None:
        s = self._server()
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=1)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            tid = queue(s, "lab-test-01", "exit")
            rc = p.wait(timeout=30)
            self.assertEqual(rc, 0)
            self.assertEqual(s.registry.get("lab-test-01").status, "gone")
        finally:
            s.stop()

    def test_loopback_gate_refuses_non_loopback_agent_connect(self) -> None:
        s = self._server()
        crypto = self.crypto()
        try:
            from hermesc2.agent import Agent
            with self.assertRaises(ScopeViolation):
                Agent(s.cfg, crypto, "lab-x", server_host="198.51.100.7")
        finally:
            s.stop()

    def test_heartbeat_interval_metrics_present(self) -> None:
        s = self._server(interval=0.12)
        try:
            p = self.spawn_agent(s.cfg, s, dry_run=1, beacons=12)
            self.assertTrue(self.wait_session(s, "lab-test-01"))
            deadline = time.monotonic() + 15
            cnt = 0
            while time.monotonic() < deadline:
                sess = s.registry.get("lab-test-01")
                cnt = sess.beacon_count if sess else 0
                if cnt >= 5:
                    break
                time.sleep(0.1)
            self.assertGreaterEqual(cnt, 5)
            st = s.status()
            self.assertGreaterEqual(st["beacons"]["sent"], cnt)
            self.assertEqual(st["beacons"]["acked"], st["beacons"]["sent"])
        finally:
            s.stop()

    def test_beacon_loss_replay_survives_server_restart(self) -> None:
        """After the listener dies, the agent replays the lost beacon and
        re-registers on a restarted listener (same loopback port)."""
        from hermesc2.server import Server

        cfg = self.cfg(agent_interval=0.3, listen_port=0)
        crypto = self.crypto()
        s1 = Server(cfg, crypto, port=0).start()
        try:
            p = self.spawn_agent(s1.cfg, s1, agent_id="lab-replay-01",
                                 dry_run=1, beacons=400, interval=0.3)
            self.assertTrue(self.wait_session(s1, "lab-replay-01"))
            s1.stop()  # closes the accepted conns -> agent sees the drop
            assert not s1.alive
            s2 = Server(cfg, crypto, port=s1.port).start()
            try:
                ok = False
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if s2.registry.get("lab-replay-01") is not None:
                        ok = True
                        break
                    time.sleep(0.1)
                self.assertTrue(ok, "agent did not replay hello on server restart")
                sess = s2.registry.get("lab-replay-01")
                self.assertGreaterEqual(sess.beacon_count, 1)
            finally:
                if s2.alive:
                    s2.stop()
        finally:
            if s1.alive:
                s1.stop()


if __name__ == "__main__":
    import unittest

    unittest.main()