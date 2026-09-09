"""Shared helpers for the Hermes lab test-suite (loopback only)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from hermesc2.config import load_config  # noqa: E402
from hermesc2.crypto import Crypto  # noqa: E402
from hermesc2.labruntime import ensure_passphrase  # noqa: E402
from hermesc2.server import Server  # noqa: E402
from hermesc2.tasks import make_task  # noqa: E402


class HermesTestCase(unittest.TestCase):
    """Base case: isolated state dir + crypto per test, auto-cleanup."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hermes-test-")
        self.tmpdir = self._tmp.name
        self.overrides = {}

    def tearDown(self) -> None:
        for p in getattr(self, "_procs", []):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill()
        self._tmp.cleanup()

    def track(self, proc: subprocess.Popen) -> subprocess.Popen:
        if not hasattr(self, "_procs"):
            self._procs = []
        self._procs.append(proc)
        return proc

    # -- config / server -------------------------------------------------
    def cfg(self, **kw) -> "LabConfig":
        kw.setdefault("state_dir", self.tmpdir)
        kw.setdefault("listen_port", 0)
        base = load_config(str(REPO_ROOT / "config" / "lab.yaml")).with_overrides(**kw)
        self.overrides = kw
        return base

    def crypto(self) -> Crypto:
        return Crypto(ensure_passphrase(self.cfg()))

    def server(self, **kw) -> Server:
        cfg = self.cfg(**kw)
        monkey = kw.get("agent_interval")
        return Server(cfg, self.crypto(), port=int(cfg.listen_port), persist=False).start()

    # -- subprocess agent ------------------------------------------------
    def spawn_agent(self, cfg, server, agent_id="lab-test-01", *, once=False,
                    dry_run=1, allowlist=False, beacons=60, interval=0.12,
                    keystate=None) -> subprocess.Popen:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [
            sys.executable, "-m", "hermesc2.sample_agent",
            "--config", str(REPO_ROOT / "config" / "lab.yaml"),
            "--id", agent_id,
            "--port", str(server.port),
            "--keystate", str(keystate or cfg.state_path),
            "--interval", str(interval),
            "--beacons", str(beacons),
            "--dry-run", str(dry_run),
        ]
        if once:
            cmd.append("--once")
        if allowlist:
            cmd.append("--lab-allowlist")
        proc = self.track(subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, text=True, env=env
        ))
        return proc

    @staticmethod
    def wait_session(server: Server, agent_id: str, timeout: float = 25.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if server.registry.get(agent_id) is not None:
                return True
            time.sleep(0.05)
        # diagnostic: agent never registered - surface process + registry state
        import traceback
        st = server.status()
        msg = [
            "wait_session TIMEOUT",
            f"agent={agent_id} status conns={st.get('connections')} "
            f"beacons={st.get('beacons')} audit={len(server.registry.audit)}",
        ]
        for ev in server.registry.audit[-5:]:
            msg.append(f"audit: {ev}")
        for t in threading.enumerate():
            msg.append(f"thread: {t.name} daemon={t.daemon} alive={t.is_alive()}")
        raise AssertionError("\n".join(msg))

    @staticmethod
    def wait_result(server: Server, agent_id: str, task_id: str,
                    timeout: float = 25.0) -> Optional[dict]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sess = server.registry.get(agent_id)
            if sess:
                with server.registry._lock:
                    for t in sess.tasks:
                        if t.task_id == task_id and t.result is not None:
                            return t.result
            time.sleep(0.1)
        return None


def queue(server: Server, agent_id: str, task_type: str, params=None, *,
          allowlisted=False, consent=False) -> str:
    return server.queue_task(
        agent_id, task_type, params, allowlisted=allowlisted, consent=consent
    )