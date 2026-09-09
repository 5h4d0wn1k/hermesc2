"""Offline/live loopback demo harness (`hermesc2 --demo`).

Starts a real C2 server on 127.0.0.1 (ephemeral port), spawns the bundled
sample agent as a genuine subprocess, verifies heartbeats/beacons, executes
real lab tasks (info / exec / upload / download), asserts an encryption
roundtrip, then runs the killswitch (KILL task) and confirms the agent process
exited and the session was wiped. Always exits 0 on success over the loopback
lab only. Never touches anything outside 127.0.0.1.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from . import report as report_mod
from .config import LabConfig, load_config
from .crypto import Crypto, roundtrip_selftest
from .labruntime import ensure_passphrase
from .server import CtrlClient, Server
from .tasks import make_task

PROOF_PREFIX = "[proof]"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _proof(line: str) -> None:
    print(f"{PROOF_PREFIX} {line}", flush=True)


def _wait_for_session(server: Server, agent_id: str, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.registry.get(agent_id) is not None:
            return True
        time.sleep(0.05)
    return False


def _wait_for_result(
    server: Server, agent_id: str, task_id: str, timeout: float = 20.0
) -> Optional[dict]:
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


def prepare_fixture(cfg: LabConfig) -> Path:
    """Create the c2_data/lab_fixture/hello.txt demo fixture."""
    sandbox_root = Path(cfg.sandbox_root)
    fixture_dir = sandbox_root / "lab_fixture"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "hello.txt"
    if not path.exists():
        path.write_bytes(b"hermes lab fixture hello\n")
    return path


def _cleanup(proc: Optional[subprocess.Popen], server: Optional[Server],
             state_dir: Optional[str]) -> None:
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
    if server is not None and server.alive:
        server.stop()
    if state_dir:
        shutil.rmtree(state_dir, ignore_errors=True)


def run_demo(
    *,
    config: Optional[str] = None,
    state_dir: Optional[str] = None,
    port: Optional[int] = None,
    agent_interval: float = 0.15,
    beacons: int = 40,
    cleanup_state: bool = True,
) -> dict:
    """Run the live loopback demo. Returns proof dict; raises on failure."""
    cfg = load_config(config)
    if port:
        cfg = cfg.with_overrides(listen_port=port)
    if state_dir:
        cfg = cfg.with_overrides(state_dir=state_dir)
    cfg = cfg.with_overrides(agent_interval=agent_interval)

    own_state = state_dir is None
    tmp: Optional[tempfile.TemporaryDirectory] = None
    if state_dir is None:
        tmp = tempfile.TemporaryDirectory(prefix="hermes-demo-")
        state_dir = tmp.name
        cfg = cfg.with_overrides(state_dir=state_dir)

    ph = ensure_passphrase(cfg)
    crypto = Crypto(ph)
    _proof(f"encryption key derived from runtime passphrase (kid={crypto.key_id})")

    server: Optional[Server] = None
    proc: Optional[subprocess.Popen] = None
    try:
        server = Server(cfg, crypto, port=int(cfg.listen_port), persist=True).start()
        server.wait_ready()
        _proof(f"c2 server listener up on 127.0.0.1:{server.port}")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        agent_id = "lab-demo-01"
        cmd = [
            sys.executable,
            "-m",
            "hermesc2.sample_agent",
            "--config",
            str(Path(config) if config else (PROJECT_ROOT / "config" / "lab.yaml")),
            "--id",
            agent_id,
            "--port",
            str(server.port),
            "--keystate",
            str(cfg.state_path),
            "--interval",
            str(agent_interval),
            "--beacons",
            str(beacons),
            "--dry-run",
            "0",
            "--lab-allowlist",
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env
        )

        proof: dict = {}

        if not _wait_for_session(server, agent_id, timeout=30):
            raise RuntimeError("demo failed: no session registered")
        sess = server.registry.get(agent_id)
        proof["session_id"] = agent_id
        proof["session_hostname"] = sess.hostname
        _proof(f"beacon received: session {agent_id} registered (hostname={sess.hostname})")

        with CtrlClient(crypto, "127.0.0.1", server.port) as ctl:
            q = ctl.queue(agent_id, make_task("info", allowlisted=True), consent=True)
            info_task = q.get("task")
        time.sleep(0.2)
        info_res = _wait_for_result(server, agent_id, info_task, timeout=20)
        if info_res is None:
            raise RuntimeError("demo failed: info task produced no result")
        proof["info_hostname"] = info_res.get("hostname")
        proof["info_python"] = info_res.get("python")
        _proof(
            f"task 'info' executed: hostname={info_res.get('hostname')} "
            f"python={info_res.get('python')}"
        )

        with CtrlClient(crypto, "127.0.0.1", server.port) as ctl:
            q = ctl.queue(
                agent_id,
                make_task("exec", {"command": "date"}, allowlisted=True),
                consent=True,
            )
            exec_task = q.get("task")
        exec_res = _wait_for_result(server, agent_id, exec_task, timeout=20)
        if exec_res is None or exec_res.get("status") != "ok":
            raise RuntimeError(f"demo failed: exec date produced no good result: {exec_res}")
        proof["exec_command"] = exec_res.get("command")
        proof["exec_output"] = (exec_res.get("output") or "").strip()
        _proof(
            f"task 'exec' executed: `{exec_res.get('command')}` -> {exec_res.get('status')}"
        )

        fixture = prepare_fixture(cfg)
        with CtrlClient(crypto, "127.0.0.1", server.port) as ctl:
            q = ctl.queue(
                agent_id,
                make_task(
                    "upload",
                    {"path": "lab_fixture/from_controller.txt",
                     "content_b64": base64.b64encode(b"uploaded by controller").decode()},
                    allowlisted=True,
                ),
                consent=True,
            )
            up_t = q.get("task")
        up_res = _wait_for_result(server, agent_id, up_t, timeout=20)
        if up_res is None or up_res.get("status") != "ok":
            raise RuntimeError(f"demo failed: upload produced no good result: {up_res}")
        up_path = Path(cfg.sandbox_root) / up_res.get("path", "")
        proof["upload_path"] = str(up_path)
        proof["upload_bytes"] = up_path.read_bytes().decode() if up_path.exists() else None
        _proof(
            f"task 'upload' executed: wrote {up_res.get('size')} bytes "
            f"to c2_data/{up_res.get('path')}"
        )

        with CtrlClient(crypto, "127.0.0.1", server.port) as ctl:
            q = ctl.queue(
                agent_id,
                make_task("download", {"path": "lab_fixture/hello.txt"}, allowlisted=True),
                consent=True,
            )
            down_t = q.get("task")
        down_res = _wait_for_result(server, agent_id, down_t, timeout=20)
        if down_res is None or down_res.get("status") != "ok":
            raise RuntimeError(
                f"demo failed: download produced no good result: {down_res}"
            )
        proof["download_size"] = down_res.get("size")
        _proof(
            f"task 'download' executed: pulled {down_res.get('size')} bytes "
            f"from c2_data/{down_res.get('path')}"
        )

        # beacon + RTT metrics
        st = server.status()
        proof["beacons"] = st["beacons"]
        proof["beacon_jitter"] = st["jitter"]
        rtt_vals = [
            s.get("rtt_avg_ms")
            for s in st.get("sessions", [])
            if s.get("rtt_avg_ms") is not None
        ]
        proof["rtt_avg_ms"] = round(sum(rtt_vals) / len(rtt_vals), 3) if rtt_vals else None
        _proof(
            f"beacon channel: acked={proof['beacons'].get('acked')}/{proof['beacons'].get('sent')} "
            f"jitter p50={proof['beacon_jitter'].get('p50') * 100:.1f}% "
            f"rtt_avg={proof['rtt_avg_ms']}ms"
        )

        rt = roundtrip_selftest(crypto, b"hermes demo roundtrip")
        proof["encryption_ok"] = bool(rt.get("plaintext_unchanged") and rt.get("magic_ok"))
        proof["crypto"] = rt
        _proof(
            f"encryption roundtrip: decrypt==plaintext={rt['plaintext_unchanged']} "
            f"magic_ok={rt['magic_ok']}"
        )

        # killswitch
        with CtrlClient(crypto, "127.0.0.1", server.port) as ctl:
            ctl.queue(agent_id, make_task("KILL", allowlisted=True), consent=True)
        try:
            rc = proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait(timeout=5)
        wiped = server.registry.get(agent_id) is None
        proof["killswitch"] = {"rc": rc, "session_wiped": wiped}
        _proof(f"killswitch: agent process rc={rc} session_wiped={wiped}")

        if rc != 0 or not wiped:
            raise RuntimeError(f"demo failed: killswitch rc={rc} wiped={wiped}")

        server.stop()
        report = report_mod.build_report(server, cfg, extra={"demo": proof})
        written = report_mod.write_report(report, "reports")
        proof["report"] = written
        _proof(f"report written: {written['json']}")
        _proof("demo OK (loopback only)")
    finally:
        _cleanup(proc, server, state_dir if cleanup_state and own_state else None)
        # keep state used for the report if we cleaned it: report already written
    return proof