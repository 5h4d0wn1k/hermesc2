"""Killswitch: unload agents, wipe sessions, stop the listener, clean state.

All killswitch actions are hard-gated to the loopback lab:
  - sends a KILL task that makes the agent unload and exit (no persistence);
  - wipes the session from the server registry;
  - `sweep` also shuts the listener down (encrypted ctl) and terminates only
    our own sample-agent pids carved from /proc cmdlines, loopback only.
Operator consent (--lab-allowlist) is mandatory for every entry point.
"""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path
from typing import Optional

from . import gating
from .config import LabConfig
from .gating import ScopeViolation
from .server import CtrlClient, Server
from .tasks import make_task

AGENT_CMDLINE_MARKER = b"hermesc2.sample_agent"

KILL_TIMEOUT = 15.0


def _require_consent(consent: bool) -> None:
    gating.require_operator_consent(consent, "killswitch")


def send_kill(session_id: str, server: Server, *, consent: bool = False) -> str:
    """Queue a KILL task for a session on an in-process Server."""
    _require_consent(consent)
    if not gating.allowlist_membership(session_id, server.cfg.allowlist):
        raise ScopeViolation(f"session {session_id!r} not in lab allowlist")
    task = make_task("KILL", {}, allowlisted=consent)
    return server.registry.queue(
        session_id, task, require_consent=False, consent=consent
    ).task_id


def send_kill_remote(
    ctrl: CtrlClient, session_id: str, *, consent: bool = False
) -> dict:
    """Queue a KILL task over the loopback ctl channel."""
    _require_consent(consent)
    task = make_task("KILL", {}, allowlisted=consent)
    return ctrl.queue(session_id, task, consent=consent)


def wait_killed(server: Server, session_id: str, timeout: float = KILL_TIMEOUT) -> bool:
    """True once the session has been wiped from the live registry."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.registry.get(session_id) is None:
            return True
        time.sleep(0.1)
    return server.registry.get(session_id) is None


def is_marker_pid(pid: int) -> bool:
    """True only for our own sample-agent process (cmdline marker match)."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmdline = fh.read().replace(b"\x00", b" ")
    except (OSError, FileNotFoundError):
        return False
    return AGENT_CMDLINE_MARKER in cmdline


def collect_agent_pids(server: Optional[Server] = None) -> list[int]:
    """Gather pids of live lab agents from the registry + marker check."""
    pids: set[int] = set()
    if server is not None:
        for sid in server.registry.live_ids():
            sess = server.registry.get(sid)
            if sess and sess.pid:
                pids.add(int(sess.pid))
    live = set()
    for pid in pids:
        if is_marker_pid(pid):
            live.add(pid)
    return sorted(live)


def sweep_processes(server: Server, *, consent: bool = False) -> list[dict]:
    """Terminate only our own sample-agent processes (loopback lab)."""
    _require_consent(consent)
    touched = []
    for pid in collect_agent_pids(server):
        try:
            os.kill(pid, signal.SIGTERM)
            touched.append(
                {"pid": pid, "signal": "SIGTERM", "status": "ok", "cmdline_marker": True}
            )
            time.sleep(0.1)
        except ProcessLookupError:
            touched.append({"pid": pid, "signal": "SIGTERM", "status": "already-gone"})
        except PermissionError:
            touched.append({"pid": pid, "signal": "SIGTERM", "status": "permission-denied"})
    return touched


def stop_listener(cfg: LabConfig, crypto, *, consent: bool = False) -> dict:
    """Send encrypted shutdown ctl to the loopback listener."""
    _require_consent(consent)
    state_path = cfg.state_path / "server_state.json"
    if not state_path.exists():
        return {"status": "no-state", "detail": "server state file absent; nothing to stop"}
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "no-state", "detail": "unreadable state file"}
    host = state.get("host", "127.0.0.1")
    port = int(state.get("port", cfg.listen_port))
    with CtrlClient(crypto, host, port) as ctl:
        return ctl.shutdown()


def wipe_all(server: Server, *, consent: bool = False) -> int:
    """Wipe every live session from the registry (still requires consent)."""
    _require_consent(consent)
    n = 0
    for sid in list(server.registry.live_ids()):
        send_kill(sid, server, consent=consent)
        n += 1
    return n