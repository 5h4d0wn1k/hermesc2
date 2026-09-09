"""Lab agent core: loopback beacon loop, task execution, unload-on-KILL.

The agent is a plain Python process that connects to the loopback C2 server,
beacons at a jittered interval, pulls tasks, executes them inside its own
sandbox, and posts results. It defaults to dry-run (exec/upload never actually
run without --lab-allowlist), it never persists, and a KILL task unloads it
cleanly (exit) while the server wipes the session.

Only allowlisted demo commands (date/hostname) can ever be executed, and file
tasks are confined to the c2_data/lab_* sandbox.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Optional

from . import gating
from .beacon import BeaconStepper
from .config import LabConfig
from .crypto import Crypto, CryptoError
from .gating import ScopeViolation
from .tasks import Sandbox, process_task


class AgentExit(Exception):
    """Clean agent unload (normal or killswitch)."""

    def __init__(self, code: int = 0, reason: str = "exit") -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


class Agent:
    """Sandboxed beacon agent (loopback only, dry-run default)."""

    def __init__(
        self,
        cfg: LabConfig,
        crypto: Crypto,
        agent_id: str,
        *,
        dry_run: bool = True,
        operator_consent: bool = False,
        server_host: Optional[str] = None,
        server_port: Optional[int] = None,
        beacon_base: Optional[float] = None,
        sandbox_root: Optional[str] = None,
    ) -> None:
        if not gating.is_lab_pattern(agent_id):
            raise ScopeViolation(
                f"agent id {agent_id!r} must match lab-* (loopback lab scope)"
            )
        gating.assert_in_scope(agent_id, cfg.allowlist, what="agent id")
        self.cfg = cfg
        self.crypto = crypto
        self.agent_id = agent_id
        self.dry_run = dry_run
        self.operator_consent = operator_consent
        self.host = gating.assert_loopback(server_host or cfg.listen_host, "agent server host")
        self.port = int(server_port or cfg.listen_port)
        self.sandbox = Sandbox(sandbox_root or cfg.sandbox_root)
        base = beacon_base if beacon_base else float(cfg.agent_interval)
        self.stepper = BeaconStepper(base_interval=base, jitter=float(cfg.jitter))
        self._seq = 0
        self._sock: Optional[socket.socket] = None
        self.log: list[dict] = []
        self.info = {
            "hostname": os.uname().nodename if hasattr(os, "uname") else socket.gethostname(),
            "python": sys.version.split()[0],
            "pid": os.getpid(),
            "platform": sys.platform,
        }

    # -- transport -----------------------------------------------------
    RECV_TIMEOUT = 10.0

    def _connect(self) -> None:
        if self._sock is not None:
            return
        self._sock = socket.create_connection((self.host, self.port), timeout=15)
        self._sock.settimeout(self.RECV_TIMEOUT)

    def _close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _send(self, msg: dict) -> dict:
        self._connect()
        self.crypto.send(self._sock, msg)
        _kid, reply = self.crypto.recv(self._sock)
        return reply

    def _beacon(self) -> int:
        """Increment and return the beacon sequence number."""
        self._seq += 1
        return self._seq

    # -- lifecycle -----------------------------------------------------
    def hello(self) -> dict:
        reply = self._send(
            {"type": "hello", "id": self.agent_id, "info": self.info, "seq": self._beacon()}
        )
        self._log("hello", reply)
        return reply

    def checkin(self) -> list[dict]:
        reply = self._send(
            {"type": "checkin", "id": self.agent_id, "seq": self._beacon()}
        )
        self._log("checkin", {"tasks": len(reply.get("tasks", []))})
        return [t for t in reply.get("tasks", [])]

    def post_result(self, result: dict) -> None:
        self._send({"type": "result", "id": self.agent_id, "result": result})
        self._log("result", {"task_id": result.get("task_id"), "type": result.get("type")})

    def bye(self) -> None:
        try:
            if self._sock is not None:
                self.crypto.send(self._sock, {"type": "byebye", "id": self.agent_id})
                self._sock.settimeout(1.0)
                try:
                    self.crypto.recv(self._sock)
                except (CryptoError, OSError):
                    pass
        except OSError:
            pass
        finally:
            self._close()

    # -- task loop -----------------------------------------------------
    def process_tasks(self, tasks: list[dict]) -> Optional[AgentExit]:
        for task in tasks:
            ttype = task.get("type")
            if ttype == "KILL":
                # Killswitch: unload the agent, report, wipe on server side.
                res = {
                    "type": "unloaded",
                    "task_id": task.get("task_id", "KILL"),
                    "status": "unloaded",
                    "reason": "killswitch",
                    "at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                }
                try:
                    self.post_result(res)
                finally:
                    raise AgentExit(0, "killswitch")
            try:
                result = process_task(
                    task,
                    sandbox=self.sandbox,
                    allowed_commands=tuple(self.cfg.safe_commands or ("date", "hostname")),
                    dry_run=self.dry_run,
                    operator_consent=self.operator_consent,
                )
            except Exception as exc:  # noqa: BLE001 - agent must not die on bad task
                result = {
                    "type": "error",
                    "task_id": task.get("task_id"),
                    "status": "error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            # stamp the originating task id onto the result envelope
            if not result.get("task_id"):
                result["task_id"] = task.get("task_id")
            self.post_result(result)
            if ttype == "exit" and result.get("exit"):
                raise AgentExit(0, "exit-task")
        return None

    def run_once(self) -> dict:
        """Single pointer: hello + one checkin cycle with a fresh connection."""
        self.hello()
        tasks = self.checkin()
        try:
            self.process_tasks(tasks)
        except AgentExit as ax:
            return {"beacons": self._seq, "exit": ax.reason, "tasks": len(tasks)}
        self.bye()
        return {"beacons": self._seq, "exit": None, "tasks": len(tasks)}

    def run(self, max_beacons: Optional[int] = None) -> dict:
        """Beacon loop with loss replay.

        One "cycle" is hello + checkin + process-tasks over a single
        connection. Any transport failure (connection reset, torn frame,
        read timeout) is logged as a lost beacon, the socket is dropped,
        and the cycle is replayed at the jittered beacon interval. The loop
        only stops on a KILL/exit task or the beacon budget. A real loopback
        beacon round-trip is therefore continuously asserted by the server's
        session heartbeats.
        """
        count = 0
        while True:
            if max_beacons is not None and count >= max_beacons:
                break
            try:
                tasks = self._cycle()
            except AgentExit as ax:
                self.bye()
                return {"beacons": self._seq, "exit": ax.reason, "tasks": count + 1}
            except (CryptoError, OSError) as exc:
                self._log(
                    "beacon-loss",
                    {"exc": f"{type(exc).__name__}: {exc}", "beacon": self._seq},
                )
                self._close()
                count += 1
                if max_beacons is not None and count >= max_beacons:
                    break
                time.sleep(self.stepper.next_interval())
                continue
            count += 1
            if max_beacons is not None and count >= max_beacons:
                break
            time.sleep(self.stepper.next_interval())
        self.bye()
        return {"beacons": self._seq, "exit": None, "tasks": count}

    def _cycle(self) -> list[dict]:
        """One hello + checkin + process-tasks round over one connection."""
        self.hello()
        tasks = self.checkin()
        self.process_tasks(tasks)
        return tasks

    def _log(self, kind: str, detail: dict) -> None:
        self.log.append(
            {"at": _dt.datetime.now(_dt.timezone.utc).isoformat(), "kind": kind, "detail": detail}
        )

    def summary(self) -> dict:
        return {
            "id": self.agent_id,
            "host": self.host,
            "port": self.port,
            "dry_run": self.dry_run,
            "beacons": self._seq,
            "pid": os.getpid(),
            "log_entries": len(self.log),
        }