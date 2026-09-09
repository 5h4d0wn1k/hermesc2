"""C2 server core: loopback TCP listener, session registry, task queue.

The listener binds 127.0.0.1 (hard-gated), accepts only loopback peers, and
speaks the AES-GCM framed envelope protocol from ``crypto``. Sessions are
registered on ``hello``, kept alive by ``checkin`` heartbeats (the real
loopback beacon), and serviced from a per-session task queue via a controller
(``CtrlClient``) which requires operator consent for side-effecting tasks.

Command/control channels (``ctl``) also require a loopback peer and a valid
encrypted envelope, so ``server stop`` and task queueing only work from the
local lab host with the runtime passphrase.
"""

from __future__ import annotations

import datetime as _dt
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from . import beacon as beacon_mod
from . import gating
from .config import LabConfig, save_json
from .crypto import Crypto, CryptoError
from .gating import ScopeViolation
from .tasks import make_task

MAX_SESSIONS = 64
SIDE_EFFECTING_TASKS = frozenset({"exec", "upload", "KILL"})


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _now() -> float:
    return time.time()


@dataclass
class Task:
    task_id: str
    type: str
    params: dict = field(default_factory=dict)
    created_at: str = field(default_factory=_utcnow)
    allowlisted: bool = False
    scope_ok: bool = False
    dispatched_at: Optional[float] = None
    result: Optional[dict] = None
    result_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "type": self.type,
            "params": self.params,
            "created_at": self.created_at,
            "allowlisted": self.allowlisted,
            "scope_ok": self.scope_ok,
            "dispatched_at": self.dispatched_at,
            "result": self.result,
            "result_at": self.result_at,
        }


@dataclass
class Session:
    id: str
    hostname: str
    info: dict = field(default_factory=dict)
    first_seen: str = field(default_factory=_utcnow)
    last_seen: float = field(default_factory=_now)
    status: str = "active"  # active | killed | timed-out | gone
    tasks: list[Task] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    checkin_times: list[float] = field(default_factory=list)
    rtts: list[float] = field(default_factory=list)
    pid: Optional[int] = None
    killed_at: Optional[str] = None

    @property
    def beacon_count(self) -> int:
        """Number of heartbeat/checkin beacons received from the agent."""
        return len(self.checkin_times)

    def timeline(self) -> list[dict]:
        evts = [
            {"kind": "hello", "at": self.first_seen, "detail": self.id},
        ]
        for t in self.tasks:
            evts.append(
                {"kind": "task", "at": t.created_at, "detail": f"{t.type}:{t.task_id}"}
            )
        for r in self.results:
            evts.append(
                {"kind": "result", "at": r.get("at"), "detail": r.get("task_id", "?")}
            )
        if self.killed_at:
            evts.append({"kind": "kill", "at": self.killed_at, "detail": self.id})
        evts.sort(key=lambda e: e.get("at") or "")
        return evts[:5000]


class SessionRegistry:
    """Session registry with heartbeat, task queue, audit record, sweep."""

    def __init__(self, allowlist: list[str]) -> None:
        self._lock = threading.RLock()
        self._allowlist = list(allowlist)
        self._sessions: dict[str, Session] = {}
        self.ended: dict[str, Session] = {}
        self.audit: list[dict] = []

    def allowlist(self) -> list[str]:
        return list(self._allowlist)

    # -- lifecycle -----------------------------------------------------
    def register(self, session_id: str, info: dict) -> Session:
        gating.assert_in_scope(session_id, self._allowlist, what="agent session id")
        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS and session_id not in self._sessions:
                raise ScopeViolation("max lab sessions reached")
            if session_id in self._sessions:
                sess = self._sessions[session_id]
                sess.status = "active"
                sess.last_seen = _now()
                return sess
            sess = Session(id=session_id, hostname=info.get("hostname", "?"), info=info)
            sess.pid = info.get("pid")
            self._sessions[session_id] = sess
            self._audit({"kind": "hello", "session": session_id, "info": info})
            return sess

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_ended(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self.ended.get(session_id)

    def heartbeat(self, session_id: str, seq: int | None = None) -> bool:
        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess or sess.status != "active":
                return False
            sess.last_seen = _now()
            sess.checkin_times.append(_now())
            self._audit({"kind": "checkin", "session": session_id, "seq": seq})
            return True

    def _audit(self, ev: dict) -> None:
        self.audit.append({"at": _utcnow(), **ev})

    def _audit_replace(self, ev: dict) -> None:
        """Replace trailing event (used to keep single checkin-noise out of files)."""
        self.audit.append({"at": _utcnow(), **ev})

    def live_ids(self) -> list[str]:
        with self._lock:
            return [
                sid for sid, s in self._sessions.items() if s.status == "active"
            ]

    # -- task queue ----------------------------------------------------
    def queue(
        self,
        session_id: str,
        task: dict,
        *,
        require_consent: bool,
        consent: bool = False,
    ) -> Task:
        sess = self.get(session_id)
        if not sess:
            raise ScopeViolation(f"no active session {session_id!r}")
        if len(sess.tasks) >= 1000:
            raise ScopeViolation("session task queue full")
        t = Task(
            task_id=task["task_id"],
            type=task["type"],
            params=task.get("params", {}),
            allowlisted=bool(task.get("allowlisted", False) or consent),
        )
        if t.type in SIDE_EFFECTING_TASKS and t.type != "KILL":
            if not gating.allowlist_membership(session_id, self._allowlist):
                t.scope_ok = False
                raise ScopeViolation(f"session {session_id!r} not in lab allowlist")
            if require_consent and not t.allowlisted:
                raise ScopeViolation(
                    f"task {t.type} requires --lab-allowlist (operator consent)"
                )
        if t.type == "KILL":
            if not gating.allowlist_membership(session_id, self._allowlist):
                t.scope_ok = False
                raise ScopeViolation(f"session {session_id!r} not in lab allowlist")
        t.scope_ok = True
        with self._lock:
            sess.tasks.append(t)
            self._audit({"kind": "queue", "session": session_id, "task": t.to_dict()})
        return t

    def pending(self, session_id: str) -> list[dict]:
        sess = self.get(session_id)
        if not sess:
            return []
        out = []
        with self._lock:
            for t in sess.tasks:
                if t.result is None and t.dispatched_at is None:
                    t.dispatched_at = _now()
                    out.append(t.to_dict())
        return out

    def finish(self, session_id: str, result: dict) -> dict | None:
        sess = self.get(session_id)
        if not sess:
            return None
        task_id = result.get("task_id")
        rtt = None
        with self._lock:
            for t in sess.tasks:
                if t.task_id == task_id and t.result is None:
                    t.result = result
                    t.result_at = _now()
                    if t.dispatched_at:
                        rtt = t.result_at - t.dispatched_at
                        sess.rtts.append(rtt)
                    break
            ev = dict(result)
            ev["at"] = _utcnow()
            ev["session"] = session_id
            sess.results.append(ev)
            self._audit({"kind": "result", "session": session_id, "result": ev})
        return {"rtt": rtt, "result": result}

    def wipe(self, session_id: str, reason: str = "kill") -> Optional[Session]:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
            if not sess:
                return self.ended.get(session_id)
            sess.status = "killed"
            sess.killed_at = _utcnow()
            self.ended[session_id] = sess
            self._audit({"kind": "wipe", "session": session_id, "reason": reason})
            return sess

    def sweep(self, timeout: float) -> list[str]:
        expired = []
        with self._lock:
            ttl = beacon_mod.SessionTimeout(timeout)
            for sid, sess in list(self._sessions.items()):
                if sess.status == "active" and ttl.is_expired(sess.last_seen):
                    sess.status = "timed-out"
                    self.ended[sid] = sess
                    del self._sessions[sid]
                    expired.append(sid)
                    self._audit({"kind": "timeout", "session": sid})
        return expired

    def session_summary(self, s: Session) -> dict:
        return {
            "id": s.id,
            "hostname": s.hostname,
            "status": s.status,
            "first_seen": s.first_seen,
            "last_seen": s.last_seen,
            "last_seen_epoch": s.last_seen,
            "pid": s.pid,
            "task_count": len(s.tasks),
            "result_count": len(s.results),
            "beacon_count": len(s.checkin_times),
            "rtt_avg_ms": (sum(s.rtts) / len(s.rtts) * 1000) if s.rtts else None,
        }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "sessions": [self.session_summary(s) for s in self._sessions.values()],
                "ended": [self.session_summary(s) for s in self.ended.values()],
                "audit_count": len(self.audit),
            }

    def full_dump(self) -> dict:
        """Complete serializable registry state (used for offline reports)."""

        def _one(s: Session) -> dict:
            return {
                **self.session_summary(s),
                "tasks": [t.to_dict() for t in s.tasks],
                "results": list(s.results),
                "checkin_times": list(s.checkin_times),
                "rtts": list(s.rtts),
                "timeline": s.timeline(),
            }

        with self._lock:
            return {
                "sessions": {sid: _one(s) for sid, s in self._sessions.items()},
                "ended": {sid: _one(s) for sid, s in self.ended.items()},
                "audit": list(self.audit),
            }


class Server:
    """Loopback C2 listener + session registry + task queue."""

    def __init__(
        self,
        cfg: LabConfig,
        crypto: Crypto,
        *,
        host: str = "127.0.0.1",
        port: int | None = None,
        persist: bool = True,
    ) -> None:
        self.cfg = cfg
        self.host = gating.assert_loopback(host or cfg.listen_host, "listen host")
        self.port = port if port is not None else int(cfg.listen_port)
        self.crypto = crypto
        self.persist = persist
        self.registry = SessionRegistry(cfg.allowlist)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._beacon = beacon_mod.BeaconChannel(loss_rate=0.0)
        self._beacon_lock = threading.Lock()
        self._conns: dict[int, socket.socket] = {}
        self._conns_lock = threading.Lock()
        self.state_file: Path = cfg.state_path / "server_state.json"
        self.started_at: Optional[str] = None
        self._connections = 0

    @property
    def alive(self) -> bool:
        return not self._stop.is_set() and self._sock is not None

    def start(self) -> "Server":
        assert self._sock is None, "server already started"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        self.port = sock.getsockname()[1]
        sock.listen(8)
        sock.settimeout(0.5)
        self._sock = sock
        self.started_at = _utcnow()
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="hermes-accept", daemon=True)
        self._thread.start()
        self._ready.set()
        self._write_state()
        return self

    def wait_ready(self, timeout: float = 5.0) -> None:
        self._ready.wait(timeout)
        assert self._sock is not None, "server failed to start"

    def stop(self) -> dict:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        # close every accepted connection so agent/ctl peers see EOF promptly
        # instead of leaving daemon handler threads parked on dead peers.
        with self._conns_lock:
            conns = list(self._conns.values())
            self._conns.clear()
        for conn in conns:
            try:
                conn.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        return self._write_state(status="stopped")

    # -- accept loop ---------------------------------------------------
    def _accept_loop(self) -> None:
        sock = self._sock
        while not self._stop.is_set() and sock is not None:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._connections += 1
            with self._conns_lock:
                self._conns[id(conn)] = conn
            threading.Thread(
                target=self._handle_connection, args=(conn, addr), daemon=True
            ).start()
        self._write_state(status="stopping")

    def _handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        host, _port = addr[:2]
        if not gating.is_loopback(host):
            try:
                conn.close()
            except OSError:
                pass
            return
        conn.settimeout(60)

        def send(msg: dict) -> None:
            self.crypto.send(conn, msg)

        try:
            while not self._stop.is_set():
                try:
                    _kid, msg = self.crypto.recv(conn)
                except CryptoError:
                    break
                except (socket.timeout, OSError):
                    break
                try:
                    self._dispatch(host, msg, send)
                except ScopeViolation as exc:
                    self.registry._audit({"kind": "scope-violation", "detail": str(exc)})
                    if msg.get("type") == "ctl":
                        try:
                            send({"type": "ctl-error", "detail": str(exc)})
                        except OSError:
                            return
                except Exception as exc:  # treat any dispatch fault as a drop
                    self.registry._audit(
                        {"kind": "dispatch-error", "detail": f"{type(exc).__name__}: {exc}"}
                    )
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._conns_lock:
                self._conns.pop(id(conn), None)

    def _dispatch(self, peer_host: str, msg: dict, send: Callable[[dict], None]) -> None:
        mtype = msg.get("type")
        if mtype == "hello":
            sid = str(msg.get("id", ""))
            gating.assert_in_scope(sid, self.registry.allowlist(), what="agent session id")
            info = msg.get("info", {}) or {}
            self.registry.register(sid, info)
            # hello is the opening loopback beacon
            with self._beacon_lock:
                bseq = int(self._beacon.send(payload=f"hello:{sid}"))
                self._beacon.ack(bseq)
            self.registry.heartbeat(sid, seq=bseq)
            send({"type": "hello-ack", "session": sid, "seq": bseq})
            return
        if mtype == "checkin":
            sid = str(msg.get("id", ""))
            seq = msg.get("seq")
            self.registry.heartbeat(sid, seq=seq)
            # each checkin is a real loopback beacon
            with self._beacon_lock:
                bseq = int(self._beacon.send(payload=f"checkin:{sid}"))
                self._beacon.ack(bseq)
            tasks = self.registry.pending(sid)
            send({"type": "tasks", "tasks": tasks, "seq": seq})
            return
        if mtype == "result":
            sid = str(msg.get("id", ""))
            self.registry.heartbeat(sid)
            result = dict(msg.get("result", {}))
            self.registry.finish(sid, result)
            if result.get("type") == "unloaded":
                self.registry.wipe(sid, reason="killswitch")
            send({"type": "result-ack", "ok": True})
            return
        if mtype == "byebye":
            sid = str(msg.get("id", ""))
            self.registry.heartbeat(sid)
            sess = self.registry.get(sid)
            if sess and sess.status == "active":
                sess.status = "gone"
                self.registry._audit({"kind": "byebye", "session": sid})
            return
        if mtype == "ctl":
            self._handle_ctl(peer_host, msg, send)
            return
        self.registry._audit({"kind": "unknown-type", "type": mtype, "peer": peer_host})

    def _handle_ctl(self, peer_host: str, msg: dict, send: Callable[[dict], None]) -> None:
        if not gating.is_loopback(peer_host):
            raise ScopeViolation("ctl channel requires a loopback peer")
        op = msg.get("op")
        if op == "shutdown":
            self.registry._audit({"kind": "ctl-shutdown", "peer": peer_host})
            send({"type": "ctl-ack", "op": "shutdown"})
            self._stop.set()
            return
        if op == "status":
            send({"type": "ctl-status", "server": self.status(), "alive": True})
            return
        if op == "queue":
            sid = str(msg.get("session", ""))
            task = dict(msg.get("task", {}))
            consent = bool(msg.get("consent", False))
            self.registry.queue(
                sid,
                task,
                require_consent=not bool(task.get("allowlisted", False) or consent),
                consent=consent,
            )
            send(
                {
                    "type": "ctl-ack",
                    "op": "queue",
                    "task": task.get("task_id"),
                    "allowlisted": bool(task.get("allowlisted", False) or consent),
                }
            )
            return
        if op == "list":
            send({"type": "ctl-list", "sessions": self.registry.snapshot()})
            return
        if op == "results":
            sid = str(msg.get("session", ""))
            sess = self.registry.get(sid)
            if not sess:
                send(
                    {
                        "type": "ctl-error",
                        "detail": f"no active session {sid!r}",
                        "op": "results",
                    }
                )
                return
            with self.registry._lock:
                results = [dict(r) for r in sess.results]
            send({"type": "ctl-results", "session": sid, "results": results})
            return
        if op == "wipe":
            sid = str(msg.get("session", ""))
            self.registry.wipe(sid, reason="ctl-wipe")
            send({"type": "ctl-ack", "op": "wipe", "session": sid})
            return
        send({"type": "ctl-error", "detail": f"unknown ctl op {op!r}"})

    # -- controller / operator API ------------------------------------
    def queue_task(
        self,
        session_id: str,
        task_type: str,
        params: dict | None = None,
        *,
        allowlisted: bool = False,
        consent: bool = False,
    ) -> str:
        """Queue a task for a session from an in-process controller."""
        if task_type in ("exec", "upload") and not (allowlisted or consent):
            gating.require_operator_consent(False, "side-effecting task")
        if task_type in ("exec", "upload") and (allowlisted or consent):
            allowlisted = True
        if task_type == "KILL" and not (allowlisted or consent):
            gating.require_operator_consent(False, "killswitch task")
        task = make_task(task_type, params, allowlisted=allowlisted)
        return self.registry.queue(
            session_id, task, require_consent=not (allowlisted or consent)
        ).task_id

    def status(self) -> dict:
        snap = self.registry.snapshot()
        beacon_metrics = self._beacon.metrics()
        intervals = []
        for s in self.registry._sessions.values():
            ct = s.checkin_times
            intervals.extend(
                ct[i] - ct[i - 1] for i in range(1, len(ct))
            )
        jit = beacon_mod.summarize_jitter(intervals, float(self.cfg.agent_interval))
        return {
            "host": self.host,
            "port": self.port,
            "alive": self.alive,
            "started_at": self.started_at,
            "connections": self._connections,
            "sessions": snap["sessions"],
            "ended": snap["ended"],
            "beacons": beacon_metrics,
            "jitter": jit,
            "crypto": self.crypto.stats(),
            "audit_count": snap["audit_count"],
        }

    def _write_state(self, status: str = "running") -> dict:
        if not self.persist:
            return {}
        state = {
            "host": self.host,
            "port": self.port,
            "status": status,
            "pid": os.getpid(),
            "updated_at": _utcnow(),
            "server": self.status(),
        }
        save_json(self.state_file, state)
        save_json(
            self.state_file.parent / "registry_dump.json",
            {"generated_at": _utcnow(), "registry": self.registry.full_dump()},
        )
        return state


class CtrlClient:
    """Controller connection for queueing tasks and reading server status.

    Speaks the same encrypted framed protocol over loopback; requires the
    runtime passphrase (a real lab operator on the same host).
    """

    def __init__(self, crypto: Crypto, host: str, port: int) -> None:
        self.host = gating.assert_loopback(host, "ctl host")
        self.port = int(port)
        self.crypto = crypto
        self._sock: Optional[socket.socket] = None

    def connect(self) -> "CtrlClient":
        self._sock = socket.create_connection((self.host, self.port), timeout=10)
        return self

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _rpc(self, msg: dict) -> dict:
        if not self._sock:
            self.connect()
        try:
            self.crypto.send(self._sock, msg)
            _kid, reply = self.crypto.recv(self._sock)
        except (CryptoError, OSError):
            # Loss replay: drop the dead connection and retry the call once.
            # On the loopback lab a dropped rpc means the server never got a
            # valid frame, so a single fresh attempt is safe and idempotent
            # from the operator's perspective.
            self.close()
            self.connect()
            self.crypto.send(self._sock, msg)
            _kid, reply = self.crypto.recv(self._sock)
        return reply

    def status(self) -> dict:
        return self._rpc({"type": "ctl", "op": "status"})

    def shutdown(self) -> dict:
        return self._rpc({"type": "ctl", "op": "shutdown"})

    def queue(self, session_id: str, task: dict, *, consent: bool = False) -> dict:
        return self._rpc(
            {
                "type": "ctl",
                "op": "queue",
                "session": session_id,
                "task": task,
                "consent": consent,
            }
        )

    def wipe(self, session_id: str) -> dict:
        return self._rpc({"type": "ctl", "op": "wipe", "session": session_id})

    def results(self, session_id: str) -> dict:
        return self._rpc({"type": "ctl", "op": "results", "session": session_id})

    def list(self) -> dict:
        return self._rpc({"type": "ctl", "op": "list"})

    def __enter__(self) -> "CtrlClient":
        return self.connect()

    def __exit__(self, *exc: Any) -> None:
        self.close()