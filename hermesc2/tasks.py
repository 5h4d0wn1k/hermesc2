"""Task definitions and sandboxed file handling for the lab agent.

Worker tasks (exec / upload / download / info / sleep / exit / KILL) are
strictly confined: `exec` only runs allowlisted demo commands, file tasks only
touch relative paths under the c2_data sandbox that start with `lab_`, and
`KILL` is the hard-gated unloader.
"""

from __future__ import annotations

import base64
import datetime as _dt
import os
import platform
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

SAFE_EXEC_FALLBACK = ("date", "hostname")
SANDBOX_REL_RE = re.compile(r"^(lab_)[A-Za-z0-9_.\-/]*$")
MAX_UPLOAD_BYTES = 256 * 1024

TASK_TYPES = frozenset({"exec", "upload", "download", "info", "sleep", "exit", "KILL"})
RESULT_TYPES = frozenset({"result", "error", "would-run", "unloaded"})


class TaskError(Exception):
    """Invalid/unsafe task."""


class SandboxViolation(Exception):
    """Path escape attempt from the c2_data lab sandbox."""


def new_task_id() -> str:
    return "t-" + str(uuid.uuid4())[:8]


def make_task(
    task_type: str,
    params: dict | None = None,
    *,
    task_id: Optional[str] = None,
    allowlisted: bool = False,
) -> dict:
    if task_type not in TASK_TYPES:
        raise TaskError(f"unknown task type {task_type!r}")
    return {
        "task_id": task_id or new_task_id(),
        "type": task_type,
        "params": dict(params or {}),
        "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "allowlisted": bool(allowlisted),
        "scope": {"host": "127.0.0.1", "allowlist_required": True},
    }


class Sandbox:
    """File confinement under c2_data/, only lab_* relative paths."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def resolve(self, rel: str, *, write: bool = False) -> Path:
        r = (rel or "").strip()
        if not r:
            raise SandboxViolation("empty sandbox path")
        r = r.replace("\\", "/")
        while r.startswith("/"):
            if write:
                raise SandboxViolation("absolute paths are forbidden for writes")
            r = r[1:]
        if not SANDBOX_REL_RE.match(r):
            raise SandboxViolation(
                f"path {rel!r} must stay inside c2_data/ and start with lab_"
            )
        candidate = self.root / r
        # final anchor check: resolved path must remain under sandbox root
        try:
            candidate.resolve().relative_to(self.root)
        except ValueError:
            raise SandboxViolation(f"path {rel!r} escapes the sandbox")
        if r == "lab_" or candidate.resolve() == self.root:
            raise SandboxViolation(f"path {rel!r} is a sandbox root alias")
        return candidate


def _command_ok(cmd: str, allowed: tuple[str, ...]) -> bool:
    """Only allow bare allowlisted demo commands (no pipes, no args abuse)."""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False
    if not parts:
        return False
    # Only the bare command token is accepted: zero arguments allowed.
    if len(parts) != 1 or any(ch in parts[0] for ch in ("`", "$", ";", "|", "&")):
        return False
    return parts[0] in allowed


def run_exec(task: dict, *, allowed_commands: tuple[str, ...], dry_run: bool,
             operator_consent: bool) -> dict:
    cmd = str(task.get("params", {}).get("command", "")).strip()
    allowlisted = bool(task.get("allowlisted", False))
    if not allowlisted:
        raise TaskError("exec task was not allowlisted by the operator (--lab-allowlist)")
    if dry_run:
        # The agent-level dry-run gate is absolute: an agent in dry-run mode
        # never executes, even with operator consent (--lab-allowlist).
        return _would_run(task, cmd, "agent-level dry-run gate active")
    if not operator_consent:
        return _would_run(task, cmd, "operator consent not granted (--lab-allowlist)")
    if not _command_ok(cmd, allowed_commands):
        raise TaskError(f"command {cmd!r} is not an allowlisted lab demo command")
    start = _dt.datetime.now(_dt.timezone.utc)
    proc = subprocess.run(
        cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15
    )
    return {
        "type": "result",
        "task_id": task["task_id"],
        "status": "ok" if proc.returncode == 0 else "rc",
        "returncode": proc.returncode,
        "command": cmd,
        "output": proc.stdout,
        "duration_ms": int((_dt.datetime.now(_dt.timezone.utc) - start).total_seconds() * 1000),
    }


def _would_run(task: dict, cmd: str, reason: str) -> dict:
    return {
        "type": "would-run",
        "task_id": task["task_id"],
        "command": cmd,
        "status": "simulated",
        "reason": reason,
        "output": f"[DRY-RUN] would run: {cmd}",
    }


def run_info() -> dict:
    """Local system info (read-only, always allowed in the lab)."""
    return {
        "type": "result",
        "task_id": None,
        "status": "ok",
        "hostname": platform.node() or None,
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "pid": os.getpid(),
    }


def run_sleep(task: dict) -> dict:
    seconds = float(task.get("params", {}).get("seconds", 0))
    seconds = min(max(seconds, 0.0), 3600.0)
    start = _dt.datetime.now(_dt.timezone.utc)
    time.sleep(seconds)
    return {
        "type": "result",
        "task_id": task["task_id"],
        "status": "ok",
        "slept": seconds,
        "duration_ms": int((_dt.datetime.now(_dt.timezone.utc) - start).total_seconds() * 1000),
    }


def run_download(task: dict, sandbox: Sandbox) -> dict:
    rel = str(task.get("params", {}).get("path", ""))
    path = sandbox.resolve(rel)
    if not path.is_file():
        return {"type": "error", "task_id": task["task_id"], "status": "missing", "path": rel}
    data = path.read_bytes()
    if len(data) > MAX_UPLOAD_BYTES:
        return {"type": "error", "task_id": task["task_id"], "status": "too-large", "path": rel}
    return {
        "type": "result",
        "task_id": task["task_id"],
        "status": "ok",
        "path": rel,
        "size": len(data),
        "content_b64": base64.b64encode(data).decode("ascii"),
    }


def run_upload(task: dict, sandbox: Sandbox) -> dict:
    rel = str(task.get("params", {}).get("path", ""))
    if not bool(task.get("allowlisted", False)):
        raise TaskError("upload task was not allowlisted by the operator (--lab-allowlist)")
    content = str(task.get("params", {}).get("content_b64", ""))
    data = base64.b64decode(content) if content else b""
    if len(data) > MAX_UPLOAD_BYTES:
        return {"type": "error", "task_id": task["task_id"], "status": "too-large", "path": rel}
    path = sandbox.resolve(rel, write=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "type": "result",
        "task_id": task["task_id"],
        "status": "ok",
        "path": rel,
        "size": len(data),
    }


def process_task(task: dict, *, sandbox: Sandbox,
                 allowed_commands: tuple[str, ...],
                 dry_run: bool, operator_consent: bool) -> dict:
    """Route one task through its handler; returns a result envelope."""
    t = task.get("type")
    if t not in TASK_TYPES:
        return {"type": "error", "task_id": task.get("task_id"), "status": "unsupported",
                "detail": f"unknown task type {t!r}"}
    if t == "exec":
        return run_exec(task, allowed_commands=allowed_commands,
                        dry_run=dry_run, operator_consent=operator_consent)
    if t == "info":
        return run_info()
    if t == "sleep":
        return run_sleep(task)
    if t == "download":
        return run_download(task, sandbox)
    if t == "upload":
        return run_upload(task, sandbox)
    if t == "exit":
        return {"type": "result", "task_id": task["task_id"], "status": "ok", "exit": True}
    # KILL handled by the agent loop directly (needs unload semantics).
    raise TaskError("handled-elsewhere: KILL offline task")