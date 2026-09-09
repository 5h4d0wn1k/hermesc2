"""Multi-stage operation definitions (plans), static scope check, audit.

An op plan is a committed JSON file describing stages such as
recon -> exec-info -> result, executed against a lab agent with operator
approval (--approved) and a static scope check that refuses any host outside
the loopback / lab-* allowlist. Every executed stage is appended to an audit
trail (JSONL) and to the final report.
"""

from __future__ import annotations

import datetime as _dt
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import gating
from .config import LabConfig
from .gating import ScopeViolation
from .server import Server
from .tasks import TASK_TYPES

OP_VERSION = "1.0"


class OpError(Exception):
    """Invalid op plan or execution failure."""


@dataclass
class Stage:
    id: str
    task: dict

    @classmethod
    def from_dict(cls, d: dict) -> "Stage":
        if not isinstance(d, dict) or not d.get("id"):
            raise OpError("stage requires an id")
        task = d.get("task")
        if not isinstance(task, dict) or task.get("type") not in TASK_TYPES:
            raise OpError(f"stage {d.get('id')!r} has no valid task type")
        return cls(id=str(d["id"]), task=task)


@dataclass
class OpPlan:
    name: str
    target: str
    stages: list[Stage]
    scope: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "OpPlan":
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OpError(f"cannot read op plan {path}: {exc}")
        if not isinstance(data, dict):
            raise OpError("op plan must be a JSON object")
        if str(data.get("version", "")) != OP_VERSION:
            raise OpError(
                f"op plan version mismatch: need {OP_VERSION}, got {data.get('version')}"
            )
        name = data.get("name")
        target = data.get("target")
        if not name or not target:
            raise OpError("op plan requires name and target")
        stages = [Stage.from_dict(s) for s in data.get("stages", [])]
        if not stages:
            raise OpError("op plan has no stages")
        return cls(name=str(name), target=str(target), stages=stages,
                   scope=list(data.get("scope", [])) or [str(target)])

    def static_scope_check(self, allowlist: list[str]) -> None:
        """Refuse the plan unless every host/name reference is in scope."""
        refs = set(self.scope) | {self.target}
        for stage in self.stages:
            params = stage.task.get("params", {}) or {}
            if "host" in params:
                refs.add(str(params["host"]))
            if "name" in params:
                refs.add(str(params["name"]))
        for ref in refs:
            gating.validate_target(ref, allowlist, what=f"op plan {self.name!r} target")
        # agent session id must additionally be allowlisted lab-* today
        for ref in refs:
            if not gating.is_loopback(ref):
                gating.assert_in_scope(ref, allowlist, what="op plan agent")

    def to_dict(self) -> dict:
        return {
            "version": OP_VERSION,
            "name": self.name,
            "target": self.target,
            "scope": self.scope,
            "stages": [{"id": s.id, "task": s.task} for s in self.stages],
        }


@dataclass
class OpRunResult:
    name: str
    target: str
    approved: bool
    dry_run: bool
    started_at: str
    finished_at: str
    steps: list[dict] = field(default_factory=list)
    success: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target": self.target,
            "approved": self.approved,
            "dry_run": self.dry_run,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "success": self.success,
            "steps": self.steps,
        }


def _nowiso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


class OpRunner:
    """Executes an approved, scope-validated plan against a session.

    ``queue_fn(session_id, task, consent) -> task_id`` queues a stage task.
    ``wait_result_fn(session_id, task_id, timeout) -> dict|None`` waits for the
    agent's result. Usable with an in-process Server or a CLI CtrlClient.
    """

    def __init__(
        self,
        plan: OpPlan,
        *,
        approved: bool,
        dry_run: bool,
        allowlist: list[str],
        agent: str,
        queue_fn: Callable[[str, dict, bool], str],
        wait_result_fn: Callable[[str, str, float], Optional[dict]],
        audit_path: Optional[Path] = None,
    ) -> None:
        if not approved:
            raise OpError("op run requires --approved (operator approval)")
        plan.static_scope_check(allowlist)
        if not gating.allowlist_membership(agent, allowlist):
            raise ScopeViolation(f"agent {agent!r} not in lab allowlist")
        self.plan = plan
        self.approved = approved
        self.dry_run = dry_run
        self.allowlist = list(allowlist)
        self.agent = agent
        self.queue_fn = queue_fn
        self.wait_result_fn = wait_result_fn
        self.audit_path = audit_path

    def _audit(self, entry: dict) -> None:
        if self.audit_path:
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": _nowiso(), **entry}) + "\n")

    def run(self, timeout: float = 30.0) -> OpRunResult:
        res = OpRunResult(
            name=self.plan.name,
            target=self.plan.target,
            approved=self.approved,
            dry_run=self.dry_run,
            started_at=_nowiso(),
            finished_at=_nowiso(),
        )
        consent = self.approved  # operator approval governs allowlisting;
        # the agent's own dry-run gate is what actually blocks execution.
        for stage in self.plan.stages:
            task = dict(stage.task)
            task["task_id"] = "op-" + stage.id.replace(" ", "_")
            task["allowlisted"] = bool(consent)
            step = {
                "stage": stage.id,
                "task": task,
                "queued_at": _nowiso(),
            }
            try:
                task_id = self.queue_fn(self.agent, task, consent)
            except Exception as exc:  # noqa: BLE001
                step["status"] = "queue-failed"
                step["error"] = f"{type(exc).__name__}: {exc}"
                res.steps.append(step)
                self._audit({"event": "stage-failed", "result": step})
                res.success = False
                res.finished_at = _nowiso()
                return res

            step["task_id"] = task_id
            step["queued"] = True
            result = None
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                result = self.wait_result_fn(self.agent, task_id, min(2.0, timeout))
                if result is not None:
                    break
                time.sleep(0.1)
            step["status"] = "done" if result else "timeout"
            step["result"] = result
            step["finished_at"] = _nowiso()
            res.steps.append(step)
            self._audit({"event": "stage", "stage_id": stage.id, "result": step})
        res.success = all(s.get("status") == "done" for s in res.steps)
        res.finished_at = _nowiso()
        self._audit({"event": "op-finished", "op": res.to_dict()})
        return res


def run_plan_on_server(
    plan: OpPlan,
    agent: str,
    server: Server,
    *,
    approved: bool,
    dry_run: bool,
    timeout: float = 30.0,
    audit_path: Optional[Path] = None,
) -> OpRunResult:
    """Execute an approved plan against an in-process Server (lab only)."""

    def queue_fn(sid: str, task: dict, consent: bool) -> str:
        return server.queue_task(
            sid,
            task["type"],
            task.get("params", {}),
            allowlisted=bool(task.get("allowlisted", False)),
            consent=consent,
        )

    def wait_fn(sid: str, task_id: str, _timeout: float) -> Optional[dict]:
        sess = server.registry.get(sid)
        if not sess:
            return None
        with server.registry._lock:
            for t in sess.tasks:
                if t.task_id == task_id and t.result is not None:
                    return t.result
        return None

    runner = OpRunner(
        plan=plan,
        approved=approved,
        dry_run=dry_run,
        allowlist=server.cfg.allowlist,
        agent=agent,
        queue_fn=queue_fn,
        wait_result_fn=wait_fn,
        audit_path=audit_path,
    )
    return runner.run(timeout=timeout)