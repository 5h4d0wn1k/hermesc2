"""Reporting: session timeline, op results, audit, metrics (all loopback).

Writes JSON + Markdown reports into reports/ (gitignored). Metrics covered:
beacon counts, measured jitter %, round-trip time (RTT) stats, cryptographic
seal/open counters, loss/replay for the simulated beacon channel.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any, Optional, Union

from .config import LabConfig


def _nowstr() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def collect_metrics(server: Any, cfg: LabConfig) -> dict:
    st = server.status()
    jitter = st.get("jitter", {})
    rtts = []
    for s in st.get("sessions", []):
        if s.get("rtt_avg_ms") is not None:
            rtts.append(s["rtt_avg_ms"])
    return {
        "server_host": st.get("host"),
        "server_port": st.get("port"),
        "beacons": st.get("beacons", {}),
        "jitter": jitter,
        "rtt_avg_ms": (sum(rtts) / len(rtts)) if rtts else None,
        "rtt_samples": len(rtts),
        "crypto": st.get("crypto", {}),
        "connections": st.get("connections"),
        "audit_count": st.get("audit_count"),
        "sessions_seen": len(st.get("sessions", [])) + len(st.get("ended", [])),
    }


def timeline_rows(server: Any, session_id: str) -> list[dict]:
    rows = []
    sess = server.registry.get(session_id) or server.registry.get_ended(session_id)
    if sess is None:
        return rows
    rows = sess.timeline()
    return rows


def build_report(
    server: Any,
    cfg: LabConfig,
    *,
    ops: Optional[list[dict]] = None,
    audits: Optional[list[str]] = None,
    extra: Optional[dict] = None,
) -> dict:
    """Assemble a full report dict (JSON/MD source of truth)."""
    st = server.status()
    sessions = []
    for s in st.get("sessions", []) + st.get("ended", []):
        sid = s["id"]
        sess = server.registry.get(sid) or server.registry.get_ended(sid)
        sessions.append(
            {
                "summary": s,
                "timeline": sess.timeline() if sess else [],
                "results": [dict(r) for r in sess.results] if sess else [],
            }
        )
    return {
        "report_id": _nowstr(),
        "generated_at": _iso(),
        "scope": "loopback-only (127.0.0.1) / lab-* allowlist",
        "server": {
            "host": st.get("host"),
            "port": st.get("port"),
            "started_at": st.get("started_at"),
            "alive": st.get("alive"),
        },
        "metrics": collect_metrics(server, cfg),
        "sessions": sessions,
        "ops": ops or [],
        "audit": audits or [],
        "extra": extra or {},
    }


def write_report(report: dict, out_dir: Optional[Union[str, Path]] = None) -> dict:
    out = Path(out_dir or "reports")
    out.mkdir(parents=True, exist_ok=True)
    rid = report["report_id"]
    json_path = out / f"report-{rid}.json"
    md_path = out / f"report-{rid}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(report_to_markdown(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path), "report_id": rid}


def build_report_from_files(cfg: LabConfig) -> dict:
    """Rebuild a report from persisted server state (works offline)."""
    import json

    state_path = Path(cfg.state_dir or "state") / "server_state.json"
    dump_path = state_path.parent / "registry_dump.json"
    report = {
        "report_id": _nowstr(),
        "generated_at": _iso(),
        "scope": "loopback-only (127.0.0.1) / lab-* allowlist",
        "server": {},
        "metrics": {},
        "sessions": [],
        "ops": [],
        "audit": [],
        "extra": {},
    }
    if not state_path.exists():
        return report
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return report
    st = state.get("server", {})
    report["server"] = {
        "host": st.get("host"),
        "port": st.get("port"),
        "started_at": st.get("started_at"),
        "alive": st.get("alive"),
    }
    report["metrics"] = {
        "server_host": st.get("host"),
        "server_port": st.get("port"),
        "beacons": st.get("beacons", {}),
        "jitter": st.get("jitter", {}),
        "rtt_avg_ms": st.get("jitter", {}).get("n") and None,  # placeholder, filled below
        "crypto": st.get("crypto", {}),
        "connections": st.get("connections"),
        "audit_count": st.get("audit_count"),
    }
    rtts = []
    if dump_path.exists():
        try:
            dump = json.loads(dump_path.read_text(encoding="utf-8")).get("registry", {})
        except (OSError, json.JSONDecodeError):
            dump = {}
        for kind in ("sessions", "ended"):
            entries = dump.get(kind, {})
            for sid, s in entries.items():
                s = dict(s)
                if s.get("rtt_avg_ms") is not None:
                    rtts.append(float(s["rtt_avg_ms"]))
                report["sessions"].append(
                    {
                        "summary": {k: s.get(k) for k in (
                            "id", "hostname", "status", "first_seen", "last_seen",
                            "pid", "task_count", "result_count", "beacon_count",
                            "rtt_avg_ms", "killed_at",
                        )},
                        "timeline": s.get("timeline", []),
                        "results": s.get("results", []),
                    }
                )
            report["audit"].extend(
                json.dumps(e, sort_keys=True)
                for e in dump.get("audit", [])
            )
    report["metrics"]["rtt_avg_ms"] = (sum(rtts) / len(rtts)) if rtts else None
    report["metrics"]["rtt_samples"] = len(rtts)
    return report


def report_to_markdown(report: dict) -> str:
    md = [
        f"# Hermes C2 lab report `{report['report_id']}`",
        "",
        f"**Scope:** {report['scope']}",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Metrics",
        "```json",
        json.dumps(report["metrics"], indent=2, sort_keys=True),
        "```",
        "",
    ]
    for sess in report["sessions"]:
        s = sess["summary"]
        md += [
            f"## Session `{s['id']}`",
            "",
            f"- status: {s.get('status')}  ",
            f"- hostname: {s.get('hostname')}  ",
            f"- pid: {s.get('pid')}  ",
            f"- beacons: {s.get('beacon_count')}  ",
            f"- tasks: {s.get('task_count')}  ",
            f"- rtt avg: {s.get('rtt_avg_ms')} ms",
            "",
            "### Timeline",
            "",
            "| kind | at | detail |",
            "| --- | --- | --- |",
        ]
        for ev in sess.get("timeline", []):
            md.append(f"| {ev.get('kind')} | {ev.get('at')} | {ev.get('detail')} |")
        md += ["", "### Results", ""]
        for r in sess.get("results", []):
            md.append("```json")
            md.append(json.dumps(r, indent=2, sort_keys=True))
            md.append("```")
    if report.get("ops"):
        md += ["## Op runs", ""]
        for op in report["ops"]:
            md.append("```json")
            md.append(json.dumps(op, indent=2, sort_keys=True))
            md.append("```")
    if report.get("audit"):
        md += ["", "## Audit trail (JSONL)", ""]
        md.append("```")
        for line in report["audit"]:
            md.append(line)
        md.append("```")
    return "\n".join(md) + "\n"