"""hermesc2 command line interface.

Entry point: ``hermesc2 = hermesc2.cli:main``. Every command is lab-scoped;
destructive/side-effecting operations require ``--lab-allowlist``. ``--demo``
is the offline-ish live loopback proof that always exits 0 on success.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import __version__, gating
from .config import load_config
from .gating import ScopeViolation
from .labruntime import (
    bump_key_id,
    current_key_id,
    ensure_passphrase,
    init_lab,
)
from .crypto import Crypto, roundtrip_selftest
from .beacon import BeaconChannel, BeaconStepper, SessionTimeout, summarize_jitter

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _parse_keyval(pairs: list[str]) -> dict:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"bad --param {p!r} (expected k=v)")
        k, _, v = p.partition("=")
        out[k] = v
    return out


def _load_crypto(cfg) -> Crypto:
    import os

    ph = os.environ.get("HERMES_LAB_PASSPHRASE")
    if ph is None:
        ph = ensure_passphrase(cfg)
    return Crypto(ph.encode() if isinstance(ph, str) else ph)


def _cmd_lab_init(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    status = init_lab(cfg, force=args.force)
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


def _cmd_lab_status(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    kid = current_key_id(cfg)
    state = cfg.state_path / "server_state.json"
    info = {
        "state_dir": str(cfg.state_path),
        "passphrase_present": (cfg.state_path / "lab.passphrase").exists(),
        "key_id": kid,
        "allowlist": cfg.allowlist,
        "listen_host": cfg.listen_host,
        "server_state_file": str(state) if state.exists() else None,
    }
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------
def _cmd_server_run(args: argparse.Namespace) -> int:
    """Foreground service loop (used by `server start` and directly)."""
    from .server import Server

    cfg = load_config(args.config)
    if args.port:
        cfg = cfg.with_overrides(listen_port=args.port)
    try:
        ph = ensure_passphrase(cfg)
    except OSError as exc:
        print(f"server: cannot set up lab key state: {exc}", file=sys.stderr)
        return 1
    crypto = Crypto(ph, seed_key_id=args.keyid or current_key_id(cfg))
    server = Server(cfg, crypto, port=int(cfg.listen_port), persist=True).start()
    server.wait_ready()
    print(f"[hermes] listener up on {server.host}:{server.port} "
          f"(pid={os.getpid()}, kid={crypto.key_id})", flush=True)
    try:
        while server.alive:
            time.sleep(0.5)
            server.registry.sweep(float(cfg.session_timeout))
    except KeyboardInterrupt:
        pass
    server.stop()
    print("[hermes] listener down")
    return 0


def _cmd_server_start(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.port:
        cfg = cfg.with_overrides(listen_port=args.port)
    state = cfg.state_path
    state.mkdir(parents=True, exist_ok=True)
    log = state / "server.log"
    ensure_passphrase(cfg)
    cmd = [
        sys.executable, "-m", "hermesc2", "server", "run",
        "--config", str(args.config),
    ]
    if args.port:
        cmd += ["--port", str(args.port)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    with open(log, "ab") as fh:
        proc = subprocess.Popen(
            cmd, stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True, env=env,
        )
    deadline = time.monotonic() + 8
    state_file = state / "server_state.json"
    while time.monotonic() < deadline:
        if state_file.exists() and proc.poll() is None:
            last = json.loads(state_file.read_text(encoding="utf-8"))
            if last.get("status") == "running":
                print(f"server started: pid={proc.pid} port={last.get('port')} "
                      f"log={log}")
                return 0
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    print("server failed to start (see state/server.log)", file=sys.stderr)
    return 1


def _cmd_server_status(args: argparse.Namespace) -> int:
    from .server import CtrlClient, Server

    cfg = load_config(args.config)
    crypto = _load_crypto(cfg)
    port = args.port or int(cfg.listen_port)
    try:
        with CtrlClient(crypto, "127.0.0.1", port) as ctl:
            reply = ctl.status()
    except OSError as exc:
        print(json.dumps({"alive": False, "error": str(exc)}, indent=2))
        return 1
    st = reply.get("server", {})
    if args.json:
        print(json.dumps(st, indent=2, sort_keys=True))
    else:
        print(f"alive={st.get('alive')} host={st.get('host')} port={st.get('port')}")
        print(f"sessions: {len(st.get('sessions', []))} live, "
              f"{len(st.get('ended', []))} ended; beacons {st.get('beacons', {})}")
        print(f"jitter: {st.get('jitter', {})}")
        print(f"crypto: seals={st.get('crypto', {}).get('seals')} "
              f"opens={st.get('crypto', {}).get('opens')}")
    return 0


def _cmd_server_stop(args: argparse.Namespace) -> int:
    from .server import CtrlClient

    cfg = load_config(args.config)
    crypto = _load_crypto(cfg)
    state_file = cfg.state_path / "server_state.json"
    port = args.port or int(cfg.listen_port)
    try:
        with CtrlClient(crypto, "127.0.0.1", port) as ctl:
            reply = ctl.shutdown()
    except OSError as exc:
        print(f"stop: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(reply, sort_keys=True))
    # wait for pid to exit if we know it
    try:
        pid = int(json.loads(state_file.read_text(encoding="utf-8")).get("pid", 0))
        if pid and pid > 0:
            for _ in range(50):
                if not _pid_alive(pid):
                    break
                time.sleep(0.1)
    except (OSError, ValueError):
        pass
    return 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _cmd_server_task(args: argparse.Namespace) -> int:
    from .server import CtrlClient
    from .tasks import make_task

    cfg = load_config(args.config)
    crypto = _load_crypto(cfg)
    port = args.port or int(cfg.listen_port)
    params = _parse_keyval(args.param)
    task = make_task(args.type, params, allowlisted=args.lab_allowlist)
    with CtrlClient(crypto, "127.0.0.1", port) as ctl:
        reply = ctl.queue(args.session, task, consent=args.lab_allowlist)
    print(json.dumps(reply, indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# agent
# ---------------------------------------------------------------------------
def _cmd_agent(args: argparse.Namespace) -> int:
    from .sample_agent import build_parser, main as sample_main

    argv = [
        "--config", str(args.config),
        "--id", args.id,
    ]
    if args.port:
        argv += ["--port", str(args.port)]
    if args.interval:
        argv += ["--interval", str(args.interval)]
    if args.beacons:
        argv += ["--beacons", str(args.beacons)]
    if args.once:
        argv += ["--once"]
    if args.dry_run is not None:
        argv += ["--dry-run", str(args.dry_run)]
    if args.lab_allowlist:
        argv += ["--lab-allowlist"]
    return sample_main(argv)


# ---------------------------------------------------------------------------
# beacon
# ---------------------------------------------------------------------------
def _cmd_beacon_sim(args: argparse.Namespace) -> int:
    stepper = BeaconStepper(base_interval=args.interval, jitter=args.jitter, seed=args.seed)
    channel = BeaconChannel(loss_rate=args.loss, replay_timeout=args.replay, seed=args.seed)
    # emulate checkin loop with real intervals
    intervals = []
    for _ in range(args.count):
        seq = channel.send()
        channel.ack(seq)
        intervals.append(stepper.next_interval())
        for replay in channel.pending():
            channel.ack(replay.seq)
    metrics = channel.metrics()
    jit = summarize_jitter(intervals, args.interval)
    out = {
        "sim": "loopback-beacon",
        "interval_base": args.interval,
        "jitter_config": args.jitter,
        "loss_config": args.loss,
        "channel": metrics,
        "jitter_measured": jit,
        "timeout_ok": SessionTimeout(args.timeout).is_expired(
            time.time() - (args.interval * args.count * 2),
            time.time(),
        )
        if args.count
        else None,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# encryption
# ---------------------------------------------------------------------------
def _cmd_encryption(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.action == "rotate":
        kid = bump_key_id(cfg)
        print(f"key id rotated to {kid} (state dir {cfg.state_path})")
        return 0
    crypto = _load_crypto(cfg)
    rt = roundtrip_selftest(crypto)
    print(json.dumps(rt, indent=2, sort_keys=True))
    if not (rt["plaintext_unchanged"] and rt["magic_ok"]):
        return 1
    return 0


# ---------------------------------------------------------------------------
# payload
# ---------------------------------------------------------------------------
def _cmd_payload(args: argparse.Namespace) -> int:
    from . import payload as pl

    cfg = load_config(args.config)
    if args.action == "demo":
        path = pl.demo_payload(cfg, agent_id=args.id)
        print(f"demo payload written: {path}")
        print(f"scope tag: {pl.PAYLOAD_TAG}")
        data = path.read_bytes()
        print(pl.opsec_page(cfg, data, {"kind": "demo-payload", "agent": args.id}))
        return 0
    if args.action == "gen":
        host = gating.assert_loopback(args.target or "127.0.0.1", "payload target")
        gating.validate_target(host, cfg.allowlist, what="payload target")
        path = pl.save_payload(
            cfg,
            target=host,
            agent_id=args.id,
            dry_run=True if args.dry_run is None else bool(int(args.dry_run)),
        )
        print(f"payload written: {path}")
        print(f"target: {host} (loopback-only)")
        return 0
    if args.action == "hex":
        data = (args.data or "").encode("utf-8")
        print(pl.poison_hex(data))
        return 0
    print(f"payload: unknown action {args.action!r}")
    return 1


# ---------------------------------------------------------------------------
# ops
# ---------------------------------------------------------------------------
def _cmd_ops(args: argparse.Namespace) -> int:
    from .ops import OpPlan
    from .report import _nowstr

    cfg = load_config(args.config)
    plan = OpPlan.load(args.plan)
    if args.action == "check":
        plan.static_scope_check(cfg.allowlist)
        print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        print("scope check: OK (loopback / lab-* only)")
        return 0
    if args.action == "run":
        from .server import CtrlClient
        from .ops import OpRunner

        if not args.approved:
            print("ops run requires --approved", file=sys.stderr)
            return 2
        crypto = _load_crypto(cfg)
        port = args.port or int(cfg.listen_port)
        dry = True if args.dry_run is None else bool(int(args.dry_run))
        audit_path = Path("reports") / f"op-audit-{_nowstr()}.jsonl"
        with CtrlClient(crypto, "127.0.0.1", port) as ctl:

            def queue_fn(sid: str, task: dict, consent: bool) -> str:
                resp = ctl.queue(sid, task, consent=consent)
                if resp.get("type") == "ctl-error":
                    raise ScopeViolation(resp.get("detail", "ctl error"))
                return resp.get("task")

            def wait_fn(sid: str, task_id: str, _t: float) -> Optional[dict]:
                try:
                    resp = ctl.results(sid)
                except OSError:
                    return None
                if resp.get("type") == "ctl-error":
                    return None
                for r in resp.get("results", []):
                    if r.get("task_id") == task_id:
                        return r
                return None

            runner = OpRunner(
                plan=plan,
                approved=args.approved,
                dry_run=dry,
                allowlist=cfg.allowlist,
                agent=args.agent,
                queue_fn=queue_fn,
                wait_result_fn=wait_fn,
                audit_path=audit_path,
            )
            result = runner.run(timeout=args.timeout)
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        print(f"op audit: {audit_path}")
        return 0 if result.success else 1
    return 1


# ---------------------------------------------------------------------------
# killswitch
# ---------------------------------------------------------------------------
def _cmd_killswitch(args: argparse.Namespace) -> int:
    from . import killswitch as ks

    cfg = load_config(args.config)
    if args.action == "sweep":
        crypto = _load_crypto(cfg)
        try:
            stopped = ks.stop_listener(cfg, crypto, consent=args.lab_allowlist)
        except ScopeViolation as exc:
            print(f"killswitch sweep refused: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(stopped, sort_keys=True))
        # process-state cleanup (only own sample agents, loopback lab)
        from .server import Server

        pid = _state_pid(cfg)
        if pid and _pid_alive(pid):
            os.kill(pid, 15)
        print("killswitch sweep: listener + own agent state cleaned (loopback only)")
        return 0
    if args.action == "session":
        from .server import CtrlClient

        cid = args.session
        try:
            gating.allowlist_membership(cid, cfg.allowlist) or _require(cid, cfg)
        except ScopeViolation as exc:
            print(f"killswitch refused: {exc}", file=sys.stderr)
            return 2
        crypto = _load_crypto(cfg)
        port = args.port or int(cfg.listen_port)
        with CtrlClient(crypto, "127.0.0.1", port) as ctl:
            task = {"task_id": "KILL-" + cid, "type": "KILL", "params": {},
                    "allowlisted": True}
            reply = ctl.queue(cid, task, consent=True)
        print(json.dumps(reply, indent=2, sort_keys=True))
        print(f"killswitch: KILL queued for {cid}; agent will unload and be wiped")
        return 0
    return 1


def _require(name: str, cfg) -> bool:
    from .gating import assert_in_scope

    assert_in_scope(name, cfg.allowlist, what="killswitch session")
    return True


def _state_pid(cfg) -> Optional[int]:
    state_file = cfg.state_path / "server_state.json"
    try:
        return int(json.loads(state_file.read_text(encoding="utf-8")).get("pid", 0))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
def _cmd_report(args: argparse.Namespace) -> int:
    from . import report as report_mod

    cfg = load_config(args.config)
    report = report_mod.build_report_from_files(cfg)
    if args.action == "session":
        sid = args.session
        match = None
        for s in report["sessions"]:
            if s["summary"].get("id") == sid:
                match = s
                break
        if match is None:
            print(f"report: no session {sid!r} in state", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(match, indent=2, sort_keys=True))
        else:
            print(report_mod.report_to_markdown(
                {"report_id": report["report_id"], "generated_at": report["generated_at"],
                 "scope": report["scope"], "metrics": report["metrics"],
                 "sessions": [match], "ops": [], "audit": []})
            )
        return 0
    if args.action == "metrics":
        print(json.dumps(report["metrics"], indent=2, sort_keys=True))
        return 0
    written = report_mod.write_report(report, args.dir)
    print(json.dumps(written, indent=2, sort_keys=True))
    print("report OK (loopback lab only)")
    return 0


# ---------------------------------------------------------------------------
# utils
# ---------------------------------------------------------------------------
def _cmd_utils(args: argparse.Namespace) -> int:
    if args.action == "tokenscan":
        from .utils import token_scan_report

        report = token_scan_report(args.path)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["clean"] else 1
    print(f"utils: unknown action {args.action!r}")
    return 1


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------
def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    try:
        proof = run_demo(
            config=args.config,
            state_dir=args.state_dir,
            port=args.port,
            agent_interval=args.interval,
            beacons=args.beacons,
        )
    except Exception as exc:  # noqa: BLE001 - demo must surface its failure
        print(f"demo FAILED: {exc}", file=sys.stderr)
        return 1
    with open(Path(args.proof_out), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(proof, sort_keys=True) + "\n")
    return 0


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hermesc2", description="Hermes C2 lab framework")
    p.add_argument("--version", action="version", version=f"hermesc2 {__version__}")
    p.add_argument("--config", default=str(PROJECT_ROOT / "config" / "lab.yaml"))
    p.add_argument("--demo", action="store_true", help="run the live loopback demo")
    p.add_argument("--state-dir", default=None, help="demo: state dir for runtime keys")
    p.add_argument("--port", type=int, default=None, help="demo: listener port (0=auto)")
    p.add_argument("--interval", type=float, default=0.15, help="demo: beacon interval (s)")
    p.add_argument("--beacons", type=int, default=40, help="demo: beacon budget")
    p.add_argument("--proof-out", default="/tmp/hermes-demo-proof.jsonl",
                   help="demo: proof JSONL output")
    sub = p.add_subparsers(dest="command")

    # lab
    lab = sub.add_parser("lab", help="runtime lab key setup")
    lap = lab.add_subparsers(dest="action", required=True)
    li = lap.add_parser("init", help="generate runtime passphrase + key-id")
    li.add_argument("--force", action="store_true")
    ls = lap.add_parser("status", help="show lab state")
    ls.add_argument("--json", action="store_true")

    # server
    svr = sub.add_parser("server", help="C2 server core")
    svc = svr.add_subparsers(dest="action", required=True)
    r = svc.add_parser("run", help="foreground service")
    r.add_argument("--port", type=int)
    r.add_argument("--keyid", type=int)
    s = svc.add_parser("start", help="start listener in background")
    s.add_argument("--port", type=int)
    st = svc.add_parser("status", help="show listener/session status")
    st.add_argument("--port", type=int)
    st.add_argument("--json", action="store_true")
    sp = svc.add_parser("stop", help="stop the loopback listener")
    sp.add_argument("--port", type=int)
    sa = svc.add_parser("task", help="queue a task for a session")
    sa.add_argument("--session", required=True)
    sa.add_argument("--type", required=True)
    sa.add_argument("--param", action="append", default=[])
    sa.add_argument("--lab-allowlist", action="store_true")
    sa.add_argument("--port", type=int)

    # agent
    ag = sub.add_parser("agent", help="run the sandboxed lab agent")
    ag.add_argument("--id", default="lab-node-01")
    ag.add_argument("mode", choices=["once", "beacon"])
    ag.add_argument("--port", type=int)
    ag.add_argument("--interval", type=float)
    ag.add_argument("--beacons", type=int)
    ag.add_argument("--once", action="store_true")
    ag.add_argument("--dry-run", type=int, default=None)
    ag.add_argument("--lab-allowlist", action="store_true")

    # beacon
    bc = sub.add_parser("beacon", help="beacon interval simulator")
    bcc = bc.add_subparsers(dest="action", required=True)
    bs = bcc.add_parser("sim", help="simulate jitter/loss/replay over loopback")
    bs.add_argument("--interval", type=float, default=1.0)
    bs.add_argument("--jitter", type=float, default=0.2)
    bs.add_argument("--count", type=int, default=8)
    bs.add_argument("--loss", type=float, default=0.0)
    bs.add_argument("--replay", type=float, default=2.0)
    bs.add_argument("--timeout", type=float, default=30.0)
    bs.add_argument("--seed", type=int)

    # encryption
    enc = sub.add_parser("encryption", help="AES-GCM transport utilities")
    encc = enc.add_subparsers(dest="action", required=True)
    encc.add_parser("selftest")
    encc.add_parser("rotate")

    # payload
    py = sub.add_parser("payload", help="lab-only payload generation")
    pys = py.add_subparsers(dest="action", required=True)
    g = pys.add_parser("gen")
    g.add_argument("--target", default="127.0.0.1")
    g.add_argument("--id", default="lab-stager-01")
    g.add_argument("--dry-run", type=int, default=None)
    dem = pys.add_parser("demo")
    dem.add_argument("--id", default="lab-stager-01")
    hx = pys.add_parser("hex")
    hx.add_argument("--data", default="")

    # ops
    op = sub.add_parser("ops", help="multi-stage op plans")
    opc = op.add_subparsers(dest="action", required=True)
    oc = opc.add_parser("check", help="static scope check on a plan")
    oc.add_argument("plan")
    or_ = opc.add_parser("run", help="execute an approved plan against a session")
    or_.add_argument("plan")
    or_.add_argument("--agent", default="lab-node-01")
    or_.add_argument("--approved", action="store_true")
    or_.add_argument("--dry-run", type=int, default=None)
    or_.add_argument("--port", type=int)
    or_.add_argument("--timeout", type=float, default=30.0)

    # killswitch
    ks = sub.add_parser("killswitch", help="kill sessions / sweep loopback lab")
    ksc = ks.add_subparsers(dest="action", required=True)
    kss = ksc.add_parser("session")
    kss.add_argument("--session", required=True)
    kss.add_argument("--port", type=int)
    kss.add_argument("--lab-allowlist", action="store_true")
    ksw = ksc.add_parser("sweep")
    ksw.add_argument("--lab-allowlist", action="store_true")

    # report
    rp = sub.add_parser("report", help="JSON + Markdown reports")
    rpc = rp.add_subparsers(dest="action", required=True)
    ra = rpc.add_parser("all")
    ra.add_argument("--dir", default="reports")
    rs = rpc.add_parser("session")
    rs.add_argument("--session", required=True)
    rs.add_argument("--json", action="store_true")
    rm = rpc.add_parser("metrics")

    # utils
    ut = sub.add_parser("utils", help="repo hygiene utilities")
    utc = ut.add_subparsers(dest="action", required=True)
    ts = utc.add_parser("tokenscan")
    ts.add_argument("--path", default=".")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.demo:
        return _cmd_demo(args)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        handler = _HANDLERS.get(args.command)
        if handler is None:
            parser.print_help()
            return 1
        return handler(args)
    except ScopeViolation as exc:
        print(f"scope violation: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

 
def _dispatch_server(args: argparse.Namespace) -> int:
    if args.action == "run":
        return _cmd_server_run(args)
    if args.action == "start":
        return _cmd_server_start(args)
    if args.action == "status":
        return _cmd_server_status(args)
    if args.action == "stop":
        return _cmd_server_stop(args)
    if args.action == "task":
        return _cmd_server_task(args)
    return 1


def _dispatch_lab(args: argparse.Namespace) -> int:
    if args.action == "init":
        return _cmd_lab_init(args)
    if args.action == "status":
        return _cmd_lab_status(args)
    return 1


_HANDLERS = {
    "lab": _dispatch_lab,
    "server": _dispatch_server,
    "agent": _cmd_agent,
    "beacon": _cmd_beacon_sim,
    "encryption": _cmd_encryption,
    "payload": _cmd_payload,
    "ops": _cmd_ops,
    "killswitch": _cmd_killswitch,
    "report": _cmd_report,
    "utils": _cmd_utils,
}


if __name__ == "__main__":
    sys.exit(main())