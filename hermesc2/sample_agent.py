"""Bundled lab agent fixture (sample_agent.py).

This is the ONLY program that Hermes agents ever execute. It is included with
the package, runs against the loopback lab config, defaults to dry-run, and
has no persistence logic. Spawned by tests / the demos with:

    python3 -m hermesc2.sample_agent --config config/lab.yaml --id lab-node-01
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sample_agent", description="Hermes lab agent fixture")
    p.add_argument("--config", default=str(Path(__file__).resolve().parent.parent / "config" / "lab.yaml"))
    p.add_argument("--id", default="lab-node-01", help="agent id (must match lab-*)")
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--interval", type=float, default=None, help="beacon base interval (s)")
    p.add_argument("--beacons", type=int, default=None, help="stop after N beacons")
    p.add_argument("--once", action="store_true", help="single beacon cycle then exit")
    p.add_argument("--dry-run", default=None, help="forced dry-run value (0/1)")
    p.add_argument("--lab-allowlist", action="store_true", help="operator consent for exec/upload")
    p.add_argument("--keystate", default=None, help="path to passphrase/key-id state dir")
    p.add_argument("--script", default=None, help="write a final report JSON to this path")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from hermesc2.config import load_config
    from hermesc2.agent import Agent
    from hermesc2.labruntime import ensure_passphrase
    from hermesc2.crypto import Crypto

    cfg = load_config(args.config)
    if args.keystate:
        cfg = cfg.with_overrides(state_dir=args.keystate)
    if args.host:
        cfg = cfg.with_overrides(listen_host=args.host)
    if args.port:
        cfg = cfg.with_overrides(listen_port=args.port)

    dry = True
    if args.dry_run is not None:
        dry = bool(int(args.dry_run))
    ph = ensure_passphrase(cfg)
    crypto = Crypto(ph)
    agent = Agent(
        cfg,
        crypto,
        args.id,
        dry_run=dry,
        operator_consent=args.lab_allowlist,
        server_host=cfg.listen_host,
        server_port=cfg.listen_port,
        beacon_base=args.interval,
    )
    print(f"[hermes] agent {agent.agent_id} pid={os.getpid()} starting "
          f"dry_run={agent.dry_run}", flush=True)
    if args.once:
        res = agent.run_once()
    else:
        res = agent.run(max_beacons=args.beacons)
    print(f"[hermes] agent {agent.agent_id} done {res}", flush=True)
    if args.script:
        Path(args.script).write_text(
            __import__("json").dumps({**res, "summary": agent.summary()}, indent=2),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())