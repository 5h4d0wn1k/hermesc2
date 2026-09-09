"""Runtime lab identity: passphrase + key-id generation (never committed).

Hermes derives its transport keys from a lab-only passphrase. The passphrase is
created at runtime by `hermesc2 lab init`, written to the (gitignored) state
directory with owner-only permissions, and never appears in the repository.
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Optional

from .config import LabConfig, save_json


def ensure_passphrase(cfg: LabConfig, force: bool = False, os_env: bool = True) -> bytes:
    """Return the lab passphrase bytes, generating it on first run.

    Precedence: HERMES_LAB_PASSPHRASE env var (runtime, ephemeral) > state file.
    """
    if os_env:
        env = os.environ.get("HERMES_LAB_PASSPHRASE")
        if env:
            return env.encode("utf-8")
    state = cfg.state_path
    pfile = Path(cfg.passphrase_file)
    if not pfile.is_absolute():
        pfile = state / pfile.name
    if force:
        pfile.unlink(missing_ok=True)
    data = None
    if pfile.exists():
        try:
            data = pfile.read_bytes()
        except OSError:
            data = None
        if len(data or b"") == 32:
            return data
    # No durable passphrase yet (or a partially-written one): generate a
    # fresh value and publish it atomically. os.link() fails with
    # FileExistsError on the loser, so exactly one generator wins and every
    # concurrent caller converges on the winner's bytes. Readers never see a
    # partial file because the target only ever appears via a complete link.
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    ph = secrets.token_bytes(32)
    tmp = pfile.with_name(f".{pfile.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(ph)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.link(tmp, pfile)
    except FileExistsError:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                data = pfile.read_bytes()
                if len(data) == 32:
                    return data
            except (FileNotFoundError, OSError):
                pass
            time.sleep(0.01)
        raise RuntimeError(f"passphrase did not materialise: {pfile}")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return ph


def init_lab(cfg: LabConfig, force: bool = False) -> dict:
    """Initialise the local lab (runtime keys). Returns a status dict."""
    ensure_passphrase(cfg, force=force)
    state = cfg.state_path
    state.mkdir(parents=True, exist_ok=True)
    kid_path = state / Path(cfg.key_id_file).name if not Path(cfg.key_id_file).is_absolute() else Path(cfg.key_id_file)
    kid = 1
    if kid_path.exists():
        try:
            kid = int(kid_path.read_text().strip())
        except ValueError:
            kid = 1
    save_json(state / "lab_manifest.json", {"lab": "loopback", "key_id": kid})
    return {"state_dir": str(state), "passphrase_file": str(kid_path.parent), "key_id": kid}


def current_key_id(cfg: LabConfig, default: int = 1) -> int:
    kid_path = cfg.state_path / Path(cfg.key_id_file).name if not Path(cfg.key_id_file).is_absolute() else Path(cfg.key_id_file)
    if kid_path.exists():
        try:
            return int(kid_path.read_text().strip())
        except ValueError:
            return default
    return default


def bump_key_id(cfg: LabConfig) -> int:
    kid = current_key_id(cfg) + 1
    kid_path = cfg.state_path / Path(cfg.key_id_file).name if not Path(cfg.key_id_file).is_absolute() else Path(cfg.key_id_file)
    kid_path.parent.mkdir(parents=True, exist_ok=True)
    kid_path.write_text(str(kid))
    return kid


def ephemeral_crypto(cfg: LabConfig, passphrase: Optional[bytes] = None):
    """Build a Crypto from the runtime passphrase (used by server/agent/demo)."""
    from .crypto import Crypto

    ph = passphrase or ensure_passphrase(cfg)
    return Crypto(ph)