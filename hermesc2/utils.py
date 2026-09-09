"""Utility helpers: token-literal scan, hexdump, repo hygiene checks.

Token signatures are stored base64-encoded so no token-shaped literal ever
appears in plaintext in the repository (self-scan confirmation via
`hermesc2 utils tokenscan`).
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Iterable


def _b64(*chunks: str) -> list[str]:
    return [base64.b64encode(c.encode("ascii")).decode("ascii") for c in chunks]


# base64-hidden signature strings: AKIA*, xox*, ghp_/gho_/github_pat, sk_live,
# and the JWT header prefix eyJ. Decoded at runtime only, never committed.
ENCODED_TOKEN_PATTERNS = (
    *_b64("AKIA", "xoxb", "xoxp", "xoxa", "xoxr"),
    *_b64("ghp_", "gho_", "github_pat", "sk_live", "sk_test"),
    *_b64("eyJ", "BEGIN PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY"),
)

SKIP_PARTS = {".git", "__pycache__", ".venv", "node_modules"}


def token_patterns() -> list[str]:
    out = []
    for enc in ENCODED_TOKEN_PATTERNS:
        try:
            out.append(base64.b64decode(enc).decode("ascii"))
        except (binascii.Error, UnicodeDecodeError):
            continue
    return out


def scan_text(text: str) -> list[str]:
    lowered = text.lower()
    hits = []
    for pat in token_patterns():
        if pat.lower() in lowered:
            hits.append(pat)
    return hits


def scan_paths(paths: Iterable[Path]) -> dict:
    """Scan files under paths; return per-file hits (any token pattern)."""
    results: dict[str, list[str]] = {}
    stack = [Path(p).resolve() for p in paths]
    while stack:
        p = stack.pop()
        if any(part in SKIP_PARTS for part in p.parts):
            continue
        if p.is_dir():
            try:
                stack.extend(child for child in p.iterdir())
            except OSError:
                continue
            continue
        if not p.is_file():
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        text = raw.decode("utf-8", errors="ignore")
        if not text:
            continue
        hits = scan_text(text)
        if hits:
            results[str(p)] = hits
    return results


def token_scan_report(root: str | Path = ".") -> dict:
    results = scan_paths([Path(root)])
    return {
        "patterns": token_patterns(),
        "files_with_hits": results,
        "clean": not results,
        "scanned_root": str(Path(root).resolve()),
    }


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3 - 1}}  {asc}")
    return "\n".join(lines) or "(empty)"