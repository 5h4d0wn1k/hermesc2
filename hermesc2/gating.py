"""Laboratory safety gates.

Hermes is hard-gated to the loopback interface and to `lab-*` allowlisted
names. Every network endpoint, target, agent id and op scope passes through
these gates. Nothing in the codebase is allowed to weaken them: callers that
need a side-effecting action must pass the `--lab-allowlist` flag and receive a
*positive* allowlist membership from the configured lab config.

Only 127.0.0.1 (and its /8 loopback aliases resolved to 127.0.0.0/8),
::1 and `localhost` are acceptable network endpoints. Agent/session names must
match `lab-*`. Op scopes are validated statically against the allowlist.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})

# Allowlist wildcard semantics: "lab-*" matches any name starting with "lab-".
_LAB_WILDCARD = re.compile(r"^lab-\*$")
_LAB_NAME = re.compile(r"^lab-[A-Za-z0-9_.\-]+$")

DEFAULT_ALLOWLIST = ["127.0.0.1", "localhost", "lab-*"]


class ScopeViolation(Exception):
    """Raised when an operation is outside the laboratory allowlist."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def is_matching(entry: str, name: str) -> bool:
    """Return True if allowlist entry matches the candidate name."""
    if entry == name:
        return True
    if _LAB_WILDCARD.match(entry):
        return bool(_LAB_NAME.match(name))
    return False


def normalize_allowlist(entries: Iterable[str]) -> list[str]:
    out: list[str] = []
    for raw in entries:
        e = str(raw).strip()
        if not e or e.startswith("#"):
            continue
        if e not in out:
            out.append(e)
    return out or list(DEFAULT_ALLOWLIST)


def allowlist_membership(name: str, allowlist: Iterable[str]) -> bool:
    """True if name is inside the allowlist (supports the lab-* wildcard)."""
    return any(is_matching(e, name) for e in normalize_allowlist(allowlist))


def is_loopback(host: str) -> bool:
    h = str(host).strip().lower()
    if h in LOOPBACK_NAMES:
        return True
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return False
    return any(addr in net for net in LOOPBACK_NETS)


def assert_loopback(host: str, what: str = "network endpoint") -> str:
    """Return normalized loopback host or raise ScopeViolation.

    Every accepted endpoint (127.0.0.0/8, ::1, localhost) is normalized to the
    single IPv4 loopback address 127.0.0.1 because the Hermes listener and
    agents are IPv4-socket only. There is no IPv6 transport in this lab.
    """
    h = str(host).strip().lower()
    if not is_loopback(h):
        raise ScopeViolation(
            f"{what} {host!r} is not a loopback endpoint; Hermes is hard-gated "
            "to 127.0.0.0/8 / ::1 / localhost (lab scope only)."
        )
    return "127.0.0.1"


def assert_in_scope(name: str, allowlist: Iterable[str], what: str = "name") -> None:
    """Raise ScopeViolation unless name is inside the allowlist."""
    if allowlist_membership(name, allowlist):
        return
    raise ScopeViolation(
        f"{what} {name!r} is not in the lab allowlist "
        f"{sorted(normalize_allowlist(allowlist))}."
    )


def require_operator_consent(flag: bool, what: str) -> None:
    """Destructive/side-effecting operations require --lab-allowlist."""
    if not flag:
        raise ScopeViolation(
            f"{what} requires explicit operator consent via --lab-allowlist."
        )


def classify_host(host: str) -> str:
    """'loopback' for network endpoints, 'lab-agent' for lab-* names."""
    h = str(host).strip().lower()
    if is_loopback(h):
        return "loopback"
    if _LAB_NAME.match(h):
        return "lab-agent"
    raise ScopeViolation(
        f"{host!r} is neither a loopback address nor a declared lab-* agent name."
    )


def validate_target(host: str, allowlist: Iterable[str], what: str = "target") -> str:
    """Validate a target string (loopback endpoint or allowlisted lab-* name)."""
    cls = classify_host(host)
    if cls == "lab-agent":
        assert_in_scope(host, allowlist, what)
    else:
        assert_loopback(host, what)
    return host


def is_lab_pattern(name: str) -> bool:
    return bool(_LAB_NAME.match(name))