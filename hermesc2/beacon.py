"""Beacon interval simulator: jitter %, loss/replay, session timeout.

Provides:
  - Beacons: intervals with jitter, sequencing, optional simulated loss and
    time-based replay (re-send of unacknowledged beacons).
  - SessionTimeout: last-seen linear-expiry checks for the session registry.
  - Metrics: measured jitter percent over real loopback checkin gaps.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Optional

MIN_INTERVAL = 0.05


class BeaconSimError(Exception):
    """Invalid beacon simulator configuration."""


@dataclass
class BeaconStepper:
    """Generates jittered beacon intervals around a base interval."""

    base_interval: float = 1.0
    jitter: float = 0.2
    seed: Optional[int] = None

    def __post_init__(self) -> None:
        if self.base_interval < MIN_INTERVAL:
            raise BeaconSimError("beacon interval must be >= 0.05s")
        if not (0.0 <= self.jitter <= 0.9):
            raise BeaconSimError("jitter must be in [0.0, 0.9]")
        self._rng = random.Random(self.seed)

    def next_interval(self) -> float:
        upper = max(MIN_INTERVAL, self.base_interval * (1.0 + self.jitter))
        lower = max(MIN_INTERVAL, self.base_interval * (1.0 - self.jitter))
        return self._rng.uniform(lower, upper)


@dataclass
class Beacon:
    seq: int
    sent_at: float
    payload: str
    acked: bool = False
    ack_at: Optional[float] = None
    replays: int = 0


@dataclass
class BeaconChannel:
    """Sequenced beacon channel with loss simulation and replay-on-timeout."""

    loss_rate: float = 0.0
    replay_timeout: float = 2.0
    seed: Optional[int] = None
    beacons: dict[int, Beacon] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.loss_rate <= 1.0):
            raise BeaconSimError("loss_rate must be in [0.0, 1.0]")
        if self.replay_timeout < 0.01:
            raise BeaconSimError("replay_timeout too small")
        self._rng = random.Random(self.seed)
        self._seq = 0

    def send(self, payload: str = "beacon") -> int:
        """Return seq for a new beacon; simulates loss by dropping an ack later."""
        self._seq += 1
        seq = self._seq
        self.beacons[seq] = Beacon(seq=seq, sent_at=time.monotonic(), payload=payload)
        return seq

    def ack(self, seq: int) -> bool:
        """Acknowledge a beacon seq (respecting simulated loss)."""
        if seq not in self.beacons:
            return False
        b = self.beacons[seq]
        if self.loss_rate > 0 and self._rng.random() < self.loss_rate:
            return False  # lost in transit
        b.acked = True
        b.ack_at = time.monotonic()
        return True

    def pending(self, now: Optional[float] = None) -> list[Beacon]:
        """Unacknowledged beacons whose replay timeout has elapsed."""
        now = now or time.monotonic()
        out = []
        for b in self.beacons.values():
            if not b.acked and (now - b.sent_at) >= self.replay_timeout:
                b.replays += 1
                b.sent_at = now
                out.append(b)
        return out

    def metrics(self) -> dict:
        sent = len(self.beacons)
        acked = sum(1 for b in self.beacons.values() if b.acked)
        replays = sum(b.replays for b in self.beacons.values())
        return {
            "sent": sent,
            "acked": acked,
            "lost": sent - acked,
            "replays": replays,
            "loss_rate": (sent - acked) / sent if sent else 0.0,
            "replay_ratio": (replays / sent) if sent else 0.0,
        }


class SessionTimeout:
    """Linear last-seen expiry for session registry sweep."""

    def __init__(self, timeout: float) -> None:
        if timeout <= 0:
            raise BeaconSimError("session timeout must be positive")
        self.timeout = timeout

    def is_expired(self, last_seen: float, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return (now - last_seen) > self.timeout

    def remaining(self, last_seen: float, now: Optional[float] = None) -> float:
        now = now if now is not None else time.time()
        return max(0.0, self.timeout - (now - last_seen))


def measured_jitter(actual: float, base: float) -> float:
    """Jitter % = (actual - base) / base. Guarded against base <= 0."""
    if base <= 0:
        return 0.0
    return (actual - base) / base


def jitter_series(intervals: list[float], base: float) -> list[float]:
    return [measured_jitter(i, base) for i in intervals]


def summarize_jitter(intervals: list[float], base: float) -> dict:
    if not intervals:
        return {"n": 0, "base": base, "avg": 0.0, "min": 0.0, "max": 0.0, "p50": 0.0}
    js = sorted(jitter_series(intervals, base))
    n = len(js)
    return {
        "n": n,
        "base": base,
        "avg": sum(js) / n,
        "min": js[0],
        "max": js[-1],
        "p50": js[n // 2],
    }