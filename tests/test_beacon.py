"""Beacon simulator tests: jitter, loss/replay, session timeout, metrics."""

from __future__ import annotations

import time

from tests.helpers import HermesTestCase

from hermesc2.beacon import (
    BeaconChannel,
    BeaconSimError,
    BeaconStepper,
    SessionTimeout,
    measured_jitter,
    summarize_jitter,
    jitter_series,
)


class BeaconStepperTest(HermesTestCase):
    def test_interval_within_jitter_bounds(self) -> None:
        s = BeaconStepper(base_interval=1.0, jitter=0.2, seed=7)
        for _ in range(200):
            v = s.next_interval()
            self.assertGreaterEqual(v, 0.8 - 1e-9)
            self.assertLessEqual(v, 1.2 + 1e-9)

    def test_seeded_determinism(self) -> None:
        a = [BeaconStepper(1.0, 0.2, seed=3).next_interval() for _ in range(10)]
        b = [BeaconStepper(1.0, 0.2, seed=3).next_interval() for _ in range(10)]
        self.assertEqual(a, b)

    def test_invalid_jitter_rejected(self) -> None:
        with self.assertRaises(BeaconSimError):
            BeaconStepper(1.0, jitter=1.2)
        with self.assertRaises(BeaconSimError):
            BeaconStepper(-0.1, jitter=0.1)

    def test_tiny_interval_ok(self) -> None:
        s = BeaconStepper(base_interval=0.05)
        self.assertGreaterEqual(s.next_interval(), 0.05)


class BeaconChannelTest(HermesTestCase):
    def test_send_ack_roundtrip(self) -> None:
        ch = BeaconChannel(loss_rate=0.0)
        seq = ch.send("beacon")
        self.assertTrue(ch.ack(seq))
        m = ch.metrics()
        self.assertEqual(m["sent"], 1)
        self.assertEqual(m["acked"], 1)
        self.assertEqual(m["lost"], 0)

    def test_full_loss_drops_ack(self) -> None:
        ch = BeaconChannel(loss_rate=1.0, seed=1)
        seq = ch.send()
        self.assertFalse(ch.ack(seq))
        self.assertEqual(ch.metrics()["lost"], 1)

    def test_partial_loss_metrics(self) -> None:
        ch = BeaconChannel(loss_rate=0.5, seed=42)
        acks = 0
        for _ in range(40):
            seq = ch.send()
            if ch.ack(seq):
                acks += 1
        m = ch.metrics()
        self.assertEqual(m["sent"], 40)
        self.assertEqual(m["acked"] + m["lost"], 40)
        self.assertGreater(acks, 0)

    def test_pending_replay_on_timeout(self) -> None:
        ch = BeaconChannel(loss_rate=1.0, replay_timeout=0.05, seed=2)
        seq = ch.send()
        self.assertFalse(ch.ack(seq))
        pend = ch.pending(now=time.monotonic() + 1.0)
        self.assertEqual([b.seq for b in pend], [seq])
        self.assertEqual(ch.beacons[seq].replays, 1)

    def test_replay_metrics_ratio(self) -> None:
        ch = BeaconChannel(loss_rate=0.5, replay_timeout=0.02, seed=9)
        for _ in range(20):
            seq = ch.send()
            ch.ack(seq)
        ch.pending(now=time.monotonic() + 5.0)  # replay all pending
        m = ch.metrics()
        self.assertGreaterEqual(m["replays"], 0)

    def test_invalid_loss_rejected(self) -> None:
        with self.assertRaises(BeaconSimError):
            BeaconChannel(loss_rate=1.5)


class SessionTimeoutTest(HermesTestCase):
    def test_expiry_logic(self) -> None:
        t = SessionTimeout(0.5)
        now = time.time()
        self.assertFalse(t.is_expired(now, now))
        self.assertTrue(t.is_expired(now - 2, now))

    def test_remaining_capped_at_zero(self) -> None:
        t = SessionTimeout(1.0)
        self.assertGreaterEqual(t.remaining(time.time() - 5), 0.0)


class JitterMathTest(HermesTestCase):
    def test_measured_jitter_matches_formula(self) -> None:
        self.assertAlmostEqual(measured_jitter(1.1, 1.0), 0.1)
        self.assertAlmostEqual(measured_jitter(0.5, 1.0), -0.5)
        self.assertEqual(measured_jitter(123, 0), 0.0)

    def test_jitter_series_and_summary(self) -> None:
        js = jitter_series([0.9, 1.0, 1.1], base=1.0)
        self.assertEqual(len(js), 3)
        s = summarize_jitter([0.9, 1.0, 1.1], 1.0)
        self.assertEqual(s["n"], 3)
        self.assertAlmostEqual(s["min"], -0.1)
        self.assertAlmostEqual(s["max"], 0.1)

    def test_summary_empty(self) -> None:
        s = summarize_jitter([], 1.0)
        self.assertEqual(s["n"], 0)


if __name__ == "__main__":
    import unittest

    unittest.main()