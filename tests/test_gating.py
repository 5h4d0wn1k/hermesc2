"""Safety-gate tests: loopback locking, allowlist semantics, consent."""

from __future__ import annotations

import os
import tempfile

from tests.helpers import HermesTestCase

from hermesc2 import gating
from hermesc2.config import load_config
from hermesc2.gating import ScopeViolation


class LoopbackGateTest(HermesTestCase):
    def test_loopback_hosts_pass(self) -> None:
        for host in ("127.0.0.1", "localhost", "::1", "127.0.0.2"):
            self.assertEqual(gating.assert_loopback(host, ""), "127.0.0.1", host)

    def test_non_loopback_hostname_refused(self) -> None:
        for host in ("198.51.100.7", "example.com", "203.0.113.9"):
            with self.assertRaises(ScopeViolation):
                gating.assert_loopback(host, "target")

    def test_non_loopback_refused_by_is_loopback(self) -> None:
        self.assertFalse(gating.is_loopback("example.com"))
        self.assertTrue(gating.is_loopback("127.0.0.1"))

    def test_wildcard_allowlist_matches_lab_names(self) -> None:
        self.assertTrue(gating.allowlist_membership("lab-node-01", gating.DEFAULT_ALLOWLIST))
        self.assertTrue(gating.allowlist_membership("lab-anything-x", ["lab-*"]))

    def test_wildcard_allowlist_rejects_non_lab(self) -> None:
        self.assertFalse(gating.allowlist_membership("node-01", gating.DEFAULT_ALLOWLIST))
        self.assertFalse(gating.allowlist_membership("evil.com", ["lab-*"]))

    def test_assert_in_scope_raises_outside(self) -> None:
        with self.assertRaises(ScopeViolation):
            gating.assert_in_scope("no-such-lab", gating.DEFAULT_ALLOWLIST, "id")

    def test_require_operator_consent(self) -> None:
        with self.assertRaises(ScopeViolation):
            gating.require_operator_consent(False, "test op")
        gating.require_operator_consent(True, "test op")

    def test_validate_target_lab_agent_in_scope(self) -> None:
        self.assertEqual(
            gating.validate_target("lab-web-01", gating.DEFAULT_ALLOWLIST),
            "lab-web-01",
        )

    def test_validate_target_loopback_in_scope(self) -> None:
        self.assertEqual(
            gating.validate_target("127.0.0.1", gating.DEFAULT_ALLOWLIST),
            "127.0.0.1",
        )

    def test_validate_target_outside_refused(self) -> None:
        with self.assertRaises(ScopeViolation):
            gating.validate_target("198.51.100.22", gating.DEFAULT_ALLOWLIST)


class ConfigScopeTest(HermesTestCase):
    def test_default_config_allowlist_enforced(self) -> None:
        cfg = load_config()
        self.assertIn("127.0.0.1", cfg.allowlist)
        self.assertIn("lab-*", cfg.allowlist)

    def test_listen_host_gate_loopback_only(self) -> None:
        # config with a non-loopback listen host must be refused
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write("lab:\n  listen_host: 198.51.100.5\n")
            name = fh.name
        try:
            with self.assertRaises(ScopeViolation):
                load_config(name)
        finally:
            os.unlink(name)

    def test_config_cannot_override_allowlist_outside_hard_scope(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write("lab:\n  allowlist:\n    - not-in-scope.example\n")
            name = fh.name
        try:
            with self.assertRaises(ScopeViolation):
                load_config(name)
        finally:
            os.unlink(name)


if __name__ == "__main__":
    import unittest

    unittest.main()