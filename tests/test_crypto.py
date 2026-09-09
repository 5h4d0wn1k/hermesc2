"""Encryption transport tests: AES-GCM roundtrip, framing, rotation, keys."""

from __future__ import annotations

import os

from tests.helpers import HermesTestCase

from hermesc2.crypto import (
    Crypto,
    CryptoError,
    DecryptionError,
    FrameError,
    KeyVault,
    MAGIC,
    roundtrip_selftest,
)

PLAIN = b"attack-surface: lab only -> 127.0.0.1"


class CryptoRoundtripTest(HermesTestCase):
    def test_roundtrip_decrypt_equals_plain(self) -> None:
        c = self.crypto()
        blob = c.seal(PLAIN)
        kid, plain = c.open(blob)
        self.assertEqual(plain, PLAIN)
        self.assertEqual(kid, c.key_id)

    def test_full_frame_roundtrip(self) -> None:
        c = self.crypto()
        frame = c.frame(PLAIN)
        kid, plain = c.deframe(frame)
        self.assertEqual(plain, PLAIN)
        self.assertTrue(frame.startswith(MAGIC) is False or frame[4:8] == MAGIC)

    def test_framing_magic_present(self) -> None:
        c = self.crypto()
        frame = c.frame(PLAIN)
        self.assertEqual(frame[4:8], MAGIC)

    def test_nonce_differs_each_message(self) -> None:
        c = self.crypto()
        f1 = c.frame(PLAIN)
        f2 = c.frame(PLAIN)
        self.assertNotEqual(f1[9:21], f2[9:21])

    def test_tamper_detected(self) -> None:
        c = self.crypto()
        blob = bytearray(c.seal(PLAIN))
        blob[-1] ^= 0x80
        with self.assertRaises(DecryptionError):
            c.open(bytes(blob))

    def test_bad_magic_rejected(self) -> None:
        c = self.crypto()
        blob = c.seal(PLAIN)
        bad = b"NOPE" + blob[4:]
        with self.assertRaises(FrameError):
            c.open(bad)

    def test_bad_bad_magic_is_frame_error(self) -> None:
        with self.assertRaises(FrameError):
            c_open = self.crypto()
            c_open.open(b"\x00\x00")

    def test_length_prefix_mismatch(self) -> None:
        c = self.crypto()
        data = c.seal(PLAIN)
        raw = (5).to_bytes(4, "big") + data
        with self.assertRaises(FrameError):
            c.deframe(raw)

    def test_wrong_passphrase_fails(self) -> None:
        c1 = Crypto(b"passphrase-alpha")
        c2 = Crypto(b"passphrase-beta")
        f = c1.frame(PLAIN)
        with self.assertRaises(CryptoError):
            c2.open(f[4:])  # body without length prefix

    def test_rotated_key_mutual(self) -> None:
        a = self.crypto()
        b = self.crypto()
        new_kid = a.vault.rotate(a.key_id)
        f = a.frame(PLAIN, key_id=new_kid)
        kid, plain = b.deframe(f)
        self.assertEqual(kid, new_kid)
        self.assertEqual(plain, PLAIN)

    def test_key_vault_derives_any_kid(self) -> None:
        v = KeyVault(b"lab-passphrase")
        k1 = v.key(1)
        k2 = v.key(2)
        self.assertEqual(k1, v.key(1))  # cached
        self.assertNotEqual(k1, k2)

    def test_stats_counters(self) -> None:
        c = self.crypto()
        c.frame(b"a")
        c.frame(b"b")
        blob = c.seal(b"z")
        c.open(blob)
        st = c.stats()
        self.assertEqual(st["seals"], 3)
        self.assertEqual(st["opens"], 1)
        self.assertGreater(st["bytes_out"], 0)

    def test_roundtrip_selftest_proof(self) -> None:
        c = self.crypto()
        rt = roundtrip_selftest(c, PLAIN)
        self.assertTrue(rt["plaintext_unchanged"])
        self.assertTrue(rt["magic_ok"])
        self.assertEqual(rt["plaintext_len"], len(PLAIN))

    def test_many_messages_roundtrip(self) -> None:
        c = self.crypto()
        for i in range(50):
            payload = f"msg {i} - loopback only".encode()
            kid, plain = c.deframe(c.frame(payload))
            self.assertEqual(plain, payload)


if __name__ == "__main__":
    import unittest

    unittest.main()