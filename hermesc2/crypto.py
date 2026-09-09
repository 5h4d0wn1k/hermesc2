"""Symmetric wire transport: AES-GCM, PBKDF2-derived keys, key rotation.

Packet framing (length-prefixed + magic):

    frame  = uint32 length BE || blob
    blob   = magic(4) "HMC1" || version(1) || key_id(4 BE) || nonce(12)
             || AES-GCM ciphertext(payload + tag)
    AAD    = magic || version || key_id

Keys are derived at runtime with PBKDF2-HMAC-SHA256 from the lab-only
passphrase plus a per-key-id salt, so both peers can derive any rotated key
without exchanging key material. Key material is never persisted in the repo.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"HMC1"
PROTO_VERSION = 1
NONCE_LEN = 12
KEY_LEN = 32
WIRE_LEN = 4
PBKDF2_ITERATIONS = 200_000
SALT_PREFIX = b"hermeslab.kid."


class CryptoError(Exception):
    """Base transport error."""


class DecryptionError(CryptoError):
    """Packet failed authentication / decryption."""


class UnknownKeyError(CryptoError):
    """Received a key id that is not part of this lab vault."""


class FrameError(CryptoError):
    """Malformed wire framing."""


class KeyVault:
    """Derive-any-keyid store; keys are cached per key id."""

    def __init__(self, passphrase: bytes, iterations: int = PBKDF2_ITERATIONS) -> None:
        self._passphrase = bytes(passphrase)
        self._iterations = iterations
        self._cache: dict[int, bytes] = {}

    def key(self, key_id: int) -> bytes:
        kid = int(key_id)
        if kid in self._cache:
            return self._cache[kid]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=SALT_PREFIX + kid.to_bytes(4, "big"),
            iterations=self._iterations,
        )
        key = kdf.derive(self._passphrase)
        self._cache[kid] = key
        return key

    def rotate(self, current: int = 0) -> int:
        return max(current, 0) + 1


class Crypto:
    """High-level sealing/opening of JSON envelopes over byte frames."""

    def __init__(self, passphrase: bytes, seed_key_id: int | None = None) -> None:
        self.vault = KeyVault(passphrase)
        self.key_id = seed_key_id if (seed_key_id is not None and seed_key_id > 0) else 1
        self._seal_count = 0
        self._open_count = 0
        self._bytes_in = 0
        self._bytes_out = 0

    # ------------------------------------------------------------------
    # Sealing / opening
    # ------------------------------------------------------------------
    def seal(self, payload: bytes, key_id: int | None = None) -> bytes:
        """Return a wire blob (no length prefix) for payload."""
        kid = key_id if key_id is not None else self.key_id
        key = self.vault.key(kid)
        nonce = os.urandom(NONCE_LEN)
        header = MAGIC + bytes([PROTO_VERSION]) + struct.pack("!I", kid) + nonce
        aesgcm = AESGCM(key)
        sealed = aesgcm.encrypt(nonce, payload, header)
        self._seal_count += 1
        self._bytes_out += len(header) + len(sealed)
        self.key_id = kid
        return header + sealed

    def open(self, blob: bytes) -> tuple[int, bytes]:
        """Return (key_id, plaintext) from a wire blob (validates magic/AES-GCM)."""
        if len(blob) < 1 + NONCE_LEN + 16 + 4:
            raise FrameError("blob too short")
        if blob[:4] != MAGIC:
            raise FrameError("bad magic")
        version = blob[4]
        if version != PROTO_VERSION:
            raise FrameError(f"unsupported protocol version {version}")
        kid = struct.unpack("!I", blob[5:9])[0]
        nonce = blob[9:21]
        sealed = blob[21:]
        try:
            key = self.vault.key(kid)
        except Exception:
            raise UnknownKeyError(f"cannot derive key id {kid} in this lab vault")
        aesgcm = AESGCM(key)
        try:
            plain = aesgcm.decrypt(nonce, sealed, blob[:21])
        except Exception as exc:
            raise DecryptionError(f"AES-GCM authentication failed: {exc}")
        self._open_count += 1
        self._bytes_in += len(blob)
        return kid, plain

    def frame(self, payload: bytes, key_id: int | None = None) -> bytes:
        """Return a full length-prefixed frame suitable for send_frame."""
        blob = self.seal(payload, key_id)
        return struct.pack("!I", len(blob)) + blob

    def deframe(self, raw: bytes) -> tuple[int, bytes]:
        """Validate length prefix + magic, return (key_id, plaintext)."""
        if len(raw) < WIRE_LEN:
            raise FrameError("truncated frame header")
        length = struct.unpack("!I", raw[:WIRE_LEN])[0]
        if length != len(raw[WIRE_LEN:]):
            raise FrameError("length prefix does not match frame body")
        return self.open(raw[WIRE_LEN:])

    # ------------------------------------------------------------------
    # Socket helpers
    # ------------------------------------------------------------------
    def send(self, sock: socket.socket, obj: Any, key_id: int | None = None) -> None:
        """Serialize JSON object and send one length-prefixed frame."""
        data = json.dumps(obj).encode("utf-8")
        if len(data) > 0xFFFF:
            raise CryptoError("envelope too large")
        sock.sendall(self.frame(data, key_id))

    def recv(self, sock: socket.socket) -> tuple[int, dict]:
        """Read one frame (blocking) and return (key_id, decoded JSON dict)."""
        blob = recv_frame(sock)
        kid, plain = self.deframe(blob)
        return kid, json.loads(plain.decode("utf-8"))

    def stats(self) -> dict:
        return {
            "seals": self._seal_count,
            "opens": self._open_count,
            "bytes_in": self._bytes_in,
            "bytes_out": self._bytes_out,
        }


def send_frame(sock: socket.socket, frame: bytes) -> None:
    sock.sendall(frame)


def recv_frame(sock: socket.socket) -> bytes:
    """Read exactly one length-prefixed frame; raises FrameError on EOF/malformed."""
    header = _recv_exact(sock, WIRE_LEN)
    length = struct.unpack("!I", header)[0]
    if length <= 0 or length > (1 << 24):
        raise FrameError(f"invalid frame length {length}")
    body = _recv_exact(sock, length)
    return header + body


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise FrameError("connection closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def roundtrip_selftest(crypto: Crypto, payload: bytes = b"hermes encryption roundtrip") -> dict:
    """Encrypt then decrypt; returns stats proving identity roundtrip."""
    frame = crypto.frame(payload)
    kid, plain = crypto.deframe(frame)
    ok_identity = plain == payload
    ok_magic = frame[4:8] == MAGIC
    return {
        "plaintext_len": len(payload),
        "plaintext_unchanged": ok_identity,
        "wire_len": len(frame),
        "magic_ok": ok_magic,
        "key_id": kid,
        **crypto.stats(),
    }