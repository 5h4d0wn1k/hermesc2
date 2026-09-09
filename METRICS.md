# Metrics

Measured on: Python 3.13.5, cryptography 49.0.0, Linux (loopback only).
Baseline captured 2026-09-09.

## Test suite

- Total tests: **72** (`python3 -m unittest discover -s tests`)
  - `tests/test_agent.py` live loopback: 12
  - `tests/test_server.py` live loopback + registry: 18
  - `tests/test_beacon.py`: 15
  - `tests/test_crypto.py`: 14
  - `tests/test_gating.py`: 13
- Green runs (7 consecutive on a loaded workstation): 7/7, exit code 0.
- Previously-flaky tests (loss-replay restart, exit-unload, killswitch-wipe)
  hammered 15/15 consecutive passes against the pre-fix failure.
- Deep-copy byte-level root-cause: 'DecryptionError' storms traced to a
  concurrent `exists()+O_TRUNC` passphrase-generation race (writer and reader
  processes ending up on different keys). Fixed with atomic first-writer-wins
  publication (`os.link`); 120/120 concurrent-init hammer rounds converged with
  zero mismatches post-fix.

## Offline demo (`python3 -m hermesc2 --demo`)

- Exit code: 0
- Proof lines emitted: listener up, beacon received / session registered,
  `info` executed, `exec date -> ok`, upload (22 B) / download (25 B) via
  sandbox fixtures, beacon channel **acked 10/10**, encryption roundtrip OK,
  killswitch agent rc=0 + session wiped, offline report written.

## Beacon / channel timing

- Beacon interval: 0.12 s lab default, jittered.
- Measured channel RTT (demo): **9.651 ms** average (loopback).
- Ack reliability: 10/10 (100%) during demo; 0 dropped frames in the suite's
  loss-replay test across a hard server restart.

## Speed

- Full suite wall time: ~42 s on the loaded workstation (single-threaded
  Python 3.13; largely dominated by subprocess agent spawns + 60 s socket
  timeouts during teardown).

## Accuracy / correctness

- AES-256-GCM roundtrip: decrypt == plaintext, magic/version validated.
- Dry-run gate verified: a dry-run agent receiving an allowlisted `exec` task
  returns "would-run" and never runs the command.
- Loss-replay: agent re-registers on a restarted listener (same port) within
  30 s with beacon continuity.