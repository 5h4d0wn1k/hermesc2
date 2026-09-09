# hermesc2

C2 & post-exploitation framework (LAB) - listener/stager/beacon, encrypted transport, payload gen, multi-stage, killswitch

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

## Quickstart

```bash
python3 -m pip install -e .
python3 -m hermesc2 --help
python3 -m hermesc2 --demo    # offline, exit 0
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

All activity is loopback-only (`127.0.0.1`/`::1`/`lab-*` allowlist configured in
`config/lab.yaml`); destructive actions require `--lab-allowlist`.

| # | What to run | Expected proof output |
|---|-------------|------------------------|
| 1 | `python3 -m hermesc2 --demo` | `[proof] demo OK (loopback only)`; exit code 0; offline demo report under `reports/` |
| 2 | `python3 -m unittest discover -s tests` | `Ran 72 tests ... OK`; exit code 0 |
| 3 | `python3 -m hermesc2 lab init` | state dir + runtime passphrase created under `state/` (gitignored), keyid=1 |
| 4 | `python3 -m hermesc2 payload --demo-variant` then run it in the lab | HTTPS-ish self-test over loopback, reports encrypted probe |
| 5 | `python3 -m hermesc2 ops synth --plan config/lab_recon_plan.json` then `ops run` | staged op plan parsed and executed against lab fixtures |
| 6 | `python3 -m hermesc2 report` | offline JSON report generated under `reports/` from session data |

The metrics below are re-measured after every feature change (see `METRICS.md`).

## Metrics

See `METRICS.md` for measured values (test counts, suite time, beacon RTT,
loss-replay reliability, demo proof lines). Baseline numbers are captured from the
committed state and updated whenever the test suite or demo behaviour changes.