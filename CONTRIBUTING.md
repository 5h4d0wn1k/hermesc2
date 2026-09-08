# Contributing

Thanks for helping make a safer, more honest security tool.

## Contributor License Agreement (CLA)

By submitting code, you agree to the **Developer Certificate of Origin (DCO)**,
version 1.1 (https://developercertificate.org/):

> I certify that I have the right to submit this contribution and that it does
> not knowingly introduce illegal, harmful, or third-party-infringing material;
> and I grant the project the rights to use it under the MIT License.

Sign-off each commit:

```bash
git commit -s
```

If the project later adopts a formal CLA, you agree to sign it before further
contributions are merged.

## Rules

1. **Authorized-use only.** Contributions may never weaken safety gates,
   allowlists, or legal notices, and must never target third parties.
2. Follow the house style: stdlib-first, argparse CLIs, `tests/` per feature,
   offline demo that exits 0, METRICS updates, placeholders only (RFC5737,
   example.com, 00:11:22:33:44:55).
3. Add tests for every engine change; keep `python -m unittest discover -s tests` green.
4. Run `python -m py_compile` on every changed file.
5. Write a clear commit message; sign off with `-s`.

## Process

- Open an issue first for large changes.
- Keep PRs focused on one feature or fix.
- Reference issues in the PR description.
- Repo owners review and merge.