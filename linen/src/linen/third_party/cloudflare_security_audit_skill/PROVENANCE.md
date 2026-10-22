# Vendored upstream: Cloudflare security-audit-skill

This directory contains a **pinned snapshot** of the upstream Cloudflare
`security-audit-skill` repository. It is the only copy inside `linen`; the
runtime resolves it through Python package resources and never downloads it.

## Upstream

- Repository: <https://github.com/cloudflare/security-audit-skill>
- Pinned commit: `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
  (also recorded verbatim in `UPSTREAM_COMMIT`)
- Upstream path of the vendored files: `skills/security-audit/`
  (except `LICENSE`, which lives at the upstream repository root)

## License

MIT, Copyright (c) 2025-2026 Cloudflare, Inc. The upstream `LICENSE` is
reproduced verbatim in this directory, as required by the MIT terms.

## Files

### From upstream (byte-identical to the pinned commit)

| File | Origin |
|---|---|
| `LICENSE` | upstream repository root |
| `ATTACK-CLASSES.md` | upstream `skills/security-audit/` |
| `HUNTING.md` | upstream `skills/security-audit/` |
| `report-schema.json` | upstream `skills/security-audit/` |
| `validate-findings.cjs` | upstream `skills/security-audit/` |
| `validate-findings.test.cjs` | upstream `skills/security-audit/` |
| `validate-coverage-ledger.cjs` | upstream `skills/security-audit/` |
| `validate-coverage-ledger.test.cjs` | upstream `skills/security-audit/` |

### Maintained by linen

| File | Purpose |
|---|---|
| `UPSTREAM_COMMIT` | the pinned upstream commit, verbatim |
| `SHA256SUMS` | SHA-256 of every upstream-origin file above |
| `PROVENANCE.md` | this file |
| `run-validator.windows.cjs` | Windows-compatible runner for the two upstream validators |

`run-validator.windows.cjs` is **not** part of the upstream snapshot and is
therefore not listed in `SHA256SUMS`. The upstream validators open their input
with `O_NOFOLLOW | O_NONBLOCK`; Node on win32 does not expose those constants,
so the upstream CLI rejects every input on Windows. The runner restores the two
sentinels and strips them again before the real open, preserving every other
upstream check. It is used by `validator_command()` in
`linen/dispatcher/analysis/cf_skill_assets.py` and by the test suite.

## Files deliberately not vendored

The 12 domain-level playbooks (`AI-AND-LLM.md`, `WEB-PROTOCOL-AND-AUTH.md`, …)
are **not** vendored: `linen` does not consume them yet, and vendoring them
would imply the deferred domain-playbook work had been adopted. `SKILL.md`,
`RECONNAISSANCE.md` and `VALIDATION-AND-REPORTING.md` are not vendored either
because no linen code path reads them.

## Local modifications

**None** to the upstream files. They are byte-for-byte identical to the pinned
commit and are verified against `SHA256SUMS` by
`linen/tests/test_cf_vendor_resources.py`.

## Line endings

Upstream stores these files with **LF** line endings — verified against the
raw bytes of the pinned commit — and the snapshot pins the same bytes on every
platform through the repository-level `.gitattributes`
(`linen/src/linen/third_party/cloudflare_security_audit_skill/* text eol=lf`).
Without that pin, a checkout on a machine with `core.autocrlf=true` rewrites
the files to CRLF, and the digests recorded in `SHA256SUMS` stop matching the
upstream bytes even though the committed blobs are unchanged. `SHA256SUMS`
therefore records the digests of the canonical LF bytes as published upstream,
and the test additionally asserts that the snapshot contains no CRLF, so a
line-ending regression fails with a readable diagnostic instead of an opaque
digest mismatch.

## Updating the snapshot

1. Clone upstream and check out the target commit.
2. Copy `skills/security-audit/{ATTACK-CLASSES.md,HUNTING.md,report-schema.json,validate-findings.cjs,validate-findings.test.cjs,validate-coverage-ledger.cjs,validate-coverage-ledger.test.cjs}`
   and the repository-root `LICENSE` into this directory.
3. Regenerate `SHA256SUMS` and update `UPSTREAM_COMMIT`.
   Compute the digests from the **canonical LF bytes** as published upstream —
   not from a CRLF-converted working tree. With `core.autocrlf=true` the
   checked-out copy differs from the upstream bytes, and recording its digests
   makes the snapshot unverifiable on Linux. Run
   `git -c core.autocrlf=false checkout -- .` (or hash the files as fetched)
   before regenerating the sums.
4. Re-run the upstream test suites:
   `node --test validate-coverage-ledger.test.cjs` and
   `node --test validate-findings.test.cjs`.
   **The canonical acceptance platform is Linux/macOS**: the upstream
   `validate-findings.test.cjs` contains CLI-path cases that cannot pass on
   Windows, because the file-protection guard does not exist there. On Windows,
   run the suites through `run-validator.windows.cjs` instead.
