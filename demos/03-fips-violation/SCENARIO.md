# 03 — Crypto module: FIPS 140 mode disabled

**Where the data came from.** A cleared-network workstation that was otherwise
hardened, but a kernel update reset `fips=1` out of the boot args. The osquery
snapshot caught `/proc/sys/crypto/fips_enabled` reporting `0`. Every other check
in this snapshot passed, isolating the single regression.

**What to expect.** Exactly **one** finding:

- `FIPS 140 mode disabled` — **VERY_HIGH** — NIST `SC-13`, STIG `V-238298`,
  CCI `CCI-002450`, ATT&CK `T1600` (Weaken Encryption).

A single finding keeps the composite score low, but **severity, not score, is
the gate** for a release: a lone VERY_HIGH must still block.

**Run it.**

```bash
comint-osquery demos/03-fips-violation/ --format markdown
# Fail a release gate on any VERY_HIGH (exits 1 even though the score is low):
comint-osquery demos/03-fips-violation/ --fail-on very_high && echo PASS || echo "BLOCKED (expected)"
```

**How to act.** Re-add `fips=1` to the kernel command line, run
`fips-mode-setup --enable`, reboot, and re-scan. Do not return the host to a
cleared network until this finding clears.
