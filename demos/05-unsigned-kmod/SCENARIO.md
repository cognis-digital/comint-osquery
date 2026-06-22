# 05 — Unsigned kernel modules on a Secure Boot host

**Where the data came from.** An engineering laptop with out-of-tree drivers.
The `kernel_modules` table shows two modules loaded with `signed='0'` — the
NVIDIA proprietary driver and the VirtualBox host driver, both DKMS-built and
never signed with an enrolled MOK. On a Secure Boot / hardened build, an
unsigned module in ring 0 defeats the chain of trust.

**What to expect.** One **HIGH** finding (`unsigned_kernel_modules`,
NIST `SI-7`, STIG `V-238230`, ATT&CK `T1547.006` — Kernel Modules and
Extensions). The finding's description reports `2 row(s) matched` so reviewers
know the count without re-reading the raw snapshot.

**Run it.**

```bash
comint-osquery demos/05-unsigned-kmod/ --format json | python -m json.tool | grep -A1 mitre
```

**How to act.** Either remove the modules or sign them against an enrolled
Machine Owner Key (`kmodsign` + `mokutil --import`) and re-scan. These are
*plausible benign* drivers — triage them, but treat any unexpected unsigned
module name as a possible rootkit indicator.
