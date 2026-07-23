# Top 50 non-research items by ROI

Ranked by value ÷ effort. Every item is buildable now — no `[RESEARCH]` items, nothing blocked on a
literature review. Source refs point back to the idea docs (`04-31` = doc 04, item 31).

Tiers group items of comparable payoff; within a tier the ordering is a judgement call, not a
precise ranking. `[S/M/L]` = effort · `[FORMAT]` = on-disk change, needs design review first.

**Why assurance dominates the top tier:** the interesting cryptography is largely built. The binding
constraint has shifted to whether the scoreboard reporting "it works" can be trusted — a repo review
found the verification suite passing while silently skipping 13 of 48 steps, one of which was hiding a
genuinely failing assertion. Until that is fixed, every other green result is unverified.

---

## Tier 1 — Trust the scoreboard, and stop catastrophic user loss (1–10)

**1. Harness strict mode + coverage accounting** `[S]` — 05-1, 05-2 — **DONE**
A skipped step must fail the suite; print `40/48 verified` every run.
*Done when:* `--strict` exits non-zero on any SKIP, and every run prints a coverage line.
*Landed:* `verification/build_and_verify.sh` now prints `N/48 steps verified, M skipped` on every run
and honours `--strict` / `VC_STRICT=1` (any SKIP → exit 3); `scripts/verify.sh` forwards `"$@"`. The
two steps that were **silently skipping** (masking real defects) are fixed at the root, not just
counted: step 6 (KeyScrub) had a genuine guard bug — `HKFScrubActiveConfig` was defined in both
`KeyScrub.c` (`KEYSCRUB && !HKF`) and `HardwareKeyFactor.c` (`KEYSCRUB` only), so a KEYSCRUB-on/HKF-off
build defined it twice; the `HardwareKeyFactor.c` guard is now `KEYSCRUB && HKF`, the exact complement.
Step 9 (Keyslots lifecycle) was missing `AfSplit.o` on its link line. With both fixed the real suite
runs **`48/48 steps verified, 0 skipped`** under `--strict` (exit 0). Negative control:
`VC_SELFTEST_FORCE_SKIP=1` injects one artificial skip — non-strict → exit 0 `47/48`, `--strict` →
exit 3. Patch: `patches/harness-strict-mode.patch` (applies `-p1` from repo root). This is also the
down-payment on item 12 (guard-complementarity) and item 13 (link-time symbol-collision).

**2. Negative controls / zeroization liveness** `[M]` — 05-3, 05-4, 02-30 — **DONE**
Assert the secret is *present* before the scrub and absent after, in the same run.
*Done when:* every behavioural test has a paired control that fails if the behaviour is absent.
*Landed:* `keyscrub_selftest.c` gains an `[L]` block that asserts the secret is PRESENT before and
ABSENT after the wipe, for both the generic `VcSecureWipe` (`[L1]`) and the security-critical
`HKFScrubActiveConfig` factor-secret scrub (`[L2]`), reading through a `volatile` alias so `-O2`
cannot elide it. The teeth are proven mechanically: `build_and_verify.sh` step 6 rebuilds the *same*
translation unit with `-DVC_NEGCTL_NO_WIPE` (wipe disabled) and asserts the "present before" lines
stay `YES` while the "absent after" lines flip to `NO` — a silent no-op wipe would now fail the suite.
The other behavioural tests were audited and already carry their own negative controls: duress
(`rejects wrong passphrase`, `one-byte difference rejected`), keyslot lifecycle (`wrong passphrase
rejected`, `revoked A no longer opens`, `B still opens after A revoked`), Shamir (`below threshold
must be 'no'`, `checksum detects below-threshold garbage`). Verified on GCC and clang.

**3. Flag-matrix + multi-compiler CI** `[M]` — 05-9, 05-10 — **DONE**
The duplicate-symbol defect lived only in the KEYSCRUB-on/HKF-off combination; GCC 12 and 13 diverge.
*Done when:* CI builds every pairwise `VC_ENABLE_*` combination on GCC 12/13/14 + clang.
*Landed:* `verification/flag_matrix.sh` sweeps every pairwise combination of the 9 `VC_ENABLE_*`
flags (none, each single, each pair, all-on = 47 configs) across every compiler on the host: it
compiles all 11 fork `Common` modules per config and partial-links them with `ld -r`, which fails on a
multiply-defined symbol but tolerates undefined externals — isolating the symbol-collision class with
no wxWidgets/full-crypto link needed. It carries its own negative control (`VC_MATRIX_NEGCTL=1`
re-injects the historical broken `HKFScrubActiveConfig` guard and asserts the matrix flags the
KEYSCRUB-only cell). `.github/workflows/flag-matrix.yml` runs it under **GCC 12, 13, 14 and clang**
(plus a strict-coverage run of the full suite). *In this sandbox only gcc-13 + clang-18 are installed,
so the local run covered 2 distinct compilers — `94/94 cells clean` — and the report names exactly
which versions it ran; GCC 12/14 coverage is the CI job's, not claimed locally.* Subsumes item 13
(link-time symbol-collision check).

**4. Fix remaining `static VC_INLINE` sites** `[S]` — 05-11 — **DONE**
`t1ha_selfcheck.c` and `jitterentropy-base-user.h` still carry it; GCC 13+ rejects it.
*Done when:* a clean build on GCC 14 with no `duplicate 'static'` errors.
*Landed:* both remaining sites fixed — `VC_INLINE` already expands to `static inline …` on GCC, so
`static VC_INLINE` is `static static inline` → `duplicate 'static'`. `t1ha_selfcheck.c:55` genuinely
failed to compile on GCC (confirmed: gcc-13 `error: duplicate 'static'`); it is now clean.
`jitterentropy-base-user.h:71` is Windows-guarded (GCC never reaches it — its two sibling
`jent_get_nstime` definitions already use bare `VC_INLINE`), fixed for consistency; single-TU header
so no MSVC linkage change. A grep confirms **zero** `static VC_INLINE` sites remain tree-wide.
`.github/workflows/flag-matrix.yml` gains an idiom-guard step that compiles the four historically
affected files (`t1ha_selfcheck.c`, `chacha256.c`, `chachaRng.c` at `-O2`; `jitterentropy-base.c` at
`-O0`) under **GCC 12/13/14 + clang** and greps for any regression. Verified locally on gcc-13 +
clang-18 (both PASS); GCC 12/14 is the CI job's. Patch: `patches/static-inline-idiom.patch` (the two
`src/Crypto` hunks apply onto stock 1.26.29).

**5. Dry-run test-mount before committing data** `[S]` — 03-44
Prove the password + factor combination works *before* any data is written.
*Done when:* a `--test-factors` path derives and verifies without creating or writing a volume.

**6. Forced backup-token enrollment at creation** `[M]` — 03-42
FIDO2 credentials cannot be cloned; one enrolled key means one lost key from permanent data loss.
*Done when:* creating a FIDO2-gated volume blocks until a second authenticator is enrolled or the
user explicitly acknowledges the risk.

**7. Recovery kit + restore rehearsal** `[M]` — 03-31, 03-32
SLIP-39 + QR, plus a drill forcing a real reconstruction from shares.
*Done when:* the kit prints, and a rehearsal command reconstructs the secret from printed shares.

**8. Keyslot management CLI (list/name/rotate/revoke)** `[M]` — 03-1, 03-5, 03-6
The keyslot table exists but is inert without management commands.
*Done when:* all four operations work against a real volume with labels and timestamps.

**9. Agent socket + OS keyring credentials** `[M]` — 04-31, 04-32, 04-33
Removes the need to put plaintext passwords in scripts — the most-repeated public complaint.
*Done when:* a scripted mount succeeds with no secret on disk or in argv.

**10. Argon2id auto-calibration to a time budget** `[S]` — 01-32 — **DONE**
You exposed the parameters; most users will pick badly. `Common/Pkcs5.c` (gated `VC_ENABLE_ARGON2_PARAMS`) adds `Argon2IterationsForBudget` — a pure, deterministic, timing-free policy (`iterations = targetMs*1000 / per-iteration-µs`, clamped to `[floor, cap]`) — and `Argon2CalibrateToTime`, which measures the per-iteration cost with a real `derive_key_argon2` probe at a given memory cost (ISO C `clock()`; the fork builds Argon2 `ARGON2_NO_THREADS` so at parallelism 1 CPU≈wall) and applies the policy. A calibrated cost is not stored — re-supplied at mount like PIM/the explicit override. Suite step `[70]` verifies two ways: the pure policy diffed byte-for-byte against `argon2_calibrate_reference.py` over a 60-point grid, and a real integration probe over the compiled Argon2 that yields monotone, floor/cap-clamped iterations with a back-to-back derive at the larger budget taking longer (measured e.g. 3 iters→0.05s vs 43 iters→0.54s). Negative control: a budget-ignoring policy fails the monotonicity/floor/cap battery. gcc-13 + clang-18; Pkcs5.c is in the flag matrix. Wall-clock calibration accuracy on other hardware and the `--argon2-time` CLI wiring are the real-build parts (the policy + probe are proven here).
*Done when:* `--iter-time 2000` benchmarks the machine and selects memory/time/parallelism.

## Tier 2 — Cheap hardening and activating built capability (11–20)

**11. Swap / hibernate / core-dump lockdown** `[S]` — 02-25, 02-26 — **DONE**
`mlockall`, `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, plus a loud hibernate warning. Scrubbing RAM is
pointless if the key already reached swap.
*Landed:* the `mlockall` / `RLIMIT_CORE=0` / `PR_SET_DUMPABLE=0` core was already shipping
(`VcKeyMemoryLockdown`, harness step 6 `[G]`). Added the missing **loud warning**: `VcSwapHibernateStatus`
detects an active swap area (`/proc/swaps`) and available suspend-to-disk (`/sys/power/state` has a
`disk` mode), and `KeyScrubManager::Enable` prints a per-exposure `stderr` warning while volumes are
mounted. The parse core is path-parametrized (`VcSwapHibernateStatusFrom`) so step 6 `[J]` drives it
with fixtures — itself the negative control: no-swap/no-hibernate → clean `0`, active-swap +
suspend-to-disk → both bits, and a `diskless` mode is not misread as `disk`. Verified on gcc-13 +
clang-18; `KeyScrubEvents.cpp` compiles on g++/clang++. Patch: `patches/swap-hibernate-warning.patch`.
Not sandbox-testable: the actual warning firing on a real mounted-volume session (the detector and its
output string are proven; the wx/CLI print path is not built here).

**12. Guard-complementarity lint** `[S]` — 05-12 — **DONE**
A symbol with a fallback stub must have genuinely complementary `#if` guards. A comment claimed this;
the code did not have it.
*Landed:* `verification/guard_lint.py` — pure static analysis (python, no compile). It scans the fork
`.c`/`.cpp` files for **external-linkage** function definitions (skips `static` / `VC_INLINE` /
`inline`), tracks each definition's `#if/#ifdef/#ifndef/#else/#elif/#endif` guard stack, and for any
symbol defined in ≥2 places SAT-checks (brute-force over the guard macros) whether some flag
assignment makes two guards **both** true — i.e. a link collision. Wired as suite step `[50]`; the
`--self-test` negative control re-injects the historical broken `HardwareKeyFactor.c` guard and
asserts the lint flags `HKFScrubActiveConfig` while the real tree stays clean. Real tree: OK.

**13. Link-time symbol-collision check** `[S]` — 05-15 — **DONE**
Catches the duplicate-definition class across all feature combinations.
*Landed:* the exhaustive version already shipped as item 3 (`flag_matrix.sh` partial-links every
pairwise `VC_ENABLE_*` combo with `ld -r`, in CI on GCC 12/13/14 + clang). Item 13 adds a **fast,
always-on** companion as suite step `[51]`: it compiles the two modules sharing `HKFScrubActiveConfig`
across all four `KEYSCRUB × HKF` combinations and `ld -r`-links each, with a negative control that
re-injects the broken guard and asserts the `KEYSCRUB`-only combo collides. Verified: all real combos
link clean; broken guard collides.

**14. Log-redaction test that greps for secrets** `[S]` — 12-24 — **DONE**
Prove no key material reaches any log, mechanically rather than by review.
*Landed:* `verification/log_redaction_test.c` loads distinctive sentinel secrets (the reconstructed
factor secret and the FIDO2 PIN) into an `HKFConfig`, drives the real integration path
(`HKFApplyIfConfigured`), then emits the verbose config summary a `--verbose`/debug mode would print.
Suite step `[52]` greps ALL output for the sentinels: a clean build must leak **none** (the summary
prints `raw secret length` and `fido pin = [set, redacted]`, never the bytes). The `-DVC_LOGLEAK`
build is the negative control — the summary dumps the PIN and the secret hex, and the grep must find
both, proving a real redaction regression would be caught. Verified on gcc-13 + clang-18: clean
`0/0`, leak `≥1/≥1`. Scope note: covers the config/secret diagnostic surface; the wx/CLI logging
paths are not built in this sandbox.

**15. Per-slot policy flags (read-only, max-attempts, expiry)** `[M][FORMAT]` — 03-2 — **DONE** (design `docs/KEYSLOT-POLICY-DESIGN.md`)
Cheap fields in a record you already wrap; converts behaviour into configuration.
*Landed* (approved design, gated behind `VC_ENABLE_KEYSLOT_POLICY` on top of `VC_ENABLE_KEYSLOTS`):
`KeyslotStore.c` gains `KeyslotAddPolicy` / `KeyslotOpenPolicy` / `KeyslotOpenAtPolicy`.
**read-only** is an encrypted flag bit (`KEYSLOT_FLAG_READONLY`); **expiry** is 8 big-endian bytes in
the v2 encrypted payload (`flags[1] || expiryUnix[8] || vmk`) — authenticated and hidden — enforced
**silently** at the constant-time mount path (an expired slot behaves exactly like a wrong
passphrase, no oracle). **max-attempts** is a cleartext pad counter on the admin path only (locks after
N failed opens, resets on success); as designed it is **rollback-defeatable** without a TPM counter,
which the harness *demonstrates* rather than hides. Legacy v1 records (`policy=0`) open byte-identically;
deniable backend stays v1. Verified two ways (step `[53]`): behavioural test of the real compiled module
with a **negative control per policy** (read-write lacks the RO bit; never-expiring slot opens in the far
future; a correct open before lockout resets the counter) + a v1 byte-compat check + the rollback demo,
and a byte-for-byte payload-layout diff vs `keyslot_policy_reference.py`. gcc-13 + clang-18, added to the
flag matrix. Not done here: the `--keyslot-*` CLI surface + wx wiring for the flags (product build).

**16. `verify` command — integrity check without mounting** `[M]` — 02-9 — **DONE**
Check a volume without exposing plaintext or taking the mount path. `KeyslotStructuralCheck` in `Common/KeyslotStore.c` (gated `VC_ENABLE_VERIFY`) validates every occupied labeled slot's framing against this build's parameters — known version, shipping KDF id, stored cost and payload-length, record fits the stride — **without the passphrase**, returning a well-formed/malformed count. It detects gross corruption/truncation offline; it deliberately does *not* authenticate a slot's ciphertext (that needs the passphrase, or the area MAC of item 42 which is `[FORMAT]`/pending). Suite step `[72]` proves it accepts a clean 3-slot area and flags each framing corruption (version / cost / payload-length) as malformed. Honest-boundary demonstration: a flipped ciphertext byte is invisible to the structural check, but the mount path (`KeyslotOpen`) still rejects it via the per-record AEAD tag — so the offline check and the mount check are complementary. gcc-13 + clang-18; in the flag matrix. (The `verify` subcommand + header-backup-integrity composition — item 44's `HeaderBackupVerify` — are the CLI/real-build wiring.)

**17. Self-test on mount** `[S]` — 12-11 — **DONE**
KATs for the algorithms actually in use, at the moment they matter.
*Landed:* `Common/SelfTest.{c,h}` (gated `VC_ENABLE_SELFTEST`) — `VcForkSelfTest()` runs KATs for the
primitives a factored/keyslot mount relies on: SHA3-512("") (FIPS-202), SHA-256("abc") (FIPS-180-4),
and a cross-compiler t1ha2 anchor (KeyScrub). Returns a bitmask of failures; the mount path must fail
closed on non-zero. Verified in suite step `[54]` over the REAL compiled Crypto objects, with a
compiled negative control (`-DVC_SELFTEST_CORRUPT` perturbs one expected value → the self-test must
flag it). gcc-13 + clang-18; added to the flag matrix. (Wiring the call into the wx mount path is the
product-build piece.)

**18. One-command security-posture report** `[M]` — 12-1 — **DONE**
Factors, slots, lockdown bits, integrity state, last check. `Common/VcPosture.{c,h}` (gated `VC_ENABLE_POSTURE`, needs `VC_ENABLE_JSON`) emits a machine-readable posture report — a JSON object built with the item-48 `VcJson` escaper whose boolean fields (keyslots / duress / keyscrub / hardware_factor / multi_token_or / argon2_params / header_backup / self_test) are derived from the real `VC_ENABLE_*` compile guards, plus a `features_on` count and a `hardened` summary. Because the fields come from the guards, a feature that is off genuinely reports false — no hand-maintained list to drift. Suite step `[71]` builds it three ways: (A) keyslots+duress ON → those true, rest false, `features_on:2`; (B) stock → all false, `features_on:0`, `hardened:false`, and the JSON validates in python's parser; (C) negative control `-DVP_NEGCTL` built with no features LIES (`keyslots:true`), proving (B)'s false values track the guards rather than a hardcoded list. gcc-13 + clang-18; in the flag matrix. (The runtime facts — mounted slots, last integrity check — are added by the CLI at the real-build layer.)

**19. Verification-coverage display** `[S]` — 12-5 — **DONE**
Show which claims are machine-verified versus documented. Directly addresses the "all green" problem.
*Landed:* `verification/coverage_report.sh` prints two sections — **A. machine-verified** (derived
*live* from `build_and_verify.sh`'s step headers, so it cannot drift out of sync) and **B. documented,
not machine-verified here** (a curated list of claims that need a real token / wx / kernel dm-crypt /
real media / multi-snapshot). Suite step `[55]` runs `--check` (asserts the verified count equals the
suite step count and that documented-only claims are not listed as verified) plus `--check-negctl`
(the negative control: a real-hardware claim injected as a fake step must be detected as
documented-only). Makes "green means section A is proven; B is the honest edge of a sandbox" explicit.

**20. Panic hotkey — dismount all + scrub** `[S]` — 08-7
Pairs with the duress work already landed; the non-destructive emergency action.

## Tier 3 — UX that determines whether the security is actually used (21–30)

**21. Auto-dismount on idle / lock / suspend** `[S]` — 04-13, 04-15
**22. Auto-mount on device insert, dismount on removal** `[M]` — 04-14
**23. Favorites with per-volume settings** `[S]` — 04-12
**24. PRF/cipher hint cache for fast mount** `[S]` — 04-19 — stop trial-and-erroring the algorithm list
**25. Mount-time honesty indicators** `[S]` — which factor was used, integrity verified, rollback suspected
**26. Time estimates everywhere** `[S]` — Argon2, VDF, KEM shown as wall-clock so "slow" ≠ "broken"
**27. Contextual warnings** `[S]` — 04-30 — SSD + hidden volume, hibernate enabled, swap on
**28. Failure disambiguation that doesn't leak** `[M]` — 12-34 — "token missing" vs "wrong password" only where safe
**29. Password strength meter tied to real KDF cost** `[S]` — 03-45 — not generic entropy theater
**30. Shell completions + config profiles** `[S]` — 04-36, 04-37 — the `--hkf-*` set is long enough to need both

## Tier 4 — Assurance depth and supply chain (31–40)

**31. Fuzz keyslot record parsing** `[M]` — 05-19 — **DONE**
`verification/keyslot_fuzz.c` feeds tens of thousands of malformed / random / half-structured
`KeyslotArea`s and randomized in-bounds configs to the REAL `KeyslotOpen` / `KeyslotOpenAt` /
`KeyslotCount` / `KeyslotRevoke` (+ the policy variants), built under **gcc ASan+UBSan** — the
sanitizers are the oracle for any OOB / UB / crash. Deterministic (fixed-seed xorshift, reproducible).
Suite step `[56]` runs it (40k iterations, no fault) with a negative control: a parser that trusts a
record-supplied length reads out of bounds and MUST fault under ASan (proving the harness would catch
a real parser OOB). Needs a sanitizer-capable toolchain (gcc libasan); a clang without compiler-rt is
skipped. Result: the real parser stays in-bounds on every malformed input.
**32. Fuzz the volume header parser with a malformed corpus** `[M]` — 05-20 — **DONE**
The fork's header-geometry parser is `KeyslotAreaFile.c`, which turns volume layout into a bounded
keyslot window. `verification/areafile_fuzz.c` feeds tens of thousands of **adversarial geometries**
(overlapping / reversed / zero / near-`UINT64_MAX` `freeStart`/`freeEnd`/`hiddenReservedStart`) to the
real `KeyslotAreaBindDeniable` and asserts every ACCEPTED window stays inside the free extent and —
the security-critical invariant — **never reaches into the hidden-volume region** (`base+len ≤
hiddenReservedStart`), with no `base+len` overflow; plus 5k bounded stdio ops over a real header-slack
window, all under **gcc ASan+UBSan**. Suite step `[57]`, deterministic, with a negative control: a
clamp that ignores `hiddenReservedStart` yields a window into hidden space and the invariant check
must flag it (`reason=5`). Result: the deniable placement provably cannot clobber the hidden volume,
for all fuzzed geometry. (The stock VeraCrypt XTS header `Deserialize` is upstream C++ that decrypts
before parsing; the fork's attacker-controlled parse surface is the keyslot record parser (item 31)
and this geometry binder.)
**33. Sanitizer builds (ASan/UBSan) across the suite** `[M]` — 05-16 — **DONE**
`verification/sanitize.sh` rebuilds the behavioural harnesses (keyslot lifecycle, per-slot policy,
KeyScrub, duress, Shamir) under **gcc ASan+UBSan** with the full feature set and runs them — extending
sanitizer coverage beyond the two fuzz targets (31/32) to the modules those harnesses drive. It carries
its own negative control: a known heap overflow compiled under the same flags must be caught, so a
silently-inactive sanitizer fails the sweep too. Suite step `[58]` (skips if no gcc libasan) + a CI
`sanitize` job in `.github/workflows/flag-matrix.yml`. Result: **5/5 harnesses clean** under
ASan+UBSan; the shipping modules are memory-safe on the exercised paths.
**34. dudect timing screens for every primitive** `[M]` — 05-27 — not just Shamir and keyslot — **DONE**
Extends the dudect coverage (Shamir GF(2⁸), keyslot path) to the **duress tag compare**, the remaining
secret-dependent comparison. `verification/duress_dudect_test.c` is a self-validating Welch t-test
(same framework as `shamir_dudect_test.c`): class 0 = tag pairs differing in the FIRST byte, class 1 =
differing in the LAST — a leaky early-exit compare separates them, a constant-time one does not. Suite
step `[59]` asserts the screen **flags** a leaky early-exit reference and **clears** the real
OR-accumulate `DuressTokenMatch` (contrast, not absolute cycles). Measured: real |t|≈0.3–1.1, leaky
|t|≈370–414 (~375× contrast) on gcc-13 + clang-18.
**35. Randomized property tests** `[S]` — 05-25 — zero-length passwords, t=n, duplicate x-coords — **DONE**
Step `[45]` does broad seeded/differential fuzzing; this pins the specific degenerate cases that
historically break threshold schemes and passphrase handling. `verification/property_test.c` drives
the real `Shamir.c` / `KeyslotStore.c`: **threshold==n** (all n reconstruct, n−1 do not), threshold==2
boundaries, **duplicate x-coordinates** (a Lagrange divide-by-zero if unguarded → asserted to return
`SHAMIR_ERR_PARAM`), parameter-range rejection (t<2, t>n, n>MAX, len 0/>MAX), all-zero/all-0xFF/1-byte
secrets, and **zero-length keyslot passwords** (add + open + a non-empty password must not open it;
empty area → no-match, no crash). 20 properties, suite step `[60]`, built under ASan+UBSan when
available (so an unguarded div-by-zero also traps). Each degenerate assertion is its own control (the
"must NOT recover" / "must reject" side). gcc-13 + clang-18.
**36. Wycheproof-style edge-case vectors** `[M]` — 05-29 — **DONE**
HMAC-SHA256 underpins salt-binding, duress-token recognition, the keyslot-area MAC and the per-share Shamir MAC, so it gets hammered with adversarial edge vectors rather than one happy-path KAT. `verification/wycheproof_vectors.py` emits 62 Wycheproof-style cases — key/message lengths at the SHA-256 block boundaries (0/1/32/64/65/128 and 55/56/63/64/65/127), all-zero and all-0xff keys, plus flipped-bit and truncated INVALID tags — whose expected tags come from python's own `hmac`/`hashlib` (independent oracle). `verification/wycheproof_test.c` recomputes each with the real in-tree `Sha2.c` and enforces valid==match / invalid==reject (suite step `[69]`): 60 valid matched, 2 invalid rejected, 0 fails on gcc-13 + clang-18. Negative control (`-DWP_NEGCTL`): a broken HMAC that truncates over-long keys instead of hashing them fails exactly the key=65/128 boundary vectors (18 of them) — proving the block-boundary vectors are load-bearing, not vacuous.
**37. Static analysis in CI (clang-tidy, CodeQL)** `[M]` — 05-45 — **DONE**
`.clang-tidy` curates a **high-signal** check set (the clang static analyzer — null-deref /
use-after-free / uninitialised reads / leaks — plus a small `bugprone-*` subset, `WarningsAsErrors`),
deliberately excluding the noisy `insecureAPI.DeprecatedOrUnsafeBufferHandling` (flags every
`memcpy`/`memset`) and stock-header diagnostics, so a clean run is meaningful.
`scripts/clang-tidy-fork.sh` runs it over the 11 fork Common modules — **all clean**. Suite step `[62]`
(skips if clang-tidy absent) + a `clang-tidy` CI job; **CodeQL** (security-and-quality suite) runs in
`.github/workflows/codeql.yml`, building the fork modules so it has real TUs to analyze.
**38. Secrets-scanning pre-commit hook** `[S]` — 05-46 — **DONE**
`scripts/secrets-scan.sh` is a dependency-free, pattern-based scanner (private keys, AWS/GitHub/Slack/
Google/Stripe tokens) — deliberately *not* entropy-based, so it doesn't drown in the repo's legitimate
crypto KAT vectors. `.githooks/pre-commit` blocks a commit with a secret in staged files (enable with
`git config core.hooksPath .githooks`); a `secrets-scan` CI job and suite step `[61]` scan the whole
tree. Built-in `--self-test` is the control: a planted AWS-key-shaped secret **is** caught and a file
of crypto KAT hex is **not** (no false positive). Whole tree currently clean.
**39. Reproducible builds + signed releases** `[M]` — 04-48, 04-49 — **DONE (repro proven; signing = real-build)**
`verification/reproducible_build.sh` (suite step `[73]`) compiles every fork Common module twice with a normalized flag set (`SOURCE_DATE_EPOCH` pinned, `-ffile-prefix-map`, `-g0`) and requires the two objects to be byte-identical (16/16 reproducible), scans the fork's own sources for build-timestamp constructs (`__DATE__`/`__TIME__`/`__TIMESTAMP__` → 0 hits), and proves the normalization is load-bearing via a negative control: the same source compiled from two different absolute directories differs without `-ffile-prefix-map` and becomes byte-identical with it. Release signing/notarization needs private keys and is the real-build part; the reproducibility that makes a signature meaningful is proven here.
**40. SBOM per release** `[S]` — 05-39 — **DONE**
`verification/sbom.py` (suite step `[74]`) generates a CycloneDX 1.5 SBOM covering the fork's gated Common modules (each tagged with its `VC_ENABLE_*` feature flag) plus the external/bundled dependencies (Argon2, wxWidgets, libfido2, libykpers-1, libpcsclite), then validates well-formedness AND that **every fork module present in the source tree is covered** — so the SBOM cannot silently drift out of date as modules are added. Negative control: an SBOM with a component removed fails validation (missing-coverage error). 22 components; validates clean; drop-a-component correctly rejected.

## Tier 5 — Structural value, higher effort, high payoff (41–50)

**41. Verifiable keyslot shredding** `[M]` — 03-4 — overwrite + AF-stripe wipe + attestation — **DONE**
`KeyslotShred` (gated `VC_ENABLE_KEYSLOT_SHRED`) hashes the slot before, overwrites the entire stride
(ciphertext + AF stripes + salt + tag) with CSPRNG random, reads back what **actually landed** on the
medium, and returns an attestation = `SHA-256("VCKSSHRED1" || index || H(before) || H(after))` — an
auditable receipt. Suite step `[63]` proves the shredded slot won't open, carries no verbatim
ciphertext remnant, and that the attestation is **independently reproducible** from the observed
hashes. **Negative control:** a weak "mark-free" (clear only the 4-byte magic) leaves the old
ciphertext recoverable *verbatim* — the harness shows the contrast. gcc-13 + clang-18; added to the
flag matrix. Honest limit (documented): this is a LOGICAL overwrite; on SSD/CoW media the physical
block may persist — the attestation records the logical erase, it does not defeat wear-levelling.
**42. Authenticate the keyslot area / header MAC** `[M][FORMAT]` — 02-5, 02-6 — XTS has no integrity — **DONE** (design reviewed → built option A, warn-and-continue). `Common/KeyslotAreaMac.{c,h}` (gated `VC_ENABLE_KEYSLOT_AREA_MAC`, needs `VC_ENABLE_KEYSLOTS`) adds a keyed tag over the whole labeled-slot table, stored in a reserved trailer: `areaMac = HMAC-SHA256(K_area, "VCKSAREA1" || u32(slotCount) || region)`, with `K_area = HKDF-SHA256(VMK, info="keyslot-area-mac")` — VMK-derived (no new stored secret), verified *after* a slot open recovers the VMK. Trailer = `magic[9]||ver[1]||count[4]||tag[32]` (46 B). Keyslot *records* were already per-record AEAD-authenticated (a bit-flip fails to open); this closes the **set-level** gap: deleting, truncating, or reordering slots is now detected even though each surviving record still verifies. Scope: labeled backends only (deniable stays markerless). Old areas with no trailer → `KAM_NO_TRAILER` = warn-and-continue (existing volumes keep opening). Honest limit: rollback to an older *complete* table still needs external monotonic state (TPM NV counter — future). Suite step `[75]` verifies two ways: the HKDF+HMAC tag byte-for-byte vs `keyslot_areamac_reference.py` over the real region bytes (anchor `1886ae38…`), plus behavioural detection. Negative controls: flip a slot byte / drop a slot / reorder two slots / wrong `K_area` all → `KAM_TAMPERED`, while the surviving records still open individually (proving the tamper is set-level). gcc-13 + clang-18; in the flag matrix. `patches/keyslot-area-mac.patch` applies -p1. (The C++ mount-path call — verify after open, warn on `KAM_NO_TRAILER` — and header-slack/sidecar trailer placement are the real-build wiring.)
**43. Encrypted volume labels** `[S][FORMAT]` — 04-11 — human names without leaking to an examiner — **DONE** (design reviewed → built, fixed-48-in-64). `Common/VolumeLabel.{c,h}` (gated `VC_ENABLE_VOLUME_LABEL`, needs `VC_ENABLE_KEYSLOTS`) stores the label as an AEAD record reusing the already-anchored `KeyslotWrap` — **no new crypto**, only a payload framing: `plaintext[64] = "LBL1" || len[1] || label[≤48] || zero-pad`, wrapped to `record[128] = salt[32] || ct[64] || tag[32]` under the passphrase (AAD `"VCKSlabel"` domain-separates it from a VMK slot). The fixed 64-byte plaintext hides the label's *length* as well as its content; without the passphrase the record is indistinguishable from random, so listing a label requires the passphrase and it leaks nothing to an examiner. Works on the deniable backend too. Suite step `[76]` verifies two ways: the framing emitted as `FRAME` lines diffed byte-for-byte vs `volume_label_reference.py`, plus a Set→Get round-trip over the real keyslot AEAD (5 labels incl. empty, max-48, non-ASCII UTF-8). Negative controls: wrong passphrase / a flipped record byte → no label; the label cleartext never appears in the 128-byte record (indistinguishability); a 49-byte label is rejected; a 1-byte and a 48-byte label yield identical record size. gcc-13 + clang-18; in the flag matrix. `patches/encrypted-volume-label.patch` applies -p1. (The `--label`/`--set-label` CLI + placement in the keyslot area are the real-build wiring.)
**44. Header backup with integrity check + reminders** `[S]` — 03-35 — **DONE**
`Common/HeaderBackup.{c,h}` (gated `VC_ENABLE_HEADER_BACKUP`) serialises a keyslot area into a self-describing blob (`magic || ver || len || area || SHA-256`) so a backup is **verified before it is trusted** and a corrupted area detected and restored. Suite step `[66]`: backup → corrupt the live area (slot stops opening) → restore recovers all slots. Negative controls: a flipped byte in the backup fails verification (`HB_ERR_INTEGRITY`) and `Restore` **refuses** it, leaving the area untouched; bad magic / truncation → `HB_ERR_FORMAT`. gcc-13 + clang-18; in the flag matrix. (The 'reminders' nag is CLI/UI, not built here.)
**45. Multi-token OR-set (any of N enrolled works)** `[M]` — 03-18 — **DONE**
`Common/HkfOrSet.{c,h}` (gated `VC_ENABLE_HKF_ORSET`, needs `VC_ENABLE_KEYSLOTS`) enrolls one keyslot per token, each wrapping the SAME master key (VMK) under a key derived from that token's challenge-response — so presenting ANY one enrolled token opens its slot and recovers the VMK. It is the OR of the keyslot building block: enrollment is one `KeyslotAdd` per token, opening is the store's existing constant-time multi-slot search — no new crypto, the security reduces to the proven keyslot AEAD + search. `HkfOrSetEnrollConfigs`/`OpenConfig` tie it to real backends via `HKFComputeResponse` (SIMULATOR/RAW_SECRET/YubiKey/FIDO2). (Distinct from the M-of-N Shamir threshold path, where shares must be *combined*: OR-set = 1-of-N-sufficient.) Suite step `[68]` proves it over the real `HkfOrSet`+`Keyslot`+`HardwareKeyFactor` objects with 4 RAW_SECRET salt-bound tokens: each token alone recovers the exact VMK. Negative controls: a never-enrolled token opens nothing (and leaves the output buffer zero); after revoking one token's slot, that token stops working while every other token still opens — proving the OR-set is per-token, not all-or-nothing. gcc-13 + clang-18; in the flag matrix.
**46. PKCS#11 / PIV smartcard factor** `[M][HW]` — 03-11 — VeraCrypt already speaks PKCS#11
**47. Structured error taxonomy + stable exit codes** `[S]` — 11-6, 16-39 — **DONE**
`Common/VcStatus.{c,h}` (gated `VC_ENABLE_STATUS`) defines a stable enum of outcomes (ok / param / io / wrong_password / factor_missing / slot_expired / slot_locked / duress / tampered / unsupported / internal), each with a fixed process **exit code**, a machine token (`VcStatusName`, for `--json`), and a human string (`VcStatusString`). Exit codes are a committed contract. Suite step `[64]` verifies completeness, distinct non-zero error codes, unique names, and safe out-of-range fallback, and diffs the name→exit-code table byte-for-byte against `status_reference.py` (the independent pin) — a renumber breaks the diff, which is the stability guarantee's negative control. gcc-13 + clang-18; in the flag matrix.
**48. `--json` machine-readable output** `[S]` — 04-34 — **DONE**
`Common/VcJson.{c,h}` (gated `VC_ENABLE_JSON`) is a bounds-checked JSON object builder with correct string **escaping** (quotes / backslash / control chars → `\uXXXX`), integrating the item-47 status taxonomy. Suite step `[65]` emits JSON via the real module and validates it with **python's own parser** (the independent oracle): valid JSON, values round-trip, and a hostile value (`a"b\c` + newline + a fake `,"injected":"..."`) is escaped — it round-trips exactly and injects no field. Negative control: a naive **unescaped** emitter whose output the parser must reject (`JSONDecodeError`), proving the escaping is load-bearing. gcc-13 + clang-18; in the flag matrix.
**49. systemd units with hardening directives** `[S]` — 16-12 — **DONE**
The network-share unlock server (item 8 / `docs/NETWORK-SHARE-SPEC.md`) is a secret-bearing, network-facing daemon, so it ships a fully-sandboxed systemd unit at `dist/systemd/vc-netshared.service` (+ `.socket` for socket activation): `DynamicUser`, empty `CapabilityBoundingSet`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateDevices`, the `ProtectKernel*`/`ProtectClock`/`ProtectHostname` set, `MemoryDenyWriteExecute`, `RestrictNamespaces/AddressFamilies/Realtime/SUIDSGID`, a `@system-service` syscall allow-list minus dangerous groups, and `KeyringMode=private`. These are packaging files — the compiled product is byte-for-byte stock. Suite step `[67]` (`verification/systemd_hardening_lint.sh`) verifies it two ways: a required-directive check (all 22 present with approved values) **and** `systemd-analyze security --offline=true` (exposure **1.2 "OK"**, gate ≤3.0). Negative control: a unit with the hardening block stripped is rejected by the directive check **and** scores exposure 9.4 — proving both checks are load-bearing.
**50. Atomic power-loss-resilient header writes** `[M][FORMAT]` — 06-27 — **DESIGN (awaiting review)** — `docs/TIER5-FORMAT-DESIGN.md §50` (A/B header pair + generation + commit-tag; torn-write recovery is sandbox-testable, true power-loss is not).

---

## Notable omissions

**Windows driver parity** and **volume shrink** are both genuinely valuable and both `[L]`. High
value, but not high *ROI* — they belong on the roadmap, not this list.

**Per-sector authentication** (the largest remaining cryptographic gap) is `[L][FORMAT]` and needs a
design review before code. Item 42 is the cheap down-payment on it.

## Sequencing note

Items 1–4 are prerequisites in a real sense, not just first in a list: until the harness fails loudly
and builds cover the flag matrix, you cannot tell whether items 5–50 actually landed. Do them first
even though they ship no user-visible feature.
