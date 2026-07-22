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

**10. Argon2id auto-calibration to a time budget** `[S]` — 01-32
You exposed the parameters; most users will pick badly.
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

**12. Guard-complementarity lint** `[S]` — 05-12
A symbol with a fallback stub must have genuinely complementary `#if` guards. A comment claimed this;
the code did not have it.

**13. Link-time symbol-collision check** `[S]` — 05-15
Catches the duplicate-definition class across all feature combinations.

**14. Log-redaction test that greps for secrets** `[S]` — 12-24
Prove no key material reaches any log, mechanically rather than by review.

**15. Per-slot policy flags (read-only, max-attempts, expiry)** `[M][FORMAT]` — 03-2
Cheap fields in a record you already wrap; converts behaviour into configuration.

**16. `verify` command — integrity check without mounting** `[M]` — 02-9
Check a volume without exposing plaintext or taking the mount path.

**17. Self-test on mount** `[S]` — 12-11
KATs for the algorithms actually in use, at the moment they matter.

**18. One-command security-posture report** `[M]` — 12-1
Factors, slots, lockdown bits, integrity state, last check.

**19. Verification-coverage display** `[S]` — 12-5
Show which claims are machine-verified versus documented. Directly addresses the "all green" problem.

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

**31. Fuzz keyslot record parsing** `[M]` — 05-19
**32. Fuzz the volume header parser with a malformed corpus** `[M]` — 05-20
**33. Sanitizer builds (ASan/UBSan) across the suite** `[M]` — 05-16
**34. dudect timing screens for every primitive** `[M]` — 05-27 — not just Shamir and keyslot
**35. Randomized property tests** `[S]` — 05-25 — zero-length passwords, t=n, duplicate x-coords
**36. Wycheproof-style edge-case vectors** `[M]` — 05-29
**37. Static analysis in CI (clang-tidy, CodeQL)** `[M]` — 05-45
**38. Secrets-scanning pre-commit hook** `[S]` — 05-46
**39. Reproducible builds + signed releases** `[M]` — 04-48, 04-49
**40. SBOM per release** `[S]` — 05-39

## Tier 5 — Structural value, higher effort, high payoff (41–50)

**41. Verifiable keyslot shredding** `[M]` — 03-4 — overwrite + AF-stripe wipe + attestation
**42. Authenticate the keyslot area / header MAC** `[M][FORMAT]` — 02-5, 02-6 — XTS has no integrity
**43. Encrypted volume labels** `[S][FORMAT]` — 04-11 — human names without leaking to an examiner
**44. Header backup with integrity check + reminders** `[S]` — 03-35
**45. Multi-token OR-set (any of N enrolled works)** `[M]` — 03-18
**46. PKCS#11 / PIV smartcard factor** `[M][HW]` — 03-11 — VeraCrypt already speaks PKCS#11
**47. Structured error taxonomy + stable exit codes** `[S]` — 11-6, 16-39
**48. `--json` machine-readable output** `[S]` — 04-34
**49. systemd units with hardening directives** `[S]` — 16-12 — `NoNewPrivileges`, `ProtectHome`
**50. Atomic power-loss-resilient header writes** `[M][FORMAT]` — 06-27

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
