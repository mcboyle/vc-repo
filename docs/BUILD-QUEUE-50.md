# Build queue — the top 50 sandboxable items, scoped and planned

**Source:** a 775-idea tracker (`IDEAS775TRACKER.xlsx`), triaged 2026-07-26 against master `a3ec1e2`.
**Method:** 704 candidates survived a hardware/community filter; nine agents triaged them in parallel
against the actual tree, then a synthesis pass re-ranked globally, deduped, and grouped into PRs.

## Read this first — three framing facts

**1. The tracker is stale, and overstates remaining work by roughly a sixth.** Its own header records a
cross-check against master `971f1be`, about 24 merged PRs ago. **124 of its rows are already built,
already declined with a recorded verdict, or already upstream behaviour** (§3). Every "open" claim below
was re-checked against the tree; nothing here is scheduled on the spreadsheet's say-so.

**2. The top of the queue is findings, not features.** Tier A is ten defects in shipped code, each
contradicting something this repo already asserts in its own docs. They were surfaced by triage and then
**independently re-verified** before being written down:

| # | Claim | Verified at |
|---|---|---|
| 1 | v2 discovery swallows every failure in a blanket `catch (...)`, so zeroing 16 bytes strips authentication silently — while the spec claims the opposite | `src/Volume/Volume.cpp:321` vs `docs/V2-FORMAT-SPEC.md:463` |
| 2 | `--quick` containers are `ftruncate`-sparse, so the host extent map discloses the hidden volume with **no password, from one image** | `VolumeCreator.cpp:330` → `Platform/Unix/File.cpp:418` |
| 3 | Four mountable PRFs (SHA3-512, BLAKE2b, Whirlpool, Streebog) have **zero** suite steps | `grep derive_key_* verification/build_and_verify.sh` → 0 |
| 4 | The status taxonomy hands out distinct codes for wrong-password (77) / factor-missing (69) / slot-expired (75) / slot-locked (76) / **duress (78)** — a coercion oracle, and it contradicts two specs | `src/Common/VcStatus.c:16-20`; zero refs in `src/Main/` |
| 5 | ChaCha RAM-protection is built and proven but reaches **no secret** — only `Init`/`Shutdown` are ever called | `src/Core/KeyScrubEvents.cpp:97,221` |
| 6 | `AesCt` (constant-time, FIPS-197-anchored, ctgrind-clean) is **not** wired into the `Common/Crypto.c` fallback it was built for | `grep -rl AesCt src/` → Adiantum/Hctr2 only |
| 7 | Exactly one `fsync` exists in the entire I/O path; data-before-tags ordering is program order only | `Platform/Unix/File.cpp:104` |
| 8 | `src/Common/Volumes.c` — the Windows C derivation path, 11 hook sites — is compiled by **nothing** on Linux | absent from `src/Makefile` and every `*.make` |
| 10 | Unix container locking is `#if 0` (**upstream-inherited**, not fork-introduced) | `Platform/Unix/File.cpp:316`, initial import `48a176d` |
| 21 | `AUDIT-GUIDE.md` advertises "steps [1]..[48]" against a 104-step suite topping out at [105] | `docs/AUDIT-GUIDE.md:23` |

Also confirmed: `.github/workflows/flag-matrix.yml:145` builds the **product binary** with `HKF_SIMULATOR=1`,
against a `CLAUDE.md` warning that says "never ship" three times with no mechanical guard (item 31).

**3. Anchor honesty is preserved throughout.** Items are tagged `[TWIN-ONLY]` where the only available
proof is a reimplementation we wrote. Per `CLAUDE.md` rule 3 those results may **not** be called
conformant — the ristretto255 finding at step [94] is why. Items carrying **OFFICIAL** vectors or a
**THIRD-PARTY** oracle (cryptsetup, libfido2, Z3, gcov, OSV, mingw-w64, openssh) are ranked above
equivalent work that lacks one.

## Sandboxability

"Sandboxable" here means the deliverable can be **built and proven** on a container with: no
`/dev/mapper/control`, no USB, no logind seat, no udev, no raw flash, no second host — but with
`/dev/fuse` + root, real file containers, open web via `curl`, `apt`, and the full product build.
Writing a spec is always possible and does not count. 94 otherwise-good items were excluded as
**not provable here**; they are listed in §5 with what each needs.

---

## 1. The Top 50

Ranked by normalised value. Merged entries list every source ID they satisfy. `[TWIN-ONLY]` marks items whose only proof is a reimplementation we wrote — per `CLAUDE.md` these results may **not** be described as "conformant".

### Tier A — demonstrated defects in shipped code (ranks 1–10)

These are findings, not features. Each contradicts something the tree already asserts.

| # | Item | IDs | Anchor |
|---|---|---|---|
| 1 | **v2 authentication is silently strippable by an adversary with write access.** Zeroing 16 bytes at tag slot 0, or truncating the tail, makes `DiscoverMode` return NONE and the volume opens as v1 with no authentication and no log line. `V2-FORMAT-SPEC.md:463` claims "a keyless downgrade yields mount failure, not silent integrity-stripping." | D06-29 | `[TWIN-ONLY]` — but it falsifies a written in-tree claim against the real product |
| 2 | **A `--quick` container's host extent map discloses the hidden volume with no password, from a single image.** Strictly stronger than the multi-snapshot attack `THREAT-MODEL.md` calls its #1 limitation. The existing warning names the wrong mechanism ("skips writing random data"). | D06-22, D06-21 (inverse) | Linux ext4 `SEEK_HOLE`/`FIEMAP` — a kernel artifact, not our model |
| 3 | **Four mountable volume PRFs have no external anchor.** `derive_key_sha3_512`, `derive_key_blake2b`, Whirlpool, Streebog: raw hashes anchored, shipping PBKDF2 compositions not. Literal repeat of the step-[97] finding on `derive_key_sha512`. | D10-22, D10-25 | **OFFICIAL** — NIST CAVP `.rsp` + OpenSSL/`hashlib.pbkdf2_hmac` |
| 4 | **The status taxonomy is a ready-made coercion oracle.** `VcStatus.c` hands out distinct exit codes for `wrong_password`(77), `factor_missing`(69), `slot_expired`(75), `slot_locked`(76) and `duress`(78) — while `KEYSLOT-POLICY-DESIGN.md:119` mandates silent expiry and `DURESS-DISMOUNT-SPEC.md:19` mandates indistinguishability. Not yet wired to the CLI: fix now. | D12-34, D05-32 | `[TWIN-ONLY]` + dudect timing arm |
| 5 | **ChaCha RAM-protection is built, proven, and reaches no secret.** `HKFConfig.rawSecret`/`simSecret`/`fidoPin` sit in cleartext for the process lifetime. Exactly the step-[106] "anchor proves a component, not that it is reached" failure. | D02-22 | ChaCha20 already libsodium-anchored [98]; liveness is `[TWIN-ONLY]` |
| 6 | **The constant-time AES ladder stops short of the path that needs it.** `CT-HARDENING-R17.md` §A1 measured 408 secret-dependent accesses in the table-AES fallback and left the decision open; `AesCt` was then built, FIPS-197-anchored and ctgrind-CLEAN — and never wired into `Common/Crypto.c`. Serpent/Twofish/Camellia/Kuznyechik were never measured at all. | D09-7, D02-34, D09-6, D02-39 | **OFFICIAL** FIPS-197 C.3 + valgrind/ctgrind |
| 7 | **No write barrier anywhere.** `Volume.cpp:560-573` and `V2SectorMacIo.h:41-48` both document data-before-tags as deliberate crash safety; there is no `fsync` between them, so it is program order only. `AtomicHeader`'s A/B scheme rests on the same unrequested ordering. `ROI-TOP-50` item 50 names it as remaining. | D06-46, D06-28, D16-49(data half) | `[TWIN-ONLY]` — syscall trace is the external check |
| 8 | **The Windows C derivation path is compiled by nothing.** `src/Common/Volumes.c` carries 11 `VC_ENABLE_*` hook sites, includes `<io.h>`, and appears in no Linux make, no flag matrix, no clang-tidy set. Its only validation is `verification/hook_typecheck.c`, a hand-written mirror that redeclares `KEY_INFO` field types — twin-agrees-with-twin. | D11-30, D04-45(partial) | **THIRD-PARTY** — mingw-w64 compiler disagreeing with our mirror |
| 9 | **No way to test a factor set before committing data.** ROI Tier-1 item 5, still open. The fork multiplies lockout modes (HKF factor, Shamir threshold, salt-binding, explicit Argon2 params, keyslots); every one is discoverable only after the data is committed. | D04-40, D03-44, D07-47 | `[TWIN-ONLY]` — byte-identical-medium invariant |
| 10 | **Container locking is a no-op on Unix (upstream-inherited, not fork-introduced).** `File.cpp:316` `#if 0`, present in the initial 1.26.29 import (`48a176d`); the comment cites remote-filesystem locking issues. Two read-write mounts of one container are permitted; mounting the *outer* volume while the hidden one is mounted destroys the hidden volume, and hidden-volume protection only defends within one process. Nothing in `docs/` mentions concurrency. | D06-35 | `[TWIN-ONLY]` |

### Tier B — assurance instrumentation on what already ships (11–20)

| # | Item | IDs | Anchor |
|---|---|---|---|
| 11 | **XTS-AES — what actually encrypts every byte — has zero suite coverage.** `EncryptionTest::TestXtsAES` exists and is called by nothing in `verification/` or CI, across a matrix that varies NOASM/compiler/AesCt in exactly the ways that break a cipher silently. | D10-21 | **OFFICIAL** IEEE 1619 / NIST CAVP XTSAES, fetched independently of `Tests.c` |
| 12 | **Line/branch coverage with a per-module floor and a zero-coverage function list.** The project measures *step* coverage, never which shipping lines the 105-step suite executes. First artifact an auditor asks for. | D05-43, D11-28, D05-6 | **THIRD-PARTY** gcov/lcov (2.0 available) |
| 13 | **Convert AF-split from TWIN to THIRD-PARTY.** `AfSplit.c` claims to implement TKS1 "as cryptsetup's af.c does" but `VERIFICATION-ANCHORS.md` files it TWIN+PROPERTY. `cryptsetup luksFormat`/`luksDump --dump-master-key` are userspace-only — no dm needed. | D10-37 | **THIRD-PARTY** cryptsetup 2.7 |
| 14 | **Make the FIDO2 backend executable without USB.** `libfido2` exposes `fido_dev_set_io_functions()`; the fork already owns the injected-transport pattern (`NetShareTransportFn`). A software CTAP2 authenticator driven through *real* libfido2 turns `CLAUDE.md`'s "largest untested surface in the fork" into a CI job. | D11-21, D11-17 | **THIRD-PARTY** libfido2 1.14 + **OFFICIAL** CTAP 2.1 hmac-secret |
| 15 | **Fork-introduced secrets live in argv.** `--hkf-sim-secret` and `--hkf-fido-pin` are plain options; `/proc/<pid>/cmdline` is world-readable. Add fd/pipe input and a mechanical `/proc` leak test. | D04-38, D12-31, D16-32 | **THIRD-PARTY** — the kernel's own `/proc` is the oracle |
| 16 | **A snapshot-diff instrument for the deniability thesis.** The multi-snapshot classifier is cited as prose in five documents and implemented nowhere; every deniability feature is currently scored by argument. | D02-12, D11-27 | **THIRD-PARTY method** — arXiv:2110.04618 run-length classifier (published, not ours) |
| 17 | **Machine-check the CRC seam's named unproven condition.** `CRC-SEAM-ADDENDUM.md:71` says entropy preservation for a 33–64-byte `RAW_SECRET` is "**unproven** — precisely the condition the analysis was commissioned to eliminate", on the threshold path that is the fork's thesis. z3 is installed and working. | D14-56, D14-57 | **THIRD-PARTY** — Z3 as a decision procedure we did not author |
| 18 | **Re-run the official vectors on a foreign-endian machine.** Every proof has only ever run on x86-64, over hand-written byte-order-sensitive code (bech32, HKDF counters, V2 tags, AtomicHeader `gen[8 BE]`, AF-split, `unsigned __int128` in NetShare). A same-endian Python twin is structurally blind to this class. | D04-47, D05-13 | **OFFICIAL, reused** — RFC 9106/8032/9496/5869, FIPS 197/202/203, google/hctr2, BIP-173/93 |
| 19 | **Fuzz the only remote-input parser in the fork.** `NetShare.c` parses attacker-supplied bytes on the mount path (`NetShareCredParse`, `NetSharePointDecompress`) and has neither fuzz nor sanitizer coverage — it shipped at [102], after `IDEAS-BACKLOG.md:339` enumerated the parsers to fuzz. | D05-22, D10-38 | **OFFICIAL** RFC 8032 §7.1 points as the seed corpus |
| 20 | **ThreadSanitizer + a written thread-safety contract.** Zero concurrency testing exists. The fork added `std::thread` to the mount-time keyslot scan while `g_hkfActiveConfig` is mutated and read with no lock. A race here is a scrub racing a derivation, not a crash. | D05-17, D11-10 | **THIRD-PARTY** TSan |

### Tier C — audit-readiness and user-loss (21–35)

| # | Item | IDs | Anchor |
|---|---|---|---|
| 21 | **Audit-pack freshness lint.** The front door is already rotted: `AUDIT-GUIDE.md` says "[1]..[48]" against a 105-step suite; §3 of the control map names zero of the 13 shipping fork modules; `SHA3-README.md` hands a reviewer a `gcc` line for six files that do not exist. Make claim→step→file resolution a CI gate. | D05-48, D13-10, D15-36, D15-34, D15-39 | `[TWIN-ONLY]` (internal consistency) |
| 22 | **Offline whole-volume verify.** Tamper detection is read-triggered only; you learn a sector was edited when something happens to read it. Compose `KeyslotStructuralCheck` + `HeaderBackupVerify` + area-MAC + a full v2 MAC scan into one no-mount command with per-extent localisation. | D08-46, D02-9, D02-10, D16-44 | Chained to HMAC-SHA256 [69] / SHA-256 [54]; composition is `[TWIN-ONLY]` |
| 23 | **Frozen golden-file corpus for the fork's on-disk formats.** Every layout is currently checked against a Python twin edited in the same commit — a deliberate-looking change passes when both move together, and existing volumes silently stop opening. `CLAUDE.md` records that this failure shape already cost a session. | D11-24, D10-33, D10-31, D10-32 | `[TWIN-ONLY]` — the committed corpus becomes the frozen artifact |
| 24 | **BLAKE3 as a shipping module.** Named as a blocker in three places; `V2Format.h:12` says keyed-BLAKE3 "remains the target if a vetted in-tree BLAKE3 is ever added (there is none today)", forcing a shipping path to diverge from `PERSECTOR-AUTH-SPEC.md`. 35 official vectors already vendored. | D01-21, D01-22(alt) | **OFFICIAL** — vendored BLAKE3-team vectors (hash/keyed/derive_key) |
| 25 | **An HKF backend that is real hardware *and* testable here.** An `ssh-ed25519` agent signature over the salt is deterministic (RFC 8032), so it is a genuine non-simulator factor exercisable end-to-end in this container — moving the fork from "2 of 4 backends have never met a device" to "3 of 4 exercised". | D03-13 | **THIRD-PARTY** — real `ssh-keygen -Y`/`age` binaries + **OFFICIAL** RFC 8032 |
| 26 | **Concrete-security parameter table.** There is no parameter justification anywhere in `docs/`; every knob is folklore or inheritance. Pair measured cost (the Balloon-vs-Argon2 benchmark precedent already exists) with cited published bounds and a stated attacker model. | D14-60, D14-58, D14-54, D01-37, D14-52 | **OFFICIAL/cited** — RFC 9106 §4, SP 800-132/57, Alwen–Blocki, Balloon paper |
| 27 | **Runtime posture, not just compile flags.** `VcPosture` reports 8 guard booleans; four proven-but-inert runtime indicators (lockdown bitmask, swap/hibernate, self-test result, flash verdict) are unreachable from the shipping binary, which has no `--posture`, `--json` or `--self-test` switch at all. | D12-1, D08-1, D04-18, D12-2, D04-34 | `[TWIN-ONLY]` + Python `json` as the parser oracle |
| 28 | **Slot AND-composition (two-person integrity).** ROADMAP marks item 91 UNBLOCKED, "not started". Cheapest sound design: 2-of-2 Shamir-split the VMK across two slots — no new record field. Completes the access-control algebra (`HkfOrSet` = 1-of-N, Shamir = M-of-N over a secret, nothing = A **and** B). | D03-10, D07-19, D03-23 | `[TWIN-ONLY]` |
| 29 | **PQ-hybrid the NetShare wire exchange.** `PQ-HYBRID-SPEC.md` names its own remaining work, and that gap went live when NetShare stopped being a PoC: a harvested MR transcript retroactively yields the share. ACVP ML-KEM-768 vectors already vendored. | D01-50, D03-28, D08-38 | **OFFICIAL** NIST ACVP FIPS-203 (`verification/mlkem_kats.{h,py}`) |
| 30 | **Recovery rehearsal + offline kit checker.** ROI Tier-1 item 7's *Done when* — "a rehearsal command reconstructs the secret from printed shares" — is unmet. All primitives exist unassembled. Recovery is the fork's likeliest real-world failure. | D15-28, D03-32, D03-33, D03-31, D08-47, D08-49 | **OFFICIAL** BIP-93 codex32 / BIP-350 for the decode leg |
| 31 | **Release gate: a shipping build must not carry `HKF_SIMULATOR`.** `CLAUDE.md` warns "never ship" three times with no mechanical guard, and `flag-matrix.yml:145,180,185` builds the product binary with `HKF_SIMULATOR=1`. A mis-set flag means a software token silently substitutes for hardware. `src/.build-flags` already exists as the gate input. | D12-39 | `[TWIN-ONLY]` (build-config invariant) |
| 32 | **CoW / snapshotting host detection.** A container on btrfs/ZFS/overlayfs/LVM/qcow2 hands the adversary the two-snapshot corpus automatically. `THREAT-MODEL.md` has no host-filesystem section at all. Same accepted shape as `FlashProbe`: probe, fail closed on unknown, warn where the user walks. | D06-15, D10-43 | `[TWIN-ONLY]` — fixture-driven, with live overlayfs/ext4 positive controls |
| 33 | **Prove no core dump carries key material.** Step [6][G] asserts the *syscalls returned success*; nobody has crashed a process holding a real derived key and checked. Negative control writes itself (rebuild without lockdown → core must exist and contain the sentinel). | D12-38, D02-40 | `[TWIN-ONLY]` — kernel core-dump machinery is the oracle |
| 34 | **Constant-time ShareCode.** `sc_charval` (`ShareCode.c:23-27`) is a linear scan with a data-dependent early return, plus a table index by secret 5-bit group, on the recovery path. Never screened. | D02-32, D02-31(residual) | **OFFICIAL, preserved** — BIP-173/350/93 vectors must still reproduce |
| 35 | **Passphrase normalization lockout.** Upstream's non-ASCII check is Windows-only (`Password.c:90` takes an `HWND`); the Linux path has none. The same visible passphrase in NFD (macOS) and NFC (Linux) is different bytes → different PBKDF2 input → a volume that will not open, in a fork whose headline claim is byte-identical cross-platform keys. | D15-20 | **OFFICIAL** — unicode.org `NormalizationTest.txt` |

### Tier D — worthwhile, lower leverage (36–50)

| # | Item | IDs | Anchor |
|---|---|---|---|
| 36 | Confirmation guards + last-credential check on destructive keyslot ops (`--keyslot-kill` currently revokes with no prompt and no undo; `KeyslotShred` is by design irreversible) | D04-28 | `[TWIN-ONLY]` |
| 37 | Page-cache plaintext: measure residency after dismount, then evict (`POSIX_FADV_DONTNEED`) and/or never cache (`direct_io`); publish the measured before/after including what the fix cannot reach | D06-47, D06-41 | `[TWIN-ONLY]` — `mincore` residency is the ground truth |
| 38 | Mutation testing — ~85 of 105 steps have no negative control; the systematic form of "does this assertion have teeth" | D05-5 | `[TWIN-ONLY]`; include one known-equivalent mutant that must survive |
| 39 | CLMUL POLYVAL — realises decision D-4, which is currently unrealised prose (`HCTR2-SPEC.md:14` justifies HCTR2 *because* of CLMUL; `Hctr2.c` has a software bit-at-a-time `gf_dot`). CLMUL is also *more* constant-time than what it replaces. `pclmulqdq` confirmed present | D01-25, D09-5, D09-6(part) | **DOUBLE OFFICIAL** — RFC 8452 POLYVAL example + 35 google/hctr2 vectors |
| 40 | Proactive share refresh — re-randomise shares without changing the secret, so a leaked share is invalidated without re-deriving the volume. Zero hits for `proactive\|reshare` anywhere in tree | D14-25, D01-40, D03-22, D14-4 | `[TWIN-ONLY]` — Herzberg et al. has no vectors |
| 41 | Deterministic I/O fault injection over `KeyslotAreaFile`/HeaderBackup/AtomicHeader — the one fault class not covered (power-loss is [77], token failure is `hw_probe.c`) | D11-22 | `[TWIN-ONLY]` |
| 42 | Differential fuzzing C vs the ~40 existing Python twins on random inputs — exactly one of 105 steps does this today ([90], 4096 inputs) | D05-24 | `[TWIN-ONLY]` by construction — scales rule 1, does not replace rule 3 |
| 43 | Signal-driven panic dismount (`SIGUSR1` → the proven duress action) + dead-man timer reusing `KeyScrubManager`'s idle thread; the headless equivalent of the un-built GUI hotkey | D16-15, D16-14, D08-8 | `[TWIN-ONLY]` |
| 44 | Feed the existing SBOM to OSV.dev + add SPDX license fields. One concrete constraint to enforce: `ROADMAP.md:452` pins libsodium ≥ 1.0.21 for CVE-2025-69277 while CI installs distro-unpinned | D05-42, D12-42, D13-27, D12-40 | **THIRD-PARTY** OSV/NVD advisory data |
| 45 | `SECURITY.md` + triage runbook + severity rubric; must exclude the validation-only bespoke groups from scope | D05-49, D13-29, D13-30, D13-32 | none — governance |
| 46 | `-Werror -Wall -Wextra` gate over fork modules only; today every harness blanket-applies `-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier`, adopted for stock TUs but silencing fork code too | D05-14 | none |
| 47 | Man page + shell completions **generated** from the parser table, with a set-equality drift check so a security-relevant flag cannot ship undocumented (~35 fork switches, zero documented) | D15-35, D04-36 | **THIRD-PARTY** `mandoc -Tlint` |
| 48 | Per-server DLEQ proofs in the threshold OPRF — today [44] (threshold, no proofs) and [96] (single-server VOPRF) exist separately, so one bad server yields a wrong key indistinguishable from a wrong password | D01-42 | **OFFICIAL** RFC 9497 §2.2 + A.1.2/A.1.3 (half the anchor) |
| 49 | v2 geometry pre-flight asserting the three invariants that broke silently at [106]: split applied once, table not overlapped, tag slot 0 reachable, MAC key length == `GetKeySize()*2` | D06-26 | `[TWIN-ONLY]` |
| 50 | Exact-error-code KAT matrix per module (today failures are asserted as "rejects", so a module rejecting for the wrong reason passes) | D05-32, D10-40 | `[TWIN-ONLY]` |

---

## 2. PR plan

Ordered by dependency, then value. Each PR is one theme; none should exceed a reviewable diff.

---

### PR 1 — `v2: close the silent-downgrade path and correct the spec`
**Items 1, 49** · IDs D06-29, D06-26

**Lands:** `src/Volume/Volume.cpp` (replace the blanket `catch(...)` with a tail-reachability probe + typed handling), `src/Main/CommandLineInterface.cpp` (`--v2` assertion, `--v2-ignore-tags` already exists as the recovery escape), `src/Common/V2Format.c` (geometry pre-flight), `docs/V2-FORMAT-SPEC.md` §Anti-downgrade rewritten, `verification/realbuild/v2_downgrade.sh`.

**Proof:** reuse the `v2_tamper_e2e.sh` fixture (real container, FUSE, no dm-crypt). (a) *Today's negative control* — zero tag slot 0, reopen, flip a data-sector ciphertext bit, show the read **succeeds** and `--list -v` reports nothing; (b) after the fix, an asserted-v2 volume with an unreadable table fails closed with a named `VcStatus`; (c) **specificity** in the `v2_hidden_guard.sh` idiom — a genuine v1 volume still opens with no assertion, an intact v2 volume still opens and still detects tamper; (d) reproduce all three [106] geometry breakages and require the pre-flight to name each.

**Anchor:** `[TWIN-ONLY]`. The deliverable's weight comes from falsifying `V2-FORMAT-SPEC.md:463` against the real product, not from a vector set.

**Do this first** — it is the only item where a shipped security control can currently be disabled without the password.

---

### PR 2 — `deniability: the host filesystem leaks the hidden volume`
**Items 2, 32** · IDs D06-22, D06-15, D06-21(refusal), D10-43

**Lands:** `src/Common/HostFsProbe.{c,h}` (gated `-DVC_ENABLE_HOSTFS_PROBE`, `statfs` + `/proc/self/mountinfo`, fail-closed on unknown — the `FlashProbe` shape), preallocation path in `src/Core/VolumeCreator.cpp` (`fallocate`, or refuse `--quick` for any container that will host a hidden volume), `src/Main/TextUserInterface.cpp` warning site, `docs/THREAT-MODEL.md` new host-filesystem section, `verification/hostfs_probe_test.c` + fixtures, `verification/realbuild/sparse_leak.sh`.

**Proof:** (a) **the audit artifact** — create a `--quick` outer container, create a hidden volume, write through FUSE, dismount, then recover the hidden volume's offset and extent with `SEEK_HOLE`/`SEEK_DATA` + FIEMAP and **no password**; (b) after preallocation, the extent map is a single uniform run before and after hidden writes; (c) classifier unit-tested against injected `mountinfo`/`statfs` fixtures with a named fail-closed check, plus live overlayfs and loop-ext4 positive controls; (d) independent Python twin over the same extent walk.

**Anchor:** the extent map is a real kernel artifact, not our model — stronger than TWIN, weaker than a published vector set. Honest statement: the btrfs/ZFS branch is **fixture-proven only** (neither is in `/proc/filesystems` here and there is no `/lib/modules`).

---

### PR 3 — `status: partition the outcome taxonomy before it reaches the CLI`
**Items 4, 50** · IDs D12-34, D05-32, D10-40

**Lands:** `src/Common/VcStatus.{c,h}` (`VcStatusMountSafe()` → the coarse class actually emitted at mount: OK / GENERIC_FAILURE, with `duress` collapsing into generic and never surfacing a distinct code, name or string; fine-grained codes retained for admin paths), `verification/no_oracle_test.c`, `verification/status_reference.py` extended, `docs/DURESS-DISMOUNT-SPEC.md` + `docs/KEYSLOT-POLICY-DESIGN.md` cross-references.

**Proof:** enumerate every internal cause (wrong password, absent factor, expired slot, locked slot, duress match, tampered record, tampered area MAC, non-matching slot) through the real `KeyslotStore.c` / `DuressToken.c` / `KeyslotAreaMac.c`; capture (exit code, `--json`, stderr) for each; assert the mount-path partition has **exactly one** non-OK equivalence class with byte-identical strings. Negative control: a `-DVC_ORACLE_LEAK` build returning the fine-grained code must **fail** the same assertion. Timing arm reuses `verification/duress_dudect_test.c`.

**Anchor:** `[TWIN-ONLY]` (fork policy) + dudect contrast. **Cheap now, expensive later** — `VcStatus` has zero call sites in `src/Main/`.

---

### PR 4 — `keyscrub: wire RAM protection to actual secrets, and prove no core dump carries keys`
**Items 5, 33** · IDs D02-22, D12-38, D02-40

**Lands:** `src/Common/HardwareKeyFactor.c` (`VcKsRamProtect` around `rawSecret`/`simSecret`/`fidoPin` and the reconstructed Shamir secret, unprotecting only across `HKFComputeResponse`), `verification/ram_protect_test.c`, `verification/coredump_test.c`, posture surfacing of the `VC_LOCKDOWN_*` bitmask.

**Proof:** sentinel present/absent liveness in the `keyscrub_selftest.c` `[L1]/[L2]` idiom — sentinel **absent** from the process's own mapped memory while protected, **present** immediately after unprotect, absent again; `-DVC_NEGCTL_NO_PROTECT` rebuild must flip every assertion. Core-dump arm: load a sentinel, `VcKeyMemoryLockdown()`, `raise(SIGSEGV)` inside a `mktemp -d` (`/proc/sys/kernel/core_pattern` is the plain `core` pattern here, root available) → no core file, zero sentinel hits; the `-DVC_NO_LOCKDOWN` control **must** produce a core containing the sentinel. Then `open_roundtrip.sh` to prove the factored create→open round trip is unchanged.

**Anchor:** ChaCha20 already libsodium-anchored [98]; the liveness property is `[TWIN-ONLY]`.

---

### PR 5 — `ct: complete the constant-time ladder and wire AesCt into the fallback`
**Item 6** · IDs D09-7, D02-34, D09-6, D02-39

**Lands:** `verification/ct_ctgrind_test.c` extended to make Serpent (scalar + SIMD), Twofish, Camellia (scalar + AES-NI), Kuznyechik and AesSmall subjects; `src/Common/Crypto.c` gains a gated `-DVC_ENABLE_CTAES_FALLBACK` branch using `AesCt` when `!HasAESNI() || HwEncryptionDisabled`; `docs/CT-HARDENING-R17.md` gains the per-primitive CT ladder table and the resolved fallback decision.

**Proof:** measurement sweep at `-O2/-O3/-O2-flto` on gcc + clang using the existing `ct_ctgrind_check.sh` driver and its self-validating leaky control. For the fallback: FIPS-197 C.3 through the product path; **byte-identical XTS ciphertext vs the table path over random sectors** (the load-bearing assertion — a volume created either way must still open); ctgrind clean where it measured 408; `open_roundtrip.sh` round trip; measured throughput cost.

**Anchor:** **OFFICIAL** FIPS-197 C.3 + **THIRD-PARTY** valgrind. Likely honest outcome: a *measured* accept-and-document decision rather than a default switch — still strictly better than today's unmeasured one.

---

### PR 6 — `io: write barriers, ordering proof, and container locking`
**Items 7, 10, 41** · IDs D06-46, D06-28, D11-22, D06-35, D16-49(data half)

**Lands:** `fsync`/`fdatasync` barriers between the data range and the tag range in `src/Volume/Volume.cpp`, and on the AtomicHeader/keyslot write paths; a lock the fork owns in `src/Platform/Unix/File.cpp` (`O_EXCL` sidecar + `flock`, with FUSE/NFS/SMB advisory locking treated as unreliable and failing closed for hidden-volume hosts, plus a documented expert bypass); `verification/io_order.sh` (LD_PRELOAD `pwrite`/`fsync` recorder); `verification/io_fault.sh`; `docs/TIER5-FORMAT-DESIGN.md` barrier contract.

**Proof:** (a) the shim asserts a barrier separates data from tags, with removal of the barrier failing the assertion; (b) fault injection aborts after the Nth write for every N and classifies the resulting state — every outcome must be intact **or** fail-closed-with-new-data-under-old-tag, never valid-tag-over-stale-data (the 553-offset sweep shape from `atomic_header_test.c`, now over a real file-backed medium); (c) deterministic `fread`/`fwrite`/`fseek` failure injection across `KeyslotAreaFile` operations asserting old-state-or-valid-new-state, never a third thing; (d) locking — demonstrate the defect (two concurrent RW mounts; outer-mounted-while-hidden-mounted destroys the hidden volume), then the guard, then specificity (single mount works, second **read-only** mount still allowed, stale lock does not brick the container). Measure and publish the write-amplification cost.

**Anchor:** `[TWIN-ONLY]`; the syscall trace is the external check.

---

### PR 7 — `ci: coverage floor, -Werror, TSan, cross-architecture`
**Items 12, 18, 20, 46** · IDs D05-43, D11-28, D05-6, D04-47, D05-13, D05-17, D11-10, D05-14

**Lands:** `verification/line_coverage.sh`, `verification/tsan.sh`, `verification/cross_arch.sh`, `scripts/werror-fork.sh`, new jobs in `.github/workflows/flag-matrix.yml`, thread-safety column added to `docs/THREAT-CONTROL-MAP.md` §3, and whatever synchronisation TSan forces on `g_hkfActiveConfig` / the `Pkcs5.c` static overrides.

**Proof:**
- *Coverage* — rebuild fork `Common/`+`Crypto/` with `--coverage -fprofile-abs-path`, run `build_and_verify.sh`, `sanitize.sh` and the realbuild tier, lcov-merge, emit per-module line/branch plus an explicit **zero-coverage function list**; plant a deliberately unreached static function and require the report to name it and the floor to fail.
- *Cross-arch* — `gcc-aarch64-linux-gnu` + `gcc-s390x-linux-gnu` + `qemu-user-static` (all confirmed installable), rebuild the wx-free harnesses, require the **same anchor hex** as native (`a8b0cbb7…`, `628882be…`, `56434b53…`, `c6f46900…`, `ab8b717f…`); negative control = an intentionally host-endian read of a documented BE field must diverge on s390x while x86-64 still passes.
- *TSan* — N threads registering/unregistering scrub entries against `VcScrubAll`, concurrent `KeyslotOpenParallel`, concurrent `Argon2SetParamsOverride` vs derive; a deliberately unlocked registry variant **must** be flagged, so an inactive sanitizer fails the sweep.
- *-Werror* — fork TUs only; narrow the harness `-Wno-*` blanket to stock TUs; plant a sign-compare and require failure.

**Anchor:** **OFFICIAL, reused** (the cross-arch leg re-runs RFC 9106/8032/9496/5869, FIPS 197/202/203, google/hctr2, BIP-173/93) + **THIRD-PARTY** gcov/TSan/qemu. Honest scope: the wx product build is **not** cross-built; the deliverable is the crypto + `Common/` modules and the KAT suite.

---

### PR 8 — `anchors: external vectors for the four unanchored mountable PRFs and for XTS`
**Items 3, 11** · IDs D10-22, D10-21, D10-25

**Lands:** new suite steps driving the **real compiled** `Pkcs5.c` TU plus real `Sha3.o`/`blake2b.o`/`Whirlpool.o`/`Streebog.o`; a `verification/prf/` harness that runs `EncryptionTest::TestXtsAES`/`TestCiphers` against independently fetched vectors; one classified row per primitive added to `docs/VERIFICATION-ANCHORS.md`.

**Proof:** hash layer against NIST CAVP `.rsp` fetched with `curl` (**not** `WebFetch` — 403s on rfc-editor per `CLAUDE.md`); PBKDF2 layer against OpenSSL EVP and `hashlib.pbkdf2_hmac` across the shapes step [97] used (partial final block, multi-block, zero-length password/salt). XTS: re-derive expected ciphertexts from independently fetched IEEE 1619 / CAVP XTSAES vectors rather than trusting the in-tree transcription in `Tests.c`, and run under every compiler in the matrix. Negative control: a one-round perturbation must break the match; flip one byte of a round key and require the XTS step to go red.

```sh
curl -sS -o /tmp/cavp-sha3.zip https://csrc.nist.gov/.../sha-3bytetestvectors.zip   # fetch to file, then slice
```

**Anchor:** **OFFICIAL** throughout. This is the highest-anchor-quality PR in the queue and it covers the code that encrypts every byte of every volume.

---

### PR 9 — `anchors: AF-split against cryptsetup, and a frozen format corpus`
**Items 13, 23** · IDs D10-37, D11-24, D10-33, D10-31, D10-32

**Lands:** `verification/afsplit_cryptsetup_xcheck.sh`, `verification/corpus/` (committed bytes + manifest), a suite step regenerating and byte-diffing the corpus, `docs/FORK-FORMATS.md` (one normative document for keyslot records v1/v2, AF stripes, area-MAC trailer, encrypted labels, AtomicHeader commit pair, v2 MAC table, share codes), `docs/VERIFICATION-ANCHORS.md` reclassification of AF-split TWIN → THIRD-PARTY.

**Proof:** `apt-get install cryptsetup-bin`; `cryptsetup luksFormat --type luks1` a **file** container (format/dump are userspace-only — no dm-crypt needed); parse the LUKS1 phdr, derive the keyslot key with PBKDF2-SHA256 via OpenSSL, AES-XTS-decrypt keyslot 0's AF material, feed the 4000-stripe blob to the **real compiled** `AfMerge`, require equality with `cryptsetup luksDump --dump-master-key`. Negatives: zero one stripe → merge must diverge; wrong passphrase. Corpus: emit every record type from the real modules today, commit the bytes plus expected-outcome manifest, and add one end-to-end arm — a container created by today's product build, committed, reopened by `open_roundtrip.sh` on every future run. Mutate each artifact by one byte and require the spec'd failure (AEAD reject / `KAM_TAMPERED` / fallback-then-fail-closed).

**Anchor:** **THIRD-PARTY** (cryptsetup 2.7) for AF-split; `[TWIN-ONLY]` for the corpus — but the corpus is the frozen artifact that makes the backward-compatibility promise machine-checkable, which is the point.

---

### PR 10 — `hkf: injectable device seam — software CTAP2 authenticator, ssh/age backend, fd secret input`
**Items 14, 15, 25** · IDs D11-21, D11-17, D03-13, D04-38, D12-31, D16-32

**Lands:** `HKFFido2OpenFn` injection point in `src/Common/HardwareKeyFactor.c` (default = today's `fido_dev_info_manifest`/`fido_dev_open`; product behaviour unchanged), `verification/ctap2_authenticator.c` (software authenticator over `fido_dev_set_io_functions`), a new `HKF_BACKEND_SSH_ED25519` (and/or age), `--hkf-secret-fd` / `--hkf-fido-pin-fd` in `src/Main/CommandLineInterface.cpp`, `verification/realbuild/argv_leak.sh`.

**Proof:**
- *FIDO2* — getInfo advertising hmac-secret, getKeyAgreement (P-256 ECDH via OpenSSL, already a build dep), AES-256-CBC salt unwrap, HMAC-SHA256, assertion response; the fork's backend must return the authenticator's bytes byte-for-byte **through real libfido2 1.14**, and equal an independent Python computation of the same CTAP 2.1 derivation. Negatives: no device → `HKF_ERR_NO_DEVICE`; wrong credential id → `HKF_ERR_DEVICE` with no response bytes; PIN required but absent → fail closed; oversized hmac-secret rejected not truncated; `salt32` wiped on every exit path.
- *ssh/age* — the in-tree response must agree byte-for-byte with what the real `ssh-keygen -Y sign` / `age` binary produces on the same salt (rule 3 via a mature implementation), plus a Python twin of the response conditioning, plus `open_roundtrip.sh` proving password-alone rejects and no-agent fails safe rather than falling through.
- *argv* — fork the real CLI with a sentinel secret and read `/proc/<pid>/cmdline` and `/proc/<pid>/environ` from a second process: zero hits on the fd path; the **same test run against `--hkf-sim-secret` on the command line must find the sentinel**, proving the grep is live (the `-DVC_LOGLEAK` idiom from step [52]).

**Anchor:** **THIRD-PARTY** libfido2 / openssh / age + **OFFICIAL** CTAP 2.1 and RFC 8032. This is the PR that removes "needs USB passthrough" from the fork's largest untested surface.

---

### PR 11 — `formal: Z3 injectivity of the CRC seam`
**Item 17** · IDs D14-56, D14-57

**Lands:** `verification/crc_seam_z3.py`, a suite step, and a status flip (or a documented collision) in `docs/CRC-SEAM-ADDENDUM.md` §3.

**Proof:** encode `HKFMixResponseIntoPassword`'s exact write schedule (rolling CRC-32, 4 bytes per input byte, mod-256 accumulate into a 128-byte pool, wrap at 33 bytes) as Z3 bitvectors; ask for `x != y` with equal pools, per input length 33..64. **UNSAT per length = a machine-checked injectivity proof closing the addendum's named gap. SAT = an explicit collision, which is a step-[94]-class finding and worth more.** Either way, replay the witness/counterexample through the **real compiled** `HardwareKeyFactor.o` (rule 2). For the indifferentiability half, exhibit the distinguisher rather than asserting it, and show the same distinguisher fails against `HKFMixResponseIntoPasswordV2`.

**Anchor:** **THIRD-PARTY** — Z3 4.8.12 (confirmed working) is a decision procedure we did not author. Classify as such in `VERIFICATION-ANCHORS.md`; the indifferentiability result is `[TWIN-ONLY]` and must **not** be called conformant.

> Note: `docs/FORMAL-ANALYSIS.md` §0.1 asserts no prover tooling is installable here. That is the `CANT-CLAIMS-AUDIT.md` pattern again — `python3-z3` installs and runs. Correct the doc as part of this PR.

---

### PR 12 — `deniability: snapshot-diff instrument`
**Item 16** · IDs D02-12, D11-27

**Lands:** `verification/snapdiff.{c,py}` (a reusable differ taking before/after images plus a declarative policy: changed extents, per-extent entropy, pass/fail), `verification/realbuild/two_snapshot.sh`, retrofits of steps [13]/[14]/[37] onto the shared utility.

**Proof:** build the product, create a real outer+hidden container, image (A), FUSE-mount the hidden volume, run a realistic FS workload, dismount, image (B). Implement the arXiv:2110.04618 changed-block run-length classifier in C **and** an independent Python twin, diff byte-for-byte. Pin the outcome as a regression value and run the same differ against a decoy-only control volume — that control is what makes the number mean anything. Retrofitting [13]/[14]/[37] and reproducing their published outcomes unchanged is the regression proof for the tool itself. Then point it at operations never snapshot-checked: keyslot rotate, shred, header backup/restore, AtomicHeader commit.

**Anchor:** the classifier is a **published method we did not author**; the fork-specific outcome is `[TWIN-ONLY]`. This becomes the bar every future deniability feature is scored against.

---

### PR 13 — `anti-lockout: dry-run, rehearsal, kit checker, destructive-op guards`
**Items 9, 30, 36** · IDs D04-40, D03-44, D07-47, D15-28, D03-32, D03-33, D03-31, D04-28, D08-47, D08-49

**Lands:** `--test-factors` / `--dry-run` on every mutating command, `--recovery-drill`, an offline kit checker (no volume required), mandatory `--yes` in non-interactive mode for `--keyslot-kill` / rotate-implied-revoke / shred, a last-credential pre-flight, `verification/realbuild/dry_run.sh` + `rehearsal.sh`.

**Proof:** extend `verification/realbuild/open_roundtrip.{sh,cpp}`, which already drives `Volume::Open` in-process with no kernel (11/11, CI-gated).
- *Dry run* — correct set reports success; wrong factor / below-threshold shares / wrong Argon2 memory-iterations-parallelism / wrong password each report failure; **SHA-256 of the container and sidecar byte-identical before and after every dry run** (the load-bearing invariant); a deliberately-mutating "dry run" must break that hash assertion.
- *Rehearsal* — decode printed `vcs1…`/codex32 strings via `ShareCode.c`, verify each with `ShamirMac`, combine, checksum, then confirm the reconstructed secret opens the real volume. M−1 shares must fail; one mistyped character must be caught **by the bech32m checksum, not by a wrong key**; a MAC-tampered share must be rejected. Drive the interactive prompt over a pty so that path is exercised too.
- *Guards* — non-interactive revoke without `--yes` exits non-zero with the container hash unchanged; revoking the last opening credential is refused unless `--force`, verified by re-opening afterwards.

**Anchor:** **OFFICIAL** BIP-93/BIP-350 for the decode leg (already in-tree at [92]/[42]); the workflow invariants are `[TWIN-ONLY]`.

---

### PR 14 — `verify: offline whole-volume scan and health report`
**Items 22, 27** · IDs D08-46, D02-9, D02-10, D16-44, D12-1, D08-1, D04-18, D12-2, D04-34

**Lands:** a `--verify` subcommand composing `KeyslotStructuralCheck` + `HeaderBackupVerify` + `KeyslotAreaMac` + a full v2 MAC-table scan; `--posture [--json]` carrying runtime facts (lockdown bitmask, swap/hibernate, self-test, occupied slots, flash verdict, v2 state); per-index and per-extent localisation rather than first-failure-only; a hardened systemd `.timer` alongside `dist/systemd/`.

**Proof:** clean volume → all-clear and 0 failures. Then inject each corruption class on real file containers and require the **exact** matching status and index set: bad version, bad cost, truncated record, dropped slot, reordered slots, flipped ciphertext bit, N seeded v2 sector flips (exactly those N reported), corrupted table region (distinguished from sector failures), v1 volume (reports "not v2", not "all bad"), no area trailer, missing/failing header backup, params below policy. **Specificity is the control** — a verifier that fails everything must not pass the clean case. Posture: extend step [71]'s three-build matrix (features-on / stock / `-DVP_NEGCTL` liar) to the runtime fields, validate the JSON with Python's own parser, and flip real bits (`RLIMIT_MEMLOCK=0`, fixture swapfile) to prove the report tracks reality.

**Anchor:** chained to HMAC-SHA256 [69] / SHA-256 [54]; the composition is `[TWIN-ONLY]`.

---

### PR 15 — `crypto: BLAKE3 module`
**Item 24** · IDs D01-21

**Lands:** `src/Crypto/Blake3.{c,h}` gated `-DVC_ENABLE_BLAKE3` / `make BLAKE3=1`, promoted from `verification/blake3_poc.c`; wired as the Merkle node hash behind the gate. **Keep the V2Format PRF swap out of this PR** — it changes v2 tag bytes and belongs in its own change.

**Proof:** drive the 35 vendored official BLAKE3-team vectors through the **real compiled object** in all three modes (hash, keyed_hash, derive_key, 131-byte extended output, inputs 0..102400) plus the independent Python twin — the exact promotion pattern already executed five times ([88] AesCt, [90] Poly1305, [91] Adiantum, [105] Hctr2). Merkle leg: re-derive the `MERKLE-SPEC.md` anchor shape (deterministic root, RFC 6962 domain tags, odd-node promotion) against a twin.

**Anchor:** **OFFICIAL** — `verification/blake3_kats.{h,py}`, already vendored.

---

### PR 16 — `netshare: PQ-hybrid the wire exchange`
**Item 29** · IDs D01-50, D03-28, D08-38

**Lands:** `src/Crypto/MlKem.{c,h}` gated `-DVC_ENABLE_MLKEM`, NetShare enroll storing `ek`, the versioned `NSC||ver||S||C||cksum` blob extended to carry `c`, and `ss_hybrid = HMAC-SHA256(ss_classical||ss_mlkem, "VC-HYBRID-v1"||SHA256(ek)||SHA256(c))` over the in-tree `Sha2.c`.

**Proof:** the vendored NIST ACVP FIPS-203 ML-KEM-768 vectors (4 keyGen, 4 encaps, all 10 decaps including the 5 modified-ciphertext implicit-rejection cases) driven through the **real compiled object**; then end-to-end over a real TCP socket against the forked local server, reusing `netshare_transport_poc.c` + `netshare_server.c` + `realbuild/netshare_cli.sh`. **The load-bearing negative:** hand a harness the recorded transcript *plus the classical scalar `e`* — i.e. grant the DL break outright — and require the share to remain unrecoverable, while the same harness with the hybrid off recovers it. Without that contrast the test proves nothing.

**Anchor:** **OFFICIAL** NIST ACVP. Hard constraint: FIPS-203 parameters must not be tuned or the NIST royalty-free patent abeyance is exited (`PQ-HYBRID-SPEC.md` §Parameter licence R-5).

---

### PR 17 — `keyslots: AND-composition, proactive share refresh`
**Items 28, 40** · IDs D03-10, D07-19, D03-23, D14-25, D01-40, D03-22, D14-4

**Lands:** `shamir_refresh` in `src/Common/Shamir.c` (over the existing branchless GF(2⁸), already ctgrind/dudect-screened at [5]/[41] — no new field arithmetic), 2-of-2 VMK split across two independent slots in `KeyslotStore.c` (no new record field), ShamirMac epoch keying, CLI surface.

**Proof:** Python twin byte-for-byte for both. AND-composition negatives carry the whole claim: slot A alone must **not** recover the VMK, slot B alone must not, revoking either breaks the pair, and the recovered VMK is byte-identical to the single-slot case; then `open_roundtrip.sh`. Refresh properties: refreshed shares reconstruct the **byte-identical** original secret (assert against the `a8b0cbb7…` anchor); any cross-epoch mix at threshold must **not** reconstruct and must be *detected* via `shamir_secret_checksum` rather than returning garbage; the refresh polynomial's constant term is provably zero; ShareCode/codex32 re-encode cleanly; `open_roundtrip.sh` opens with the refreshed set and rejects the pre-refresh set.

**Anchor:** `[TWIN-ONLY]` — Herzberg et al. proactive secret sharing publishes no vectors. Say so; do not call it conformant.

---

### PR 18 — `docs: audit-pack freshness lint + concrete parameter table + SECURITY.md`
**Items 21, 26, 45, 47** · IDs D05-48, D13-10, D15-36, D15-34, D15-39, D14-60, D14-58, D14-54, D01-37, D14-52, D05-49, D13-29, D13-30, D13-32, D15-35, D04-36, D13-37

**Lands:** `scripts/audit-pack-lint.sh` (CI-gated), `docs/CONCRETE-PARAMETERS.md`, `docs/GLOSSARY.md`, `SECURITY.md` + triage runbook, `dist/man/veracrypt.1` generated from the parser table, generated shell completions, mermaid key-hierarchy and mount-flow diagrams in `AUDIT-GUIDE.md`, and the actual fixes the lint surfaces.

**Proof (the lint is the deliverable, the prose is the payload):**
1. every `[NN]` citation in `docs/`, `ROADMAP.md`, `CLAUDE.md` resolves to a real `echo "[NN]"` step — currently fails: `AUDIT-GUIDE.md:23,45` and `THREAT-CONTROL-MAP.md:63` claim `[1]..[48]` against 104 steps topping out at [105];
2. every fork module under `src/Common` and `src/Crypto` appears in the `THREAT-CONTROL-MAP` §3 API table with a gate name that exists in `src/Makefile` — currently fails for **all** of AtomicHeader, V2Format, KeyslotAreaMac, NetShare, HeaderBackup, FlashProbe, VcPosture, SelfTest, VcJson, VcStatus, VolumeLabel, HkfOrSet, KeyslotKdf, AesCt, Adiantum, Hctr2, Poly1305, Sha3;
3. every referenced repo path resolves — currently 6 dead files in `SHA3-README.md`, 2 in `BLAKE2b-README.md`;
4. every option registered in `CommandLineInterface.cpp` appears in the man page and vice versa;
5. every fenced runnable block executes with exit 0.
Negative control in each direction: inject a dangling `[999]`, a stale count, a missing API row, a deleted man-page option — the lint must fail each.

Parameter table: reuse the existing Balloon-vs-Argon2 benchmark precedent (`build_and_verify.sh:999`) to **measure** wall-clock and peak RSS for every shipped PRF at every shipped parameter set on real binaries, pair each with a cited published bound and a stated attacker model, and add a step that re-measures and fails if a default drifts out of band. Include PBKDF2-HMAC-SHA512 as the **known-not-memory-hard negative control** producing a flat curve — otherwise the numbers are unfalsifiable. Label the ASIC extrapolation as modelling, with its error bars stated.

**Anchor:** `[TWIN-ONLY]` (internal consistency) + **OFFICIAL/cited** for the parameter bounds. State plainly where the measurement cannot bound an ASIC adversary.

---

### PR 19 — `windows: cross-compile the C derivation path and prove key parity`
**Item 8** · IDs D11-30, D04-45(partial)

**Lands:** `scripts/cross-build.sh` + a CI job cross-compiling `Common/Volumes.c`, `Common/Pkcs5.c`, `Common/HardwareKeyFactor.c`, `Common/V2Format.c` and `Crypto/*` under `-DTC_WINDOWS` with the full fork `-D` set and every pairwise flag combination the Linux matrix sweeps; `Volumes.c` added to `flag_matrix.sh` MODULES and `clang-tidy-fork.sh` MODULES.

**Proof:** `apt-get install gcc-mingw-w64-x86-64` (13.2.0 confirmed available). Compile-conformance across the matrix, failing on any error — this alone replaces `hook_typecheck.c`'s hand-written `KEY_INFO` mirror with a real compiler. Then, if `wine` is available, a Win32 harness calling the real `ReadVolumeHeader`/`CreateVolumeHeader` C-path wrappers with a fixed salt and password, asserting the mixed password and derived header key equal the C++ path's proven anchors (`f965c9e3…`, `628882be…`) — which converts "keys are byte-identical cross-platform (proven)" from an argument into a machine check.

**Anchor:** **THIRD-PARTY** — a compiler we did not author disagreeing with our mirror. Honest scope: driver build and signing remain out of reach; if wine is unavailable, the deliverable is compile-conformance plus a stated remainder, which is still strictly more than today's zero.

---

### PR 20 — `harness: mutation testing, differential fuzzing, NetShare fuzz, error-code matrix`
**Items 19, 38, 42, 50** · IDs D05-22, D05-5, D05-24, D05-32, D10-38

**Lands:** `verification/netshare_fuzz.c`, `verification/mutate.sh`, `verification/differential_random.sh`, an exact-error-code KAT table per module, NetShare added to `sanitize.sh` HARNESSES, exported seed corpora.

**Proof:**
- *NetShare fuzz* — deterministic fixed-seed fuzzer over `NetShareCredParse`, `NetSharePointValidate/Decompress/RoundTrip`, `NetShareRecover` with an injected hostile `NetShareTransportFn` returning arbitrary bytes, under gcc ASan+UBSan (the sanitizers are the oracle), seeded from RFC 8032 §7.1 compressed points. Assert the module's own claims: bad blob → `ERR_CRED` not a share; unreachable/hostile server → `ERR_TRANSPORT`, never a share; no unbounded decompression. Negative control: a variant trusting `blobLen` must fault under ASan.
- *Mutation* — N seeded source mutations per fork module (comparison flips, constant increments, `memcmp`→0, loop off-by-one), re-running only the steps that link that module; every mutant must be **killed**; surviving mutants are the finding. Include one known-**equivalent** mutant that must survive, so a harness reporting everything red also fails.
- *Differential* — drive the ~40 existing `*_reference.py` twins over seeded random inputs (Shamir, ShamirMac, ShareCode, AfSplit, Keyslot wrap, HKF v1/v2 mixing, KeyslotAreaMac, AtomicHeader, V2Format tags); perturb one twin by a byte and require the run to go red.
- *Error codes* — assert exact constants, not mere non-zero; swap two codes in a module and require the table to fail.

**Anchor:** **OFFICIAL** RFC 8032 seeds; the rest is `[TWIN-ONLY]` by construction — differential fuzzing scales rule 1 and does not substitute for rule 3.

---

### PR 21 — `hygiene: constant-time ShareCode, normalization warning, simulator release gate`
**Items 31, 34, 35** · IDs D02-32, D15-20, D12-39

**Lands:** branch-free `sc_charval` + arithmetic-select table index in `src/Common/ShareCode.c` (mirroring `Shamir.c`'s masked pattern); a passphrase classifier (non-ASCII / non-printable / non-NFC / non-portable-layout) called from the Linux create and mount paths beside the existing `PASSWORD_LENGTH_WARNING` site; a startup banner for any relaxing flag plus `scripts/release-gate.sh` reading `src/.build-flags`.

**Proof:**
- *ShareCode* — all official BIP-173/350/93 vectors still reproduce (steps [42]/[92] unchanged); byte-for-byte agreement with `sharecode_reference.py`; a new self-validating dudect screen that must **flag** the current early-return version and **clear** the rewrite, plus ctgrind with share bytes poisoned.
- *Normalization* — Python twin, real compiled object, and rule 3 against the official Unicode `NormalizationTest.txt`: the classifier must flag every NFD form differing from its NFC form. Then the integration proof: create with an NFD passphrase and show via `open_roundtrip.sh` that the NFC form does **not** open it — the concrete failure the warning prevents.
- *Release gate* — build with `HKF_SIMULATOR=1` → banner present and gate **rejects**; build without → silent and accepted; the gate passing a simulator build must fail the test.

**Anchor:** **OFFICIAL** BIP-173/350/93 (preserved) and unicode.org UAX #15; the release gate is `[TWIN-ONLY]`.

---

### PR 22 — `memory + response: page cache, panic signal, dead-man`
**Items 37, 43** · IDs D06-47, D06-41, D16-15, D16-14, D08-8

**Lands:** `POSIX_FADV_DONTNEED` eviction at dismount plus a gated `-DVC_ENABLE_DIRECT_IO` path; an async-signal-safe `SIGUSR1`/`SIGTERM` handler feeding the existing `UserInterface::DuressDismount`; dismount (not just scrub) wired into `KeyScrubManager`'s idle thread; `docs/MEMORY-SCRUB.md` measured results.

**Proof:** FUSE + loop-ext4 both confirmed working here. Measure inner-file page residency with `mmap`+`mincore` (plaintext **is** resident), dismount and re-measure, then add eviction and prove residency goes to zero with a skip-the-step negative control; publish the three-way table (default / evict / direct-io) including whichever residue the fix cannot reach. Correctness gate: `open_roundtrip.sh` byte-identical with and without `direct_io`, and unaligned/partial-sector requests still refused. Panic: mount two containers, signal, assert `--list` empty and FUSE services gone; an unrelated signal does nothing; a handler that only logs must fail the test. Dead-man: no check-in within T → dismounted + `ScrubNow`; check-in inside T → still mounted; `T=0` → still mounted.

**Anchor:** `[TWIN-ONLY]`; `mincore` residency is the measured ground truth. State the honest ceiling: on a kernel dm-crypt mount the master key is kernel-resident and out of user-space reach.

---

### PR 23 — `perf: CLMUL POLYVAL and the overhead accounting D-4 rests on`
**Item 39** · IDs D01-25, D09-5, D09-42, D04-22, D09-28

**Lands:** runtime-dispatched CLMUL POLYVAL in `src/Crypto/Hctr2.c` behind the existing `cpu.c` detection (software `gf_dot` retained as the fallback rung), `verification/mode_bench.c`, a deliberate `scripts/ct-primitive-guard.sh` allowlist entry with written rationale, measured numbers into `docs/HCTR2-SPEC.md` and `docs/V2-FORMAT-SPEC.md`.

**Proof:** (a) CLMUL and software paths byte-identical over randomised inputs, and both reproduce the RFC 8452 published POLYVAL example; (b) all 35 official google/hctr2 AES-256 vectors still pass through the **real compiled** `Hctr2.o` with the accelerated path selected — this is the [105] harness re-run, not new scaffolding; (c) ctgrind + the self-validating `hctr2_dudect_test.c` contrast extended to the CLMUL path; (d) the dispatch ladder itself exercised by forcing the fallback on a box that *has* CLMUL and requiring identical output; (e) `realbuild/hctr2_mode.sh` (17/17) unchanged. Benchmark: HCTR2-over-AesCt < Adiantum-over-AesCt < XTS as *property* assertions (machine-independent), substantiating decision D-4, which is currently a header comment. `pclmulqdq`, `aes` and `avx512f` are all present; `vaes` is **not**.

**Anchor:** **DOUBLE OFFICIAL** — RFC 8452 + vendored google/hctr2 KATs. Honest ceiling on the overhead accounting: the FUSE-vs-kernel-dm-crypt leg the v2 fail-closed decision actually turned on **cannot** be measured here; report v1-over-FUSE vs v2-over-FUSE and state the missing leg rather than estimating it.

---

### PR 24 — `supply chain: OSV scanning, licenses, threshold VOPRF proofs`
**Items 44, 48** · IDs D05-42, D12-42, D13-27, D12-40, D01-42

**Lands:** `verification/sbom.py` extended with SPDX `licenses` per component and versions read from source (`ZLIB_VERSION`, libzip `NEWS.md`, lzma headers) rather than a hand list; an OSV batch-query CI job; per-share public keys `pk_i = k_i·G` from the Feldman commitment vector [31] and per-server DLEQ in the threshold OPRF.

**Proof:** OSV — fail CI on any advisory at or above threshold outside a dated, justified allowlist; assert the documented constraint specifically (a shipping build on libsodium < 1.0.21 must fail for CVE-2025-69277, while the verification-only oracle at distro 1.0.18 stays allowed per D-8); inject an ancient zlib and require the job to go red. Licenses: fail when a vendored directory has no recorded license or an unrecognised SPDX id. VOPRF — build on **libsodium**, not the bespoke group (`VERIFICATION-ANCHORS.md` records the hash-to-group as non-conformant at [94]); re-anchor DLEQ to RFC 9497 A.1.2 through the real object; an honest t-subset reconstructs the byte-identical [95] output; **the load-bearing negative** — a server returning `k'·BE` is rejected *and identified by index*, and t−1 valid + 1 rejected fails **closed** rather than emitting a wrong key. n forked servers over real TCP, the [49]/[101] pattern.

**Anchor:** **THIRD-PARTY** OSV/NVD; **OFFICIAL** RFC 9497 for half the VOPRF work.

---

## 3. Tracker corrections — 124 items already built

The spreadsheet materially overstates remaining work. These were cross-checked against master `a3ec1e2` and are **already built and proven**, **formally declined with a recorded verdict**, or **already upstream behaviour**. Do not write specs for them.

### Already built and proven (89)

**Crypto/KDF (10):** `D01-32` Argon2 wall-clock calibration (`Pkcs5.c:2103`, step [70], budget-ignoring negative control) · `D01-46` Feldman/Pedersen VSS ([31]/[32], `docs/VSS-SPEC.md`) · `D01-41` PPSS/threshold-OPRF ([44]) · `D01-23` Ascon-Hash256 vs NIST ACVP SP 800-232 ([28]) · `D01-17` independent per-layer cascade keys (`EncryptionAlgorithm.cpp:206-236` — upstream already slices distinct key ranges) · `D01-18` independent per-layer tweak schedules (`EncryptionModeXTS.cpp:56-67,115-120`) · `D14-1` key rotation without body re-encryption (the keyslot model itself) · `D14-13` cryptographically rate-limited decryption (OPRF [43]/[44]/[95]/[96]) · `D14-15` MPC key reconstruction with no trusted reconstructor ([44]) · `D14-47`/`D14-50` symmetric-only PQ architecture + Grover policy (ROADMAP D-13, `PQ-HYBRID-SPEC.md`).

**Harness/CI (24):** `D05-1` `--strict` · `D05-2` coverage accounting line · `D05-3`/`D05-4` negative controls + liveness guard · `D05-8` deterministic seeds · `D05-9` pairwise flag matrix · `D05-10` gcc-12/13/14 + clang · `D05-11` static `VC_INLINE` fixes + CI guard · `D05-12` guard-complementarity lint [50] · `D05-15` symbol-collision check [51] · `D05-16` ASan/UBSan sweep · `D05-19`/`D05-20`/`D05-21` keyslot, area-file and Shamir/ShareCode fuzzing [56]/[57]/[45] · `D05-25` randomized property tests [60] · `D05-27` dudect screens [41]/[46]/[59]/[82] · `D05-28` ctgrind · `D05-29` Wycheproof-style edge cases [69] · `D05-30` second-library cross-checks (all rows CLOSED) · `D05-31` anchor-provenance doc · `D05-38` threat→control→test map · `D05-39` SBOM [74] · `D05-45` clang-tidy + CodeQL · `D05-46` secrets scanning · `D05-47` honest coverage statement · `D11-25` property-based framework · `D11-42` fuzz templates.

**Keyslots/recovery (17):** `D02-5`/`D02-6` area MAC + anti-downgrade binding [75]/[23] · `D02-16` deniable keyslot backend · `D02-37` constant-time keyslot search [46]/[99] · `D03-2` per-slot policy (read-only/expiry/max-attempts) [53] · `D03-4` verifiable shred with attestation [63] · `D03-5` rotation without body re-encryption · `D03-18` multi-token OR-set [68] · `D03-35` header backup with integrity check [66] · `D03-47` duplicate-x rejection (`Shamir.c:126`) · `D07-11` per-user keyslots · `D07-15` reader/writer capability (`KEYSLOT_FLAG_READONLY`) · `D07-16`/`D16-35` time-boxed credentials · `D07-21` M-of-N escrow mechanism · `D07-27` escrow rotation · `D07-30`/`D13-11`/`D13-16` crypto-erase + certificate · `D13-12` retention via slot expiry · `D16-37` rate limiting.

**Memory/physical (9):** `D02-25`/`D02-26` mlockall + swap/hibernate detector [6][G]/[J] · `D02-30` zeroization liveness [L1]/[L2] · `D02-31` CT screens across primitives · `D02-20` SSD/TRIM deniability advisor [83] · `D06-1` flash warning (same) · `D06-27`/`D16-49`(header half) atomic header, 553 torn-write offsets [77] · `D08-12` screen-capture resistance (upstream default-on) · `D08-34/35/36` forensic-imaging, recovery-service and chip-off notes (`THREAT-MODEL.md`) · `D08-38` per-component quantum posture.

**Platform/observability (17):** `D09-17` parallel PRF trial (`VolumeHeader.cpp:157-224`) · `D09-6` runtime CPU dispatch (`cpu.h:254-330`) · `D09-35` feature-gated builds · `D06-10` sector-size detection + mismatch refusal · `D11-6`/`D04-39`/`D16-39` error taxonomy + exit-code contract [64] · `D11-26` synthetic-block-device harness · `D11-31` pre-commit hooks · `D11-40`/`D12-6` feature-flag introspection [71] · `D11-23` deterministic RNG (already at the harness layer; a product-level switch would be a foot-gun) · `D12-5` verification-coverage display [55] · `D12-9` swap/hibernate indicator · `D12-10` memory-lock indicator · `D12-11` self-test on mount [54] · `D12-24` log-redaction grep test [52] · `D12-40` dependency report · `D04-11` encrypted volume labels [76] · `D04-30` contextual warnings · `D04-34` machine-readable status [65] · `D04-48`/`D08-23/24/28` reproducible builds [73] + SBOM [74].

**Interop/compliance/docs (12):** `D10-30` codex32/bech32m conformance [92]/[42] · `D10-36` capability manifest · `D13-20`/`D13-21` jurisdiction matrix + duress legality (`KEY-DISCLOSURE-LEGAL.md`, `COUNSEL-BRIEF.md`) · `D13-28` patent landscape (`COUNSEL-BRIEF.md` §3-8) · `D13-36` SBOM per release · `D16-12`/`D16-13` hardened systemd unit + socket activation [67] · `D16-3` network-bound unlock · `D16-38` fail-closed on unreachable server · `D16-31` per-volume credential namespacing (salt binding [93]/[12]) · `D16-42` structured JSON [65] · `D16-48` hidden-volume overwrite protection (upstream `--protect-hidden`) · `D15-22`/`D15-23`/`D15-27` threat-model explainer, "what this does NOT protect against", legal primer · `D08-45`/`D08-47`/`D08-49`/`D08-27` recovery-after-damage, lost-token, rapid rotation, parameter downgrade prevention.

### Formally declined with a recorded verdict (13)

`D01-3` EME2 (birthday-bound + data-dependent GF multiply) · `D01-4` AEZ (missed CAESAR portfolio, published key-recovery) · `D01-5` FAST (adds nothing over the vetted pair) · `D01-6` XCB (**cryptanalytically broken**, three attacks 2024-25, being removed from IEEE 1619.2) · `D01-20` LEA · `D01-27` cSHAKE labels (**SUBSUMED** — HKDF `info` already provides it) · `D02-11` free-space chaff (does not defeat the change-chain classifier) · `D02-17` StegFS · `D03-24` Rabin/AONT-RS dispersal (weaker than the shipped split, and shards conflict with deniability) · `D03-26`/`D03-30` guardian/notary social recovery · `D10-30` SLIP-39 (D-2: would duplicate the shipped Shamir) · `D14-11` formal Canetti deniable encryption (needs iO; `THREAT-MODEL.md:74-79` already forbids the claim).

### Already upstream behaviour (5)
`D01-17`, `D01-18`, `D06-10`, `D08-12`, `D16-48` — counted above; listed again because a triage row treating upstream behaviour as fork work is the most expensive kind of false positive.

**Net effect: 124 of 704 candidates need no work at all, and a further 94 are not completable in this environment.** The genuinely open, sandboxable surface is roughly 486 rows, of which the 50 above are the ones worth building.

---

## 4. Deliberately excluded despite a high triage score

| Item | Score given | Why excluded |
|---|---|---|
| **D05-35** TLA+/Alloy keyslot model | 5 | A model proves the model. Only worth it with TLC-trace replay against the real `KeyslotStore.c`, which is what makes it L-effort. Item 38 (mutation testing) buys more assurance per hour on the same code. |
| **D05-36** HACL*/fiat-crypto behind a stable API | 4 | **Relitigates a decided item.** ROADMAP D-8 resolved this the opposite way — single-provider libsodium, HACL* explicitly dropped — and `ed25519_hacl_xcheck.c` already uses HACL* as an *oracle*, which captures the assurance without the dependency. |
| **D02-24 / D12-8** IOMMU/DMA posture check | 6 and "not sandboxable" | **Two agents disagreed; the pessimist is right.** `/sys/class/iommu` and `/sys/kernel/iommu_groups` are empty here, so only the negative case is observable. A status indicator never seen to say "yes" is not proven. Buildable as a fixture-only classifier — fold into PR 14 if desired, do not schedule as its own item. |
| **D01-24** KMAC256 keyslot-area auth | 4 | Genuine ROADMAP row, but it duplicates an already-OFFICIAL-anchored construction (`areaMac` = HMAC-SHA256 [69] over HKDF [103]) **and** changes the trailer bytes. Format surface for marginal gain is the rubric's explicit penalty. |
| **D03-28** PQ escrow slot | 5 | An escrow slot is by construction a coercion target — the exact threat the fork exists to resist. The ML-KEM work is better spent on PR 16, where it protects a wire protocol that already ships. |
| **D03-29** Time-delayed recovery (VDF) | 5 | Genuinely sandboxable and on-thesis, but `COUNSEL-BRIEF.md` §5 flags VDF/time-lock patents as **unresolved**, and the honest holder pays the delay too. Blocked on counsel, not on engineering. |
| **D14-6** Big-key / ROM-hard KDF · **D01-33** | 5 / 4 | Closes a named backlog row and is buildable here (30 GB free), but VeraCrypt already supports arbitrarily large keyfiles — the delta is only the pseudorandom access pattern, a narrower claim than the row implies, with no external anchor. |
| **D02-29** Secure allocator · **D02-23** guard pages | 5 / 4 | ASan+UBSan already sweep these harnesses and both parsers are fuzzed clean; the fork's secret-bearing allocations are few and mostly struct-resident. Item 5 (wiring `VcKsRamProtect` to real secrets) is the same goal with a far better return. |
| **D03-21** Hierarchical trustee groups | 6 | Real expressiveness gap and cleanly buildable, but no external anchor (`ShareCode.h` records the deliberate decision *not* to adopt SLIP-39's group thresholds) and no named tracker row. Revisit after PR 17. |
| **D10-1 / D10-2** LUKS1/LUKS2 read support | 6 / 5 | Strong third-party anchor, but it adds a large attacker-reachable parser to a fork whose parse surface is deliberately two modules. The *assurance* payoff — anchoring AF-split — is obtained at M effort by PR 9 without the parser. |
| **D06-30** Container self-description block · **D06-21** sparse containers · **D02-19** timestamp normalization · **D02-18** plausible-fill wizard | 2 each | Listed as **do-not-build with the reason recorded**, so a future planner does not re-propose them. The first two are direct deniability regressions (a fixed recognisable structure; an extent map that discloses the hidden volume). The last two sit on or across the DESCOPED evidence-fabrication line — `CLAUDE.md`'s scope section and `KEY-DISCLOSURE-LEGAL.md` both apply, and D02-19 needs an owner ruling before any work, not a spec. |
| **D01-14** Simon/Speck "reference only" | 1 | Actively harmful to goal (a). ISO/IEC rejected them over provenance; shipping them even disabled hands an auditor a question that costs more than the feature is worth. Decline explicitly and record it. |
| All 94 **NOT-SANDBOXABLE** rows | — | Cannot be completed *and proven* here. The largest — YubiKey/FIDO2 on real hardware — is partially defeated by PR 10's injectable seam; the residue (a genuine token over USB) stays open and should keep saying so. |

---

## 5. Two standing cautions for whoever executes this

1. **`make clean` on every feature-flag change.** A mixed build does not fail loudly — it fails as a volume that will not open, which reads exactly like a crypto bug. Prefer `scripts/build-product.sh` (true clean, stamps `src/.build-flags`) over bare `make`. This already cost one session.
2. **Fetch vectors with `curl` to a file, then slice.** `WebFetch` 403s on `rfc-editor.org` and `datatracker.ietf.org`; piping `curl` into `sed`/`grep` truncates at 4096 bytes. CFRG machine-readable vector JSON is easier to parse than RFC text. And before declaring anything un-testable here, run the probe — this synthesis found `z3` working and `python3-z3`, `cryptsetup-bin`, `gcc-mingw-w64`, `gcc-aarch64-linux-gnu`, `gcc-s390x-linux-gnu` and `qemu-user-static` all installable, against in-tree documentation claiming otherwise.