# Roadmap & idea log

Consolidated record of everything explored in this project so nothing is lost. Status tags:
**DONE** (built + verified) · **DESIGN** (specced, not built) · **DESCOPED** (deliberately not built) ·
**BACKLOG** (good idea, not started) · **DECIDED** (advisory conclusion, no code).

Everything here is *access-control cryptography* for VeraCrypt — strengthening the factor that is
actually the weak link (password entropy), not the cipher. The one exception (an evidence-fabrication
tool) is explicitly DESCOPED; see the note at the end and `CLAUDE.md`.

---

## DONE — built and verified

Each was proven byte-for-byte against an independent Python reference **and** against real compiled
VeraCrypt objects (see `verification/` and `CLAUDE.md` §Verification).

1. **BLAKE2b-512 PRF** — HMAC/PBKDF2 KDF reusing the in-tree Argon2 BLAKE2b primitive (no new .c, no
   build change). Verified vs RFC 7693 + Python. `docs/BLAKE2b-README.md`, `patches/blake2b-prf.patch`.
2. **SHA3-512 PRF** — from-scratch portable FIPS-202 Keccak (`src/Crypto/Sha3.{c,h}`) + C++
   `Pkcs5HmacSha3_512` KDF. Verified 3 layers incl. real compiled objects. `docs/SHA3-README.md`,
   `patches/sha3-prf.patch`.
3. **HardwareKeyFactor module** (`src/Common/HardwareKeyFactor.{c,h}`) — an optional hardware second
   factor. A token computes a response from a challenge (the volume's PBKDF2 salt); the response is
   mixed into the password before PBKDF2 using VeraCrypt's exact keyfile pool method, so **no
   header-format change**. Backends (compiled behind `-DVC_ENABLE_*`):
   - **YubiKey HMAC-SHA1 challenge-response** (`libykpers-1`).
   - **FIDO2 hmac-secret** assertion (`libfido2`).
   - **Software simulator** (self-contained SHA-1/SHA-256; testing only).
   - **RAW_SECRET** — mix a caller-supplied secret (used by the Shamir split-key factor).
   `docs/HARDWARE-2FA.md`.
4. **C-path hooks** (`src/Common/Volumes.c`) — mount + format derivation, for the Windows driver /
   shared code. `patches/volumes-hkf-hooks.patch`.
5. **C++-path hooks** (`src/Volume/VolumeHeader.cpp` mount, `src/Core/VolumeCreator.cpp` create) —
   the path the Linux/macOS app actually uses. Helper `src/Volume/HardwareKeyFactorMix.h`.
6. **CLI options** (`src/Main/CommandLineInterface.{h,cpp}` + `src/Main/HardwareKeyFactorCli.h`) —
   `--hkf-backend`, `--hkf-yk-slot`, `--hkf-fido-rp`, `--hkf-fido-credid`, `--hkf-fido-pin`, simulator
   opts. Parsing verified (wx glue compiles in a full build). `patches/cli-hkf-options.patch`.
7. **Factor-gated decoy** (`HKF_APPLY_HIDDEN_ONLY` + `HKFShouldApply`) — the outer (decoy) header
   derives from the password alone while the hidden (real) header additionally requires the factor.
   Rides VeraCrypt's existing hidden-volume layout; no format change. `docs/DECOY-VOLUME-SPEC.md`,
   `patches/decoy-hkf-hooks.patch`.
8. **Shamir threshold / split-key factor** (`src/Common/Shamir.{c,h}` + `RAW_SECRET`) — the secret is
   reconstructed from any *M-of-N* shares (Shamir over GF(2⁸)) and mixed into the password. Gives
   split trust, a safe (non-destructive) dead-man, and redundancy. A share can be a keyfile,
   passphrase value, YubiKey/FIDO2 response, or network fetch. `docs/SPLIT-KEY-SPEC.md`.
9. **Cross-platform memory-key scrub** (`src/Common/KeyScrub.{c,h}`, `src/Core/KeyScrubEvents.{h,cpp}`)
   — closes the Linux/macOS RAM-exposure gap the Windows driver handled alone. User-space secrets (the
   reconstructed Shamir secret, HardwareKeyFactor material) are kept **ChaCha-encrypted at rest in RAM**
   (the Windows `VcProtectMemory` scheme — t1ha2 over a 1 MiB decoy area → ChaCha12 — reusing the
   in-tree primitives) and **erased on unmount / idle timeout / screen-lock / new-device-connect** via
   a barrier-hardened secure-wipe + scrub registry. The crypto core is proven two ways (independent
   Python reimpl of t1ha2+ChaCha12 vs. real compiled objects; anchor `d28b461b…`). Gated behind
   `-DVC_ENABLE_KEYSCRUB` (`make KEYSCRUB=1`). **Honest limits:** the mounted master key lives in the
   kernel device-mapper, not this process, so it is out of user-space reach; and the screen-lock /
   new-device triggers are OS glue that must be validated on a real desktop session.
   `docs/MEMORY-SCRUB.md`, `patches/keyscrub.patch`.
10. **Safe duress-dismount** (`src/Common/DuressToken.{c,h}`, `UserInterface::DuressDismount`) — a
   non-destructive coercion response: dismount every volume and scrub user-space RAM secrets (the
   KeyScrub `ScrubNow()` path), mounting nothing. Triggered by an explicit `--duress-dismount` switch
   or a **duress passphrase** recognised in user space via `HMAC-SHA256(salt, passphrase)` with a
   constant-time compare — no plaintext stored, no header change. Verified two ways (independent
   Python HMAC vs. real compiled Sha2; anchor `3d874ea9…`). Gated `-DVC_ENABLE_DURESS`
   (`make DURESS=1`). Destroys nothing on disk, leaves no "destruction" tell.
   `docs/DURESS-DISMOUNT-SPEC.md`, `patches/duress-dismount.patch`.
11. **Explicit Argon2id parameters** (`Common/Pkcs5.c`, gated `-DVC_ENABLE_ARGON2_PARAMS`,
   `make ARGON2PARAMS=1`) — expose Argon2's **memory / iterations / parallelism** as explicit CLI
   inputs (`--argon2-memory/-iterations/-parallelism`) instead of shoehorning them into PIM and fixing
   parallelism at 1. No header change (supplied like PIM at both create and mount). Verified: the real
   in-tree Argon2 reproduces the **RFC 9106** Argon2id vector (parallelism 4); the override plumbs
   parallelism (p=1 == stock, p=4 differs); the resolver matches an independent Python reimpl; and the
   stock `Pkcs5.o` is byte-for-byte identical without the flag (`verification/argon2_params_test.c`,
   step `[11]`). `docs/ARGON2-PARAMS-SPEC.md`, `patches/argon2-params.patch`.
12. **Salt-binding for RAW_SECRET** (`Common/HardwareKeyFactor.c`, gated `-DVC_ENABLE_HKF_SALT_BIND`,
   `make HKF_SALT_BIND=1`) — the `RAW_SECRET` factor optionally returns `HMAC-SHA256(secret, volume
   salt)` instead of the raw secret, binding a reconstructed/threshold secret to the specific volume
   (the same shares yield a different factor per volume, like the challenge-response hardware backends).
   No header change; CLI `--hkf-bind-salt`. Verified two ways — the real `HKFComputeResponse` over the
   in-tree `Sha2.c` vs. independent Python HMAC-SHA256, byte-for-byte (anchor `4619ed18…`), plus
   unbound-unchanged and salt-dependence checks (`verification/saltbind_test.c`, step `[12]`).
   `docs/SALT-BINDING-SPEC.md`, `patches/salt-binding.patch`.
13. **Constant-time GF(2⁸) in Shamir** (`Common/Shamir.c`) — P0 hardening (`IDEAS-BACKLOG.md` §P0.1).
   The reconstruction path's `gf_mul` did `gf_exp[gf_log[a]+gf_log[b]]` with an `if (a==0||b==0)`
   early-out, and `gf_inv` indexed a table by `gf_log[a]` — both **secret-dependent memory indices and
   branches**, a cache-timing / branch side channel in the strongest coercion primitive. Replaced with
   a branchless Russian-peasant multiply (fixed 8 iterations, reduction 0x1b) and `a^254` via a
   fixed-exponent square-multiply — no tables, no secret-dependent control flow. Proven byte-identical
   to the table version over **all 65536 inputs** and `a·inv(a)=1` for every `a≠0`; all existing Shamir
   KATs/threshold checks unchanged (`verification/shamir_test.c`, step `[5]`). **The recommended
   `dudect` timing-leakage screen is now built** (`verification/shamir_dudect_test.c`, step `[41]`): a
   Welch t-test over two input classes on the real `gf_mul`/`gf_inv`, made robust by being
   **self-validating** — the same screen runs on a deliberately variable-time leaky multiply and must
   flag it (|t| ≈ 700) while clearing the real branchless primitives (|t| < 2), so the pass/fail is a
   machine-independent *contrast*, not an absolute cycle count. (A screen is evidence, not a proof of
   constant-timeness.) `patches/shamir-constant-time.patch`.
15. **Verifiable Shamir reconstruction** (`Common/Shamir.c`) — `shamir_secret_checksum` (CRC-32) so a
   reconstruction is *verified*: a mistyped share or a below-threshold combine is detected instead of
   silently returning garbage (the header's own "wrong shares yield an incorrect secret" caveat). Matches
   Python `zlib.crc32` byte-for-byte (`3b8cfe40`); detection shown in step `[5]`. Self-contained, no new
   dependency. **The keyed per-share MAC (adversarial share tamper/fabrication) is now built & proven**
   (`Common/ShamirMac.{c,h}`, gated `-DVC_ENABLE_SHAMIR_MAC`; `HMAC-SHA256(macKey, "VCSMshare1"‖x‖len‖y)`
   over the real Sha2.c, keeping Shamir.c dependency-free): a flipped, truncated, x-relabelled, or
   fabricated share is rejected, and the wrong MAC key rejects — proven two ways in step `[40]` (real
   Shamir.c + ShamirMac.c vs independent Python; tags diffed byte-for-byte). **Feldman/Pedersen
   *dealer-consistency* VSS stays the prime-field scheme** (steps `[31]`/`[32]`): its homomorphic check
   `g^{share}==∏C_j^{i^j}` has **no GF(2⁸) analogue**, so it is a parallel verifiable-sharing scheme,
   not a byte-wise add-on — the MAC and VSS are complementary (share authentication vs dealer honesty),
   documented in `docs/VSS-SPEC.md`. `IDEAS-BACKLOG.md` §D; `patches/shamir-verifiable-shares.patch`.
14. **Memory-hygiene lockdown + zeroization tests** (`Common/KeyScrub.c`) — P0 hardening
   (`IDEAS-BACKLOG.md` §P0.4/§P0.6). `VcKeyMemoryLockdown` (called from `KeyScrubManager::Enable` before
   any secret is derived): `mlockall` (no swap), `RLIMIT_CORE=0` (no core dump), `PR_SET_DUMPABLE=0`
   (no ptrace/core) — best-effort, returns a bitmask. Runtime-verified in the sandbox (step `[6]` `[G]`:
   core disabled + non-dumpable after the call); and a zeroization matrix (`[H]`) asserts `VcSecureWipe`
   zeroes every size/alignment and survives `-O2`. Hibernation writes all of RAM to disk and is **not**
   covered — documented in `docs/MEMORY-SCRUB.md`. Gated `-DVC_ENABLE_KEYSCRUB`.
   `patches/keyscrub-lockdown.patch`.
15. **HKF mix v2 (HKDF-SHA256) — Rank-1 remediation of the CRC-32 keyfile-pool seam** — replaces the
   v1 CRC pool combine with `HKDF-SHA256(IKM = password‖response, info = "VeraCrypt/HKF/mix/v2", L=128)`,
   a PRF that preserves entropy for any response length (the v1 pool is only provably injective for
   ≤32-byte inputs; a 33–64-byte raw Shamir secret wrapped it). No on-disk format change — the mix only
   changes the value fed to PBKDF2/Argon2. Gated `-DVC_ENABLE_HKF_MIX_V2`; default and `VC_ENABLE_HKF`-only
   builds stay byte-for-byte stock. `docs/HKF-MIX-V2-SPEC.md`, `docs/CRC-SEAM-ADDENDUM.md` §7.
   - **Primitive + mount-time version-try loop** — suite step `[80]`, the v2 mixed password diffed
     byte-for-byte against an independent Python HKDF (anchor `78b0e7e5…`); wrong response opens neither
     version; v1≠v2; 1-bit response flip avalanches ~half the v2 output (PRF diffusion).
   - **Wired at all five derivation call sites** — C path (`Volumes.c` mount wrapper + `CreateVolumeHeader…`
     create) and C++ path (`VolumeHeader::Decrypt` + both `VolumeCreator.cpp` sites, via
     `HardwareKeyFactorMix.h`). New volumes enroll under v2; mount tries v2 then falls back to v1 for a
     legacy volume. Seam proven in suite step `[81]` over the real `HardwareKeyFactor.o`: **compute-once**
     (one backend query across both version attempts — no double token round-trip), v2-first/v1-fallback,
     wrong-factor-opens-neither, **cross-path byte-identity** (C create path == the C++ overload), and
     no-factor pass-through; the v2-enrolled key cross-checked against the independent Python HKDF.
     New seam helpers `HKFComputeActiveResponse` / `HKFApplyIfConfiguredVer` in `HardwareKeyFactor.{c,h}`.
   - **Honest ceiling.** The behavioural header round-trip (create a volume, then mount it through the real
     KDF/cipher pipeline) links the whole mount/create stack and is **real-build-only**; and the C-path
     edits (`Common/Volumes.c`) build only under the **Windows driver toolchain** — that file is Windows-only
     (in no Linux `.make`, uses `<io.h>`/`WORD`/`TC_EVENT`), so on Linux the mount/create runs entirely
     through the C++ path. Acceptance items in `docs/REAL-BUILD-VALIDATION.md`.
   `patches/hkf-mix-v2.patch`, `patches/hkf-mixv2-wiring.patch`.

---

## Post-R27 dispositions — items 91/96/97/98

R27 Rank-1 (HKF mix v2) has landed (primitive PR #4, wiring PR #5), which releases the holds that project
planning had parked on several `ROI-51-100` items pending that analysis. The ranked `ROI-51-100.md`
backlog that tracks these items lives in the handoff package and is **not committed to this repo** (only
`docs/ROI-TOP-50.md` is in-tree), so this section records the dispositions here so a session reading the
repo alone is not misled. Full rationale is in `docs/CRC-SEAM-ADDENDUM.md` §7.

| Item | Disposition | Note |
|---|---|---|
| **91 — slot AND-composition** `[FORMAT]` | **UNBLOCKED** | Keyslot policy; unrelated to the password-derivation seam. The R27 hold is released; the `[FORMAT]` design review still stands. Not started this session. |
| **98 — KMAC256 keyslot-area auth** `[FORMAT]` | **UNBLOCKED** | Authenticates the keyslot area, not the derivation input. R27 hold released; `[FORMAT]` review still stands. Not started this session. |
| **97 — cSHAKE domain-separated KDF labels** | **SUBSUMED — do not build** | Rank-1's HKDF-Expand `info` label `"VeraCrypt/HKF/mix/v2"` already provides the domain separation. See `docs/HKF-MIX-V2-SPEC.md` and `CRC-SEAM-ADDENDUM.md` §7. Building it separately would be duplicated work. |
| **96 — two-stage derivation (cheap factor pre-check)** | **Design against v2, not the current seam** | Still not started; out of scope for this session. When taken up, design it on top of the v2 HKDF mix rather than the legacy CRC pool. |

Being "unblocked" means only that the R27 hold is released — the `[FORMAT]` tags on 91 and 98 stay, so
the on-disk format design review is **not** waived.

---

## DESIGN — specced, not yet built

- **Multiple independent keyslots** (like LUKS2's 8+) — **core built & verified; CLI/mount integration
  remains.** *(The enabling primitive for per-person keys, rotation, revocation, and a real duress
  keyslot — the one deliberately fork-only on-disk format.)* One master key, many independent
  wrappings: slot 0 is the untouched native header, slots 1..N wrap the same VMK, so add/rotate/revoke
  never re-encrypts the body. Built (`-DVC_ENABLE_KEYSLOTS`, `make KEYSLOTS=1`):
  `Common/Keyslot.{c,h}` (record wrap/unwrap), `Common/KeyslotStore.{c,h}` (**all three backends** —
  in-header table, deniable bare-record placement, sidecar), `Common/KeyslotKdf.c` (in-tree
  `derive_key_sha512` binding). Verified: wrapping two ways (`verification/keyslot_poc.c`, step `[8]`,
  anchor `56434b53…`) and the full add/open/rotate/revoke + deniable + duress-flag lifecycle against
  the real modules (`verification/keyslot_store_test.c`, step `[9]`). The **`KeyslotArea` volume-I/O
  bindings are now built & verified** (`Common/KeyslotAreaFile.{c,h}`, step `[37]`): header-slack
  window `[512, 64K)` with the real header/hidden-header/data byte-untouched and cold-reopen
  persistence, whole-file sidecar, and the deniable free-extent binding clamped below a hidden-volume
  start — with the snapshot diff confined to one blending slot and the multi-snapshot location leak
  asserted as the documented limitation. AF records (`[36]`) compose through the bindings.
  **Remaining (real-build):** the C++ stream adapters for the mount path, mount-time slot search +
  duress-slot hook, the enroll/rotate/revoke CLI, backup-header-group mirroring of the slot table,
  and deniable-backend validation on real media (`docs/KEYSLOTS-SPEC.md §9`). `docs/KEYSLOTS-SPEC.md`.
- **Network-bound share source** (Tang/Clevis-style, McCallum–Relyea) — **exchange proven, AND now
  proven at production parameters (full Ed25519); network client + wire format remain.** A split-key
  share whose recovery needs a network server's participation, where the **server never sees the key**
  and a stolen off-network machine stays locked; composes as a Shamir share (no new derivation seam).
  The **MR exchange is proven** two ways in the toy field (provision `K=S^c`; blinded recover
  `X=C·g^e`, `Y=X^s`, `K=Y·(S^e)⁻¹`; anchor `cc288fab…`, step `[10]`), and the **production-parameter
  group is now proven** on the **full Ed25519 curve** (step `[39]`, `verification/netshare_ed25519_poc.c`):
  a from-scratch extended-coordinate group on the proven 256-bit bignum core, validated against the
  **official RFC 8032 §7.1 public-key KAT** AND diffed byte-for-byte vs independent Python for the
  whole MR flow (share anchor `ab8b717f…`; recover==provision, wrong-server-differs,
  server-sees-only-blinded-X). Remaining (real-build): the client transport, the `C`-blob wire
  format, the enroll/unlock CLI, and a constant-time group for shipping (the validation group is not
  side-channel-hardened). `docs/NETWORK-SHARE-SPEC.md`.
- **Write-only ORAM access-pattern hiding** *(the real mitigation for the multi-snapshot attack — the
  #1 documented limitation).* Every logical write touches K PRNG-chosen physical blocks with fresh
  ciphertext, independent of the logical target, so repeat-imaging cannot detect hidden-volume activity.
  **The access-pattern-hiding property is proven** two ways (public-only vs public+hidden workloads
  yield a byte-identical observable access trace; correctness reads==writes; real in-tree ChaCha20/Sha2
  vs. independent Python; anchor `203b068d…`, `verification/oram_poc.c` step `[13]`). The block-layer +
  position-map integration into the volume layout is a large real-build effort. `docs/ORAM-SPEC.md`.
- **Anti-forensic (AF) key splitting** (LUKS/TKS1) — **core proven AND keyslot-format integration
  built & proven (`[FORMAT]` done); real-flash validation remains.** The concrete answer to the
  SSD-remnant caveat: diffuse a keyslot's wrapped key across s stripes so recovery needs all of them
  and a partial wear-leveling remnant yields nothing. Core proven two ways (anchor `ddb23937…`,
  step `[15]`); the record integration is shipping code (`src/Common/AfSplit.{c,h}` +
  `KeyslotStore.c` `afStripes`: labeled v2 records with authenticated s, field-free bare records,
  byte-identical legacy when off) and proven two ways in step `[36]` (full record bytes vs.
  independent Python, bare-record anchor `76b60553…`; partial-remnant defeat at record level; AF +
  legacy coexistence). Remaining: the write/erase discipline on real flash. `docs/AF-SPLIT-SPEC.md`.
- **Decoy-fragments-by-default** (upstream issue #1072) — **indistinguishability core proven;
  write-into-volumes + SSD validation remain.** Write plausible hidden-volume creation artifacts on
  *every* volume so their presence proves nothing. A real hidden header (`salt || encrypted`) and a
  decoy fragment (`salt || keystream`) are the same uniform distribution, so a free-space scanner
  cannot tell a with-hidden volume from a decoy-only one. **Proven** two ways (identical layout; real
  and decoy batches pass the same integer byte-uniformity test; real in-tree ChaCha20 vs. independent
  Python, byte-for-byte; anchors `47067dd6…`/`a52a1326…`, `verification/decoyfrag_poc.c` step `[14]`).
  Strictly indistinguishable-random storage — not fabricated activity (stays on the right side of the
  DESCOPED line). Remaining (real-build): write the fragments at real hidden-volume offsets on every
  volume, and validate remnant behaviour on real SSDs. `docs/DECOY-FRAGMENTS-SPEC.md`.
- **Decoy content generator** (Phase 2 of the decoy) — prepare believable staged content with
  consistent metadata (filesystem vs in-file timestamps, coherent persona). Content helper only.
  *Caution:* on reflection this sits close to the DESCOPED evidence-fabrication line — keep it to
  indistinguishable-random storage artifacts, not a synthesized record of user activity.
  `docs/DECOY-VOLUME-SPEC.md §4`.

---

## BACKLOG — good ideas from the research, not started

The research-grade tracks below are surveyed with honest verifiability/effort/scope assessments in
**`docs/RESEARCH-NOTES.md`** (read that before starting one). (Write-only **ORAM** and
**decoy-fragments-by-default** have moved to DESIGN above — their core properties are now proven.) In
brief:

- **Mobile (Android/iOS).** VeraCrypt has none; academic PDE-for-mobile work shows flash-specific
  attacks. Very large; a platform port, not sandbox-verifiable.
- **UEFI/GPT hidden OS.** Upstream hidden-OS creation is MBR/legacy-BIOS only. Firmware/bootloader work;
  not sandbox-verifiable.
- **TPM / measured boot / Secure Boot signing.** Hardens evil-maid resistance beyond the bootloader
  fingerprint check, with a deniability/portability tradeoff. PCR-policy logic could be tested against a
  software TPM; real sealing needs hardware.

---

- **Balloon memory-hard KDF** (candidate alongside Argon2id, `IDEAS-BACKLOG.md` §C) — **algorithm
  proven AND wired as a selectable mountable PRF.** Provably memory-hard password hash built on the
  in-tree SHA-256 (expand/mix `delta=3`/extract). Core proven two ways (anchor `635ebeac…`, step
  `[16]`); now shipping gated `-DVC_ENABLE_BALLOON_KDF`: `BALLOON` PRF id, `derive_key_balloon` in
  `Common/Pkcs5.c` (heap buffer, abort fail-closed, dk ≤ 32 = the Balloon output, longer via
  counter expansion), PIM→(rounds, space-KiB) resolver with an explicit override mirroring the
  Argon2 params model, `Volumes.c` + thread-pool dispatch, and the `Pkcs5Balloon` C++ class
  (never shadowing `Pkcs5HmacSha256` in hash→KDF matching). Proven in step `[38]`: the real
  compiled `Pkcs5.c` TU vs. independent Python (which first re-derives the `[16]` anchor),
  REF-diffing dk32/dk64/dk192 + the resolver; benchmarked vs the real Argon2id (informational —
  ~0.4 s at 1 MiB/t=3 vs Argon2id's ~4.5 s at its 416 MiB default; hash-bound vs memory-bound,
  so equal-time comparisons must be done on target hardware before recommending either).
  Remaining (real-build): mount/create round-trip with `--hash Balloon` on a real volume.
  `docs/BALLOON-SPEC.md`.
- **OPRF password hardening** (2HashDH / CFRG DH-OPRF, `IDEAS-BACKLOG.md` §C) — **protocol proven,
  AND now proven at production parameters over the full ristretto255 group; server + threshold remain.**
  The derived key depends on the password AND a rate-limited server's secret; the server never sees the
  password or output, so a **seized disk cannot be brute-forced offline**. Proven two ways in the toy
  field (anchor `ca5691bd…`, step `[17]`), and the **production-parameter group is now proven** on the
  **full ristretto255 curve** (step `[43]`, `verification/oprf_ristretto_poc.c`): a from-scratch
  ristretto255 (RFC 9496 encode + Elligator2) + `expand_message_xmd(SHA-512)` on the step-`[39]` field,
  validated against the **official RFC 9496 §A.1 basepoint-multiples KAT** AND diffed byte-for-byte vs
  independent Python for `Blind`/`Evaluate`/`Finalize` (identity, blind-independence,
  wrong-key-differs). The **threshold OPRF/PPSS split is now also proven over ristretto255** (step
  `[44]`, `verification/toprf_ristretto_poc.c`): the server key Shamir-split over the scalar field
  `Z_L`, `t` partial evaluations combined by Lagrange-in-the-exponent to the byte-identical single-key
  output, `t-1` differ, servers oblivious; diffed byte-for-byte vs Python (3-of-5). Remaining
  (real-build): a constant-time group (the validation group is not side-channel-hardened), the
  rate-limited servers + transport, and RFC 9497 e2e vectors. `docs/OPRF-SPEC.md`.

---

## DECIDED — advisory conclusions (no code, keep for reference)

- **Cipher choice.** At a 256-bit key, brute force is moot. AES-256 is the most-analyzed;
  Serpent-256 has the largest security margin; a cascade (**AES–Twofish–Serpent**) is the maximum
  hedge. A 5-cipher cascade adds ~nothing over 3. The cipher is never the weak link — password
  entropy is, which is why the hardware factor / split-key work matters.
- **Post-quantum.** VeraCrypt's password-derived *symmetric* disk encryption is already effectively
  post-quantum: there is no key exchange for Shor to break and no ciphertext-in-transit to harvest;
  Grover only halves an already-256-bit key. PQ KEM/signatures (Kyber/Dilithium) add attack surface,
  not security, for this use case. Heavily requested upstream (issue #1406, third-party PQ-VeraCrypt
  fork) but low real value here.

---

## DESCOPED — deliberately not built

- **Automated "keep-warm" decoy staging daemon.** A background process that forges activity
  timestamps and injects synthetic usage history so a decoy survives forensic examination. This is
  *evidence fabrication* — categorically different from confidentiality/access control, and most
  useful against exactly the legitimate investigative processes the sympathetic threat model is not
  about. Not built, not specified. The honest way to keep a decoy believable is to actually use it
  (as upstream guidance recommends); the sound research direction for believability against a capable
  adversary is the ORAM access-pattern hiding above. See `docs/DECOY-VOLUME-SPEC.md §6` and
  `CLAUDE.md`. **A future session should maintain this boundary.**

---

## Known limitations / honest threat model

See `docs/THREAT-MODEL.md`. In brief: hidden-volume deniability is weak against a **multi-snapshot**
(repeat-imaging) adversary and on **SSDs** (TRIM + wear-leveling); an adversary who **images first**
is unaffected by any post-hoc measure; for the split-key factor, **share distribution** is the real
risk surface, not the math; and the **real-hardware USB round-trip** for YubiKey/FIDO2 is the one
thing not testable in a sandbox — validate it on a physical device.
