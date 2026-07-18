# CLAUDE.md — context for continuing this project

This repo is a **private fork of VeraCrypt 1.26.29** that hardens the *key-derivation* path with
optional hardware/threshold factors and a factor-gated decoy. It is defensive disk-encryption work:
strengthening password entropy (the real weak link), not the cipher.

## Scope & boundary (read first)

Everything here is **access-control cryptography** — protecting data the user holds. That is in
scope. **One thing is deliberately out of scope and must stay out:** an automated tool that
*fabricates a false record of computer activity* (forged timestamps, synthetic browser/history
artifacts) to deceive a forensic examiner. That is evidence fabrication, not confidentiality, and it
was declined on purpose (see `ROADMAP.md` → DESCOPED and `docs/DECOY-VOLUME-SPEC.md §6`). Keep the
line where it is: build confidentiality/deniability *storage* and access control; do not build
tooling whose function is to manufacture fake evidence. Everything the users actually want
(coercion resistance, split trust, safe dead-man) is achievable with the threshold/split-key design
already here — no fabrication required.

## Architecture: the one seam everything hangs off

VeraCrypt derives a header key as `PBKDF2/Argon2(password, salt)` and encrypts the volume under keys
stored (encrypted) in the header. **All of this project's factors work by mixing an extra secret into
the password *before* PBKDF2**, using VeraCrypt's exact keyfile pool method (rolling CRC-32 into a
128-byte pool, then `password[i] += pool[i]`). Consequence: **no header-format change** — a factored
volume behaves like one with a dynamically-computed keyfile.

There are **two derivation code paths**, and both are hooked:
- **C path** — `src/Common/Volumes.c` (`ReadVolumeHeader` mount, and the format path). Used by the
  **Windows driver** and shared code.
- **C++ path** — `src/Volume/VolumeHeader.cpp::Decrypt` (mount) and `src/Core/VolumeCreator.cpp`
  (create). Used by the **Linux/macOS application** (the CLI and GUI). *This is the one that runs on
  Linux — C-path hooks alone do not fire there.*

The mixing math is identical across both, so keys are **byte-identical cross-platform** (proven).

## Module map (the new/changed files)

```
src/Common/HardwareKeyFactor.{c,h}   the factor module: backends + mixing + gating
   backends: YK_HMAC_SHA1 (libykpers), FIDO2_HMAC_SECRET (libfido2), SIMULATOR, RAW_SECRET
   HKFComputeResponse()  -> response from (challenge=salt); HKFMixResponseIntoPassword() -> pool mix
   HKFApplyIfConfigured() -> compute+mix in one call (used at the derivation sites)
   HKFShouldApply(cfg, isHidden) -> factor-gating decision (HKF_APPLY_ALL / HKF_APPLY_HIDDEN_ONLY)
   g_hkfActiveConfig / HKFSetActiveConfig() -> process-wide active config (set by CLI before op)
src/Common/Shamir.{c,h}              Shamir M-of-N over GF(2^8); shamir_split/shamir_combine
src/Volume/HardwareKeyFactorMix.h    C++ glue: HKFMixPassword(VolumePassword, salt) for Volume/Core
src/Main/HardwareKeyFactorCli.h      wx-free option-string -> HKFConfig parser (BuildHKFConfig)
src/Crypto/Sha3.{c,h}                from-scratch FIPS-202 (for the SHA3-512 PRF)
src/Common/KeyScrub.{c,h}            cross-platform RAM key hygiene (gated -DVC_ENABLE_KEYSCRUB)
   VcSecureWipe() -> barrier-hardened zeroize; scrub registry -> VcScrubAll() erases all live secrets
   VcKsRamTransform()/VcKsRamProtect() -> ChaCha-at-rest for secrets (mirrors Common/Crypto.c VcProtectMemory)
   HKFScrubActiveConfig() (in HardwareKeyFactor.c) -> wipe+detach the active factor secret
src/Core/KeyScrubEvents.{h,cpp}      C++ event manager: scrub on unmount/idle/screen-lock/new-device
src/Common/DuressToken.{c,h}         duress-passphrase recognition (gated -DVC_ENABLE_DURESS)
   DuressTokenDerive() -> HMAC-SHA256(salt,passphrase) over in-tree Sha2; DuressTokenMatch() const-time
   used by UserInterface::DuressDismount (Main) = dismount all + KeyScrub ScrubNow(), mount nothing
src/Common/Keyslot.{c,h}             per-slot VMK wrap/unwrap (gated -DVC_ENABLE_KEYSLOTS; fork-only)
   KeyslotWrapWithDK/UnwrapWithDK -> KDF(pluggable)->ChaCha20 wrap + HMAC-SHA256 selector; proven [8]
src/Common/KeyslotStore.{c,h}        3 backends over a KeyslotArea (KSB_HEADER/SIDECAR labeled table,
   KSB_DENIABLE bare records at a passphrase-derived slot); KeyslotAdd/Open/Revoke/Count; lifecycle [9]
src/Common/KeyslotKdf.c              shipping KeyslotKdfSha512 = in-tree derive_key_sha512 (PBKDF2-512)
```
Keyslots model: one master key (VMK), many independent wrappings. Slot 0 = untouched native header;
slots 1..N wrap the same VMK, so add/rotate/revoke never re-encrypts the body. Payload = flags[1]||vmk
(duress bit encrypted). CLI + mount-time slot search remain (docs/KEYSLOTS-SPEC.md §9).

src/Common/Pkcs5.c (gated -DVC_ENABLE_ARGON2_PARAMS) — explicit Argon2id memory/iterations/parallelism
   Argon2SetParamsOverride()/Argon2GetResolvedParams()/Argon2GetParallelism(); CLI --argon2-memory/
   -iterations/-parallelism. Not stored (supplied like PIM at create+mount). docs/ARGON2-PARAMS-SPEC.md

Config: `HKFConfig` (in `HardwareKeyFactor.h`) carries the backend, YubiKey slot, FIDO2 rp/credid/pin,
simulator secret, `rawSecret` (Shamir reconstruction), and `applyPolicy`.

## Build (Linux)

```sh
sudo apt-get update && sudo apt-get install -y libykpers-1-dev libfido2-dev libwxgtk3.2-dev
# feature flags (opt-in; a build with none is behaviourally stock):
#   -DVC_ENABLE_HKF            derivation hooks + CLI options
#   -DVC_ENABLE_YUBIKEY_HMAC   YubiKey backend   (link -lykpers-1)
#   -DVC_ENABLE_FIDO2          FIDO2 backend     (link -lfido2)
#   -DVC_ENABLE_HKF_SIMULATOR  software token    (testing only — never ship)
cd src && make   # add the flags via CFLAGS/CXXFLAGS/LIBS (see docs/HARDWARE-2FA.md §Build)
```
Add `Common/HardwareKeyFactor.c` and `Common/Shamir.c` to the Common object list (next to
`Keyfiles.o`) and set the defines + `-lykpers-1 -lfido2`. Windows: add to `Common.vcxproj`.

## Verification methodology (the project's convention — keep it)

**Every crypto change is proven two ways before it's considered done:**
1. byte-for-byte against an **independent Python reimplementation** of the same math, and
2. against **real compiled VeraCrypt objects** (e.g. the actual `derive_key_sha3_512` /
   `Pkcs5HmacSha3_512`), so the integration — not just the algorithm — is exercised.
Real hardware backends are additionally **compiled and linked against the real libraries**
(`-lykpers-1 -lfido2`) and shown to fail safe with no device.

Self-contained checks (no VeraCrypt build needed):
```sh
cd verification && ./build_and_verify.sh
```
covers: HMAC-SHA1 (RFC 2202), FIDO2-profile HMAC-SHA256, keyfile-pool mixing, CLI parsing, the
factor-gated decoy property, and Shamir (GF(2⁸) KATs + threshold + Python cross-check). Harnesses that
need compiled VeraCrypt objects (`htest.c`, `hkf_cpp.cpp`, `hkf_decoy.cpp`, `shamir_chain.c`,
`verification/prf/*`) are included for reference; their expected results are in the docs.

Key proven values (regression anchors): mixed password `f965c9e3…`; SHA3-512 header key `628882be…`;
Shamir 3-of-5 header key `a8b0cbb7…`; wrong secret / below-threshold flips 64/64 header-key bytes.

## Conventions

- Gate all additions behind `#if defined(VC_ENABLE_HKF*)` so the default build is byte-for-byte stock.
- Never change the on-disk header format; mix into the password pool instead.
- Keep docs honest: state the multi-snapshot / SSD / imaged-first / share-distribution limitations
  rather than overselling deniability (`docs/THREAT-MODEL.md`).
- Match VeraCrypt's existing style in each file; C for `Common/Crypto`, C++ for `Volume/Core/Main`.

## Good next tasks (see ROADMAP.md)

1. **Multiple keyslots — finish the integration** (`docs/KEYSLOTS-SPEC.md §9`). The core is built &
   verified (`Common/Keyslot*.{c,h}`, `KeyslotKdf.c`; steps `[8]`/`[9]`). Remaining, real-build only:
   the `KeyslotArea` volume-I/O bindings per backend, the mount-time slot search + duress-slot hook,
   the enroll/open/rotate/revoke/list CLI, and multi-snapshot validation of the deniable backend.
2. **Network-bound share source — finish the integration** (`docs/NETWORK-SHARE-SPEC.md`). The
   McCallum–Relyea exchange is proven (step `[10]`). Remaining, real-build only: EC/bignum at
   production parameters (P-256/Ed25519 or 2048-bit MODP), the client transport, and enroll/unlock CLI.
3. **End-to-end validate the explicit Argon2id params on a real build** (create with
   `--argon2-memory/-iterations/-parallelism` → mount with the same → opens; mount without → fails).
   The crypto is proven (step `[11]`); the create/mount round-trip is not sandbox-testable.
3. **Validate the KeyScrub OS triggers on real hardware** (logind screen-lock, udev device-connect)
   and, separately, the kernel-side dm-crypt master-key scrub the user-space scrub can't reach.
4. **End-to-end duress-dismount test on a real build** (mounted volumes → `--duress-dismount` and the
   duress passphrase → everything dismounts + scrubs); the crypto core is proven, the wx orchestration
   is not sandbox-testable.
```
```
