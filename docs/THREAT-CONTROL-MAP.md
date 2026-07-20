# Threat → control → verification map, and the public API surface

Audit-preparation artifact (`IDEAS-BACKLOG.md` §"Audit preparation"). It gives an external reviewer
three things in one place: (1) which control answers each threat, (2) where that control is proven,
and (3) the residual limit that survives it. It is a *map*, not a promise — the honest limits in
`docs/THREAT-MODEL.md` are authoritative and repeated here per row. Verification step numbers `[n]`
refer to `verification/build_and_verify.sh`; anchors and file paths are in `docs/SESSION-SUMMARY.md`.

## 1. Threats this fork addresses

| Threat | Control | Gate | Verified | Residual limit (honest) |
|---|---|---|---|---|
| Offline brute-force of a seized disk (password-only) | Extra factor mixed into the password before PBKDF2/Argon2 (keyfile-pool method, no header change) — YubiKey / FIDO2 / threshold / raw secret | `VC_ENABLE_HKF` (+backend) | `[1]`–`[3]` mixing + CLI; cross-platform byte-identical; wrong factor flips 64/64 header-key bytes | Real YubiKey/FIDO2 USB round-trip needs a physical token (fails safe with none) |
| Password leaked/guessed alone | Factor is *required in addition*; the derived header key depends on both | `VC_ENABLE_HKF` | `[2]` (wrong/absent factor ⇒ different key) | Same token-round-trip caveat |
| Online-guess / rate-limit evasion of the password | OPRF password hardening (server secret + password; server never sees either) — incl. **production ristretto255**, **threshold/PPSS**, **verifiable (DLEQ)** | (PoC / real-build) | `[17]` toy, `[43]` ristretto255 (RFC 9496 KAT), `[44]` threshold, `[47]` VOPRF | Needs a live rate-limited server + transport; validation group not constant-time |
| Coercion — give up *something* | Factor-gated decoy: outer volume opens on the password; the real one still needs the factor | `VC_ENABLE_HKF` (`HKF_APPLY_HIDDEN_ONLY`) | `[14]` decoy gating; hidden header vs decoy fragment indistinguishable-random | Multi-snapshot / SSD caveats below still apply to the hidden volume |
| Coercion — no single person can open | Shamir M-of-N threshold / split-key factor; withholding a share = inaccessible-not-destroyed (safe dead-man) | `VC_ENABLE_HKF` (raw secret) | `[5]` GF(2⁸) KATs + threshold; `[45]` 44.8k fuzz invariants | "Where the shares live is the real security" — N shares in one drawer = 1-of-1 |
| Coercion — panic / duress passphrase | Safe duress-dismount: dismount all + scrub RAM, mount nothing; salted-HMAC duress-passphrase recognition, no header change | `VC_ENABLE_DURESS` | `[7]` duress token vs Python + const-time match | wx orchestration + end-to-end not sandbox-testable; the stored (salt,tag) reveals a duress scheme exists |
| Tampered/fabricated recovery share (adversarial) | Keyed per-share MAC (HMAC-SHA256) — flip/truncate/relabel/fabricate all rejected | `VC_ENABLE_SHAMIR_MAC` | `[40]` tags vs Python; `[45]` fuzz | Authenticates shares, not dealer consistency (that is prime-field VSS, `[31]`/`[32]`) |
| Cheating *dealer* (inconsistent shares) | Feldman / Pedersen VSS (prime-order group) | (PoC) | `[31]` Feldman, `[32]` Pedersen | Prime-field scheme; no GF(2⁸) analogue — a parallel sharing, not a byte-wise add-on |
| Transcription error in a hand-copied share | bech32/BIP-173 checksummed share encoding — ≤4 substitution errors detected (≤90 chars) | `VC_ENABLE_SHARECODE` | `[42]` BIP-173 anchor + every 1-char typo caught; `[45]` fuzz | Formal bound only ≤90 chars; longer shares detect most but not all |
| Network-bound unlock (stolen off-network machine stays locked) | McCallum–Relyea share source; server never sees the key — proven at **production Ed25519** | (PoC / real-build) | `[10]` toy, `[39]` full Ed25519 (RFC 8032 §7.1 KAT) | Needs the client transport + server; validation group not constant-time |
| RAM key exposure (cold-boot / DMA), user-space | Cross-platform memory-scrub: ChaCha-at-rest for user-space secrets, erased on unmount/idle/lock/new-device | `VC_ENABLE_KEYSCRUB` | `[6]` wipe/registry/round-trip vs Python (anchor `d28b461b…`) | **Mounted master key is kernel-resident (dm-crypt) — out of user-space reach**; lock/new-device triggers not sandbox-testable |
| Downgrade of KDF/cipher parameters | Anti-downgrade parameter binding (header version + bound params) | (PoC) | `[23]` reject silent parameter downgrade | Format integration is real-build |
| SSD remnant of an "overwritten" keyslot | Anti-forensic (AF) key splitting — a *partial* remnant is worthless | `VC_ENABLE_KEYSLOTS` (`afStripes`) | `[15]` split/merge, `[36]` keyslot-record integration | Does not control where the FTL writes; real-flash erase discipline is real-build |
| Hidden-volume artifact presence on flash | Decoy-fragments-by-default — presence is uninformative (indistinguishable-random) | (PoC) | `[14]` indistinguishability | Write-into-volume + real-SSD validation real-build |
| Key material integrity of the keyslot table | Encrypt-then-MAC per slot; MAC-as-selector fails closed; area MAC | `VC_ENABLE_KEYSLOTS` | `[8]` wrap/unwrap, `[9]`/`[45]` lifecycle, `[20]` area MAC | — |
| Side channel in the split-key / keyslot primitives | Branchless table-free GF(2⁸); constant-time tag compare — timing-screened | (always / `VC_ENABLE_KEYSLOTS`) | `[41]` Shamir dudect, `[46]` keyslot dudect (both self-validating) | A screen is evidence, not a proof of constant-timeness |

## 2. Threats explicitly NOT addressed (from `docs/THREAT-MODEL.md`)

- **Multi-snapshot / repeat imaging** — detects a hidden volume from block-change patterns; affects
  essentially all hidden-volume systems. Real mitigation is write-only ORAM (`[13]` core proven,
  block-layer integration is a large real-build effort).
- **Imaged-first** — a copy taken before coercion is untouchable by any measure on your machine.
- **Mounted master key in the kernel** — dm-crypt holds it; user-space scrub cannot reach it.
- **Evil maid / firmware below the bootloader** — measured boot / Secure Boot is backlog.
- **Operational: where the shares/decoy live** — discovery of a decoy scheme, or shares held together,
  defeats the math.

## 3. Public API surface (stable, gated entry points)

Every addition is behind an `#if defined(VC_ENABLE_*)` gate; a build with no flags is byte-for-byte
stock (each new module compiles to **0 exported symbols** without its gate — checked in the harness).

| Module | Gate | Public entry points |
|---|---|---|
| `Common/HardwareKeyFactor.{c,h}` | `VC_ENABLE_HKF*` | `HKFComputeResponse`, `HKFMixResponseIntoPassword`, `HKFApplyIfConfigured`, `HKFShouldApply`, `HKFSetActiveConfig`, `HKFScrubActiveConfig` |
| `Common/Shamir.{c,h}` | (ungated core) | `shamir_split`, `shamir_combine`, `shamir_secret_checksum` |
| `Common/ShamirMac.{c,h}` | `VC_ENABLE_SHAMIR_MAC` | `ShamirShareMac`, `ShamirShareVerify`, `ShamirMacAll`, `ShamirVerifyAll` |
| `Common/ShareCode.{c,h}` | `VC_ENABLE_SHARECODE` | `ShareCodeEncode`, `ShareCodeDecode` |
| `Common/Keyslot.{c,h}` | `VC_ENABLE_KEYSLOTS` | `KeyslotWrapWithDK`, `KeyslotUnwrapWithDK`, `KeyslotUnwrapCT`, `KeyslotWrap`, `KeyslotUnwrap`, `KeyslotConstTimeEqual` |
| `Common/KeyslotStore.{c,h}` | `VC_ENABLE_KEYSLOTS` | `KeyslotAdd`, `KeyslotOpen`, `KeyslotRevoke`, `KeyslotCount` (+ `KeyslotStoreCfg`, `KeyslotArea`) |
| `Common/KeyslotAreaFile.{c,h}` | `VC_ENABLE_KEYSLOTS` | `KeyslotAreaFileOpen/Close`, `KeyslotAreaBindHeaderSlack/Sidecar/Deniable/Window` |
| `Common/AfSplit.{c,h}` | `VC_ENABLE_KEYSLOTS` | `AfSplit`, `AfMerge` |
| `Common/KeyScrub.{c,h}` | `VC_ENABLE_KEYSCRUB` | `VcSecureWipe`, `VcScrubAll`, `VcScrubUnregister`, `VcKeyMemoryLockdown`, `VcKsRamProtectInit`, `VcKsRamTransform`, `VcKsRamUnprotect` |
| `Common/DuressToken.{c,h}` | `VC_ENABLE_DURESS` | `DuressTokenDerive`, `DuressTokenMatch`, `DuressTokenCheck` |
| `Common/Pkcs5.c` (Balloon) | `VC_ENABLE_BALLOON_KDF` | `derive_key_balloon`, `BalloonSetParamsOverride`, `BalloonGetResolvedParams` (+ `BALLOON` PRF id, `Pkcs5Balloon`) |
| `Common/Pkcs5.c` (Argon2 params) | `VC_ENABLE_ARGON2_PARAMS` | `Argon2SetParamsOverride`, `Argon2GetResolvedParams`, `Argon2GetParallelism` |

## 4. How to reproduce every claim

`cd verification && ./build_and_verify.sh` runs steps `[1]`–`[48]`. Each step either (a) diffs the real
compiled VeraCrypt/module objects against an independent Python reference byte-for-byte, (b) checks an
official KAT (RFC 8032/9496, FIPS 203, BIP-173, NIST/Google vectors), or (c) asserts behavioural
invariants / a self-validating timing contrast. `docs/SESSION-SUMMARY.md` is the index of anchors and
spec files; per-feature detail is in the `docs/*-SPEC.md` files referenced above.

## 5. Convention (so the map stays true)

- Every crypto change is proven **two ways** (independent Python + real compiled objects) before it is
  considered done; hardware backends additionally compile/link against the real libraries and fail safe.
- The on-disk header format is **never** changed; factors mix into the password pool instead.
- Docs state the multi-snapshot / SSD / imaged-first / share-distribution limits rather than overselling.
- "Real-build" in the tables above means: needs a full VeraCrypt build (wx / device I/O / a server /
  physical hardware) and so is scoped, not sandbox-verified — call it out, never imply otherwise.
