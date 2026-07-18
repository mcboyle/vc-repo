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
  the real modules (`verification/keyslot_store_test.c`, step `[9]`). **Remaining (real-build):** the
  `KeyslotArea` volume-I/O bindings, mount-time slot search + duress-slot hook, and the enroll/rotate/
  revoke CLI (`docs/KEYSLOTS-SPEC.md §9`); the deniable backend needs multi-snapshot validation on real
  media. `docs/KEYSLOTS-SPEC.md`.
- **Network-bound share source** (Tang/Clevis-style, McCallum–Relyea) — **exchange proven; network
  client + real curve/wire format remain.** A split-key share whose recovery needs a network server's
  participation, where the **server never sees the key** and a stolen off-network machine stays locked;
  composes as a Shamir share (no new derivation seam). The **MR exchange is proven** two ways
  (provision `K=S^c`; blinded recover `X=C·g^e`, `Y=X^s`, `K=Y·(S^e)⁻¹`): recovered `K` == provisioned
  `K`, the server sees only the blinded `X` (a different ephemeral recovers the same `K`), and a wrong
  server key fails — real `Sha2.c` share vs. independent Python bigint, anchor `cc288fab…`,
  `verification/netshare_poc.c` step `[10]`. Remaining (real-build): EC/bignum at production
  parameters, the client transport, and the enroll/unlock CLI. `docs/NETWORK-SHARE-SPEC.md`.
- **Write-only ORAM access-pattern hiding** *(the real mitigation for the multi-snapshot attack — the
  #1 documented limitation).* Every logical write touches K PRNG-chosen physical blocks with fresh
  ciphertext, independent of the logical target, so repeat-imaging cannot detect hidden-volume activity.
  **The access-pattern-hiding property is proven** two ways (public-only vs public+hidden workloads
  yield a byte-identical observable access trace; correctness reads==writes; real in-tree ChaCha20/Sha2
  vs. independent Python; anchor `203b068d…`, `verification/oram_poc.c` step `[13]`). The block-layer +
  position-map integration into the volume layout is a large real-build effort. `docs/ORAM-SPEC.md`.
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
