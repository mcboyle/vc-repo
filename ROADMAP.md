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

---

## DESIGN — specced, not yet built

- **Multiple independent keyslots** (like LUKS2's 8+). *(The enabling primitive for per-person keys,
  rotation, revocation, and a real duress keyslot — the one deliberately fork-only on-disk format.)*
  One master key, many independent wrappings: slot 0 is the untouched native header, slots 1..N wrap
  the same VMK under their own passphrase/factor, so add/rotate/revoke never re-encrypts the body.
  **All three storage backends** behind one seam: in-header table (visible, in the 63.5 KiB header
  slack), deniable free-space slots (presence deniable; inherits hidden-volume limits), and a sidecar
  file (volume untouched; sidecar is a tell). The **per-slot wrapping crypto is proven** two ways
  (PBKDF2→ChaCha20 wrap + HMAC auth; round-trip + wrong-passphrase rejection; real Sha2/chacha objects
  vs. independent Python; anchor `56434b53…`, `verification/keyslot_poc.c` step `[8]`). Storage
  backends + mount/CLI integration remain to build. `docs/KEYSLOTS-SPEC.md`.
- **Decoy content generator** (Phase 2 of the decoy) — prepare believable staged content with
  consistent metadata (filesystem vs in-file timestamps, coherent persona). Content helper only.
  `docs/DECOY-VOLUME-SPEC.md §4`.
- **Salt-binding for RAW_SECRET** — optionally return `HMAC(secret, salt)` instead of the raw secret,
  binding a reconstructed/threshold secret to the specific volume salt.

---

## BACKLOG — good ideas from the research, not started

- **Network-bound unlock** (Tang/Clevis-style, McCallum–Relyea). Bind a share/key to a network
  server's presence; a stolen or off-network machine stays locked; the server never sees the key.
  Composes cleanly as a **Shamir share source** (fits the split-key factor already built).
- **Argon2id multi-parameter UI.** Argon2id shipped upstream (1.26.29) but its memory/time/
  parallelism are shoehorned into the single PIM value. Expose them as explicit inputs with sane
  high-risk defaults. In the same KDF seam this project already works in.
- **TPM / measured boot / Secure Boot signing.** VeraCrypt deliberately omits the TPM; measured boot
  and first-class bootloader signing would harden evil-maid resistance beyond the existing bootloader
  fingerprint check. (The DCS/EFI bootloader has experimental TPM support.)
- **ORAM access-pattern hiding** (write-only ORAM: HIVE, DataLair). The real mitigation for the
  multi-snapshot deniability attack — hides which blocks the hidden volume touches.
- **Decoy-fragments-by-default** (upstream issue #1072). Write fake hidden-volume/creation artifacts
  on *every* volume so their presence on an SSD (via wear-leveling remnants) proves nothing. Partial
  SSD-deniability hardening.
- **Mobile (Android/iOS).** VeraCrypt has none. Academic PDE-for-mobile work (MobiGyges, Mobiflage,
  MobiPluto) shows demand and flash-specific attacks (capacity-comparison, fill-to-full).
- **UEFI/GPT hidden OS.** Upstream hidden-OS creation is MBR/legacy-BIOS only.

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
