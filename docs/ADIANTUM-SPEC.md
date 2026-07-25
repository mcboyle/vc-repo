# Adiantum — wide-block mode (sector-atomic encryption)

**Status: full construction proven against the official published vectors AND promoted to a shippable
module `src/Crypto/Adiantum.{c,h}` (steps `[90]`/`[91]`, gated `-DVC_ENABLE_ADIANTUM` / `make ADIANTUM=1`);
the XTS-replacement `EncryptionMode` wiring is `[FORMAT]`/real-build.** Addresses `IDEAS-BACKLOG.md` §B —
the backlog calls wide-block modes "the single strongest *cryptographic* upgrade available to a disk
encryptor."

## The gap it closes

XTS is malleable at 16-byte granularity: an attacker who flips one ciphertext bit corrupts exactly one
16-byte plaintext block, predictably, with the rest of the sector intact — the foundation of targeted
data-tampering attacks that no confidentiality argument prevents. A **wide-block tweakable
super-pseudorandom permutation** makes the *whole sector* one block: flipping any single ciphertext bit
randomizes the entire sector on decryption (and vice versa). Tampering stops being surgical and becomes
obvious destruction. Combined with the integrity tier (steps `[18]`–`[23]`) this closes both halves of
the malleability story: Adiantum destroys the attacker's precision, the MACs detect the attempt.

**Adiantum** (Crowley & Biggers, ToSC 2018; used in Android storage encryption) is the chosen instance:
`XChaCha12 + AES-256 + NH + Poly1305` in an HBSH (hash–block–stream–hash) construction. It was picked
because the fork already had two of its three primitives proven — ChaCha (in-tree) and Poly1305 (step
`[18]`) — and it is length-preserving (a 4096-byte sector encrypts to exactly 4096 bytes: **no format
change for the data area itself**; only the mode selection is new).

## Construction (Adiantum_XChaCha12_32_AES256)

```
Key schedule: ks = XChaCha12(K, nonce = 0x01 || 0^23) keystream, 1136 bytes:
              K_E = AES-256 key | rt, rm = Poly1305 hash keys | K_N = NH key (1072 B)
Hash:         H(T, L) = Poly1305_rbar(rt, le128(8|L|) || T) + Poly1305_rbar(rm, NH-chunks(L))  mod 2^128
Encrypt:      PL, PR = P[:-16], P[-16:]
              PM = PR + H(T, PL)                (mod 2^128)
              CM = AES256_Enc(K_E, PM)          (the single block-cipher call)
              CL = PL xor XChaCha12(K, CM || 0x01 || 0^7)
              CR = CM - H(T, CL)                (mod 2^128)
              C  = CL || CR
```

NH is the UMAC-family almost-universal hash (u32 pairs multiplied into u64 sums, 4 passes, 1024-byte
chunks); its outputs feed Poly1305, so hashing a 4096-byte sector costs mostly cheap integer multiplies.
The security reduction is in the paper: HBSH is a tweakable SPRP if the stream cipher and block cipher
are secure and the hash is ε-almost-∆-universal.

## What the PoC proves (`verification/adiantum_poc.c` + `adiantum_reference.py`, step `[24]`)

Three-way agreement, which is stronger than the fork's usual two:

1. **The official published vectors** (`verification/adiantum_kats.{h,py}` — 18 vectors extracted from
   google/adiantum, MIT, one per message-length × tweak-length combination over 16/31/128/512/1536/4096
   bytes × 0/17/32-byte tweaks). Both implementations reproduce **all 18 ciphertexts exactly** and
   decrypt them back (`kat_all_match`, `roundtrip_all`). Anchor: 16-byte-message vector ciphertext
   `820ae444…`.
2. **Real in-tree objects**: the C PoC's ChaCha keystream is entirely the real `Crypto/chacha256.c`, its
   AES-256 the real `Aescrypt/Aeskey/Aestab.c` (FIPS-197 KAT `8ea2b7ca…` asserted), its Poly1305 the
   step-`[18]` implementation. Only HChaCha12 and NH are PoC-local (the in-tree ChaCha does not export
   the keyless permutation; stated in the file header — their correctness is forced transitively by the
   official vectors).
3. **Independent Python** (`adiantum_reference.py`, stdlib-only, own AES): byte-identical `^REF` output.

Property checks on the 4096-byte vector, asserted identically on both sides: **single-bit plaintext flip
→ ≥40% of all ciphertext bits change** including both ends of the sector (`enc_diffusion`); single-bit
ciphertext flip → whole-sector randomized plaintext (`dec_diffusion`); wrong key and wrong tweak each
change the output.

## Shippable module (`src/Crypto/Adiantum.{c,h}`, steps `[90]`/`[91]`, T2-4c/d)

The mode is now a shippable C module (gated `-DVC_ENABLE_ADIANTUM` / `make ADIANTUM=1`; default builds
are byte-for-byte stock), so the remaining `EncryptionMode` wrapper is a thin real-build-only shim over
proven code rather than new crypto:

- **`src/Crypto/Adiantum.c`** — `AdiantumInit` / `AdiantumEncrypt` / `AdiantumDecrypt`, transcribed
  byte-for-byte from the PoC math that reproduces every official vector. The three block primitives are
  the **real in-tree objects**: the AES-256 block runs through the constant-time `src/Crypto/AesCt`
  (VC_ENABLE_CTAES — one block per sector, so a table-free AES is affordable and closes the cache-timing
  leak, `docs/CT-AES-SPEC.md`); the bulk XChaCha12 stream through `src/Crypto/chacha256`; the polynomial
  hash through the new `src/Crypto/Poly1305`. HChaCha12, NH and the 128-bit add/sub stay local (the
  in-tree ChaCha does not export the keyless permutation), exactly as in the proven PoC. `AdiantumEncrypt`/
  `AdiantumDecrypt` bound-check `len ∈ [16, ADIANTUM_MAX_SECTOR]` and `tlen ≤ ADIANTUM_MAX_TWEAK`, support
  `in == out` aliasing, and return 0 (output untouched) on a bounds violation.
- **`src/Crypto/Poly1305.{c,h}`** (gated `-DVC_ENABLE_POLY1305` / `make POLY1305=1`, pulled in by
  `ADIANTUM=1`) — the shippable form of the step-`[18]` RFC 8439 PoC, used as the ε-almost-Δ-universal
  hash's polynomial term (called with key `r‖0^16` so the trailing `+s` vanishes and the output is the
  hash mod 2^128).

Proven the fork's two ways by **linking the real objects**:

- **Step `[90]`** (`verification/poly1305_module_test.c`): the real `Poly1305.o` reproduces the published
  RFC 8439 §2.5.2 (`a8061dc1…`) and A.3 #1/#2 vectors and agrees byte-for-byte with the independent
  `verification/poly1305.h` reference over 4096 random key/length inputs.
- **Step `[91]`** (`verification/adiantum_module_test.c`): the real `Adiantum.o` — linked against the real
  `AesCt.o` + `chacha256.o` + `Poly1305.o` — reproduces **every official google/adiantum vector** both
  directions (`kat_all_match`, `roundtrip_all`), cross-checked line-for-line against `adiantum_reference.py`,
  plus whole-sector diffusion, wrong-key/wrong-tweak separation, `in==out` aliasing, and the bounds guard.

Make knobs: `POLY1305=1` links `Crypto/Poly1305.o`; `ADIANTUM=1` links `Crypto/Adiantum.o` and implies
`CTAES=1` + `POLY1305=1` (top-level `Makefile` + `Core/Core.make`). Remaining T2-4: the C++
`EncryptionModeAdiantum` that calls `AdiantumEncrypt`/`AdiantumDecrypt` per sector and selects Adiantum on
non-AES-NI hardware (real-build only), which then unblocks the T1-1 v2 mount/create call sites.

## Integration & honest notes

- **Where it plugs in.** VeraCrypt's cipher-mode seam is `EncryptBufferXTS`/`DecryptBufferXTS`
  (`Common/Crypto.c`, `Volume/EncryptionModeXTS.cpp`). An `EncryptionModeAdiantum` alongside XTS is a
  mode addition — volumes must record the mode, which rides the anti-downgrade parameter binding
  (step `[23]`) so mode choice cannot be silently rolled back. New volumes only; converting existing
  volumes means re-encrypting the body.
- **Tweak discipline.** The per-sector tweak is the sector index (as XTS already uses); Adiantum accepts
  arbitrary tweak lengths, proven here at 0/17/32 bytes.
- **Performance.** Adiantum was designed for CPUs *without* AES acceleration (one AES call per sector,
  everything else ChaCha/NH). On AES-NI hardware, HCTR2 (same authors) is the faster sibling — the
  backlog keeps it listed; this PoC's NH/Poly1305/stream scaffolding is reusable for it.
- **Not authenticated.** A wide-block mode randomizes tampering but does not *detect* it — pair with the
  per-sector MAC (step `[21]`) or Merkle tree (step `[19]`) when detection is required.
- **PoC is not constant-time-audited.** The reference limb code and table-based in-tree AES are fine for
  verification; a shipping mode should use the vetted kernel/BoringSSL implementations. Stated per the
  fork's honesty convention.
- **Scope.** A stronger confidentiality mode for the user's own storage — squarely inside the project's
  access-control boundary.

## The `EncryptionMode` shim — BUILT (2026-07-25, step `[103]`)

`src/Volume/EncryptionModeAdiantum.{h,cpp}`, gated `-DVC_ENABLE_ADIANTUM_MODE` (`make ADIANTUM_MODE=1`).
This is the class whose absence made `V2FormatBinding.h` record itself as *"BLOCKED ON the wide-block
cipher mode classes"*: the algorithm was proven at `[91]` against all 18 official KATs, but there was no
`EncryptionMode` subclass, so no volume path existed to exercise it.

**Tweak convention.** The data-unit / sector number as 8 little-endian bytes — the same identity XTS
binds — plus `SectorOffset`. What changes is granularity: XTS tweaks per 16-byte block *within* a unit;
Adiantum takes one call *per unit* and diffuses across the whole thing.

**Proven by property, not by another KAT run** (`verification/adiantum_mode_test.cpp`, 17/17). The KATs
cannot see integration faults — a wrong tweak convention, an ignored `SectorOffset`, a sector/data-unit
confusion, an aliasing bug. The load-bearing assertion is the one that justifies the mode at all:

> flipping **one plaintext bit** changed **509 of 512** ciphertext bytes.

Under XTS that number would be 16. The test requires >90% and separately requires >16, so a shim that
quietly degraded to per-block calls would fail rather than pass looking fine. Also asserted: round-trip
over multiple sectors; the sector index and `SectorOffset` both participate (and it is their *sum* that
forms the tweak); a wrong key does not recover plaintext; a partial data unit and an oversized sector are
**refused** rather than silently truncated or split; an unkeyed instance throws.

A real bug surfaced on the first run and is worth recording: `SetKey` called `SecureBuffer::Free()` on a
never-allocated buffer, which throws `NotInitialized`. It reads as correct hygiene and is not — the test
caught it immediately.

### Two things this does NOT yet mean

1. **Adiantum is not selectable.** The shim is not registered in `EncryptionMode::GetAvailableModes()`,
   so no volume can be created with it. That is deliberate, not an oversight — it is a format decision
   with on-disk and compatibility consequences and should be taken explicitly. Note also that the product
   binary linking cleanly with `ADIANTUM_MODE=1` proves little on its own: nothing references the class,
   so the archive member is simply never pulled in.
2. **It does not compose into cascades.** Adiantum is a *self-contained* construction bundling its own
   constant-time AES-256, XChaCha12 and NH/Poly1305; it accepts `SetCiphers()` and ignores it. So
   "AES-Adiantum" and "Serpent-Adiantum" would be the same construction, and `GetKeySize()` is Adiantum's
   own 32 bytes rather than a sum over `Ciphers`. It must not be offered in cipher-cascade UI as though
   it composed. This is a property of Adiantum, not a defect in the shim — but the `EncryptionMode`
   interface is shaped for "mode over a cipher list", and Adiantum genuinely does not fit that shape.

Still open: exercising it on genuinely **non-AES-NI** hardware, which is what the original claim was
about and remains untested.
