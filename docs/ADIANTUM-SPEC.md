# Adiantum — wide-block mode (sector-atomic encryption)

**Status: full construction proven against the official published vectors; the XTS-replacement wiring
is `[FORMAT]`/real-build.** Addresses `IDEAS-BACKLOG.md` §B — the backlog calls wide-block modes "the
single strongest *cryptographic* upgrade available to a disk encryptor."

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
