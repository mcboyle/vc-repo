# HCTR2 — wide-block mode for AES-accelerated hardware

**Status: full construction proven against the official published vectors; the XTS-replacement wiring
is the same mode seam as Adiantum.** Completes `IDEAS-BACKLOG.md` §B's wide-block pair: **Adiantum**
(step `[24]`) for hardware without AES acceleration, **HCTR2** for the AES-NI/CLMUL machines a desktop
VeraCrypt actually runs on. HCTR2 (Crowley, Huckleberry & Biggers, eprint 2021/1441) is what the Linux
kernel ships for fscrypt filename encryption — the most deployment-proven wide-block mode there is.

## Why both modes

Same goal as Adiantum — a tweakable super-pseudorandom permutation over the whole sector, so a single
flipped bit randomizes the entire sector in either direction, destroying XTS's surgical 16-byte
malleability. The difference is the cost profile: Adiantum's bulk work is ChaCha12+NH (fast without AES
hardware); HCTR2's is AES-XCTR + POLYVAL, both of which map directly onto AES-NI and carry-less-multiply
instructions. A real deployment picks per-platform; the fork now has both cores proven, sharing the
mode-seam and anti-downgrade integration story.

## Construction (HCTR2 with AES-256)

```
Setup:   hbar = E_K(le128(0))          # POLYVAL key
         L    = E_K(le128(1))          # XCTR offset mask
Hash:    H(T, M) = POLYVAL(hbar,  le128(2·bitlen(T) + 2 + [16 ∤ |M|])
                                  ‖ zeropad16(T)
                                  ‖ (M            if 16 | |M|
                                     zeropad16(M ‖ 0x01)  otherwise) )
Encrypt: M, N = P[:16], P[16:]
         MM = M ⊕ H(T, N)
         UU = E_K(MM)                  # the one extra block-cipher call
         S  = MM ⊕ UU ⊕ L
         V  = N ⊕ XCTR_K(S, |N|)      # XCTR block i (from 1) = E_K(S ⊕ le128(i))
         U  = UU ⊕ H(T, V)
         C  = U ‖ V
```

POLYVAL is RFC 8452's GF(2¹²⁸) hash (the AES-GCM-SIV one): little-endian bit order, polynomial
`x¹²⁸+x¹²⁷+x¹²⁶+x¹²¹+1`, `dot(a,b) = a·b·x⁻¹²⁸`. The length block's `+2+[remainder]` encoding and the
`0x01` partial-block padding follow the paper and the kernel implementation exactly. Security reduction
is in the paper: HCTR2 fixes the proof gaps and tweak-handling weaknesses of the original 2005 HCTR.

## What the PoC proves (`verification/hctr2_poc.c` + `hctr2_reference.py`, step `[26]`)

Three-way agreement, same bar as Adiantum:

1. **The official published vectors** (`verification/hctr2_kats.{h,py}` — 35 vectors extracted from
   google/hctr2, MIT: every message-length {16,17,31,48,128,255,512} × tweak-length {0,1,16,32,47}
   combination, so the one-block edge case, partial-block padding, and partial-tweak padding are all
   exercised). Both implementations reproduce **all 35 ciphertexts exactly** and decrypt them back.
2. **Real in-tree objects + published sub-KATs**: the C PoC's AES-256 is the real
   `Aescrypt/Aeskey/Aestab.c` (FIPS-197 `8ea2b7ca…` asserted). POLYVAL is PoC-local — there is no
   POLYVAL in the VeraCrypt tree, stated honestly — but anchored to the **RFC 8452 published example**
   (`f7a3b47b…`), an authority independent of both implementations.
3. **Independent Python** (`hctr2_reference.py`, stdlib-only, reusing the FIPS-197-anchored pure-python
   AES from the Adiantum reference): byte-identical `^REF` output (43 lines).

Property checks on the 512-byte/32-byte-tweak vector, asserted identically on both sides: single-bit
plaintext flip → ≥40% of ciphertext bits change including both the U block and the tail
(`enc_diffusion`); single-bit ciphertext flip → whole-message randomized plaintext (`dec_diffusion`);
wrong key and wrong tweak each change the output.

## Integration & honest notes

- **Same seam as Adiantum.** An `EncryptionModeHCTR2` beside XTS; the mode id rides the anti-downgrade
  parameter binding (step `[23]`); new volumes only. The per-sector tweak is the sector index. Where
  Adiantum and HCTR2 are both built, mode choice is a per-volume parameter — the spec pair
  (`docs/ADIANTUM-SPEC.md`) discusses pick-per-platform.
- **Fallback for hardware without AES acceleration is Adiantum — not LEA.** On ARM / entry-level targets
  with no AES instructions, HCTR2's AES-XCTR + POLYVAL are slow; the recommended compile-time alternative
  is **Adiantum** (ChaCha12 + NH + Poly1305, fast without AES hardware), which already has a proven PoC
  (`verification/adiantum_poc.c`, step `[24]`). Do not reach for LEA or another lightweight block cipher
  as the no-AES fallback — Adiantum is the vetted, already-in-tree choice.
- **Performance path is real hardware.** This PoC's bit-by-bit GF(2¹²⁸) and table AES establish
  correctness only; a shipping build uses AES-NI + PCLMULQDQ (the kernel's implementation is the
  reference) and must be constant-time. Benchmarking Adiantum vs HCTR2 vs XTS on target hardware is the
  real-build follow-up.
- **Still not authenticated.** Wide-block randomizes tampering; detection remains the integrity tier's
  job (per-sector MAC `[21]`, Merkle `[19]`). They compose: HCTR2 for the data, MAC for detection.
- **Scope.** A stronger confidentiality mode for the user's own storage — inside the project's
  access-control boundary.

## Shippable module + EncryptionMode (steps `[105]` / `hctr2_mode.sh`) — T2-4 complete

HCTR2 is no longer PoC-only. It had been the **last** of the wide-block pieces still living solely in
`verification/` — `AesCt` `[88]`, `Poly1305` `[90]` and `Adiantum` `[91]` were all promoted into `src/`
while HCTR2 was not, so the mode D-4 selects for AES-NI hardware had no shippable implementation at all.
That gap is closed in two pieces:

- **`src/Crypto/Hctr2.{c,h}`** (gated `-DVC_ENABLE_HCTR2` / `make HCTR2=1`). Step `[105]` runs all **35
  official google/hctr2 AES-256 vectors** through the real compiled object, in **both directions**, with
  one cryptographically material change from the PoC: the block cipher is the **constant-time
  `src/Crypto/AesCt`**, not the table-driven in-tree AES. That substitution is exactly what can silently
  break a mode — wrong key schedule, wrong direction on the inverse cipher, an endianness slip in the
  XCTR counter — while still yielding ciphertext that round-trips convincingly. Reproducing the official
  vectors byte-for-byte is what rules it out. (The HCTR2 analogue of `[89]`.) Anchor class: **OFFICIAL**.
- **`src/Volume/EncryptionModeHctr2.{h,cpp}`** (gated `-DVC_ENABLE_HCTR2_MODE` / `make HCTR2_MODE=1`),
  proven by `verification/realbuild/hctr2_mode.sh` at 17/17 against the real `EncryptionMode` base — a
  one-bit plaintext flip changed **509 of 512** ciphertext bytes, where XTS would change 16.

**Why this had to land before the v2 mount-side work.** `V2Mode` is `{HCTR2 = 0, ADIANTUM = 1,
NONE = -1}` and `V2FormatDiscoverMode` identifies a volume's mode by trying each mode's MAC key against
the stored tag. With only one mode implemented, discovery could never be shown to **discriminate** —
only to return `NONE` on a wrong key. Two modes make that property testable for the first time.

**The honest cost, restated.** HCTR2 runs its block cipher over the **whole sector** (XCTR, one AES call
per 16 bytes) plus two POLYVAL passes. Over software `AesCt` that is substantially slower than Adiantum,
which calls AES once per sector. It is correct everywhere and appropriate where AES-NI exists — which is
precisely the D-4 split. Do **not** swap in the table-driven AES for speed: that trades a measured
cache-timing leak (`docs/CT-HARDENING-R17.md`) for performance on exactly the hardware that cannot
afford it.

**Not offered as a volume format.** Like Adiantum, HCTR2 is deliberately absent from
`EncryptionMode::GetAvailableModes()`. Selecting it is a header change (D-10), and it bundles its own
primitives so it does **not** compose into cipher cascades — "AES-HCTR2" and "Serpent-HCTR2" would name
the same construction.
