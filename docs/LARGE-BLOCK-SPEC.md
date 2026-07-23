# Threefish — large-block cipher for birthday-bound headroom

**Status: algorithm proven (512 against official vectors, 1024 cross-verified); mode wiring is
real-build.** Addresses `IDEAS-BACKLOG.md` "Large-block ciphers" row (Threefish-1024, Rijndael-256).

## The gap it closes

AES has a 128-bit block. Any 128-bit-block mode has a birthday bound at ~2^64 blocks (~2^70 bytes)
after which collision-type distinguishers appear — comfortable for most volumes but not limitless for
very large arrays, and a real constraint when a wide-block construction hashes over the whole sector.
**Threefish** (the tweakable block cipher inside Skein) offers 256-, 512-, and **1024-bit** blocks; the
1024-bit block pushes the birthday bound to ~2^512 blocks — effectively unlimited — and makes it a
strong core for wide-block modes and huge-volume encryption.

## Construction

Threefish is an ARX cipher: each round applies the MIX function (`y0 = x0+x1; y1 = (x1 <<< R) ^ y0`) to
word pairs, permutes the words, and injects a subkey every 4 rounds. Threefish-512 is 72 rounds over 8
64-bit words; Threefish-1024 is 80 rounds over 16 words. The key schedule appends a parity word
(`k_Nw = C240 ^ ⊕k_i`) and folds in a 128-bit tweak; the rotation tables and word permutations are the
Skein 1.3 constants (transcribed from the reference, not memory).

## What the PoC proves (`verification/threefish_poc.c` + `threefish_reference.py`, step `[29]`)

Not in the VeraCrypt tree, so proven the fork's dual way:

- **Threefish-512 against the OFFICIAL Botan published vectors** (`threefish_kats.{h,py}`, extracted
  from randombit/botan) — this pins down the entire shared machinery: MIX, rotation constants, the word
  permutation, the parity-word key schedule, and the tweak schedule. All four Botan vectors reproduce
  exactly.
- **Threefish-1024** is the identical construction with 16 words and its own rotation table/permutation
  (both extracted from the reference). It is proven by **byte-identical C-vs-python agreement** on a
  deterministic vector plus **encrypt/decrypt round-trip**; because the 512 machinery is pinned by
  official vectors and 1024 reuses it, the cross-check is strong.

`threefish_poc.c` (C, both block sizes) and `threefish_reference.py` (Python) emit identical REF lines,
and both assert `tf512_official_match`, `tf1024_roundtrip`, and `tf512_roundtrip`.

## Integration & honest notes

- **Mode, not raw block.** A block cipher needs a mode; Threefish-1024 would slot in as the block
  cipher for a wide-block construction (it is a natural HBSH/HCTR2 block) or a large-block XTS variant.
  That mode selection rides the anti-downgrade parameter binding (step `[23]`), new volumes only.
- **Rijndael-256** (256-bit-block Rijndael, distinct from AES) is the row's other candidate for the same
  birthday-headroom goal; Threefish is proven here as the more modern, tweakable choice.
- **Performance.** Threefish is fast in software (ARX, no tables) but has no dedicated hardware; on
  AES-NI machines AES-based modes are faster. The value is block size, not speed.
- **Not constant-time-audited / undersized-nothing.** The PoC is correct-by-vector; a shipping build
  uses a reviewed implementation.
- **Scope.** A stronger cipher core for the user's own storage — inside the project boundary.
