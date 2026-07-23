# Fast hashes — BLAKE3 and Ascon-Hash256

**Status: both proven against official published vectors; selectable-hash wiring is real-build.**
Covers the `IDEAS-BACKLOG.md` "Hashes" row (BLAKE3, KangarooTwelve, Ascon-Hash). Two complementary
choices are built: BLAKE3 for speed/parallelism on general CPUs, Ascon-Hash256 for constrained targets.

## Why these two

- **BLAKE3** (O'Connor, Aumasson, Neves, Wilcox-O'Hearn, 2020) — a 7-round BLAKE2s-style compression
  over a 1024-byte-chunk binary tree, with built-in keyed-hash and derive-key (KDF) modes and
  arbitrary-length XOF output. It is a natural fast **keyfile/pool hash** and, because its chunk tree is
  itself a Merkle tree, a direct fit for the volume integrity work (`docs/MERKLE-SPEC.md`).
- **Ascon-Hash256** (Dobraunig, Eichlseder, Mendel, Schläffer) — the **NIST Lightweight Cryptography
  winner**, standardized in **SP 800-232** (2025): a 320-bit-state sponge with a 12-round permutation.
  Compact and side-channel-friendly for embedded/constrained builds.

## What the PoCs prove

Neither is in the VeraCrypt tree, so (like Poly1305, step `[18]`) each is proven the fork's dual way:
the **official authority** plus **C-vs-independent-python** agreement, byte-for-byte.

- **BLAKE3** (`blake3_poc.c` + `blake3_reference.py`, step `[27]`): all **35 official BLAKE3-team test
  vectors** (`blake3_kats.{h,py}`) — inputs 0…102400 bytes of the standard repeating 251-byte pattern,
  each producing 131-byte extended output for **hash, keyed_hash, and derive_key** — reproduced exactly
  by both implementations (106 REF lines cross-diffed). This exercises multi-chunk trees, the
  power-of-two-left subtree rule, and multi-block XOF.
- **Ascon-Hash256** (`ascon_poc.c` + `ascon_reference.py`, step `[28]`): the **official NIST ACVP
  SP 800-232** vectors (`ascon_kats.{h,py}`), byte-aligned messages up to 8192 bytes, every 256-bit
  digest reproduced by both C and python. The permutation (round constants, χ S-box, linear diffusion)
  and the little-endian-word sponge with `0x01` padding and the SP 800-232 IV are all pinned by the
  vectors.

## Integration & honest notes

- **Selectable hash = a PRF/hash id.** Wiring either as a mountable keyfile-pool or KDF hash means a
  hash identifier recorded per volume, which rides the anti-downgrade parameter binding (step `[23]`).
  BLAKE3's tree hash would slot into the Merkle work as the node hash.
- **Not constant-time-audited.** The PoCs establish correctness; a shipping build uses vetted reference
  implementations (both have well-reviewed public code).
- **Scope.** Faster/leaner hashing for the user's own key material and integrity trees — inside the
  project boundary.
