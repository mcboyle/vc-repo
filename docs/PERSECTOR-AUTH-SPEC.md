# Per-sector authentication — dm-integrity-style tamper detection

**Status: MAC construction + integrity properties proven; tag storage is `[FORMAT]`/real-build.**
Addresses `IDEAS-BACKLOG.md` §A ("Per-sector authentication (dm-integrity style)") — the second consumer
of the proven Poly1305 primitive (`docs/POLY1305-SPEC.md`), and the finest-grained answer to XTS
malleability.

## The gap it closes

XTS is malleable at 16-byte granularity and offers **no integrity**: an attacker with disk write access
can flip ciphertext bits (localized plaintext corruption) or **copy whole sectors around** without
detection. The Merkle tree (`docs/MERKLE-SPEC.md`) detects *any* offline change against one off-disk
root; per-sector authentication is the complementary fine-grained mechanism — an independent MAC tag per
sector that says *which* sector changed and lets a single sector be verified on read without touching
the rest of the volume. This is what Linux `dm-integrity` provides beneath `dm-crypt`.

## Construction (per-sector one-time MAC, index-bound)

```
sector_mac_key = KDF(VMK, "per-sector-auth")        # 32 bytes, never on disk
nonce_i        = le64(sector_index)                 # the sector index IS the nonce
otk_i          = ChaCha20(sector_mac_key, nonce_i, counter=0)[0..32]
tag_i          = Poly1305(otk_i, ciphertext_i)      # 16 bytes, in a separate tag area
verify:        recompute tag_i; constant-time compare; refuse the sector on mismatch
```

Tags are computed over the **ciphertext** (encrypt-then-MAC), so verification needs no decryption and a
tampered sector is rejected before its plaintext is ever produced. `ChaCha20` is the in-tree
`Crypto/chacha256.c`; `Poly1305` is the step-`[18]` implementation (shared `verification/poly1305.h`).

**Why `nonce = sector_index` is the whole design.** It gives every sector its own one-time Poly1305 key,
which simultaneously satisfies Poly1305's one-time-key rule (no `(r,s)` reuse across sectors) and buys
two properties a single whole-area MAC cannot:

- **Per-sector independence** — tampering sector *i* fails only sector *i*'s check; every other sector
  still verifies. A read verifies one sector in O(sector size), not the whole volume.
- **Relocation resistance** — a valid `(ciphertext, tag)` pair copied to a *different* sector verifies
  under that sector's `otk`, which differs, so it is rejected. XTS's per-sector tweak hides bit-flips
  but not an attacker relocating entire authenticated sectors; the index-bound tag closes that.

## What the PoC proves (`verification/persector_poc.c` + `persector_reference.py`, step `[21]`)

Proven the two ways the fork requires — the C PoC drives the **real in-tree ChaCha20 + Poly1305**; an
independent Python reference reproduces every value byte-for-byte over 12 vectors (8 sector tags,
anchor `tag_0 = 74e883b1…`, for `sector_mac_key[i] = 0x40+i` and deterministic 64-byte sectors):

- **Accept all** — every untampered sector verifies.
- **Per-sector independence** — flipping one bit in sector 5 fails *only* sector 5; sectors 0–4, 6–7
  still verify.
- **Relocation detected** — swapping the `(ciphertext, tag)` of sectors 3 and 5 is rejected at both new
  positions (each verifies under the wrong index-derived `otk`).
- **Wrong key detected** — a `sector_mac_key` off by one bit fails verification.

## Integration & honest notes

- **Tag storage is a format change → `[FORMAT]`.** `N` sectors need `N × 16` bytes of tags in a separate
  area (or interleaved journal), plus a mapping from data-sector → tag location. That touches on-disk
  layout, so — like the Merkle tree — it lives behind the project's `[FORMAT]` gate and is **out of
  scope for the no-header-change core**. This PoC establishes the crypto so the format work starts from
  a proven, property-tested construction.
- **Crash consistency is the real engineering cost.** A sector write must update the sector *and* its
  tag atomically enough that a crash between them cannot present old data with a new tag (or vice versa).
  `dm-integrity` uses a journal/bitmap for exactly this; the honest tradeoff (write amplification,
  performance) must be specified before shipping. This is the same class of problem as the Merkle path
  update — the two integrity mechanisms could share a journal.
- **Space overhead.** 16 bytes per sector is ~3% on 512-byte sectors, ~0.4% on 4 KiB sectors. Larger
  sectors amortize the tag but coarsen the granularity.
- **Composition with XTS.** MAC-over-ciphertext (encrypt-then-MAC) is the safe order and needs no change
  to the existing XTS layer — the tag simply authenticates whatever ciphertext XTS produced.
- **Detects modification, not rollback.** A per-sector MAC catches tampering and relocation but not
  *replay* of an older `(ciphertext, tag)` pair at the **same** index. Whole-volume replay is covered by
  the Merkle root + monotonic-counter items (§A); pair them if snapshot-replay is in the threat model.
- **Scope.** Authenticating stored ciphertext is integrity infrastructure — well inside the project's
  access-control boundary.
