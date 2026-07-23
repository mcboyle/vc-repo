# Merkle tree over the volume — offline-tamper detection with an off-disk root

**Status: tree + authentication-path proven; block-layer integration is `[FORMAT]`/real-build.**
Addresses `IDEAS-BACKLOG.md` §A ("Merkle tree over the volume with the root held off-disk") — the
*data* half of evil-maid that a bootloader fingerprint does not cover.

## The gap it closes

XTS is malleable at 16-byte granularity: an attacker with write access to the disk can flip ciphertext
bits and produce controlled plaintext changes **with no detection**. A Merkle tree hashes every sector
into a single **root**; if that root is held somewhere the attacker cannot reach — the header field
covered by the keyslot MAC, a hardware token, or TPM NV — then *any* offline modification of *any*
sector changes the root and is detected on next mount. Unlike a flat whole-volume hash, the tree lets a
single sector be verified in **O(log N)** (an authentication path of `log₂N` sibling digests), so a
normal read does not have to rehash the entire volume.

## Construction

Domain separation follows **RFC 6962** (Certificate Transparency) so a leaf can never be reinterpreted
as an interior node, and the leaf is **bound to its sector index**:

```
leaf(i, data) = SHA256( 0x00 || le64(i) || data )
node(l, r)    = SHA256( 0x01 || l || r )
```

- `SHA256` is VeraCrypt's in-tree `Crypto/Sha2.c` (the PoC links the real object).
- The `0x00`/`0x01` tag bytes prevent leaf↔node confusion (second-preimage across the two shapes).
- `le64(i)` binds each leaf to its position, so a valid `(sector, data)` pair cannot be relocated
  elsewhere in the tree (defence-in-depth on top of XTS's per-sector tweak).
- **Odd node counts promote the lone node unchanged** to the next level (no duplication) — this avoids
  the CVE-2012-2459 duplicate-leaf root-collision that Bitcoin-style duplication suffers.

## What the PoC proves (`verification/merkle_poc.c` + `merkle_reference.py`, step `[19]`)

Proven the two ways the fork requires — the C PoC drives the **real in-tree SHA-256**, and an
independent Python reference (`hashlib`) reproduces it **byte-for-byte** over 12 vectors (anchor root
`6dbdb1c1…` for `N=8` sectors of 64 deterministic bytes each):

- **Deterministic root** — same sectors → same root.
- **Authentication paths** — for every one of the 8 leaves the emitted sibling path is byte-identical
  across C and Python, and recomputing the root from `(index, data, path)` equals the trusted root.
- **Tamper detection** — flipping a single bit in one sector changes the root (`16124e87…`), and that
  sector's *stale* authentication path is **rejected** against the trusted root. Both the C and Python
  sides assert `tamper_detected = YES` and `tamper_path_rejected = YES`.

`N=8` and 64-byte "sectors" keep the KAT fast; the tree math is identical for 512-byte sectors and
volume-scale `N`.

## Integration & honest notes

- **Where the root lives is the whole security argument.** An on-disk root the attacker can rewrite
  buys nothing. Options, strongest first: TPM NV / hardware-token-held root (survives full-disk
  imaging); a header field **covered by the keyslot-area MAC** (`docs/POLY1305-SPEC.md`, §P0.5) so the
  root cannot be silently swapped; at minimum a root the user carries out-of-band. The PoC deliberately
  does not pick storage — that is the integration decision.
- **This needs a place to store the tree → `[FORMAT]`.** Interior-node digests must persist (or be
  recomputed on each mount, trading I/O for space). Either way it touches on-disk layout, so — like
  per-sector authentication — it lives behind the project's `[FORMAT]` gate and is **out of scope for
  the no-header-change core**. This PoC establishes the cryptographic core so the format work starts
  from a proven tree.
- **Crash consistency is the real cost.** A write must update the sector *and* its path to the root; a
  crash between the two must not wedge the volume. That journalling/ordering discipline (the same issue
  dm-integrity documents) is the main engineering item, and must be specified before shipping.
- **Rollback ≠ tamper.** A Merkle root detects modification but not *replay* of a whole older tree
  (root and all). Snapshot-replay is covered separately by the monotonic-counter item (§A) — pair the
  two if replay is in the threat model.
- **Scope.** Detecting modification of stored ciphertext is integrity/access-control infrastructure —
  well inside the project's boundary. Nothing here fabricates or hides activity.
