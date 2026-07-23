# Per-sector authentication — dm-integrity-style tamper detection

**Status: PRF-MAC construction + integrity properties proven; tag storage is `[FORMAT]`/real-build.**
Addresses `IDEAS-BACKLOG.md` §A ("Per-sector authentication (dm-integrity style)") — the finest-grained
answer to XTS malleability.

> **Construction change (research batch-2 C2).** The tag was originally a per-sector *one-time* MAC:
> `otk_i = ChaCha20(sector_mac_key, le64(index))[0..32]; tag_i = Poly1305(otk_i, ct_i)`. That defends
> only "no `(r,s)` reuse **across** sectors" — true in space, **false in time**. `otk_i` is a pure
> function of the sector index, so **every rewrite of sector *i* reuses the same one-time Poly1305 key**
> under different content. Poly1305 is a one-time Wegman–Carter MAC and is catastrophically fragile
> under key reuse: an adversary with **two tag versions of one sector** — exactly what a multi-snapshot
> adversary has, and what a chip-off adversary recovers from stale tag-area pages the FTL retained —
> recovers `(r, s)` by standard nonce-reuse key recovery and can then forge that sector's tags forever.
> The fix replaces the one-time MAC with a **PRF** (keyed BLAKE3), which degrades gracefully under key
> reuse and is naturally constant-time. *Two-way verification never caught this: the old PoC and Python
> reference agreed byte-for-byte and both faithfully implemented the spec — implementation fidelity, not
> spec soundness under rewrite. That gap is what research review is for.*

## The gap it closes

XTS is malleable at 16-byte granularity and offers **no integrity**: an attacker with disk write access
can flip ciphertext bits (localized plaintext corruption) or **copy whole sectors around** without
detection. The Merkle tree (`docs/MERKLE-SPEC.md`) detects *any* offline change against one off-disk
root; per-sector authentication is the complementary fine-grained mechanism — an independent MAC tag per
sector that says *which* sector changed and lets a single sector be verified on read without touching
the rest of the volume. This is what Linux `dm-integrity` provides beneath `dm-crypt`.

## Construction (per-sector PRF-MAC, index-bound)

```
K_mac  = KDF(VMK, "per-sector-auth")                # 32 bytes, never on disk; domain-separated from the
                                                    #   encryption key
tag_i  = keyed_BLAKE3(K_mac, le64(sector_index) || ciphertext_i)[0..16]   # 128-bit tag, separate tag area
verify: recompute tag_i; constant-time compare; refuse the sector on mismatch
```

Tags are computed over the **ciphertext** (encrypt-then-MAC), so verification needs no decryption and a
tampered sector is rejected before its plaintext is ever produced. `keyed_BLAKE3` is the in-tree-proven
BLAKE3 keyed-hash mode (step `[27]`, `blake3_poc.c` — the PoC reuses it directly rather than a second
implementation).

**Why keyed BLAKE3 (a PRF), not a one-time MAC.** A PRF's security does not depend on a
never-reuse-the-key precondition, so the *same* `K_mac` authenticating the *same* sector index across
many rewrites is safe: each `(index, content)` maps to an unpredictable tag, and observing many
`(content, tag)` pairs for one sector reveals nothing that forges a new one. That is precisely the
guarantee the one-time Poly1305 construction lacked. **KMAC256** (SHA-3 / NIST SP 800-185) is the
conservative standardised alternative; keyed BLAKE3 was chosen to reuse a primitive already proven
in-tree with no new dependency.

**Why `le64(sector_index)` stays INSIDE the PRF input.** It binds the tag to its sector, giving two
properties a single whole-area MAC cannot:

- **Per-sector independence** — tampering sector *i* fails only sector *i*'s check; every other sector
  still verifies. A read verifies one sector in O(sector size), not the whole volume.
- **Relocation resistance** — a valid `(ciphertext, tag)` pair copied to a *different* sector is hashed
  under a different `le64(index)` prefix, so it is rejected. XTS's per-sector tweak hides bit-flips but
  not an attacker relocating entire authenticated sectors; the index-bound tag closes that.

## What the PoC proves (`verification/persector_poc.c` + `persector_reference.py`, step `[21]`)

Proven the two ways the fork requires — the C PoC drives the **real in-tree keyed BLAKE3**; an
independent Python reference (`blake3_reference.py`) reproduces every value byte-for-byte over 13 REF
lines (8 sector tags, anchor `tag_0 = 13fdf100…`, for `K_mac[i] = 0x40+i` and deterministic 64-byte
sectors):

- **Accept all** — every untampered sector verifies.
- **Per-sector independence** — flipping one bit in sector 5 fails *only* sector 5; sectors 0–4, 6–7
  still verify.
- **Relocation detected** — swapping the `(ciphertext, tag)` of sectors 3 and 5 is rejected at both new
  positions (each hashed under the wrong `le64(index)` prefix).
- **Wrong key detected** — a `K_mac` off by one bit fails verification.
- **Rewrite / key-reuse safe (NEW — the property the one-time Poly1305 construction FAILED)** — two
  rewrites of the *same* sector under the *same* `K_mac` (different content) produce **independent** tags:
  the two tags differ, each verifies only its own content, and neither authenticates the other's content.
  There is no one-time `(r, s)` key to recover from the pair, so the multi-snapshot / stale-tag adversary
  gains no forgery. This assertion is the whole point of the C2 change and is checked explicitly in the
  step output (`REF rewrite_reuse_safe YES`).

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
- **Detects modification, not rollback.** A per-sector PRF-MAC catches tampering and relocation but not
  *replay* of an older `(ciphertext, tag)` pair at the **same** index. Whole-volume replay is covered by
  the Merkle root + monotonic-counter items (§A); pair them if snapshot-replay is in the threat model.
  Note the PRF construction removes the *key-recovery-under-rewrite* break but not same-index replay —
  the two are different threats.
- **Deniability leak — a visible tag/journal area is a tell.** A dedicated MAC/tag area (or an integrity
  journal) is a structure a naive random-looking volume does not have; its mere presence signals that
  authentication — and therefore *something worth authenticating* — exists on the device. That is in
  direct tension with hidden-volume deniability. Per-sector authentication is therefore **opt-in and
  never a default**, and must not be enabled on a volume whose threat model includes deniability under
  inspection.
- **Scope.** Authenticating stored ciphertext is integrity infrastructure — well inside the project's
  access-control boundary.
