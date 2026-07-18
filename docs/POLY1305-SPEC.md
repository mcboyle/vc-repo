# Poly1305 (RFC 8439) — one-time authenticator for the integrity tier

**Status: algorithm proven; integration deferred to the tier that consumes it.** Poly1305 is the
polynomial one-time MAC that the integrity work depends on: authenticated per-sector storage
(`IDEAS-BACKLOG.md` §A), a keyslot-area MAC so a tampered slot table is detected before unwrap
(`§P0.5`), and the two wide-block cipher modes on the research list — **Adiantum** (which is literally
`XChaCha + NH + Poly1305`) and **HCTR2**. Building the authenticator now, proven, means those items
start from a known-correct primitive instead of an unverified one.

## Why Poly1305 (and not another MAC)

- **It is what the target constructions actually use.** Adiantum specifies Poly1305 by name;
  ChaCha20-Poly1305 (RFC 8439) is the AEAD the per-sector-integrity item would most naturally reach for.
  Picking the MAC the designs call for avoids re-deriving security arguments for a substitute.
- **One-time MAC, exact-fit cost.** Poly1305 is a single pass of multiply-accumulate in the field
  `2^130 − 5`; with a per-message key (from a stream cipher) it needs no block cipher of its own.
- **Well-specified KATs.** RFC 8439 ships worked test vectors (§2.5.2) and a vector table (A.3), so
  correctness is checkable against an authority independent of any one implementation.

## Algorithm (RFC 8439 §2.5)

```
key = 32 bytes = r (16) || s (16)
clamp r:  r &= 0x0ffffffc0ffffffc0ffffffc0fffffff       # low 4 top bits + 2 low bits cleared per 32-bit word
acc = 0
for each 16-byte block m (last may be short):
    n   = int_le(m) + 2^(8*len(m))                       # append a 1 bit just past the block bytes
    acc = ((acc + n) * r) mod (2^130 - 5)
tag = (acc + s) mod 2^128                                # 16-byte little-endian
```

The clamp on `r` is what bounds the limb sizes so the field multiply fits fixed-width arithmetic; the
trailing `2^(8*len)` bit is what makes a short final block unambiguous from a full one.

## What the PoC proves (`verification/poly1305_poc.c` + `poly1305_reference.py`, step `[18]`)

Poly1305 is **not part of the VeraCrypt tree**, so — unlike the SHA-2/ChaCha/Argon2 work — there is no
in-tree compiled object to link against. It is instead proven the two independent ways this fork
requires, stated honestly:

1. **Two independent implementations agree byte-for-byte.** `poly1305_poc.c` is a radix-2⁶ ("donna")
   32-bit-limb one-shot; `poly1305_reference.py` is a transparent Python big-integer implementation with
   no carry tricks. They are compared over the RFC KATs **plus a deterministic fuzz battery** — 22
   message lengths chosen to straddle block boundaries (0, 1, 15–17, 31–33, 47–49, 63–65, 127–129,
   255–256, 300), with keys and messages drawn from an identical `xorshift64*` stream on both sides. 25
   vectors match.
2. **Both reproduce the RFC 8439 published tags** — the authority independent of both:
   - §2.5.2: key `85d6be…f51b`, message `"Cryptographic Forum Research Group"` → **`a8061dc1305136c6c22b8baf0c0127a9`**.
   - A.3 #1: all-zero key/message → all-zero tag (`r=0, s=0`).
   - A.3 #2: `r=0`, `s=36e5…863e` over the IETF-submission note → tag `36e5f6b5c5e06070f0efca96227a863e` (tag == s).

## Integration & honest notes

- **This is a primitive, not a feature.** By itself Poly1305 changes nothing a user mounts. It becomes
  product code only inside a consumer:
  - **Keyslot-area MAC (§P0.5).** Authenticate the slot table under a key derived alongside the wrap key
    so tampering/truncation is caught before any unwrap attempt. Smallest, most self-contained consumer;
    the natural first integration once the keyslot volume-I/O bindings land (`docs/KEYSLOTS-SPEC.md §9`).
  - **Per-sector authentication (§A).** Needs a per-sector key/nonce discipline and somewhere to store
    tags — which is a **format change**, so it lives behind the same `[FORMAT]` gate as the other
    storage-layout work and is out of scope for the no-header-change core.
  - **Wide-block modes (Adiantum/HCTR2).** Larger constructions; this MAC is one component.
- **One-time key discipline is mandatory.** Poly1305 is a *one-time* authenticator: reusing an `(r,s)`
  pair across two messages leaks `r` and breaks unforgeability. Any consumer must derive a fresh
  `(r,s)` per message (the standard route: first block of a stream cipher keyed by a per-message nonce),
  exactly as ChaCha20-Poly1305 does. The PoC deliberately does not fix a key-derivation policy — that
  belongs to each consumer.
- **Constant-time follow-up.** The PoC's field arithmetic is branch-free in its carry/reduction path
  (the final "subtract p and select" is masked, not branched), which is the property a MAC needs. A
  production port should still be reviewed for compiler-introduced timing and, on the platforms that
  matter, use the vetted formally-verified Poly1305 rather than this reference limb code.
- **Scope.** This is confidentiality/integrity infrastructure — authenticating stored ciphertext — and
  sits well inside the project's access-control boundary.
