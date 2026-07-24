# Verification anchors — what each proof is actually anchored to

**Why this document exists.** Suite step `[94]` found a real defect: the from-scratch ristretto255
hash-to-group diverged from RFC 9496/9497. It had passed verification for months. The reason it survived
is structural, not careless — and it is the single most important lesson in this project's methodology:

> The project's convention is "prove it two ways: an independent Python reimplementation, and against real
> compiled objects." But **when we write the Python twin ourselves, it encodes the same reading of the spec
> as the C.** If our reading is wrong, both are wrong *identically*, and they agree — loudly and
> reassuringly — for the same wrong reason. Running the C against real compiled objects doesn't help
> either: it proves the integration, not the interpretation.

A twin can only catch *implementation* slips (a typo, a bad index, an endianness flip in one of the two).
It is structurally blind to *interpretation* errors. Only an artifact we did **not** author can catch those:
an official test vector, or a mature third-party implementation.

## Anchor classes

| Class | Meaning | Catches interpretation errors? |
|---|---|---|
| **OFFICIAL** | Published test vectors from the standard/reference (RFC, NIST/FIPS, BIP, upstream project KATs) | **Yes** — strongest |
| **THIRD-PARTY** | Cross-checked against a mature implementation we did not write (libsodium, OpenSSL/hashlib) | **Yes** |
| **TWIN** | Our own independent reimplementation (typically Python) | No — shares our reading |
| **PROPERTY** | Behavioural/structural invariants (round-trip, tamper-reject, indistinguishability, timing) | Partially |

**TWIN is not a defect.** For fork-specific constructions — the keyfile-pool mixing, keyslot record
formats, the decoy layout, write-only ORAM — *no standard exists*, so there is nothing external to anchor
to and a twin plus properties is the right and honest tool. The rule is narrower:

> **Wherever a construction claims conformance to a published standard, a TWIN alone is insufficient.
> It must carry an OFFICIAL or THIRD-PARTY anchor.**

## Current state (as of step `[97]`)

**OFFICIAL / THIRD-PARTY anchored.** Argon2id `[11]` (RFC 9106) · Poly1305 `[18]`,`[90]` (RFC 8439) ·
Adiantum `[24]`,`[89]`,`[91]` (google/adiantum) · ML-KEM-768 `[25]` (NIST ACVP) · HCTR2 `[26]`
(google/hctr2) · BLAKE3 `[27]` (official vectors — hash **+ keyed_hash + derive_key**) · Ascon `[28]`
(NIST ACVP) · Threefish `[29]` (Botan) · scrypt `[34]` (RFC 7914) · Ed25519 `[39]` (RFC 8032 §7.1) ·
bech32m `[42]` (BIP-350) · HMAC-SHA256 `[69]` (Wycheproof-style) · AES `[87]`,`[88]` (FIPS-197) ·
codex32 `[92]` (BIP-93) · ristretto255 `[94]` (RFC 9496 A.1+A.2, libsodium) · OPRF `[95]` and
VOPRF/POPRF `[96]` (RFC 9497 A.1.1/A.1.2/A.1.3, libsodium) · **PBKDF2-HMAC-SHA512 `[97]`**
(published KATs + OpenSSL).

**Closed by this audit.** `derive_key_sha512` — the shipping `KeyslotKdfSha512` that wraps **every**
keyslot VMK, and a mountable volume PRF — had *no* external anchor. Steps `[8]`/`[9]` exercised it only
inside fork-specific compositions checked against our own Python. Step `[97]` now anchors it to published
PBKDF2-HMAC-SHA512 KATs **and** OpenSSL, across partial-final-block, multi-block, and zero-length
password/salt shapes. **Result: it is correct** — no defect. The value is converting an assumption into a
proof on a load-bearing primitive.

**Known non-conformant (carried, documented).** The from-scratch ristretto255 group in
`oprf_ristretto_poc.c`, `voprf_ristretto_poc.c`, and `toprf_ristretto_poc.c` `[43]`,`[44]`,`[47]` has an
RFC-conformant *encoding* (A.1) but a **non-conformant hash-to-group**. Those PoCs remain internally
self-consistent and their properties hold, but their outputs would not interoperate with an RFC 9497 peer.
ROADMAP **D-8** deletes that code in favour of libsodium, which `[95]`/`[96]` prove conformant. Do not
reuse the bespoke map.

**Open candidates (TWIN-only, standard exists).** Not yet anchored; each is a candidate for the same bug
class and worth a `[97]`-style check:

| Primitive | Used by | Available anchor |
|---|---|---|
| In-tree ChaCha20 (20-round) | `[6]` KeyScrub RAM transform, `[8]` keyslot wrap | RFC 8439 §2.4.2 keystream vectors |
| ChaCha20-Poly1305 AEAD composition | `[20]` keyslot-area MAC | RFC 8439 §2.8.2 |

(The ChaCha *core* is exercised indirectly by the official Adiantum vectors at `[24]`/`[89]`/`[91]`, but
via XChaCha12 inside Adiantum — not the plain 20-round RFC 8439 construction those steps rely on.)

**TWIN + PROPERTY, appropriately.** No published standard exists for these, so a self-written twin plus
behavioural properties is the correct tool: keyfile-pool mixing `[2]` · KeyScrub registry `[6]` ·
keyslot record/store/lifecycle `[8]`,`[9]`,`[36]`,`[37]` · McCallum–Relyea `[10]`,`[39]`,`[49]` ·
write-only ORAM `[13]` · decoy fragments `[14]` · AF-split `[15]` · Balloon `[16]`,`[38]` · Merkle `[19]` ·
per-sector auth `[21]` · rollback counter `[22]` · anti-downgrade `[23]` · Sloth/Feldman/Pedersen/RSW
`[30]`–`[33]` · Catena `[48]` · v2 format `[84]`–`[86]` · HKF v1/v2 mixing `[78]`–`[81]`,`[93]`.

## The rule going forward

When adding a verification step, state its anchor class in the step comment. If the construction claims to
implement a published standard, a TWIN alone does not discharge the claim — find the official vectors, or
cross-check against an implementation you did not write. If neither exists, say so plainly in the docs and
do not describe the result as "conformant".
