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

**Closed by this audit (2): the edwards25519 group beneath step `[39]`.** Step `[39]` carries an OFFICIAL
anchor — the RFC 8032 §7.1 public-key KAT — and it passes. But §7.1 exercises exactly one operation:
scalar multiplication of the **fixed basepoint**. The McCallum–Relyea exchange that `[39]` exists to
support also multiplies **arbitrary** points and **adds** points, and neither is covered by that vector.
That is structurally the same hole as the step-`[94]` defect: an official KAT anchoring one layer while
the layer that matters goes unchecked.

`verification/ed25519_hacl_xcheck.c` closes it against **HACL\*** (formally verified in F\*, code this
project did not write): basepoint, basepoint mult, **arbitrary-point mult**, **point addition**,
negation, `P + (-P) == identity` (HACL\* independently confirms the point at infinity), and the MR
commutativity `k1*(k2*B) == k2*(k1*B)` — **all MATCH**. So the coverage hole was real and the code in it
is correct. Anchor class: THIRD-PARTY.

> **Reference harness, deliberately not a suite step.** HACL\* is not installable in CI (no distro
> package; vendoring is ~13 MB), so a gated step would SKIP and `--strict` would fail the run. Following
> the project convention for harnesses whose inputs aren't available in CI, it ships with its expected
> result recorded here. To re-run: extract a HACL\* release, then compile `ed25519_hacl_xcheck.c` with
> `Hacl_EC_Ed25519.c`, `Hacl_Ed25519.c`, `Hacl_Curve25519_51.c`, `Hacl_Hash_SHA2.c`,
> `Hacl_Streaming_SHA2.c` plus the real `Crypto/Sha2.o`; expect
> `ED25519 HACL XCHECK: from-scratch group == HACL* on all operations`.

**Open candidates (TWIN-only, standard exists).** Not yet anchored; each is a candidate for the same bug
class and worth a `[97]`-style check:

| Primitive | Used by | Status |
|---|---|---|
| In-tree ChaCha20 (20-round) | `[6]` KeyScrub RAM transform, `[8]` keyslot wrap | **CLOSED — step `[98]`**, vs libsodium |
| ~~ChaCha20-Poly1305 AEAD composition~~ | ~~`[20]` keyslot-area MAC~~ | **WITHDRAWN — the construction does not exist** |
| HKDF-SHA256 (RFC 5869) | HKF v2 mix, `[20]` keyslot-area MAC key | **CLOSED — step `[103]`**, vs RFC 5869 A.1–A.3 |

**A withdrawn row, and why it is left visible.** This table used to list *"ChaCha20-Poly1305 AEAD
composition — `[20]` keyslot-area MAC — still open"*. **No such construction exists in the tree.**
`Poly1305` in `src/` is used by Adiantum and nothing else; it is never composed with ChaCha20 into an
AEAD. The thing `[20]` actually computes is `HMAC-SHA256(K_area, …)` with
`K_area = HKDF-SHA256(VMK, …)`, and the "keyslot AEAD" referred to elsewhere is `KeyslotWrap/UnwrapCT`
= **ChaCha20 + HMAC-SHA256** — both already anchored (`[98]`, `[69]`). So the last open row was chasing a
primitive the project does not have, while the primitive it *does* have there — HKDF — sat unanchored
directly beneath it. Recorded rather than deleted, because "the anchor table named the wrong
construction" is the same failure mode as the ChaCha20 variant mix-up below: **an anchor is only as good
as the identification of what it is anchoring.**

**Closed by this audit (3): HKDF-SHA256, step `[103]`.** RFC 5869 appeared nowhere in the tree, yet
HKDF-SHA256 is load-bearing in two shipping places — `HardwareKeyFactor.c`'s Rank-1 **v2 mix** (which
derives the mixed password for *every* v2 factored volume) and `KeyslotAreaMac.c`'s `K_area`. Same class
as `[97]`. Because both in-tree HKDFs are **specialised** (fixed `info`, fixed output length, static
linkage), the RFC's generic `(salt, info, L)` vectors cannot be fed to them directly, so the anchor is a
**chain**: generic HKDF built on the real in-tree HMAC-SHA256 (itself OFFICIAL-anchored at `[69]`) is
matched to RFC 5869 **A.1/A.2/A.3** — PRK *and* OKM, including the 3-block `L=82` case and the
zero-length salt/info case — and then `KeyslotAreaMacDeriveKey` is required to equal that anchored HKDF
byte for byte. The second half is the load-bearing one: it is what rules out a lookalike (counter
starting at 0, `info`/counter transposed, `T(0)` not empty, salt and IKM swapped), none of which
reproduce the vectors. Negative controls confirm the comparison is not vacuous — a one-character `info`
change does not reproduce `K_area`, and a different VMK yields a different key. **Result: correct** — no
defect. 10/10. Anchor class: OFFICIAL.

> **Still uncovered by `[103]`, stated plainly:** the harness anchors the *keyslot-area* specialisation.
> The **HKF v2 mix** shares the same HKDF shape but has its own inlined copy in `HardwareKeyFactor.c`
> (`hkf_v2_hmac` + `hkf_v2_mix`, `info = "VeraCrypt/HKF/mix/v2"`, multi-block expand to `HKF_POOL_SIZE`).
> It is anchored to its own TWIN at `[80]`/`[93]` but has **not** been shown equal to RFC-5869 HKDF the
> way `K_area` now has. That is the next `[103]`-style step, and it matters more than the one just
> closed — it is on the mount path of every v2 volume.

**Correction — the ChaCha20 anchor was initially mis-specified, and the mistake is worth keeping.** This
table first named *RFC 8439 §2.4.2* as ChaCha20's available anchor. That was **wrong**. ChaCha20 has two
incompatible framings of the last four state words:

| | counter | nonce |
|---|---|---|
| original (Bernstein) | words 12,13 — 64-bit | words 14,15 — **8 bytes** |
| RFC 8439 ("ietf") | word 12 — 32-bit | words 13,14,15 — **12 bytes** |

`src/Crypto/chacha256.c` is the **original** variant (`ChaCha256Init` zeroes `input_[12]`/`input_[13]` and
copies exactly 8 nonce bytes to `input_[14]`). RFC 8439's vectors therefore *cannot* reproduce its
keystream, and a mismatch against them would be a **category error, not a defect** — precisely the kind of
phantom bug-hunt this document exists to prevent. VeraCrypt uses ChaCha for RNG and RAM encryption, never
for interop, so the original framing is sound; it simply is not the IETF one. The matching oracle is
libsodium's `crypto_stream_chacha20` (**not** `_ietf`), which step `[98]` uses — agreement across
zero-key, multi-block, partial-block and varied key/nonce cases, with the all-zero keystream reproducing
the well-known original-ChaCha20 value `76b8e0ada0f13d90…`.

Moral: *check which construction you actually have before deciding which standard anchors it.* An anchor
applied to the wrong variant is worse than no anchor — it manufactures false failures.

(The ChaCha *core* is also exercised indirectly by the official Adiantum vectors at `[24]`/`[89]`/`[91]`,
but via XChaCha12 inside Adiantum — not the plain construction `[6]`/`[8]` rely on.)

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
