# Verifiable secret sharing — authenticated shares + catch a cheating dealer

**Status: keyed per-share MAC built & proven (`[40]`); Feldman/Pedersen dealer-consistency proven
two ways (`[31]`/`[32]`); enrollment/CLI wiring is real-build.** Addresses `IDEAS-BACKLOG.md`
"Sharing" row (keyed per-share MAC, Feldman/Pedersen VSS, SLIP-39), extending the plain Shamir split
proven at step `[5]` and its CRC-32 checksum. See "Two complementary guarantees" below for why the
share-MAC lives in GF(2⁸) with the shipping shares while dealer-consistency VSS is a prime-field scheme.

## The gap it closes

Plain Shamir (step `[5]`) assumes an honest dealer. A malicious or buggy dealer can hand out
**inconsistent** shares: different `t`-subsets then reconstruct different secrets, and nobody notices
until a reconstruction silently yields the wrong key. Feldman VSS (1987) makes the split
**verifiable**: the dealer publishes commitments to the polynomial coefficients, and every shareholder
checks its own share against them — catching a cheat at distribution time, without any shareholder
learning the secret.

## Construction

Over the order-`q` subgroup of `Z_p*` (`p` a safe prime, `g` a generator of order `q`):

```
f(x) = s + a_1 x + ... + a_{t-1} x^{t-1}   (mod q),   share_i = (i, f(i))
C_j  = g^{a_j} mod p          (a_0 = s)         — public commitments
verify i:   g^{share_i}  ==  prod_{j=0}^{t-1} C_j^{(i^j mod q)}   (mod p)
```

The verification identity holds iff `share_i = f(i)` for the *same* polynomial the commitments describe,
so an inconsistent share fails. The commitments are hiding (they reveal only `g^{a_j}`, not `a_j`), so
verification leaks nothing about the secret.

## What the PoC proves (`verification/feldman_poc.c` + `feldman_reference.py`, step `[31]`)

No standard KAT, so the proof is dual-implementation agreement plus the verifiability properties.
`feldman_poc.c` (256-bit fixed-width bignum with a modulus-parameterized `mulmod`/`powmod` and a
Fermat modular inverse) and `feldman_reference.py` (Python bigint) agree **byte-for-byte** on all
commitments and shares of a 3-of-5 split, and both assert: every honest share verifies against the
commitments (`all_shares_verify`); a single-bit-tampered share is **rejected** (`tampered_share_rejected`
— the property Shamir lacks); any `t` shares reconstruct the secret (`reconstruct_t`); and `t-1` shares
reconstruct a wrong value (`below_threshold_wrong`).

## Two complementary guarantees — and why they use different fields

There are two distinct threats to a threshold split, and they need different machinery:

1. **A tampered or fabricated *share*** (an attacker flips, truncates, relabels, or invents a share).
   Caught by a **keyed per-share MAC** — and this integrates directly with the shipping GF(2⁸) Shamir.
2. **A cheating *dealer*** (hands out shares that do not all lie on one polynomial, so different
   `t`-subsets reconstruct different secrets). Caught by **Feldman/Pedersen VSS** — which requires a
   prime-order group's homomorphism and therefore is a *parallel* scheme, not a GF(2⁸) add-on.

### 1. Keyed per-share MAC — built & proven (step `[40]`)

`src/Common/ShamirMac.{c,h}` (gated `-DVC_ENABLE_SHAMIR_MAC`, kept out of `Shamir.c` so that module
stays standalone) tags each share `tag = HMAC-SHA256(macKey, "VCSMshare1" ‖ x ‖ len ‖ y[0..len))`
over the in-tree `Sha2.c`. A bit-flipped, truncated, x-relabelled or fabricated share is rejected,
and the wrong MAC key rejects; `ShamirVerifyAll` checks every share with no early-out (no
which-share leak). Proven two ways in step `[40]`: the real compiled `Shamir.c + ShamirMac.c` vs an
independent Python (`hmac` + a reimplemented GF(2⁸) split), tags diffed byte-for-byte. This is the
adversarial upgrade over the CRC-32 `shamir_secret_checksum`, which only detects *accidental*
corruption. It authenticates shares against a key the holders share; it does **not** substitute for
the threshold (a below-threshold set of MAC-valid shares still reconstructs the wrong secret — tested).

### 2. Feldman/Pedersen dealer-consistency — the prime-field scheme (steps `[31]`/`[32]`)

- **Why it can't be a GF(2⁸) add-on.** Feldman's verification identity is `g^{share_i} == ∏ C_j^{i^j}`
  in a prime-order group; the whole point is the homomorphism between the exponent field (where the
  polynomial lives) and the group (where the commitments live). GF(2⁸) has no such public-key
  homomorphism, so dealer-consistency verification is a **second, prime-field sharing scheme**, exactly
  as `IDEAS-BACKLOG.md` §D notes ("needs a prime-order group — a second sharing scheme"). It is proven
  in its own right at steps `[31]` (Feldman) / `[32]` (Pedersen).
- **Feldman vs Pedersen.** Feldman's commitments are computationally hiding; Pedersen VSS adds a
  blinding term for information-theoretic hiding of the secret. Feldman is the simpler, most common
  choice; Pedersen is the drop-in extension if the stronger hiding is wanted.

### Integration (real-build)

- The per-share MAC composes with the split-key factor now: MAC the shares at enrollment, ship the
  `macKey` in the recovery kit (or derive it from an enrollment passphrase), verify before
  `shamir_combine`. Publishing the tags (recovery kit / sidecar) and the enroll/verify CLI are the
  remaining real-build wiring.
- For dealer-consistency, the Shamir factor gains a commitment vector at enrollment and a share-check
  at reconstruction using the prime-field VSS; publishing the commitments and its CLI are real-build.
- **Undersized PoC prime.** 256-bit safe prime is a PoC parameter; production uses ≥3072-bit (or an
  elliptic-curve group). The group must have a known large prime-order subgroup, as here.
- **Scope.** Verifiable split-trust over the user's own key material — access-control, inside the
  project boundary.
