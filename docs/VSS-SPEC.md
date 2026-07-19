# Feldman verifiable secret sharing — catch a cheating dealer

**Status: scheme proven two ways; enrollment/CLI wiring is real-build.** Addresses
`IDEAS-BACKLOG.md` "Sharing" row (Feldman/Pedersen VSS, SLIP-39), extending the plain Shamir split
already proven at step `[5]`.

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

## Integration & honest notes

- **Where it plugs in.** The Shamir factor (`Common/Shamir.c`, step `[5]`) gains a commitment vector at
  enrollment and a share-check at reconstruction. Publishing the commitments (header field or sidecar)
  and the enroll/verify CLI are the real-build items.
- **Feldman vs Pedersen.** Feldman's commitments are computationally hiding; Pedersen VSS adds a
  blinding term for information-theoretic hiding of the secret. Feldman is proven here as the simpler,
  most common choice; Pedersen is a drop-in extension if the stronger hiding is wanted.
- **Undersized PoC prime.** 256-bit safe prime is a PoC parameter; production uses ≥3072-bit (or an
  elliptic-curve group). The group must have a known large prime-order subgroup, as here.
- **Scope.** Verifiable split-trust over the user's own key material — access-control, inside the
  project boundary.
