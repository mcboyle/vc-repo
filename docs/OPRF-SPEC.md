# OPRF password hardening — design & status

**Status: protocol proven (toy field `[17]`), at production parameters over the full ristretto255
group (`[43]`), AND the threshold OPRF/PPSS split proven over that group (`[44]`); the rate-limited
servers + transport are real-build.** An Oblivious PRF (2HashDH / CFRG DH-OPRF) makes the derived key
depend on both the **password** and a **secret held by a rate-limited server**, while the server
learns neither the password nor the output. Consequence: a **stolen disk
cannot be brute-forced offline** — every password guess needs one online query the server can
rate-limit or lock out. `IDEAS-BACKLOG.md` §C calls this "the most powerful realistic anti-brute-force
primitive available"; it composes with the Shamir factor as a **threshold OPRF / PPSS** (split the
server role across several servers so none is trusted).

## Why this is different from the network-bound share (McCallum–Relyea)

Both blind a value against a server key, but the purpose differs:

- **Network-bound share (`docs/NETWORK-SHARE-SPEC.md`)** recovers a *stored* secret `K = g^{s·c}` with
  server help; it binds unlock to server *presence*.
- **OPRF (here)** hardens the *password itself*: the output `F = H(pw, H2(pw)^k)` cannot be computed
  offline without the server's `k`, so it defeats **offline dictionary attack** on a seized disk. The
  server never receives `pw` or `F`, so a compromised server cannot crack passwords either.

## The protocol

```
public:  prime p, prime order q, generator g of the order-q subgroup
server:  secret k in [1, q-1]
H2(pw) = g^( int(SHA256("h2" || pw)) mod q ) mod p        # hash the password to a group element
blind:  r in [1, q-1];  A = H2(pw)^r mod p                # client -> server (blinded; hides pw)
eval:   B = A^k mod p                                      # server (sees only A)
unblind:U = B^(r^-1 mod q) mod p = H2(pw)^k mod p          # client removes the blind
output: F = SHA256("oprf" || pw || U)                      # the hardened key, fed into the KDF seam
```

The unblinding works because `B^{1/r} = (H2(pw)^{r·k})^{1/r} = H2(pw)^k`, independent of the random
blind `r` — so the output is a deterministic PRF of `(pw, k)` while every message to the server is
freshly randomized.

## What the PoC proves (`verification/oprf_poc.c` + `oprf_reference.py`, step `[17]`)

Proven two ways — the C PoC drives the **real in-tree SHA-256 (`Sha2.c`)**, an independent Python
reference (bigint + hashlib) reproduces it **byte-for-byte** (anchor `ca5691bd…`):

- **Deterministic PRF, blind-independent** — two different blinds `r1, r2` give **the same** output `F`.
- **Server-oblivious** — the messages `A(r1)` and `A(r2)` **differ** and neither equals `H2(pw)`; the
  server sees only a fresh blinded element, never the password or the output.
- **Offline-guessing resistant** — a wrong server key `k` yields a **different** output, so without the
  server nothing is computable.
- **Password-bound** — a different password yields a different output.

The PoC group is `p = 17592186046427` (45-bit, prime order `q`) so modular multiply fits `__int128`;
the OPRF identity is size-independent, so this proves the protocol, not the parameters.

## Production-parameter group — proven (step `[43]`)

The CFRG ciphersuite group is no longer just named — it is implemented and proven. Step `[43]`
(`verification/oprf_ristretto_poc.c`) runs **DH-OPRF over the full ristretto255 group**
(RFC 9497 `OPRF(ristretto255, SHA-512)`): a from-scratch ristretto255 (RFC 9496 encode + Elligator2
map) with `expand_message_xmd(SHA-512)` (RFC 9380), built on the step-`[39]` edwards25519 field, over
the real in-tree `Sha2.c`. Validated three ways:

1. **Official KAT** — the ristretto255 encodings of `1B..5B` reproduce RFC 9496 Appendix A.1
   ("multiples of the generator") exactly, anchoring the group + encode + scalar-mult to the standard.
2. **Two-way** — `Blind`/`Evaluate`/`Finalize` (`blindedElement`, `evaluatedElement`, and the SHA-512
   `output`) diffed byte-for-byte against the independent `oprf_ristretto_reference.py`.
3. **Properties** — the OPRF identity (`r⁻¹·(k·(r·P)) == k·HashToGroup(input)`), blind-independence
   (a fresh blind gives the same output), wrong-server-key-differs, and server-sees-only-blinded-element.

**Third oracle + a hash-to-group finding (D-8, step `[94]`).** A libsodium cross-check
(`verification/ristretto255_libsodium_xcheck.c`) was added as an independent third oracle for the group,
pinned to RFC 9496 **A.1 and A.2**. It confirmed the group-**encoding** + base-scalar-mult layer three
ways — **from-scratch == libsodium == RFC 9496 A.1** — but it also **surfaced a defect**: the bespoke
**hash-to-group** (the ristretto255 Elligator map + point-add) **diverges from RFC 9496 / libsodium**.
libsodium reproduces the official RFC 9496 **A.2** hash-to-group vector exactly; the from-scratch map does
not. The two existing oracles missed this because the C PoC and its Python twin share the same convention
and the KAT above only exercises A.1 (base multiples), which do not touch hash-to-group. Consequences:
the from-scratch OPRF is **internally self-consistent** (the properties above all hold, because Blind /
Evaluate / Finalize use the same map), but its `HashToGroup` — and therefore its OPRF outputs — would
**not interoperate with an RFC 9497 server**. This is not chased to root-cause here because **D-8**
replaces the bespoke group with libsodium (which this oracle pins to the RFC), deleting the divergent map;
the finding is recorded so the "reproduces RFC 9497" framing is not over-read. The same map is shared by
`toprf_ristretto_poc.c` and `voprf_ristretto_poc.c`, so the finding applies to all three.

**Finding resolved — RFC 9497 conformance on libsodium (step `[95]`).** The OPRF(ristretto255, SHA-512)
chain rebuilt on libsodium (`verification/oprf_ristretto255_rfc9497.c`) reproduces the **official CFRG
RFC 9497 Appendix A.1.1 vectors** — `BlindedElement`, `EvaluationElement`, and `Output` — byte-for-byte
for both vectors, including the `expand_message_xmd(SHA-512) → crypto_core_ristretto255_from_hash`
`HashToGroup` that the from-scratch map got wrong. Crucially this anchors to the **standard's own
vectors**, not a self-consistent Python twin, so a hash-to-group that is merely internally consistent
cannot pass — it is exactly the check that would have caught the original bug. The bespoke-map divergence
stands as documented above; D-8's libsodium adoption is now **proven conformant in the verification
layer** (the product OPRF / network-share swap to libsodium remains real-build).

**VOPRF/POPRF too, including the DLEQ proof (step `[96]`).** The verifiable family is proven conformant on
libsodium against the official RFC 9497 **A.1.2 (VOPRF)** and **A.1.3 (POPRF)** vectors
(`verification/voprf_poprf_ristretto255_rfc9497.c`): HashToGroup + chain, the **DLEQ proof** of RFC 9497
§2.2 (`VerifyProof` accepts the official `Proof`, `GenerateProof(ProofRandomScalar)` reproduces its bytes),
a tampered-`EvaluationElement`-rejected negative, and POPRF's Info-tweaked key (`tweakedKey == T·G + pkS`).
With step `[95]` this resolves the step-`[94]` hash-to-group finding for all three ristretto255 PoCs
(`oprf`/`voprf`/`toprf`).

**Verifiable mode (VOPRF) — proven (step `[47]`).** In verifiable mode the server commits a public
key `pk = k·G` and, with each `EE = k·BE`, proves in zero knowledge (Chaum–Pedersen / **DLEQ**) that
the *same* `k` relates `(G, pk)` and `(BE, EE)`. The client verifies before finalizing, so a server
that swaps in a different key — or a MITM that tampers with `EE` — is **caught, not silently trusted**.
`verification/voprf_ristretto_poc.c` implements GenerateProof (`a1=rr·G`, `a2=rr·BE`, `c=challenge`,
`s=rr−c·k`) / VerifyProof over the step-`[43]` group: the proof `(c,s)` + `pk` diff byte-for-byte vs
Python (fixed nonce), a valid proof verifies, and both a tampered `EE` and a wrong committed key are
rejected. (The exact RFC 9497 verifiable-mode transcript with batched composites stays real-build;
this is a faithful single-element DLEQ.)

**Scope of the defect — check this claim, don't take it on trust:** `grep -rliE 'ristretto|oprf' src/`
returns **nothing**. No shipped product code implements or calls the OPRF, so **no user-reachable code path
uses the non-conformant map** — it exists only under `verification/`. The step-`[94]` finding is therefore
a defect in *research code*, not a live exposure, and D-8's "product swap" is a **constraint on future
work** (when the OPRF / network-share feature is built into the product, build it on libsodium) rather
than a repair of something users run today. This distinction must not erode as green PRs accumulate: three
merged conformance PRs prove the *verification layer* is RFC-correct, and prove nothing about a shipped
feature that does not yet exist.

**Still real-build / not shipping:** the from-scratch group is RFC-anchored **on the encoding + scalar
layer (A.1)** — but its hash-to-group diverges from the RFC (finding above), and it is **not
constant-time** (validation, not deployment); a shipping build uses a side-channel-hardened
ristretto255/P-256 (or delegates), plus the rate-limited server, the transport, full RFC 9497
end-to-end test vectors, and the threshold split below.

## Shipping parameters & integration (real-build)

- **Real group.** Use a CFRG prime-order group — **ristretto255** (proven at step `[43]`) or NIST
  P-256 — via a side-channel-hardened implementation, never the PoC field. The construction is exactly
  the CFRG OPRF (RFC 9497).
- **Threshold OPRF / PPSS — proven at production parameters (step `[44]`).** Split `k` across `n`
  servers (each holds a share `k_i`); the client combines partial evaluations so no single server can
  compute or crack. Step `[44]` (`verification/toprf_ristretto_poc.c`) proves this **over the full
  ristretto255 group** (composing step `[43]`): the server key is Shamir-split over the scalar field
  `Z_L` (degree `t-1`), each server returns a partial `k_i·BE`, and any `t` combine by
  Lagrange-in-the-exponent to `k·BE` — reconstructing **exactly the single-key OPRF output**
  (byte-identical), while `t-1` partials give a different value and no server sees the password or the
  unblinded element. Diffed byte-for-byte vs an independent Python (3-of-5), group anchored to the RFC
  9496 KAT. The rate-limited servers + transport remain real-build. This is the natural fit with the
  Shamir factor already built.
- **KDF seam.** `F` becomes a `RAW_SECRET`-style factor (mixed into the password before PBKDF2/Argon2),
  or a keyslot passphrase — no new derivation seam.

## Honest limits

- **Availability.** No server (or fewer than the threshold) → no unlock. Deploy as one factor among a
  recoverable set, exactly as advised for the network-bound share.
- **Post-quantum.** The DH-OPRF transcript is quantum-exposed; a stored transcript could be attacked by
  a future quantum adversary. Hybridize (see the PQ item in `IDEAS-BACKLOG.md` §H) for long-term
  secrets.
- **Trust-on-provision & metadata.** Pin the server's parameters at enrollment; the server still learns
  *that* a query happened and can rate-limit — which is the point — so treat query metadata as sensitive.
- **Not deniable.** This is anti-brute-force access control, not hidden-volume deniability.
