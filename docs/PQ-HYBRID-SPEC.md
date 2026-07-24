# ML-KEM-768 + hybrid combiner — post-quantum hedge for the asymmetric exchanges

**Status: ML-KEM-768 proven against the NIST ACVP vectors; the hybrid seam is defined and proven; wiring
into the network-share/OPRF protocols is real-build.** Addresses `IDEAS-BACKLOG.md` §H.

## The gap it closes

The fork's *symmetric* core (AES/XTS, ChaCha, the KDFs) is already post-quantum-safe at the 256-bit
level — Grover halves the exponent, nothing more. The quantum exposure is the **asymmetric exchanges**:
the McCallum–Relyea network-bound share (`docs/NETWORK-SHARE-SPEC.md`) and the OPRF password hardening
(`docs/OPRF-SPEC.md`) both rest on discrete-log-type assumptions that Shor's algorithm breaks outright.
The realistic attack is **harvest-now-decrypt-later**: record the blinded exchanges today, decrypt them
when a cryptographically relevant quantum computer exists, and recover the share/hardening secret —
retroactively weakening volumes whose passwords leaned on those factors.

The standard remedy is a **hybrid**: run the classical exchange *and* a post-quantum KEM, and derive the
working secret from **both**, so an adversary must break both to learn anything. ML-KEM-768 (FIPS 203,
the standardized Kyber, NIST security category 3) is the KEM; the combiner is an HMAC over both shared
secrets bound to the KEM transcript.

## Construction

```
ML-KEM-768 (FIPS 203): n=256, q=3329, k=3, eta1=eta2=2, du=10, dv=4
  KeyGen(d, z)  -> ek (1184 B), dk (2400 B)          H=SHA3-256, G=SHA3-512, J=SHAKE256
  Encaps(ek, m) -> c (1088 B), K (32 B)
  Decaps(dk, c) -> K   — with implicit rejection: a tampered c yields J(z || c), not an error oracle

Hybrid combiner (the fork's seam):
  ss_hybrid = HMAC-SHA256( key = ss_classical || ss_mlkem,
                           msg = "VC-HYBRID-v1" || SHA256(ek) || SHA256(c) )
```

Binding the transcript (`ek`, `c`) into the message follows the KEM-combiner literature (Giacon–
Heuer–Poettering; draft-ietf-tls-hybrid-design): it prevents mix-and-match across sessions. The
combiner is a PRF keyed by the concatenated secrets, so **either** secret remaining unknown keeps the
output pseudorandom — a quantum break of the classical exchange, or a future ML-KEM break, alone
reveals nothing.

## Parameter licence — do not alter the ML-KEM parameters (R-5)

The parameters in the Construction block above (`n=256, q=3329, k=3, eta1=eta2=2, du=10, dv=4`) are the
FIPS-203 ML-KEM-768 set and **must stay fixed.** This is a *licensing* constraint, not only a security
one. NIST's US-Portfolio patent licence for the standardized PQC algorithms is royalty-free only for
implementations that meet the definition of the standardized algorithm. Quoting §2.9 verbatim:

> "For the sake of clarity, any implementation or use of the LICENSED PATENT by LICENSOR, SUBLICENSEE
> or any of the party that does not meet the definition of the PQC ALGORITHM, including any
> modification, extension, or derivation of the parameters of the PQC ALGORITHM, is not an
> implementation or use of the PQC algorithm."

Consequence, in one line: **altering the ML-KEM parameters exits the royalty-free abeyance** and
re-exposes the implementer to the underlying patents. Any proposal to tune these values is therefore an
FTO question for the counsel brief (`docs/COUNSEL-BRIEF.md`), not a routine parameter change. This
constraint must survive staff turnover — it is the reason the numbers are frozen, recorded here so no
future reader "optimizes" them. `[COUNSEL-REVIEW]`

## What the PoC proves (`verification/mlkem_poc.c` + `mlkem_reference.py`, step `[25]`)

Three-way agreement against the primary authority:

1. **NIST ACVP FIPS-203 vectors** (`verification/mlkem_kats.{h,py}`, extracted from usnistgov/
   ACVP-Server): 4 keyGen cases `(d,z) → (ek,dk)` reproduced byte-exactly (anchor `SHA256(ek₀) =
   4158f6af…`); 4 encapsulations `(ek,m) → (c,K)`; **all 10 decapsulations, including the 5
   modified-ciphertext cases** — the implicit-rejection path returns exactly the expected
   `J(z‖c)` secret (anchor `K₀ = 9652336b…`), proving the tamper path, not just the happy path.
2. **Real in-tree objects**: the C PoC's Keccak is verified lane-for-lane against the real in-tree
   `Crypto/Sha3.c` on inputs straddling the rate boundary (`CHK sha3_512_intree_match YES`), and the
   combiner's HMAC-SHA256 runs on the real `Crypto/Sha2.c`.
3. **Independent Python** (`mlkem_reference.py`, hashlib-only): byte-identical `^REF` output (32 lines).

Hybrid properties (anchor tag `5f44c605…`): flipping one bit of the *classical* secret changes the
output, and flipping one bit of the *ML-KEM* secret changes the output (`hybrid_needs_both`) — the
either-alone-is-useless property the hedge exists for.

## Integration & honest notes

- **Where it wires in.** The network-share enrollment gains an ML-KEM keypair alongside the MR/OPRF
  state: enrollment stores `ek` server-side (or on the share medium), unlock runs classical exchange +
  `Encaps`, and the reconstructed share becomes `ss_hybrid`. The salt-binding path
  (`docs/SALT-BINDING-SPEC.md`) then ties it to the volume as today. Client transport work is the same
  real-build item the network-share spec already tracks.
- **The classical secret in the PoC is modeled** (deterministic 32 bytes) — the real one is the proven
  MR/OPRF output. The combiner does not care which classical exchange feeds it.
- **Production implementation.** This PoC is plain-C for clarity and correctness (KAT-forced); a
  shipping build should use a vetted constant-time ML-KEM (e.g. the reference `libcrux`/BoringSSL
  implementations) behind the same seam. Decaps here compares `c` with `memcmp` — real code must select
  in constant time.
- **Sizes are the cost**: +1184 B public key, +1088 B ciphertext per enrollment/exchange — trivial for
  a network protocol, and nothing touches the volume header.
- **No PQ signatures needed**: the fork has no signature surface; confidentiality-side KEM hybrid is the
  complete PQ story here.
- **Scope.** Hardening the key-establishment path of the user's own volumes — inside the access-control
  boundary.
