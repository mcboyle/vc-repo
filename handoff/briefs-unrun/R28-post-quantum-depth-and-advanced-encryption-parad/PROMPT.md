# R28 — Post-quantum depth and advanced encryption paradigms

**Paste this entire file into a new chat.**

---

## Context

**Project context.** I maintain a private fork of VeraCrypt 1.26.29 that hardens *key derivation*.
Core architecture: an extra secret is mixed into the password **before** PBKDF2/Argon2, using
VeraCrypt's own keyfile pool method (a rolling CRC-32 accumulated into a 128-byte pool by modular
addition, then `password[i] += pool[i]`). Because of this, added factors require **no on-disk header
change**. Already built and verified: BLAKE2b-512 and SHA3-512 PRFs; a hardware-factor module
(YubiKey HMAC-SHA1, FIDO2 hmac-secret, and a raw-secret backend); constant-time Shamir M-of-N
threshold sharing over GF(2⁸); a factor-gated decoy (the outer volume opens with the password alone,
the hidden volume additionally requires the factor); multiple keyslots with anti-forensic splitting;
cross-platform key scrubbing; a non-destructive duress dismount; explicit Argon2id parameters; and
proof-of-concept implementations of write-only ORAM, threshold-OPRF, McCallum–Relyea network
binding, Merkle integrity, and an ML-KEM hybrid combiner. Constraints: every crypto change is
verified twice (against an independent reference implementation *and* against real compiled
objects); features are compile-time gated so a default build stays byte-for-byte stock; on-disk
format changes require explicit design review. Users are high-risk individuals (journalists,
activists) plus ordinary privacy-conscious people. **Scope boundary:** this is confidentiality,
integrity, access control, and deniable *storage*. It does **not** include tooling that fabricates a
false record of user activity to deceive forensic examination — permanently out of scope. Give me
the honest state of the art, including where a technique does **not** apply; a well-argued negative
result is a valuable outcome.

## Research question

Two connected questions. **First, post-quantum.** My symmetric, password-derived disk encryption
needs no PQ migration — there is no key exchange for Shor to break and no ciphertext in transit to
harvest, and Grover only halves an already-256-bit key. But I have introduced asymmetric crypto in
two places: a Diffie–Hellman-based network-binding exchange whose transcripts could be stored, and
public-key recovery/escrow slots that are directly harvest-now-decrypt-later exposed. Cover: hybrid
KEM construction and combiner choice (X25519 + ML-KEM-768), Classic McEliece as a conservative
alternative given key sizes are irrelevant inside a header, stateful hash-based signatures (XMSS,
LMS) versus SLH-DSA for header or boot signing and the state-management hazard, the isogeny situation
after the SIDH break, whether a QRNG adds anything, and whether QKD has any applicability here (I
suspect none — say so if so). **Second, advanced paradigms for storage.** Assess which are practical
today: updatable encryption (rotating the volume key without re-encrypting the body — this would be
genuinely transformative for me), puncturable and forward-secure encryption, key-insulated and
intrusion-resilient schemes, leakage-resilient constructions, incompressible/big-key encryption in
the bounded-retrieval model, proxy re-encryption for delegating access, and attribute-based
encryption for policy-driven keyslots. For each: is there a working implementation, and at what cost?

## Deliverable

Deliver: (a) a ranked shortlist of viable approaches with the strongest reference for each;
(b) concrete parameters/algorithms if I were to implement the top choice; (c) known attacks,
limitations and failure modes; (d) an explicit recommendation — including "don't do this" if that is
the honest answer; (e) full citations. Prefer peer-reviewed sources and IETF/NIST specs. Flag
anything unimplemented, withdrawn, or broken. Say clearly when the evidence is thin rather than
guessing, and distinguish what is deployed in production somewhere from what exists only on paper.