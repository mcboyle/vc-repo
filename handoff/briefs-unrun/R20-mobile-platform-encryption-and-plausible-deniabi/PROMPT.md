# R20 — Mobile platform encryption and plausible deniability

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

Survey what is genuinely possible for an encrypted-container app on modern Android and iOS: the
file-provider and FUSE-equivalent APIs available, background execution and access limits, hardware
keystore and StrongBox integration, and what the OS forces you to expose. Then cover the academic
plausibly-deniable-encryption-on-mobile literature (Mobiflage, MobiPluto, MobiGyges) including the
flash-specific attacks that broke several of these schemes. Also compare per-file encryption layouts
(Cryptomator, gocryptfs) against container layouts for cloud-sync friendliness. Concretely: is a
read-only mobile viewer feasible today, and what would a write path additionally require?

## Deliverable

Deliver: (a) a ranked shortlist of viable approaches with the strongest reference for each;
(b) concrete parameters/algorithms if I were to implement the top choice; (c) known attacks,
limitations and failure modes; (d) an explicit recommendation — including "don't do this" if that is
the honest answer; (e) full citations. Prefer peer-reviewed sources and IETF/NIST specs. Flag
anything unimplemented, withdrawn, or broken. Say clearly when the evidence is thin rather than
guessing, and distinguish what is deployed in production somewhere from what exists only on paper.