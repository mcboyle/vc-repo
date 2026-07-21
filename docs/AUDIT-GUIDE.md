# Reviewer's guide — the front door for a security review

One page that points an external reviewer at everything, in reading order, and is honest about what is
proven, what is argued, and what is not done. This fork is **defensive** access-control cryptography for
a VeraCrypt derivative; it strengthens password entropy and never changes the on-disk header format.

## Read in this order

1. **`CLAUDE.md`** — architecture (the one seam: mix an extra secret into the password before
   PBKDF2/Argon2) and the **scope boundary** (evidence *fabrication* is deliberately excluded).
2. **`docs/THREAT-MODEL.md`** — the authoritative threats, assumptions, and honest limits.
3. **`docs/THREAT-CONTROL-MAP.md`** — each threat → the control that answers it → where it's verified →
   the residual limit; plus the **public API surface** (the stable gated entry points to review).
4. **`docs/SESSION-SUMMARY.md`** — the index: every proven anchor value and its verification step.
5. **`docs/FORMAL-ANALYSIS.md`** — the pen-and-paper security arguments (DDH / one-more-gap-DH / ROM)
   and the mechanization plan; note the honest "not mechanized here" status.
6. The per-feature **`docs/*-SPEC.md`** for anything you want to go deep on — each states its status
   and its honest limits.

## How to check the claims yourself

```sh
cd verification && ./build_and_verify.sh     # steps [1]..[48]; proves each crypto claim two ways
```

Each step diffs real compiled VeraCrypt objects against an *independent* Python reimplementation and,
where a standard exists, an **official KAT** (RFC 8032/9496 for the EC groups, RFC 9106 Argon2, FIPS 203
ML-KEM, Google KATs for the wide-block modes, BIP-173 for the share codes, etc.). The anchors are listed
in `docs/SESSION-SUMMARY.md`.

## What is proven vs. argued vs. not done (be precise)

- **Proven (machine-checked here):** functional correctness + algebraic-security *properties* of every
  crypto component, byte-for-byte and KAT-anchored. This is the strong part.
- **Argued (pen-and-paper):** the reduction-style secrecy proofs in `docs/FORMAL-ANALYSIS.md`. Not
  mechanized — a computational prover (CryptoVerif/EasyCrypt) is the pending step.
- **Not done (real-build / hardware):** mount-path wiring, CLIs, the network/OPRF servers + transports,
  and all device/OS-trigger validation — enumerated in `docs/REAL-BUILD-VALIDATION.md`.

## Two things a reviewer should weigh explicitly

- **From-scratch EC/group code (Ed25519, ristretto255) is validation-only** — correct against the
  official KATs but **not constant-time**. A deployment must swap in a vetted, side-channel-hardened
  library. It exists to prove the fork reproduces the standard, not to ship.
- **"48 steps pass" ≠ "48 features shipped."** The suite proves the crypto; the product integration is
  the separate, larger, still-open real-build work. Judge the fork on the specs' honest-limits sections,
  not the checkmark count.

## Scope reminder

Confidentiality / deniability *storage* and access control are in scope. Automated **evidence
fabrication** (forged activity records) is permanently out of scope and not built (`CLAUDE.md`,
`docs/DECOY-VOLUME-SPEC.md §6`). The deniability claims are about indistinguishable-random storage, with
the multi-snapshot / SSD / imaged-first caveats stated in `docs/THREAT-MODEL.md`.
