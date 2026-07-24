# Deltas for the repo's existing `ROADMAP.md` and `CLAUDE.md`

House style matched: bold lead-in, parenthetical file references, honest about what isn't done.
**Splice these in — do not create parallel documents.** The repo's ROADMAP already has the right
sections and its CLAUDE.md already has the right shape.

---

## `ROADMAP.md` → append to **`## DECIDED — advisory conclusions (no code, keep for reference)`**

```markdown
- **ML-KEM parameters are frozen.** NIST's PQC licence (US Portfolio §2.9) states that "any
  modification, extension, or derivation of the parameters of the PQC ALGORITHM, is not an
  implementation or use of the PQC algorithm" — so a parameter tweak exits the royalty-free abeyance
  and re-exposes the implementer to the underlying patents. `PQ-HYBRID-SPEC.md`'s stock FIPS 203
  parameters are correct and must stay fixed. Verbatim clause in `docs/VERIFIED-CLAIMS.md`.
- **Write-only ORAM — not a default.** Measured hidden-write cost is ~72× dm-crypt (DataLair 2.92 MB/s
  vs dm-crypt 210.10 MB/s; HIVE 0.60 MB/s, PoPETs 2017 Table 1), and *both* reference systems were
  broken — HIVE's implementation via RC4 keystream bias (Paterson–Strefler, AsiaCCS 2015), DataLair's
  DL-ORAM via free-block selection bias (Roche et al., CCS 2017 §6). Opt-in experimental at most;
  revisit only for a peer-reviewed unbroken construction under ~5× overhead (`docs/ORAM-SPEC.md`).
- **EME2 is a security rejection, not a patent one.** No granted patent ever covered EME/EME2/CMC; the
  only filing (US 2004/0131182, Rogaway, Regents of the University of California) was abandoned in
  2007. Avoid it for the ~2^(n/2) birthday bound and the data-dependent multiply side channel
  (Mancillas-López et al., ICISS 2009). XCB is separately **broken** (2024, two CRYPTO 2025 papers;
  SISWG moved to remove XCB-AES from 1619.2). Verdicts unchanged — the stated grounds were wrong.
- **HCTR2 has a standardisation trajectory.** NIST SP 800-197A (pre-draft, 6 June 2025) proposes
  developing "variants of the HCTR2 technique" as the basis for its Acc128 accordion, citing HCTR2's
  maturity and deployment. Note Acc128 is itself only birthday-bound. No reason to move off HCTR2.
- **The delay/VDF slot is in scope after all.** R25's "no applicability to access control" was refuted
  by brief R06, which frames a 24–72 hour delayed recovery slot as a coercion defence outright — "an
  interrogation with a hard time limit cannot succeed" (backlog 01-44, 03-29, 14-13, 14-14). R25 had
  answered a freedom-to-operate question, which is a different question. Chia's application-layer
  patents remain open `[COUNSEL-REVIEW]`.
```

## `ROADMAP.md` → append to **`## BACKLOG — good ideas from the research, not started`**

```markdown
- **Recovery-share encoding — close the bech32 gap** (`docs/VSS-SPEC.md`). BIP-173 has an
  insertion-deletion weakness at *any* length (trailing `p`, inserted/deleted `q`), which BIP-350
  bech32m fixes with one constant (`0x2bc830a3`). Separately, MAC-bearing codes reach ~118 chars,
  outside the 89-char guarantee window the spec already flags. Options: bech32m (one line), the
  SLIP-39-style segmenting the spec already proposes, or BIP-93 codex32 (corrects rather than detects).
- **Re-authentication on resume.** The genuinely missing suspend-path piece: `PrepareForSleep` appears
  only in comments and `StartLogindScreenLockMonitor()` is called but never defined.
- **Replace the bespoke ristretto255/Ed25519** with libsodium or HACL*/fiat-crypto. Hand-rolled group
  arithmetic passing KATs is not the same as being safe, and this project's own notes say so.
- **Authenticated FDE** — per-sector or per-extent authentication. HCTR2 diffuses tampering; it does
  not detect it. This is the largest structural gap.
- **YubiKey firmware pinning / EUCLEAK awareness.** Firmware below 5.7 is affected (ePrint 2024/1380).
- **HQC as the code-based PQ hedge.** NIST-selected 11 March 2025 (IR 8545); draft expected 2026.
```

## `ROADMAP.md` → append to **`## Known limitations / honest threat model`**

```markdown
- **Flash sanitization is unreliable and we do not promise otherwise.** Wei et al. (FAST 2011) found
  4–75% of file contents surviving single-file overwrite on SATA SSDs, 0.57–84.9% on USB, and 1%
  surviving 20 whole-disk overwrites on one drive. Rely on FDE plus verifiable ATA/NVMe sanitize.
- **Multi-snapshot detection of hidden volumes is a solved attack.** Fredrickson–Barker–Long
  (MASCOTS 2021, arXiv 2110.04618): "hidden volumes in excess of 0.75 GB are always identified
  successfully." Deniability against a multi-snapshot adversary should be claimed cautiously or not at
  all.
- **The constant-time measurements are single-environment.** The 408 / 1000+ error counts in
  `CT-HARDENING-R17.md` come from one machine, one valgrind, one container, x86-64. Not generalisable,
  and not worth further research budget — worth continued honesty.
```

---

## `CLAUDE.md` → append to **`## Verification methodology (the project's convention — keep it)`**

```markdown
**Source-checkable vs repo-checkable.** Some claims cannot be settled by reading code — patent status,
licence terms, published-paper contents, statutes, recent vendor statements. Those live in
`docs/VERIFIED-CLAIMS.md` with their sources, and the ones still open are listed there too. Keep the
two classes separate: a defect in a research report is not automatically a defect in the tree. Several
"corrections" carried over from the research pack turned out to have no target here because the repo
was already correct — `CRC-SEAM-ADDENDUM.md` in particular reasons about injectivity directly rather
than repeating Stigge et al.'s false irreducibility claim.

**Don't resolve unverifiable claims.** "Unverifiable from available sources" is a correct output. A
plausible guess is not. If a search fails, record that it failed.
```

## `CLAUDE.md` → append to **`## Conventions`**

```markdown
- **Deliverables go in files with readable names.** Two verification reports in this project were
  nearly lost because they existed only as chat artifacts under opaque `compass_artifact_…` filenames.
- **`0 SKIP` is part of the gate**, not just exit 0. The suite once reported success while skipping 13
  of 48 steps, one of which masked a genuine failure.
- **Absence claims get re-derived by reading the module**, never asserted from a grep. One confirmed
  error in this project's history came from a malformed search followed by asserting a negative from it.
```
