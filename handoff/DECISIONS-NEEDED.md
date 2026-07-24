# DECISIONS NEEDED — VeraCrypt hardened fork

**How to use this:** answer inline after each `>` marker. Short answers are fine — "A", "defer", "don't
care" are all useful. Send the whole file back and I'll fold every answer into the roadmap, task
tracker and execution plan, then re-issue the handoff.

Skip anything you don't have a view on; I'll flag it as owner-deferred rather than guess.

Every question below is here because **I can't settle it from the repo, the corpus, or any published
source.** Anything I could determine myself, I already did.

---

## Section 1 — Blocking. These gate work already queued.

### D-1. Was the HKF-v2 zero salt deliberate?

The as-built v2 mix drops the volume salt from HKDF-Extract. R27's Rank-1 design specified binding it,
to get per-volume independence and close factor reuse. RFC 5869 permits a zero salt, so this isn't a
bug — but it forfeits exactly the property Rank-1 existed to deliver, and the spec says nothing about
the trade-off. The verification report could establish *what* was built but not *why*.

This is the one item in the entire pack that is unresolvable by any means except asking you.

- **A.** It was an oversight — bind the volume salt as Rank-1 specified.
- **B.** It was deliberate — I'll record the reasoning you give as an explicit trade-off.
- **C.** Don't remember / wasn't me — treat as A and re-derive.

> **Answer:**
> **If B, the reasoning was:**

---

### D-2. Recovery-share encoding — bech32m or codex32?

MAC-bearing codes run ~118 characters. bech32's 4-error guarantee dies past 89. Both replacements work;
they trade differently.

- **A. bech32m (BIP-350).** Minimal change — one constant (`0x2bc830a3`). Restores the checksum's
  integrity but *not* the length guarantee. Cheapest path.
- **B. BIP-93 codex32.** Purpose-built for exactly this: long secret-sharing codewords, corrects 4
  substitutions or 8 erasures or 13 consecutive erasures. Bigger change, materially better for
  hand-transcription.
- **C. Both** — codex32 as the default export, bech32m for anything short.

*My recommendation: B.* Your users are hand-copying these onto paper or metal under stress, and the
Höltervennhoff data says most keep exactly one copy. Error *correction* rather than mere detection is
worth the implementation cost. But A is defensible if you're schedule-constrained.

> **Answer:**

---

### D-3. Write-only ORAM — downgrade or remove?

Pass 2 closed the question of shipping it as default: no. What's left is how visible it stays.

- **A. Keep as opt-in experimental**, with an honest limits section (throughput, break history).
- **B. Remove from the roadmap entirely**, document as a researched negative result.
- **C. Keep the PoC, remove all user-facing exposure.**

*My recommendation: A or C.* The PoC has research value and the write-up is a genuine contribution;
what it shouldn't be is a "flagship" a user might enable thinking it helps them.

> **Answer:**

---

### D-4. HCTR2 promotion into `src/`

Currently verification-only, absent from `src/`. The PR #10 review flagged that promoting it inherits
the measured table-AES leak on the no-AES-NI path, and deferred the decision.

- **A. Promote now**, documenting the no-AES-NI caveat.
- **B. Defer** until the constant-time AES work lands.
- **C. Not planned** — HCTR2 stays a research artefact.

> **Answer:**

---

## Section 2 — Direction. These shape sequencing, not correctness.

### D-5. What is the actual end state?

This changes almost every priority below, and I've been inferring it rather than knowing it.

- **A. Public release** — a fork other people install. Publication hygiene (Pass 4) becomes urgent;
  so does the ristretto255 replacement.
- **B. Published research** — papers or a write-up, code as artefact. Citation accuracy is paramount;
  shippability much less so.
- **C. Personal / small-group use.** Pass 4 becomes near-worthless; engineering hardening matters most.
- **D. Undecided / exploratory.**

> **Answer:**

---

### D-6. Do you have counsel for the `[COUNSEL-REVIEW]` items?

Several conclusions are marked as needing a lawyer: the compelled-disclosure statutes, the Chia VDF
patents, the Joye–Libert question if you pursue FROST, the OPAQUE IPR disclosure, and the general
freedom-to-operate posture.

- **A. Yes** — I'll write those items up as a counsel-ready brief with specific questions.
- **B. No, and not planning to** — I'll keep marking them and never let a legal conclusion be asserted
  as settled.
- **C. Not yet, but eventually.**

> **Answer:**

---

### D-7. Which unrun briefs, in what order?

Eleven remain. I ranked **R22 (migration safety)** first — the fork's premise is that on-disk formats
never change, which makes the one seam where they might the least-examined part of the design. Then
**R06 (VDF)**, since it's already partly self-justifying.

That ranking is my inference, not your stated priority. Correct it:

- R03 memory-hard KDFs · R04 OPRF/aPAKE/PPSS · R05 threshold OPRF + refresh · R06 VDF/time-release ·
  R07 threshold sigs + DKG/VSS · R11 verifiable computation · R20 mobile PDE · R22 migration safety ·
  R23 FIPS/Common Criteria · R26 formal methods · R28 post-quantum depth

> **Run these, in this order:**
> **Never run these:**

---

### D-8. Replacing the bespoke ristretto255/Ed25519

I called this the single scariest item in the tree and put it top of the engineering backlog — hand-
rolled group arithmetic passing KATs isn't the same as being safe, and your own docs say so.

- **A. libsodium** — mature, widely deployed, easy.
- **B. HACL\* / fiat-crypto** — formally verified, better story, more integration work.
- **C. Keep and harden the bespoke implementation.**
- **D. Not a priority** — it's PoC code that will never ship.

> **Answer:**

---

### D-9. Platform priority

Both derivation paths are hooked, but effort should probably concentrate.

- **A. Linux/macOS (C++ path)** — the actual target-user platform.
- **B. Windows (C path / driver).**
- **C. Both equally.**

> **Answer:**

---

### D-10. Are on-disk format changes ever on the table?

The no-header-change property is the fork's central design win. Several backlog items — authenticated
FDE, per-sector MACs, integrity metadata — can't be done without breaking it.

- **A. Never.** Anything requiring a format change is descoped; I'll prune the backlog accordingly.
- **B. Yes, with design review**, as a v2 format alongside the compatible v1.
- **C. Undecided** — keep both branches alive in planning.

> **Answer:**

---

## Section 3 — Pace and process. Answer only if you have a preference.

### D-11. How much Pass 4 is worth doing?

~40 open items, none gating a decision. Answer depends heavily on D-5.

- **A. All of it** before anything goes public.
- **B. Priority A only** (patents/licences) — the highest-liability group.
- **C. Skip** — accept the citations as flagged-unverified.

> **Answer:**

---

### D-12. Anything in the corrections register you disagree with?

Seven queued in `docs/CORRECTIONS-REGISTER.md`. The CRC one (C-1) says a published paper is wrong; I
quoted it in full so you can check me rather than take my word. If any of the seven look wrong, say so
and I'll re-derive rather than defend.

> **Disagree with:**

---

### D-13. Anything I got wrong about the project itself?

I've inferred things from the corpus — the "research prototype, not shippable" framing, the risk
ranking, the scope-boundary interpretation. If any of that misreads what you're building, correcting it
now is cheaper than propagating it through another handoff.

> **Notes:**

---

## For my reference — what I did *not* ask you

To be explicit about the line: I didn't ask you to confirm anything checkable. The ML-KEM parameter
constraint, the ORAM throughput figures, the statute penalties, the CRC-32 reducibility, the bech32
length limit and the EME2 attribution are all settled against primary sources and recorded in
`docs/TECHNICAL-REFERENCE.md`. Those aren't decisions — they're facts, and if any turns out wrong the
fix is re-derivation, not a preference.
