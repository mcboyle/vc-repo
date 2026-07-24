# Claude Code kickoff — Tier 0

Paste into Claude Code from the root of a clean checkout of `github.com/mcboyle/vc-repo` at `master`
(`3ec5ec1` or later). This runs the six no-dependency tasks from `TASK-TRACKER.md`. Do **not** start
Tier 1+ — those gate on a v2-format design review.

---

You are working in the VeraCrypt hardened fork. Thirteen owner decisions were just resolved; the
authoritative record is `handoff/DECISIONS-ANSWERED.md` and `handoff/TASK-TRACKER.md`. Your job this
session is **Tier 0 only** (T0-1 through T0-6). Follow the repo's existing conventions — read
`CLAUDE.md` and `ROADMAP.md` first.

## Ground rules

1. **Verify the target before editing.** This project's hardest-won lesson: a defect in a research
   report is not automatically a defect in the code. `grep`/read the actual file before writing any
   patch. If the claimed defect isn't there, record that as a finding and move on — do not "fix" a
   correct file.
2. **No legal conclusion is asserted as settled.** Anything touching patents, statutes, or FTO is phrased
   as an open question and routed to the counsel brief (T0-6). "No patent basis was found" — never "there
   is no patent problem."
3. **Two-way verification for any crypto change.** (No crypto changes in Tier 0, but keep the convention
   in mind — Tier 2 will need independent reference cross-checks.)
4. **Scope boundary holds.** Confidentiality / integrity / access control / deniable storage only.
   Nothing that fabricates a false record of user activity. The A-1 SSD warning defends against a
   distinguisher; it does not manufacture history.
5. Work on a branch. Small, reviewable commits, one task per commit, message prefixed with the task ID.

## Tasks

**T0-1 — verify the prompt patch.** `prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` around line 21 previously read
"UC San Diego's US 2004/0131182." It should now name the **Regents of the University of California**
(Rogaway is **UC Davis**) and say **"no patent basis found,"** not "no patent problem." Confirm the fix
is present; if the file still shows the old text, patch it. This is documentation provenance — verify,
don't assume.

**T0-2 — narrow correction R-1** in `docs/RESEARCH-NOTES.md`. The doc groups AEZ/FAST/XCB/EME2 as
"don't build" on patent-encumbrance grounds. Keep the **don't-build verdict** — it's correct — but
replace the patent reasoning with per-mode security grounds:
- **XCB**: cryptanalytically broken (three plaintext-recovery attacks; SISWG moved to remove XCB-AES).
- **EME2**: avoid on security grounds (~2^(n/2) birthday bound + data-dependent multiply side channel).
- **AEZ**: CAESAR round-3, missed final portfolio, published key-recovery attacks.
Add one line: the only located patent filing (US 2004/0131182, Regents of the University of California,
Rogaway) was abandoned in 2007; **no patent basis was found for the others**; freedom-to-operate is an
open question in the counsel brief, not a settled fact here.

**T0-3 — apply corrections R-4, R-5, R-6.**
- **R-5** (`docs/PQ-HYBRID-SPEC.md`): add the NIST US-Portfolio licence **§2.9** verbatim (the clause
  stating that modifying PQC-algorithm parameters is not an implementation/use of the algorithm), then
  one line: altering ML-KEM parameters exits the royalty-free abeyance. Parameters themselves are
  already correct — do not change them.
- **R-6** (`docs/KEY-DISCLOSURE-LEGAL.md`): France penalty amounts (€270,000 → €450,000; Conseil
  constitutionnel 2018-696 QPC); Australia s.3LA tiering (5 yr/300 units → 10 yr/600 units, not just the
  ceiling); US biometric split (*Payne*, 9th Cir. 2024, thumbprint non-testimonial vs *Brown*, D.C. Cir.
  2025, testimonial; no SCOTUS merits ruling). Mark all `[COUNSEL-REVIEW]` and list them in T0-6.

**T0-4 — ORAM downgrade** (`docs/ORAM-SPEC.md`), completing R-4. Change status flagship → **opt-in
experimental**. Add a limits section: DataLair hidden write 2.92 MB/s vs dm-crypt 210.10 MB/s; HIVE
hidden write 0.60 MB/s; both reference systems broken (HIVE: Paterson & Strefler, ePrint 2014/901;
DataLair: Roche et al., CCS 2017 §6); R13's mandatory public-write cloak requirement.

**T0-5 — SSD deniability warning** (A-1). At **decoy-volume creation**, detect non-rotational storage
(Linux: `/sys/block/<dev>/queue/rotational` == 0; macOS: `diskutil info` SSD flag) and surface an
explicit warning that TRIM and wear-levelling degrade hidden-volume deniability on flash. This is a
**code path**, not a docs paragraph — the warning must fire at creation time. Wire it to the creation
flow; if that flow isn't reachable in this session, stub the detection function with tests and a `TODO`
referencing A-1, and note it in the tracker.

**T0-6 — counsel brief.** Create `docs/COUNSEL-BRIEF.md`: a structured list of open legal questions,
each phrased as a question with the specific facts and the decision it would inform. Include everything
tagged `[COUNSEL-REVIEW]` plus: compelled-disclosure statutes, Chia VDF patents, OPAQUE IPR disclosure,
Joye–Libert if FROST is pursued, general FTO, the R-1 wide-block-mode patent question, and the R-6
biometric split. Assert nothing as settled.

**T0-7 — splice the roadmap deltas.** Apply `handoff/repo-merge/ROADMAP-DELTAS-FROM-DECISIONS.md` into
the repo's existing `ROADMAP.md`. Each block in that file names its target section (`## DESIGN`,
`## BACKLOG`, `## DECIDED`, `## DESCOPED`). Rules:
- **Merge into the existing sections. Do not create a second roadmap** and do not restructure the file —
  the repo owns `ROADMAP.md` and a parallel one silently diverges. That mistake was made once already.
- Where a delta supersedes an existing entry, **edit that entry in place** rather than appending a
  duplicate. Specifically: the existing HCTR2/wide-block entry is superseded by the D-4 HCTR2+Adiantum
  split; the existing write-only ORAM entry gains the opt-in-experimental status from D-3; the existing
  bespoke-ristretto entry is superseded by the D-8 libsodium+HACL\* split.
- Preserve the file's existing heading levels, tone, and bullet conventions.
- The `## DESCOPED` block is a **reaffirmation with no change** — confirm the existing text already says
  it and add nothing if so. Report it as verified-already-correct.
- After splicing, re-read `ROADMAP.md` start to finish and confirm it reads as one coherent document,
  not a document with an appendix bolted on.

## When done

Update `handoff/TASK-TRACKER.md` marking T0-1..7 DONE/partial with per-task notes. Summarize what you
changed, what you verified as **already correct** (report those explicitly), and anything you could not
complete. **Then stop.** Do not start Tier 1. T1-1 (v2 on-disk format design) is an owner-gated decision, not a
mechanical task: it sets the deniability constraint that every later feature is tested against, and it
needs a human to approve the shape before code exists. End your run by stating what T1-1 needs decided —
at minimum: where the mode selector field lives, how v1/v2 detection works without becoming a
distinguisher, and whether per-sector MACs can be stored without revealing sector allocation.
