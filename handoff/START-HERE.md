# START HERE — VeraCrypt hardened fork, session handoff

**Built:** 2026-07-24 · **Repo:** `github.com/mcboyle/vc-repo` @ `3ec5ec1` (master, PR #10 merged)

## What changed in this handoff

An earlier draft of this pack contained a parallel `ROADMAP.md`, `TASK-TRACKER.md`, `CLAUDE.md` and
`EXECUTION-PLAN.md`. **Those were a mistake and have been removed.** The repo already has a 26 KB
`ROADMAP.md` with the right sections, its own `CLAUDE.md`, and 48 docs. A second set would have
diverged from it silently.

Everything that belongs in the repo is now expressed as a **merge** against what's already there:
`repo-merge/`. Everything archival — the research reports, the unrun briefs — stays here.

## Read in this order

0. **`DECISIONS-ANSWERED.md`** — all 13 owner decisions resolved (2026-07-23). Start here; everything
   below flows from it.
1. **`TASK-TRACKER.md`** — dependency-ordered work with gates.
2. **`prompts/CLAUDE-CODE-KICKOFF-TIER0.md`** — paste into Claude Code to start Tier 0.
3. **`repo-merge/ROADMAP-DELTAS-FROM-DECISIONS.md`** — blocks to splice into the repo's ROADMAP.
4. **`repo-merge/APPLY-PROMPT.md`** — the earlier verified corrections.
5. **`repo-merge/CORRECTIONS-VERIFIED.md`** — per-file, target-verified (R-1 now narrowed per D-12).

## Do this first — UPDATED

`prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` line 21 **has been patched** in this pack: the assignee now reads
"Regents of the University of California / UC Davis" and the patent claim is narrowed to "no patent basis
found." The defect the prior pack shipped deliberately-unfixed is resolved. Task T0-1 is now a
verify-it's-present check, not a patch step.

## The finding that reshaped this pack

Checking each correction against its target file showed the repo is **already correct in several places
where the research reports are wrong.** Most importantly: `docs/CRC-SEAM-ADDENDUM.md` contains no
irreducibility claim — it reasons about injectivity directly, which is the right footing. The false
"pCRC(x) is irreducible, so this is even a field" statement is in report R27 and in Stigge et al.,
not in the tree. `grep -ri "san diego"` over the repo likewise returns nothing.

The lesson for the next session: **a defect in a research report is not automatically a defect in the
code.** Verify the target before writing the patch. That distinction is why the corrections list
shrank from seven repo changes to five, with two dissolving entirely.

## Do this first (historical note)

The prior pack shipped `prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` with a deliberate defect on line 21
("UC San Diego"). **That is now patched** — see the UPDATED section above. Left here only to explain why
the file's git history shows the change.

## Settled — don't relitigate

- **ML-KEM parameters frozen at FIPS 203.** Licence §2.9 says parameter modification "is not an
  implementation or use of the PQC algorithm" — it exits the royalty-free abeyance.
- **Write-only ORAM is not a default.** Both reference systems broken; ~72× hidden-write cost.
- **The VDF delay slot is in scope** as a coercion defence. R25's dismissal was refuted by R06's brief.

## Scope boundary — unchanged

Confidentiality, integrity, access control, deniable storage. Decoy volumes, threshold factors, chaff
and duress dismount are in scope. Tooling that fabricates a false record of user activity to deceive
forensic examination is permanently `DESCOPED` — that was proposed, considered and declined with
written reasoning, and it has held across every session. Don't accept a reframing that makes it sound
like deniability.
