# Consolidated VeraCrypt-fork corpus — deduplicated, repo-stripped

Built from `Veracrypt.zip` (16 nested zips, extracted recursively) and checked against
**`github.com/mcboyle/vc-repo` @ `3ec5ec1`** (latest master — **PR #10 is now merged**).

| Stage | Count |
|---|---|
| Files extracted (incl. nested zips) | 5,241 |
| Unique by content | 2,311 |
| — already in the repo (dropped) | 979 unique / 2,202 copies |
| — `.git` internals, `__MACOSX`, etc. (dropped) | 1,085 |
| — stale/superseded (dropped) | 81 |
| **Kept** | **151** |

Duplicate copies collapsed: **2,930**.

## What's here

| Folder | Files | What it is |
|---|---|---|
| `briefs/` | 28 × (PROMPT + ITEMS) | **All 28 research briefs**, incl. the **14 unrun**. `ITEMS.md` traces each brief to its source backlog items. |
| `reports/` | 18 | The completed research reports. |
| `analysis/` | 11 | Addenda, the three audits, batch-2 syntheses. Working analyses, not authorities. |
| `roadmap/` | 17 | The 775-idea triage (sandboxable / partially / needs-research / as-needed) + index. |
| `planning/` | 21 | `IDEAS-01..16`, `IDEAS-BACKLOG`, `ROI-TOP-50`, **`ROI-51-100`** (still uncommitted). |
| `prompts/` | 9 | Claude Code prompts. **BATCH3-A is now merged as PR #10** — B and C are the live queue. |
| `attachments/` | 7 | Source/spec attachments shipped with individual briefs. |
| `meta/` | 12 | READMEs, `HANDOFF`, `START-HERE`, `RESEARCH-PROMPTS`, pack indexes. |

## Dropped as stale

| Count | Reason |
|---|---|
| 40 | Old repo snapshot (`veracrypt-hardened-fork/vc-repo/` — superseded by current master) |
| 31 | Source/build artefacts superseded by the repo |
| 3 | Session transcripts (provenance only) |
| 2 | Old doc snapshots (`handoff/docs/`) |
| 2 | Old source snippets (`handoff/src-snippets/`) |
| 2 | My own deliverables round-tripped back in |
| 1 | `CLAUDE-CODE-BATCH2-ACTIONS` (superseded draft, per the artifacts README) |

Note: 40+ `handoff/patches/*.patch` were also dropped — all already merged into the tree.

## Unrun briefs (the 14)

`R03` memory-hard KDFs · `R04` OPRF/aPAKE/PPSS · `R05` threshold OPRF + proactive refresh ·
**`R06` VDF / time-release** · `R07` threshold sigs + DKG + VSS · `R11` verifiable computation ·
`R20` mobile PDE · `R22` migration safety · `R23` FIPS/Common Criteria · `R26` formal methods ·
`R28` post-quantum depth. (Plus R13/R14/R15 variants already run.)
