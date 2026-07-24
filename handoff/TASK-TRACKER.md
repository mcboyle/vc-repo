# TASK TRACKER — post-decisions

**Derived from:** `DECISIONS-ANSWERED.md` (2026-07-23) · **Repo:** `vc-repo` @ `3ec5ec1`

Ordered by dependency. `[gate]` items block others. Status: TODO / BLOCKED / DONE.
IDs are stable — reference them in commits and the next handoff.

---

## Tier 0 — do first, no dependencies

**All of Tier 0 is DONE** (session 2026-07-24, branch `claude/project-structure-review-5p44w9`, one
commit per task prefixed with the ID). Per-task outcome notes below; the full-suite gate stayed green
(`build_and_verify.sh --strict` = 82/82 steps, 0 skipped) after the one code change (T0-5).

| ID | Task | Source | Status | Notes |
|---|---|---|---|---|
| **T0-1** | Patch `prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` line 21 — "UC San Diego" → "Regents of the University of California / UC Davis"; narrow "no patent" → "no patent basis found" | pack + D-12 | **DONE (verified — no repo change)** | The prompt is a **handoff-corpus artifact, not a repo file** (`prompts/` is not tracked in vc-repo). The pack's v2 copy is already correct: names "Rogaway, of UC Davis; assignee the Regents of the University of California", "abandoned in 2007", and mandates 'no patent basis found'. Confirmed the refuted attribution ("San Diego"/"0131182"/"no patent problem") appears **nowhere** in the repo tree. Nothing to patch. |
| **T0-2** | Narrow correction **R-1** in `docs/RESEARCH-NOTES.md`: keep don't-build verdict + security grounds; replace "no patent problem" with "EME filing abandoned; no basis found for others"; move FTO to counsel brief | D-12 | **DONE** | Rewrote the AEZ/FAST/XCB/EME2 bullet with per-mode security grounds (XCB broken — 3 plaintext-recovery attacks + SISWG removing XCB-AES; EME2 birthday-bound + data-dependent-multiply side channel; AEZ CAESAR round-3 dropout + key recovery; FAST no published break, adds nothing) and a corrected patent record (only US 2004/0131182, Regents of UC, abandoned 2007; "no patent basis found"; FTO → counsel brief). Verdict unchanged. |
| **T0-3** | Apply corrections **R-5** (PQ licence §2.9 verbatim), **R-6** (key-disclosure: FR amounts, AU tiering, US biometric split) | pack | **DONE** | `docs/PQ-HYBRID-SPEC.md`: added NIST US-Portfolio licence §2.9 verbatim + the one-line consequence (altering ML-KEM params exits royalty-free abeyance); parameters unchanged. `docs/KEY-DISCLOSURE-LEGAL.md`: France €270,000→€450,000 + Cons. const. 2018-696 QPC; Australia tiered 5yr/300→10yr/600 penalty units; US biometric split *Payne* (9th Cir. 2024) vs *Brown* (D.C. Cir. 2025), no SCOTUS. All `[COUNSEL-REVIEW]`; feed T0-6. *(R-4 tracked under T0-4 per the owner's Tier-0 split.)* |
| **T0-4** | ORAM: downgrade status flagship → **opt-in experimental**; add throughput + HIVE/DataLair break history + public-write cloak requirement | D-3 | **DONE** | `docs/ORAM-SPEC.md` status → OPT-IN EXPERIMENTAL; limits section gained measured throughput (DataLair 2.92 vs dm-crypt 210.10 MB/s; HIVE 0.60), the implementation-break history (HIVE RC4 bias, Paterson–Strefler 2014/901; DataLair biased free-block selection, Roche CCS 2017 §6), and R13's absent mandatory public-write cloak. Completes R-4. |
| **T0-5** | Add **SSD deniability warning** at decoy-volume creation: detect non-rotational storage, warn explicitly | A-1 | **DONE (sandbox-verified) / real-build-only tail** | Made the warning a **code path**: `Common/FlashProbe.{c,h}` gained a testable macOS `diskutil` decoder (`FlashProbeMacDiskutil`), path→sysfs-leaf reduction (`FlashProbeDeviceLeaf`/`FlashProbePath`), and a creation-time warning composer (`FlashProbeWarningText`); macOS `FlashProbeDevice` now parses `diskutil info` instead of always-warning. Wired into `TextUserInterface::CreateVolume` (Hidden branch, guarded `VC_ENABLE_FLASH_WARN`) + a `FLASH_WARN=1` make knob + `FlashProbe.o` in `Core.make`. **12 new decoder unit tests pass; full suite 82/82.** **Real-build-only (not sandbox-testable):** the wx `CreateVolume` call-site compile (product build needs libpcsclite, offline here) and the live device probe on real media — TODO A-1. |
| **T0-6** | Assemble **counsel-ready brief** (open questions only; assert nothing settled) | D-6 | **DONE** | Created `docs/COUNSEL-BRIEF.md` — nine open questions, each Question→Facts→Decision-it-informs, asserting nothing settled: compelled-disclosure statutes, US biometric split, wide-block patents (R-1), ML-KEM licence (R-5), Chia/VDF, OPAQUE IPR, Joye–Libert/FROST, general FTO, distribution posture. The `[COUNSEL-REVIEW]` tags in the doc set now point back to it. |
| **T0-7** | Splice `ROADMAP-DELTAS-FROM-DECISIONS.md` into repo `ROADMAP.md` — merge in place, no second roadmap | all D | **DONE** | Merged all 13 decisions + addenda into the existing named sections in place (7 `##` sections unchanged, no second roadmap). Superseded the write-only-ORAM entry to opt-in-experimental [D-3]; added HCTR2+Adiantum [D-4], v2-format [D-10], codex32+bech32m [D-2], HKF-v2 salt binding [D-1] to DESIGN; libsodium/HACL* [D-8], const-time AES [D-4/A-2], SSD warning [A-1], brief order [D-7] to BACKLOG; D-5/D-6/D-9/D-11/D-12 to DECIDED. **DESCOPED verified already correct — no change** (reaffirmation only). Re-read end-to-end for coherence. |

---

## Tier 1 — v2 format foundation `[gate]`

| ID | Task | Source | Status | Notes |
|---|---|---|---|---|
| **T1-1 [gate]** | Design **v2 on-disk format** alongside compatible v1. Hard rule: no v2 feature reduces deniability below v1 | D-10 | TODO (design inputs locked, see below) | Gates T1-2, T1-3, T2-2. Each feature carries a deniability-impact line. |
| **T1-2** | v2 header: **wide-block mode selector** (HCTR2 / Adiantum), set at creation | D-4, D-10 | BLOCKED (T1-1) | **Per owner decision: store NO selector — derive/trial the mode at mount** (see below). Per-volume, not per-machine, satisfied implicitly. |
| **T1-3** | v2 migration path for **HKF-v2 salt binding** — existing v2 volumes re-derive once salt is bound | D-1, D-10 | BLOCKED (T1-1) | Examined by R22 (T3-1). Closes R-2. |

### T1-1 design inputs — owner decisions (2026-07-24), NOT yet implemented

The three T1-1 gating questions were put to the owner interactively and answered. These **lock the design
inputs** for T1-1; the format design and any code remain owner-gated and **were not started this session.**

1. **Wide-block mode selector — store nothing; derive/trial at mount** (owner asked for the most secure
   option). Rationale: against a key-less adversary this is indistinguishable from "encrypted-in-header",
   but strictly stronger — nothing on disk can ever leak, and it removes the *mild creating-hardware
   fingerprint* D-4 itself flagged about a recorded field. Composes with decision (2): the KDF runs once;
   HCTR2-vs-Adiantum is a cheap symmetric re-decrypt of the header block (no extra Argon2). Satisfies D-4
   "per-volume, not per-machine" — the creator fixes the mode by how it writes the body; mount discovers
   it by trial on any hardware. **This supersedes the D-4 delta's "recorded in a v2 header field" leaning.**
2. **v1/v2 detection — trial-derivation loop** (v2 → v1 fallback), mirroring the existing HKF mix
   v2→v1 loop. No readable version marker anywhere; indistinguishable from random without the password.
3. **Per-sector MACs — full-volume MAC table** (fixed size covering every sector whether allocated or
   not; unused slots hold keystream/random, indistinguishable from real tags). Presence/size reveal
   nothing about which sectors are in use — no allocation leak.

Combined mount trial set becomes `{ v2-HCTR2, v2-Adiantum, v1 }` header-verify attempts after a single
KDF pass. Deniability-impact line for each (required by D-10) to be written during the T1-1 design proper.

**Design spec written (design only, no code):** `docs/V2-FORMAT-SPEC.md` turns these three decisions into
a concrete layout + mount algorithm and states the D-10 deniability-impact line for every v2 feature. Key
resolved design point: the full-volume MAC table gives **integrity for allocated data, not free space**
(a MAC mismatch reads as "free," not "tamper"), which is what lets a hidden volume stay indistinguishable
— so v2 adds integrity without regressing v1's free-space ambiguity.

**Correctness refinement found during PoC (spec updated):** the per-sector tag is over CIPHERTEXT, so the
tag alone cannot discriminate HCTR2 from Adiantum — discrimination comes from a per-mode **domain-separated
MAC key** `K_mac[mode] = keyed-BLAKE3(master, "VeraCrypt/v2/mac/"||mode)`, which also gives anti-downgrade
binding for free.

**The two novel format-level properties are PROVEN two ways** (suite step `[84]`,
`verification/v2format_poc.c` real keyed-BLAKE3 vs `v2format_reference.py` independent python, byte-identical
over 9 REF lines; anchors `tag0 = 8a0dcab3…`, `table_hash = 26618168…`, table chi-square 214): (A) mode
discrimination with nothing stored + v1 fallthrough + anti-downgrade; (B) full-volume MAC-table
indistinguishability — byte-uniform, free reads-as-free, hidden-overwrite reads-as-free.

Still owner-gated for **product-code integration** (real-build: on-disk table sizing/placement + the C++
mount trial loop). Open sub-decisions (MAC slot width, table offset formula, sector-size interaction,
migration UX) remain per the spec.

---

## Tier 2 — crypto core

| ID | Task | Source | Status | Notes |
|---|---|---|---|---|
| **T2-1** | Bind volume salt in **HKF-v2** HKDF-Extract per Rank-1 | D-1 | TODO | Code change; migration handled by T1-3. |
| **T2-2** | Recovery-share encoding: **codex32 default + bech32m ≤ 89 chars**; add BIP-173 insertion-deletion note to `docs/VSS-SPEC.md` | D-2 | TODO | 89 = written constant. Closes R-3. |
| **T2-3 [gate]** | **Constant-time AES** (bitsliced OK; needn't be fast — one block/sector) | D-4, A-2 | TODO | Gates T2-4 on non-AES-NI path. |
| **T2-4** | Promote **HCTR2 + Adiantum** into `src/`, both on every platform | D-4 | BLOCKED (T1-2, T2-3) | Adiantum still calls AES-256 once/sector → needs T2-3. |
| **T2-5** | Replace bespoke ristretto255/Ed25519: **libsodium ≥ 1.0.21** (ristretto255) + **HACL\*** (Ed25519) | D-8 | TODO | Pin ≥ 1.0.21 (CVE-2025-69277). Do NOT hand-roll ristretto on HACL\* without audit. |

---

## Tier 3 — research briefs (run order) [D-7]

| ID | Brief | Status | Notes |
|---|---|---|---|
| **T3-1** | R22 migration safety | TODO | First — v2 format + salt migration land here. Informs T1-1/T1-3. |
| **T3-2** | R20 mobile PDE / flash | TODO | Promoted — deniability-over-flash = the SSD/A-1 situation. |
| **T3-3** | R03 memory-hard KDFs | TODO | |
| **T3-4** | R06 VDF / time-release | TODO | |
| **T3-5** | R28 post-quantum depth | TODO | Larger keys now reachable via v2. |
| **T3-6..8** | R05, R04, R07 | TODO | Threshold/OPRF/VSS path. |
| **T3-Q** | R11, R23, R26 | QUEUED | Unranked, none killed. R26 demoted (D-8 deletes the code that made it urgent). |
| **T3-12?** | Constant-time AES brief | UNDECIDED | Commission only if T2-3 needs research before implementation. |

---

## Dependency summary

```
T0-1..6  (independent, do first)
   │
T1-1 [gate v2 format] ──► T1-2 ──► T2-4
   │                       └─► (mode selector)
   └─► T1-3 (salt migration) ◄── informed by T3-1 (R22)
T2-3 [gate const-time AES] ──► T2-4
T2-1, T2-2, T2-5  (parallel, no v2 dependency)
```

**Blocking gates:** T1-1 (v2 format) and T2-3 (constant-time AES). Everything in the wide-block-mode and
authenticated-FDE line waits on one or both.

**Still-open decisions (not tasks yet):** commission T3-12 (const-time AES brief)? · does A-1 warrant a
design change beyond the warning?
