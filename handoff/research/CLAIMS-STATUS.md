# Claims status — what has already been checked

**Read before starting.** This is not exhaustive; it records the claims that have been explicitly checked
against the repo, so you neither repeat that work nor assume it was done where it wasn't.

Status values: **CONFIRMED** (checked against code, holds) · **REFUTED** (checked, wrong) ·
**UNVERIFIABLE** (no available source can settle it) · **UNCHECKED** (nobody has looked).

---

## Already REFUTED — do not treat these as true

| Claim | Source | What is actually true | Where recorded |
|---|---|---|---|
| EME2 is encumbered by an **IBM patent** | R01 → repo `RESEARCH-NOTES.md:95` | No IBM — no granted — patent ever covered EME/EME2/CMC. Only filing was UC San Diego's US 2004/0131182, abandoned 2007. EME2 still don't-build, on *security* grounds. | `R25-ADDENDUM.md` Finding 1 |
| *"There is no suspend/sleep/resume hook anywhere in the fork"* | `R16-ADDENDUM.md` Finding 1 — **an error in this pack's own material** | `KeyScrubEvents.h:12` routes logind `PrepareForSleep`. Five triggers exist. What's actually missing: `StartLogindScreenLockMonitor()` is called but never defined (deliberate packager stub). | `AUDIT-R16-R25-phases-6-15.md` Phase 10a |
| R21's claim about a hardcoded AF stripe count | R21 | `af_of()` in `KeyslotStore.c` reads a config field; no hardcoded value | `BATCH2-SYNTHESIS.md` |

---

## Already CONFIRMED against the repo — no need to recheck

| Claim | Report | Evidence |
|---|---|---|
| `gf_dot` in `hctr2_poc.c` had two secret-dependent branches | R01 addendum | Verified, then fixed in PR #7; now branch-free, ctgrind-clean |
| `gf_mul`/`gf_inv` are correct constant-time GF(2⁸) | R17 | Verified: fixed iterations, `0u-(b&1)` masking, no tables |
| `KeyslotConstTimeEqual` uses the OR-accumulate idiom | R17 | Verified |
| `KeyslotUnwrapCT` design (fixed slot count, byte-mask, no early return) | R17 | Verified |
| `KeyslotOpenAt` is a documented non-CT admin exception | R17 | Verified as documented |
| Per-sector auth spec used a one-time Poly1305 key reused on every sector rewrite | R02-derived | Verified; fixed in PR #7 to keyed BLAKE3 |
| `Common/Volumes.c` is not compiled on Linux (Windows-driver only) | — | Verified: absent from all `.make` OBJS; uses `<io.h>`, `WORD`, `TC_EVENT` |
| No rotational/flash detection existed pre-PR #7 | R15 | Verified; `FlashProbe.c` added since |
| No jurisdiction/legal doc existed | R24 | Verified; `KEY-DISCLOSURE-LEGAL.md` added since |
| ML-KEM-768 params are stock FIPS 203 and consumed as a black box | R25 | Verified: `n=256, q=3329, k=3, eta1=eta2=2, du=10, dv=4`, ACVP vectors, HMAC combiner outside the KEM |
| `KeyScrub.c`, `VcScrubAll`, `VcSwapHibernateStatus`, `VcKeyMemoryLockdown` all exist | R16 | Verified |
| `THREAT-MODEL.md` already covers cold boot + DMA accurately | R16 | Verified — no gap, contrary to expectation |
| AES fallback is table-based Gladman (`Aestab.c`, 18 table symbols) | R17 | Verified; `Crypto.c:1179` gates HW AES on `HasAESNI()` |

---

## Already found MISSING from the repo — confirmed gaps

| Gap | Report | Notes |
|---|---|---|
| No IOMMU / DMA-protection advisory | R16 | R16 names it one of only two items worth building |
| HQC appears nowhere | R25 | Recommended as the code-based PQ hedge |
| No blessed-module CI rule for constant-time primitives | R17 | R17's systematic answer to finding the next duplicate implementation |
| `KeyslotConstTimeEqual` not in the ctgrind sweep | R17 | dudect covers it; ctgrind does not |
| No YubiKey firmware pinning / EUCLEAK awareness | R17 | |
| No power-EM or Spectre out-of-scope statement in `THREAT-MODEL.md` | R17 | |
| AES never a *subject* of any constant-time harness | R17 | Only ever a linked dependency |

---

## UNVERIFIABLE — flag, do not guess

- **Every patent fact in `R25-patent-landscape.md`.** Filing numbers, assignees, abandonment and lapse
  dates, licence terms, jurisdiction coverage. Note also that R25 **omits its full-citations section**,
  which the brief required — so even the inline pointers are less complete than they should be.
- **R16's AMD TSME narrative** (silent disable via AGESA 1.2.7.0, April 2026 discovery, June 2026
  reinstatement statement, July 2026 BIOS). Very recent; vendor-sourced.
- **R16's cold-boot remanence figures** (3mdeb 2024–25 testing; the ~1-minute Kingston DDR4 outlier).
- **R17's ctgrind result generalization.** The measured result (0 secret-dependent-branch errors at
  `-O2`/`-O3`/`-O2 -flto`, gcc + clang) is real but is **one machine, one valgrind version, one
  container, exercised paths only.**
- **Any 2025–2026 attack or vendor-response detail** across all reports: WireTap, Battering RAM, Heracles,
  BadRAM specifics, EUCLEAK firmware thresholds.

---

## Known internal conflicts the reports flag themselves

- **Schnorr patent expiry**: R25 says Feb 2008; notes Wikipedia says 2010. Immaterial — long expired.
- **XCB lapse date**: R25 could not verify the exact maintenance-fee lapse verbatim. Moot — XCB is broken.
- **R15a vs R15b**: two runs of one brief. Do not conflict; `b` adds quantitative data and probe bits.

---

## Disputed — a prior analysis disagrees with a report

| Item | Report says | Prior analysis says | Status |
|---|---|---|---|
| VDFs | *"Do not pursue — no applicability to confidentiality/integrity/access-control/deniability"* (R25) | The project's use case is **coercion cooling-off** (`IDEAS-BACKLOG.md:138`, 262) — that *is* access control. RSW time-lock was invented for time-release crypto. Fork already has `rsw_poc.c`, Sloth, `DELAY-SPEC.md` | **Open.** R6 is the dedicated VDF brief and is unrun. Your view welcome. |
| Which tool is the "primary gate" | R17: promote ctgrind to primary gate | `CT-HARDENING-R17.md` (repo): dudect stays the always-on gate, ctgrind is on-demand | **Resolved as a terminology collision** — they answer different questions (CI composition vs. claim authority). Check whether that resolution holds. |
| AEZ | R25: patent-free, "viable," possible fallback | R01: not selected in CAESAR, key-recovery attacks, expanding — don't build | **Not a conflict** (patent vs. security judgment) but easily misread as rehabilitation. Worth confirming R01's security grounds independently. |

---

## Highest-value targets if your time is limited

1. **R25's patent claims** — the least verified material in the pack, and it triggered a correction to a
   repo document. If you have access to patent databases, this is where you add most.
2. **The prior addenda and audits themselves** — one contains a confirmed error. They have not been
   independently reviewed by anyone.
3. **R17's code-review claims** — five specific claims about the fork's source; all confirmed once, but
   a second pass is cheap.
4. **Cross-report contradictions** — 18 reports written independently; only a few pairs have been
   compared.
