# Claude Code task — batch 3 / B: documentation corrections (R16, R17, R25)

**Repo:** `vc-repo`, branch off `master` (`7c08337` or later).
**Gate:** `verification/build_and_verify.sh --strict` exits 0, **0 SKIP**, anchors intact, negative
control still fails. This session is documentation — the suite should be untouched.

Corrections and new documentation from research batch 3. **One item fixes a factual error currently
asserted in the repo** (B1); the rest close gaps the three reports identified. Self-contained.

---

## B1 — The EME2 patent claim in the repo is wrong *(priority)*

`docs/RESEARCH-NOTES.md:95` currently reads:

> **AEZ, FAST, XCB, EME2** (wide-block alternatives to Adiantum/HCTR2) — **don't build.** Patent
> encumbrance and/or known side-channel and analysis concerns…

The patent claim attached to EME2 traces to R1, which named an **IBM** patent. R25 (the dedicated patent
brief) found this is mistaken: no granted patent has been found covering EME/EME2/CMC. The only
filing located was **US 2004/0131182** (naming Rogaway, of **UC Davis**; assignee the **Regents of the
University of California**), **abandoned in 2007** per the IEEE
P1619.2/SISWG record. The confusion is a co-author's employer (Halevi, IBM) becoming, in retelling, the
assignee of a patent that belonged to a university and never issued. Per D-12, phrase this as "no patent
basis found," not "no patent problem exists" — the affirmative clearance question is FTO territory and
lives in the counsel brief (D-6), not in repo docs.

**Fix, precisely:**

- **EME2 stays don't-build** — on its *real* grounds: birthday-bound (≈2^{n/2}) security, and the
  timing/power side channel from its data-dependent GF multiplication (Mancillas-López et al., ICISS
  2009). Remove the patent claim.
- **Split XCB out with a different reason.** Cisco's US 7,418,100 has lapsed, so the patent objection is
  gone — but XCB-AES was **cryptanalytically broken in 2024**: a two-query attack (Bhati, Verbauwhede &
  Andreeva, eprint 2024/1554, CRYPTO 2025) and full plaintext recovery (Wang et al., eprint 2024/1527).
  Clean don't-build on security grounds; the patent point is now irrelevant.
- **AEZ keeps its don't-build, unchanged, on R1's security grounds** — not selected in CAESAR,
  key-recovery attacks, ciphertext-expanding. R25 calls AEZ patent-free and mentions it as a
  hypothetical fallback; that is a *patent* judgment and **does not rehabilitate AEZ**. Do not soften
  this entry.

**Honesty requirement:** R25's patent facts cannot be verified from code, and R25 itself omitted its
full-citations section. Write the corrected entry so it cites R25 as the source and notes the underlying
filing number, so the next reader can check rather than inherit. If you are not confident restating a
patent fact, state the disposition (don't-build, security grounds) and attribute the patent correction
rather than asserting it as your own finding.

---

## B2 — Cite every verdict in the don't-build section *(the reason B1 was possible)*

The EME2 error survived because that section records conclusions without sources. Counting citations
across the consolidated don't-build block in `RESEARCH-NOTES.md` (~lines 88–110): **one** — the MASCOTS
2021 reference on free-space chaff, which is there only because the task that wrote it demanded a
citation.

Every other verdict is a bare assertion. That is the actual defect: a verdict with a citation is
falsifiable by the next reader; one without is folklore that propagates into planning docs.

**Task.** Give every entry in that section a source. Where the only authority is a research brief rather
than a primary reference, **say that explicitly** — "R1, uncited" is useful information, because it tells
a future reader the claim has never been checked against a primary source. R17 is the model here: 23
inline venue/ePrint/CVE markers, every load-bearing claim checkable.

---

## B3 — `docs/KEYS-IN-RAM.md` (R16) — lead with what already exists

R16 concluded: **do not build** register-resident keys (TRESOR/PRIME), TEE integration, or any hard
dependency on CPU memory encryption. Unverifiable under the project's ceiling, broken by active DMA
(TRESOR-HUNT, ACSAC 2012), unmaintained since ~2011, and — the argument specific to this project —
**hardware-bound key storage is itself a forensic tell**, which cuts against the deniability posture.

Mark `docs/IDEAS-BACKLOG.md:179` ("Keys in registers, never in RAM (TRESOR / PRIME model)") as
**researched and declined**, citing R16.

Then write `docs/KEYS-IN-RAM.md`. **Structure it "what we already do" first**, because R16 under-credited
the fork twice and a doc that opens with the decline would repeat that error. Already shipping:

- **Timed scrubbing** with a registry — `VcScrubRegister`/`VcScrubUnregister`/`VcScrubAll` (`KeyScrub.h`).
- **Five routed scrub triggers** into one `ScrubNow()` (`Core/KeyScrubEvents.{h,cpp}`): unmount (hooked in
  `CoreUnix.cpp::DismountVolume`), idle timeout, screen lock, **logind `PrepareForSleep`** (the
  suspend signal), and new-device-connect — plus duress via `HKFScrubActiveConfig`.
- **In-RAM encryption of secrets at rest** — `VcKsRamTransform` / `VcKsRamProtectInit`, initialised at
  `KeyScrubEvents.cpp:97`. R16 never mentions this, though it is the project's software answer to the
  brief's own title.
- **`mlockall` lockdown** — `VcKeyMemoryLockdown()` (no swap / no core / no ptrace).
- **Swap + hibernation detection** — `VcSwapHibernateStatus()`, warning while volumes are mounted, with
  the correct reasoning already in its header and a fail-toward-unknown default.
- **Non-destructive duress dismount** (`docs/DURESS-DISMOUNT-SPEC.md`).

Be accurate about status: `StartLogindScreenLockMonitor()` is **called but not defined** — the sd-bus
subscription is a documented sketch, *"left to the packager to wire to their event loop; intentionally
not linked by default."* `docs/MEMORY-SCRUB.md:102` already records this honestly as "no — validate on a
real session." Do not overstate it as working, and do not understate it as absent.

Then the decline, then **user-side platform guidance** (not dependencies): enable Intel TME / AMD TSME in
BIOS where present, enable IOMMU / Kernel DMA Protection, disable unused Thunderbolt/FireWire, prefer
full shutdown over sleep at at-risk moments.

---

## B4 — Threat-model additions (R17)

Add to `docs/THREAT-MODEL.md`:

- **Power / EM / DPA is out of software scope.** These require physical proximity and specialized
  equipment, and for hardware factors they belong to the token vendor, not this code. Concrete live
  example: **EUCLEAK** (Roche/NinjaLab 2024, IACR ePrint 2024/1380) extracted ECDSA keys from YubiKey 5
  via EM analysis of a non-constant-time modular inversion — enabling **cloning** of a FIDO device.
  Fixed by Yubico in firmware **5.7** (advisory YSA-2024-03).
  **Operational guidance that matters for this user population:** pin hardware factors to patched
  firmware (YubiKey ≥ 5.7), and **treat a token that has been out of the user's possession as
  potentially cloned.** For a journalist whose devices may be seized and returned, that is directly
  actionable.
- **Full Spectre resistance is out of scope** for a userspace tool and requires OS/hardware cooperation.
  R17 assessed the fork as already well-positioned: no secret-dependent branches to mistrain, and
  `KeyslotStore.c`'s fixed-slot-count, byte-mask, no-early-return design is Spectre-v1-friendly as a side
  effect of being cache-safe. The recommendation is explicitly **not** to add broad speculative-execution
  mitigations — just document the boundary.
- **Data-operand timing and DVFS (Hertzbleed) are hardware channels no constant-time tool detects.**
  dudect, ctgrind, ct-verif and Binsec/Rel all reason about branches and memory addresses only.

---

## B5 — ML-KEM parameter fixity (R25)

`docs/PQ-HYBRID-SPEC.md` uses stock FIPS 203 ML-KEM-768 parameters (`n=256, q=3329, k=3, eta1=eta2=2,
du=10, dv=4`), validates against NIST ACVP vectors, and consumes ML-KEM as a black box inside the HMAC
combiner. **This is already correct — no code change.**

Add a note recording *why* the parameters must stay fixed: NIST's royalty-free patent-license abeyance
covers ML-KEM **"as published by NIST,"** and the US portfolio agreement (§2.9) states that *"any
modification, extension, or derivation of the parameters of the PQC ALGORITHM is not an implementation or
use of the PQC algorithm"* — i.e. altering them exits the licence safe harbour. Note that the ACVP vectors
are what keeps this honest: parameter drift fails the suite rather than passing silently.

This is a non-obvious constraint a future contributor optimizing parameters would not guess.

---

## B6 — Backlog entries

Add to `docs/IDEAS-BACKLOG.md`:

- **HQC as the code-based PQ hedge** `[L]` — NIST selected it 2025-03-11 (NIST IR 8545) as the fifth PQC
  algorithm; draft standard ~2026, finalisation expected 2027. The hedge against a lattice break or an
  ML-KEM licence setback. Gated externally on finalisation.
- **Multi-triple ctgrind** `[M]` — R17 Stage 2. Run the constant-time check on every release target triple,
  not one container; compiler re-introduction of a branch/`cmov`-address from a bitmask is the documented
  realistic failure mode ("Breaking Bad", ASIA CCS 2025, found it even in verified HACL*). x86-64 and
  aarch64 least affected; 32-bit ARM / i386 / MIPS / RISC-V most.
- **Binsec/Rel on release binaries** `[L]` — binary-level relational symbolic execution. Its authors found
  `gcc -O0` and clang-backend constant-time violations in binaries an LLVM-IR-level tool had passed, so
  it is not redundant with IR-level checking.
- **`__builtin_ct_select`** `[S]` — Trail of Bits' LLVM intrinsics, landing in LLVM 21; once in the
  toolchain, a first-class way to stop a bitmask select being lowered to a branch or `cmov` address.
- **IOMMU / DMA-protection advisory** `[M]` — R16. Detect and warn on IOMMU/Kernel-DMA-Protection state
  the way `VcSwapHibernateStatus()` already does for swap and hibernation; same fixture-testable shape,
  fail toward "unknown, not safe." **Note the open design question:** which signal — IOMMU enablement,
  Kernel DMA Protection state, or Thunderbolt security level? Three different reads with different
  cross-platform availability. Specify before building.

---

## B7 — VDF: do **not** record a don't-build

R25 concludes *"do not pursue VDFs"* on the grounds that they serve randomness beacons and blockchains.
**Do not action this.** That reasoning does not engage with this project's use case:
`IDEAS-BACKLOG.md:138` describes a *"volume that provably cannot be opened faster than N hours of
sequential computation,"* and line 262 gives the purpose as **"coercion cooling-off"** — which is access
control. RSW time-lock puzzles were invented for time-release cryptography, not consensus. The fork has
already built in this space: `verification/rsw_poc.c` + `rsw_reference.py` (step `[33]`), Sloth (step
`[30]`), `docs/DELAY-SPEC.md`.

R25's *patent* finding on VDFs is sound and worth recording — Chia's patents are application-layer, the
core math is clear, Wesolowski/Pietrzak function as prior art. Its *applicability* judgment is outside a
patent brief's remit. **R6 is the dedicated VDF brief and is unrun; defer to it.**

---

## Working style

- **Verify before editing.** Every target was checked at `7c08337`; confirm before changing, and if
  something has already been fixed, say so and skip rather than duplicating.
- **Do not soften negative results.** These entries exist to stop work; hedged language invites someone
  to try anyway.
- **Cite.** Every claim from research gets its source inline — that is the whole point of B2.
- **Where a fact cannot be verified from code, attribute it** rather than asserting it.
- **Small commits, one concern each.**
- **Scope boundary unchanged.** B4 touches operational security guidance; describe risk, never advise
  beyond what the sources support.

## Out of scope

- Everything in prompt A (ctgrind/AES/CI guard) and prompt C (IOMMU advisory build, resume re-auth).
- Building HQC, Binsec/Rel, multi-triple ctgrind — B6 records them as backlog only.
- Replacing AES, implementing the logind monitor, or any code change at all.

## Definition of done

1. `RESEARCH-NOTES.md:95` corrected: EME2 on security grounds, XCB split with its 2024 break, AEZ
   unchanged.
2. Every verdict in that section carries a source, with brief-only authorities marked as such.
3. `docs/KEYS-IN-RAM.md` written, leading with existing mitigations, accurate about the logind sketch.
4. `THREAT-MODEL.md` carries power/EM, EUCLEAK guidance, Spectre, and data-operand/DVFS boundaries.
5. `PQ-HYBRID-SPEC.md` carries the parameter-fixity note.
6. Backlog entries added; VDF **not** recorded as declined.
7. `--strict` unchanged and green.
8. Closing summary: what changed, what was already done and skipped, what was attributed rather than
   asserted.
