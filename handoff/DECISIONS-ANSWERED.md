# DECISIONS ANSWERED — VeraCrypt hardened fork

**Completed:** 2026-07-23 · Against `DECISIONS-NEEDED.md` from `vc-handoff-2026-07-24`
**Repo state at time of answering:** `github.com/mcboyle/vc-repo` @ `3ec5ec1` (master, PR #10 merged)

All 13 answered. Four answers changed mid-session as later questions altered the premises of earlier
ones; where that happened, both the answer and the reason for the change are recorded. Three findings
emerged that were not among the 13 — they are in the addendum, and two of them are more consequential
than most of the questions.

---

## Section 1 — Blocking

### D-1. HKF-v2 zero salt — deliberate?

> **Answer: A.** Oversight. Bind the volume salt as R27's Rank-1 specified.

Consequence: any volume already created under the as-built v2 mix derives differently once the salt is
bound. This is a derivation-level migration and it lands on the R22 seam — part of why R22 ranked
first. Closes correction R-2.

---

### D-2. Recovery-share encoding — bech32m or codex32?

> **Answer: C.** Both. codex32 (BIP-93) as the default export; bech32m (BIP-350) for short codes.

**Cut-over length: 89 characters.** At or below, bech32m; above, codex32. The boundary is set at the
point where bech32's 4-error guarantee actually holds, so that "short" is not a judgement call at each
call site. Set this elsewhere if you disagree — but it must be written down.

Steers correction R-3. Note the VSS spec already states the ≤90-character condition and already
proposes SLIP-39-style segmenting; what it omits is BIP-173's insertion-deletion weakness, which is
independent of length and affects short shares too.

---

### D-3. Write-only ORAM — downgrade or remove?

> **Answer: A.** Keep as opt-in experimental, with an honest limits section.

Partly settles correction R-4, which requires adding the throughput figures, the break history for both
HIVE and DataLair, and R13's mandatory public-write cloak requirement — none of which the spec
currently carries.

---

### D-4. HCTR2 promotion into `src/`

> **Answer: superseded — neither A, B nor C.**
> **HCTR2 where AES-NI is present; Adiantum where it is not.**

Answered A, then changed to B once D-5 established a public release, then superseded entirely when a
better option surfaced. The reasoning trail:

- **A** ships a measured table-AES cache-timing leak to users without AES-NI — a population skewing
  toward older and cheaper hardware, which correlates with the risk profile in D-5 and D-13.
- **B** avoids the leak but forfeits wide-block security for those users indefinitely.
- **The split** gives every user a wide-block SPRP. Adiantum is a super-pseudorandom permutation over
  the whole sector, the same property HCTR2 delivers; it is in the Linux kernel since 5.0; and on an
  ARM Cortex-A7 it decrypts 4096-byte messages at 10.6 cycles/byte, over five times faster than
  AES-256-XTS, with a constant-time implementation.

**Two things this does not do.**

1. **It does not remove the AES dependency.** Adiantum invokes AES-256 on a single 16-byte block per
   sector. Constant-time AES is still required — but it now only has to *exist*, not to be fast, since
   it runs once per sector rather than over the whole sector. The usual performance objection to
   bitsliced AES largely evaporates. The item stays on the roadmap; its cost drops sharply.
2. **It does not come for free in the format.** The mode must be a per-volume property recorded in the
   header, not a per-machine runtime choice — otherwise a volume created on AES-NI hardware will not
   open on hardware without it, and these users move media between borrowed and unreliable machines.
   Both modes must be implemented on every platform, selected at creation time. That is a header
   change, so it lands in v2 (see D-10). The recorded selector is also a mild distinguisher of the
   creating hardware, and should be tested against D-10's deniability constraint rather than waved
   through.

---

## Section 2 — Direction

### D-5. What is the actual end state?

> **Answer: A**, with a stated posture.

Maximum security and robustness for the most sensitive risk profiles, on the view that this kind of
security matters for everyone. **Refined by D-13:** not mass public release — shippable to a select few
vulnerable and high-risk individuals.

This is the answer that repriced the most. It reopened D-11, reversed D-8, superseded D-4, and it is
why the SSD finding in the addendum is treated as a safety issue rather than a documentation one.

---

### D-6. Counsel for the `[COUNSEL-REVIEW]` items?

> **Answer: A.** Yes — write those items up as a counsel-ready brief with specific questions.

Answered B first, changed with D-5. Scope of the brief: the compelled-disclosure statutes, the Chia VDF
patents, the OPAQUE IPR disclosure, the Joye–Libert question if FROST is pursued, the general FTO
posture, and — added during this session — the wide-block mode patent question from R-1, plus the R-6
biometric circuit split.

No legal conclusion is asserted as settled anywhere in the tree pending that brief.

---

### D-7. Which unrun briefs, in what order?

> **Run these, in this order:**
> 1. **R22** migration safety
> 2. **R20** mobile PDE / flash
> 3. **R03** memory-hard KDFs
> 4. **R06** VDF / time-release
> 5. **R28** post-quantum depth
> 6. **R05** threshold OPRF + proactive refresh
> 7. **R04** OPRF / aPAKE / PPSS
> 8. **R07** threshold signatures + DKG/VSS
>
> Remaining queued, unranked: **R11**, **R23**, **R26**.
>
> **Never run: none.** Nothing killed outright.

Two changes from the pack's ranking, both driven by answers in this session:

- **R20 promoted from near-kill to second.** The original argument for dropping it was that neither
  platform in D-9 is mobile. That reasoning fails: mobile PDE is the literature on deniability over a
  flash translation layer, which — per the addendum — is the desktop situation too.
- **R26 demoted.** It was promoted earlier because D-8 = C left machine-checked proof as the only
  assurance lever on the bespoke group arithmetic. D-8 changing to Split deletes that code instead,
  which is the better fix, so R26's urgency falls.

**Not covered by any brief:** constant-time AES, now on the critical path via D-4. It is an engineering
item rather than a research one. If it should be researched first, that is a twelfth brief and needs
commissioning.

---

### D-8. Replacing the bespoke ristretto255/Ed25519

> **Answer: Split — confirmed final.** libsodium **≥ 1.0.21** for ristretto255; HACL\* for Ed25519.

Answered C first under D-5 = personal use, reversed once D-5 became a release, then confirmed final
after dedicated research (2026-07-23) closed the open caveat.

**Research findings that settled it:**

- **HACL\* confirmed to have no ristretto255 or decaf448** — no module, no issue, no PR requesting or
  attempting one, across hacl-star and hacl-packages. The earlier "found no evidence of" is now
  "confirmed absent."
- **No formally verified ristretto255 exists in C anywhere.** The closest anything comes is Rust:
  curve25519-dalek's fiat-crypto backend verifies field arithmetic only (ristretto group logic
  unverified), and the Aeneas/Lean verification of dalek is academic and in progress.
- **One nuance the original reasoning understated:** HACL\* does export verified low-level edwards25519
  point and field operations (`Hacl_EC_Ed25519`: point add/double/negate/mul, compress/decompress,
  felem arithmetic). A ristretto layer is therefore *buildable* on verified primitives — but the
  ristretto-specific glue (Elligator 2, sqrt_ratio_m1, canonical encode/decode, constant-time equality)
  would be new unverified C, which is precisely the error-prone part ristretto exists to encapsulate.
  Rejected for now; viable later only with an independent audit and exhaustive RFC 9496 vector testing.
- **libsodium version pin — mandatory:** CVE-2025-69277 (disclosed 2025-12-30, fixed in 1.0.21) was a
  point-validation flaw in `crypto_core_ed25519_is_valid_point` — the ristretto255 API was **not**
  affected, and the maintainer's own advisory recommends ristretto255 as the mitigation for exactly
  this bug class. The CVE strengthens rather than weakens the choice, but anything ≤ 1.0.20 must not
  ship.

**Watch conditions that would reopen this:** HACL\* or libcrux shipping a verified ristretto255 module
(would become the outright best option), or the dalek Lean verification completing with a usable
C/FFI export.

---

### D-9. Platform priority

> **Answer: A.** Linux/macOS (C++ path).

Answered C first, changed to A. Note this interacts with D-4: even with a single platform priority,
both HCTR2 and Adiantum must exist on every platform the volume might travel to.

---

### D-10. Are on-disk format changes ever on the table?

> **Answer: B, with a hard constraint.** v2 alongside the compatible v1, deniability-preserving.

**The constraint: no v2 feature may reduce deniability below v1, or the feature is descoped.**

There is no single most-secure answer here, and the constraint exists because the two properties pull
against each other. B buys integrity — XTS is malleable, and per-sector MACs make tampering by an
attacker with write access detectable. But MACs and integrity metadata have to be stored somewhere, and
that storage reveals which sectors are in use, which is corrosive to hidden-volume deniability. A second
format is also a fingerprint, and a dual-format world invites downgrade attacks.

The SSD finding in the addendum shifted this toward B: the deniability leg is already partly leaked by
the hardware, so withholding integrity features to protect it buys less than it first appeared. That is
a reason to reprice the trade, not to abandon the constraint.

Un-prunes: authenticated FDE, per-sector MACs, integrity metadata. Also provides the home for D-4's
mode selector and D-1's salt-binding migration.

---

## Section 3 — Pace and process

### D-11. How much Pass 4 is worth doing?

> **Answer: C.** Skip — accept the citations as flagged-unverified.

Held through D-5 changing from personal use to release. **One condition attached:** with a public
release, "accept as flagged" only holds if the flags survive into the published documents rather than
staying internal. An unverified citation that reads as verified is worse than an absent one.

**Known risk of this choice:** R-1's overreach (see D-12) was a Pass 1 conclusion, and skipping Pass 4
means that class of claim will not be re-checked. If R-1 got through, others may have.

---

### D-12. Anything in the corrections register you disagree with?

> **Disagree with: R-1.** Narrowed as proposed. R-2 through R-6 stand.

**Note on provenance:** `DECISIONS-NEEDED.md` cites seven corrections in `docs/CORRECTIONS-REGISTER.md`
under a C-n scheme. That file does not exist at `3ec5ec1` and nothing in the repo references it. The
live enumeration is `repo-merge/CORRECTIONS-VERIFIED.md` under R-1…R-6 plus dissolved N-1 and N-2.
There is no "C-1" — the CRC item is N-1, and its finding is the reverse of what D-12's text implies:
the repo is already correct and the published paper is wrong. The substance survived the renumbering;
the label and path did not.

**The R-1 defect.** The entry generalizes from a single abandoned filing to "no granted patent ever
covered EME/EME2/CMC," then to "none of these is a patent problem" across a group including XCB. Two
gaps: EME2 is Halevi's extension rather than Rogaway's EME, so an abandoned application on the latter
establishes nothing about the former; and XCB is McGrew and Fluhrer's, from a different institution
entirely. There is also published material cutting against the flat conclusion — a 2022 systems paper
attributes wide-block encryption's limited adoption to performance *and* patenting considerations, with
XCB-AES and EME2-AES named as the two certified methods.

**The fix.** Keep the verdict — don't build any of them — and keep the security grounds, which stand
independently. XCB in particular is not a close call: all versions have been shown insecure via three
plaintext-recovery attacks. Replace the affirmative "no patent problem" with the narrower and true
statement: *the EME filing was abandoned in 2007; no patent basis was found for the others.* Move
freedom-to-operate to the D-6 counsel brief as an open question rather than a resolved fact.

---

### D-13. Anything I got wrong about the project itself?

> **Notes:** Shippable to a select few vulnerable / high-risk individuals.

Corrects the "research prototype, not shippable" framing that had been carried through prior sessions,
and refines D-5 = A: not mass public release, but real distribution to real users with real adversaries.
Different bar from either a prototype or a mass release — the code must work under a serious threat
model, but the audience is small and reachable.

This is why the addendum's first item is treated as blocking rather than as a documentation note.

---

## Addendum — surfaced during the walkthrough, not among the 13

### A-1. SSDs materially weaken the deniability guarantee. **Treat as blocking.**

Raised by the owner during D-10. Both mechanisms attack deniability specifically:

- **TRIM** lets an adversary tell which sectors contain free space, because trimmed blocks are zeroed
  while used sectors are not. This directly breaks the assumption a hidden volume rests on — free space
  indistinguishable from random. Recoverable only by disabling TRIM on the volume, at a cost in
  throughput and endurance.
- **Wear-levelling** cannot be switched off. The FTL remaps logical blocks to physical pages, so a
  logical overwrite does not overwrite the physical page. Old headers and prior outer-volume state can
  persist in retired pages reachable by chip-off or vendor commands. Residue from the hidden-volume
  creation process is the specific concern, since it evidences that the wizard was run at all. Drives
  also maintain per-sector write counters, from which the written region can be inferred.

**Consequence.** For the audience named in D-13, on hardware that is now effectively universal, the
decoy-volume feature promises something the hardware does not deliver. **New backlog item:** detect
non-rotational storage and surface an explicit warning at decoy-volume creation, rather than leaving it
to a documentation section.

**Scope note.** The obvious countermeasure — writing chaff so hidden-volume artefacts are not
distinguishable — reads as in scope, since START-HERE lists chaff explicitly. It sits close to the
descoped line and the distinction should be stated before anyone implements it: uniform write and trim
patterns at the storage layer are a countermeasure against a distinguisher. Manufacturing a false record
of what the user did is not, and remains permanently descoped.

### A-2. Constant-time AES moves onto the critical path

Via D-4. Required by the Adiantum branch's single AES-256 block invocation per sector. No longer a
background hardening item — but see D-4: it only has to exist, not to be fast.

### A-3. `prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` line 21 remains defective

Unchanged from the pack's own warning, verified still present at `3ec5ec1`. Reads "UC San Diego's US
2004/0131182." The assignee is the Regents of the University of California; Rogaway is UC Davis.
Running the prompt unpatched writes a refuted attribution into the repo. Task T0-1, a prompt fix rather
than a repo fix.

---

## Summary table

| # | Answer | Changed during session |
|---|---|---|
| D-1 | A — bind the volume salt | — |
| D-2 | C — both, codex32 default, cut-over at 89 chars | B → C |
| D-3 | A — opt-in experimental | — |
| D-4 | HCTR2 / Adiantum split by hardware | A → B → split |
| D-5 | A + posture, refined by D-13 | C → A |
| D-6 | A — counsel brief | B → A |
| D-7 | R22, R20, R03, R06, R28, R05, R04, R07; none killed | — |
| D-8 | Split, final — libsodium ≥ 1.0.21 + HACL\* Ed25519 | C → Split → confirmed |
| D-9 | A — Linux/macOS | C → A |
| D-10 | B — v2, deniability-preserving | — |
| D-11 | C — skip, flags must be visible | — |
| D-12 | R-1 narrowed; R-2…R-6 stand | — |
| D-13 | Select few vulnerable / high-risk individuals | — |

**Unblocked by these answers:** R-2 (D-1), R-3 (D-2), R-4 (D-3), and the queued work behind D-1 through
D-4.

**Still open:** whether to commission a twelfth brief for constant-time AES; whether A-1 warrants a
design change beyond the warning. (The HACL\* ristretto255 question is closed — confirmed absent,
research report on file.)
