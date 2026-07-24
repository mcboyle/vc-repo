# Counsel brief — open legal questions

> **THIS IS A LIST OF QUESTIONS FOR COUNSEL, NOT LEGAL ADVICE AND NOT A SET OF ANSWERS.** It is written
> by the software authors to hand to a lawyer. Every item below is **open**: nothing in this document,
> and nothing in the rest of the tree, asserts any of these questions as settled. Where the code or docs
> currently take a position, that position is provisional and tagged `[COUNSEL-REVIEW]` pending this
> brief. Commissioned per decision **D-6**.

## How to read this

Each question is stated as **Question → Facts (as the authors understand them) → Decision it informs**.
The "facts" are the authors' non-lawyer understanding and may be wrong or incomplete; they are here to
save counsel research time, not to constrain the answer. The "decision it informs" says what the project
would do differently depending on the answer — so counsel can prioritise by impact.

Cross-references: `docs/KEY-DISCLOSURE-LEGAL.md` (compelled disclosure), `docs/RESEARCH-NOTES.md` R-1
(wide-block modes), `docs/PQ-HYBRID-SPEC.md` (ML-KEM licence), `docs/DELAY-SPEC.md` (time-release),
`docs/IDEAS-BACKLOG.md` (OPAQUE, FROST). Source register: `handoff/repo-merge/CORRECTIONS-VERIFIED.md`.

---

## 1. Compelled key/password disclosure — statutory exposure by jurisdiction

**Question.** For each jurisdiction where a user may be, what is the current exposure for refusing to
disclose a decryption key or password, and does surrendering only a **decoy** (while a hidden volume
exists) convert a disclosure defence into an additional offence?

**Facts.** `docs/KEY-DISCLOSURE-LEGAL.md` records the authors' understanding: UK RIPA 2000 Part III
(s.49 notice, s.53 offence — up to 2 years, 5 for national-security/CSAM); France Code pénal
Art. 434-15-2 (up to 3 years / €270,000, rising to 5 years / €450,000 if disclosure would have prevented
a crime — amounts per Conseil constitutionnel 2018-696 QPC); Australia Crimes Act 1914 s.3LA, tiered
5 years / 300 penalty units rising to 10 years / 600. These figures are transcribed from secondary
sources and current as of the doc date only. `[COUNSEL-REVIEW]`

**Decision it informs.** The wording of the user-facing duress/decoy guidance, and whether the tool
should actively discourage decoy use in specific jurisdictions rather than merely warn.

---

## 2. Compelled biometric unlock — US circuit split

**Question.** In the United States, is compelling a **biometric** (fingerprint / face) to unlock a device
testimonial and thus protected under the Fifth Amendment, or not — and how should the tool advise users
who unlock biometrically?

**Facts.** The federal circuits currently disagree: *United States v. Payne*, 99 F.4th 495 (9th Cir.
2024) held a compelled thumbprint **not** testimonial; *United States v. Brown*, 125 F.4th 1186 (D.C.
Cir. 2025) held a compelled unlock **testimonial**. The authors are aware of **no SCOTUS merits ruling**
resolving the split. This is distinct from the password-from-the-mind line of cases. `[COUNSEL-REVIEW]`

**Decision it informs.** Whether to recommend against biometric unlock for the D-13 high-risk audience,
and how strongly; the threat-model text for biometric users.

---

## 3. Wide-block sector-mode patents (R-1)

**Question.** Is there any live patent barrier to implementing **EME/EME2/CMC, XCB, AEZ, or FAST**, and
separately, what is the freedom-to-operate position for the wide-block modes the project *does* intend to
ship (**HCTR2**, **Adiantum**)?

**Facts.** The project's earlier claim of "patent encumbrance" over the EME2 group was found overbroad
and has been corrected (R-1 / D-12): the authors located **no granted patent** covering EME/EME2/CMC; the
only filing found was **US 2004/0131182** (naming Rogaway of UC Davis; assignee the Regents of the
University of California), **abandoned in 2007**. The don't-build verdict for those modes now rests on
**security** grounds, not patents. The authors have **not** performed an affirmative FTO search for HCTR2
or Adiantum. `[COUNSEL-REVIEW]`

**Decision it informs.** Whether HCTR2 and Adiantum (the D-4 wide-block pair) can be shipped without
licence risk; whether the abandoned '182 filing has any surviving continuation.

---

## 4. ML-KEM parameter licence (R-5)

**Question.** Does the NIST US-Portfolio royalty-free patent licence for the standardized PQC algorithms
in fact cover the project's ML-KEM-768 use as built, and does the licence's §2.9 (below) mean that any
deviation from the FIPS-203 parameters re-exposes the implementer to the underlying patents?

**Facts.** `docs/PQ-HYBRID-SPEC.md` uses the fixed FIPS-203 ML-KEM-768 parameter set and quotes the
US-Portfolio licence §2.9 verbatim: "any implementation or use … that does not meet the definition of the
PQC ALGORITHM, including any modification, extension, or derivation of the parameters … is not an
implementation or use of the PQC algorithm." The authors read this as: **altering the parameters exits
the royalty-free abeyance.** The parameters are therefore frozen in the tree. `[COUNSEL-REVIEW]`

**Decision it informs.** Whether the "do not alter ML-KEM parameters" constraint is correctly stated, and
what the actual patent exposure would be if a future maintainer tuned them.

---

## 5. Time-release / VDF patents (if `DELAY-SPEC.md` is pursued)

**Question.** If the project builds a verifiable-delay-function or time-lock feature, what patents cover
the candidate constructions — in particular **Wesolowski** and **Pietrzak** VDFs and any **Chia Network**
filings — and RSW time-lock puzzles?

**Facts.** `docs/DELAY-SPEC.md` surveys time-release constructions. The authors are aware that Chia
Network has pursued VDF-related patent filings and that the Wesolowski/Pietrzak VDFs are the practical
candidates, but have done **no** patent search. This feature is **not built** — it is a backlog item, so
the question is a gate on *whether to start*, not on shipped code. `[COUNSEL-REVIEW]`

**Decision it informs.** Whether a time-release feature is buildable without a licence, and which
construction to choose if so.

---

## 6. OPAQUE aPAKE IPR (if OPAQUE is pursued)

**Question.** What is the IPR/patent-disclosure position around **OPAQUE** (the asymmetric PAKE in the
CFRG process) and its underlying OPRF, and is it clear for an open-source implementation?

**Facts.** OPAQUE appears in `docs/IDEAS-BACKLOG.md` as a candidate for password-hardened key retrieval.
The authors have not reviewed the CFRG IPR disclosures for OPAQUE or its dependencies. This feature is
**not built**. `[COUNSEL-REVIEW]`

**Decision it informs.** Whether to adopt OPAQUE versus the already-proven bespoke OPRF/PPSS path, on IP
grounds.

---

## 7. Joye–Libert / threshold-signature IP (if FROST is pursued)

**Question.** If the project adds threshold signatures (e.g. **FROST**), do the **Joye–Libert**
threshold-cryptography patents (or any others) read on the intended construction?

**Facts.** No threshold-signature feature is built; the project's threshold work to date is secret
sharing and threshold OPRF, not signatures. FROST is a possible future direction only. The authors have
done no patent search on it. `[COUNSEL-REVIEW]`

**Decision it informs.** Whether FROST is a viable direction if threshold signatures are ever wanted, or
whether an alternative construction avoids the IP.

---

## 8. General freedom-to-operate for the shipped feature set

**Question.** Taking the features that are actually built and gated on (HKF factor mixing, Shamir
splitting, keyslots, duress-dismount, KeyScrub, salt-binding, the McCallum–Relyea network share, the
ML-KEM hybrid), is there any freedom-to-operate concern across the set as a whole?

**Facts.** The project is a private fork of VeraCrypt 1.26.29 (itself derived from TrueCrypt). Individual
primitives are standard and mostly old, but the authors have performed **no** portfolio-level FTO review.
`[COUNSEL-REVIEW]`

**Decision it informs.** Whether the intended limited public release (D-5/D-13) can proceed, and under
what licence terms.

---

## 9. Distribution posture and the deniability features themselves

**Question.** Given the intended release to a **small, high-risk audience** (D-13), does distributing
deniable-storage and duress-dismount tooling create liability for the authors or distributors in any
target jurisdiction (e.g. as "obstruction" or under dual-use export rules), independent of any single
user's conduct?

**Facts.** The tool builds confidentiality and deniability storage and access control. The one item the
project deliberately keeps **out of scope** — tooling that fabricates a false record of user activity —
is permanently descoped precisely to stay on the confidentiality side of the line (see `ROADMAP.md`
DESCOPED and `docs/DECOY-VOLUME-SPEC.md §6`). The authors have not assessed distributor-side exposure.
`[COUNSEL-REVIEW]`

**Decision it informs.** Whether and how to distribute; what author-facing disclaimers and
audience-vetting the release needs.

---

## Status

All nine items are **OPEN**. No answer here is asserted; the `[COUNSEL-REVIEW]` tags elsewhere in the
tree point back to the corresponding item above and remain in force until counsel responds. Update this
brief in place as answers arrive, converting each "Question" to a dated "Response" — but do **not** remove
the `[COUNSEL-REVIEW]` tags from the source docs until the specific position they guard is confirmed.
