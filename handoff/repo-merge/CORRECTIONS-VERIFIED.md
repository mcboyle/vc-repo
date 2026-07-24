# CORRECTIONS — rescoped against the actual tree

The first version of this register assumed the repo carried every defect the research reports carried.
**It doesn't.** Each item below was re-checked by reading its target file. Five of the original seven
changed scope; two dissolved entirely because the repo is already correct.

This is the repo-checkable / source-checkable distinction that `VERIFICATION-REPORT.md` drew and the
first register blurred. Corrections to the *research reports* live in the corpus, not here.

---

## Real defects in the repo — fix these

### R-1. `docs/RESEARCH-NOTES.md` — EME2 patent encumbrance (half-remediated)

**Current text:** "**AEZ, FAST, XCB, EME2** … **don't build.** Patent encumbrance and/or known
side-channel and analysis concerns".

"IBM" was scrubbed from the tree, but the encumbrance claim survives over a group containing EME2 —
and Pass 1 established that **no granted patent ever covered EME/EME2/CMC.** The only filing (US
2004/0131182, Rogaway, assigned to the Regents of the University of California) was abandoned in 2007.

**Fix:** split the reasoning per mode. XCB is *cryptanalytically broken* (2024, two independent CRYPTO
2025 papers; SISWG moved to remove XCB-AES from 1619.2). EME2 is avoid-on-**security** grounds —
~2^(n/2) birthday bound plus a data-dependent multiply side channel (Mancillas-López et al., ICISS
2009). AEZ is a CAESAR round-3 candidate that missed the final portfolio, with published key-recovery
attacks. None of these is a patent problem. Verdict unchanged — only the reasoning is wrong.

**Severity:** medium. The conclusion is right; the stated ground is false and quotable.

**RESOLVED [D-12]:** narrowed, not dropped. Keep the don't-build verdict and per-mode security grounds; replace "no patent problem" with "EME filing abandoned; no patent basis found for the others"; FTO to counsel brief. Task T0-2. Owner confirmed R-1 was overbroad (generalized one abandoned filing to a group spanning three institutions).

---

### R-2. `docs/HKF-MIX-V2-SPEC.md` — the zero salt (§4.2)

**Current text, line 24:** `password[0..128) = HKDF-SHA256(salt = <empty>, …)`
**Line 31:** `PRK = HMAC-SHA256(0^32, password ‖ response)`

Confirmed as built. RFC 5869 permits this — salt is optional and defaults to HashLen zeros, and the
only hard constraint is that it must not be attacker-controlled, which a public per-volume salt
satisfies either way. So this is **not a bug.**

But R27's Rank-1 specified binding the volume salt precisely to obtain per-volume independence and
close factor reuse, and the spec is silent on having dropped it. As built, v2 does **not** deliver
Rank-1's "fixes factor-reuse for free" property.

**Fix:** either bind the volume salt as specified, or add an explicit trade-off note. Do not leave it
silent — silence is what made this look like an oversight. **Blocked on owner decision D-1.**

**Severity:** high — it is a derivation-path property.

---

### R-3. `docs/VSS-SPEC.md` — bech32 is BIP-173, and BIP-173 has a known weakness

The spec is more careful than the verification report credited it. Lines 86 and 90–92 already state the
≤90-character condition, already note that larger shares "drop the formal bound," and already propose
SLIP-39-style segmenting to restore it. Credit where due.

**What is genuinely missing:** BIP-173 bech32 has a documented insertion-deletion weakness independent
of length — when the final character is `p`, inserting or deleting `q` characters immediately before it
does not invalidate the checksum. BIP-350 bech32m fixes this by replacing the final XOR constant 1 with
`0x2bc830a3`. The spec doesn't mention this at all, and it affects short shares too.

Also: "larger shares still detect the overwhelming majority of errors" is unquantified. Past 89
characters there is **no** formal guarantee, and MAC-bearing codes reach ~118 characters.

**Fix:** three options, in order of cost — (a) switch the constant to bech32m, one-line change,
removes the insertion-deletion weakness but not the length limit; (b) implement the segmenting the spec
already proposes; (c) move to BIP-93 codex32, which corrects rather than merely detects. Replace
"overwhelming majority" with the honest statement that no formal bound applies past 89 characters.
**Blocked on owner decision D-2.**

**Severity:** high — this is the actionable finding gating a shipped feature.

---

### R-4. `docs/ORAM-SPEC.md` — missing the strongest counter-arguments

Line 19 names HIVE and DataLair but the doc carries **no** throughput figures, **no** implementation-
break history, and **no** mandatory-public-write cloak requirement. R13 and this spec therefore give
opposite guidance on a scheduled item, with the repo's version omitting everything that argues against.

**Fix — add to a limits section:**
- Measured cost (DataLair, PoPETs 2017 Table 1): hidden write **2.92 MB/s** against dm-crypt public
  write **210.10 MB/s**; HIVE hidden write **0.60 MB/s**. Note the comparison is public-vs-hidden
  because dm-crypt has no hidden mode.
- Both reference systems were broken. HIVE: Paterson & Strefler, ePrint 2014/901, AsiaCCS 2015 — RC4
  keystream bias in the free-block fill; implementation-specific, design and proof not refuted.
  DataLair: Roche et al., CCS 2017 §6 — free-block selection biased toward free blocks, violating
  write-only obliviousness; authors acknowledged and proposed a fix.
- R13's mandatory public-write cloak requirement, which is absent entirely.

Then downgrade the status from flagship to opt-in experimental. **Partly blocked on D-3.**

**Severity:** high — two project documents currently contradict each other.

---

### R-5. `docs/PQ-HYBRID-SPEC.md` — no licence note at all

The parameters are correct and verified (`n=256, q=3329, k=3, eta1=eta2=2, du=10, dv=4`, ACVP vectors,
HMAC combiner outside the KEM). There is simply **nothing** recording *why* they must stay fixed.

**Fix — add, verbatim, from the NIST US-Portfolio licence §2.9:**

> "For the sake of clarity, any implementation or use of the LICENSED PATENT by LICENSOR, SUBLICENSEE
> or any of the party that does not meet the definition of the PQC ALGORITHM, including any
> modification, extension, or derivation of the parameters of the PQC ALGORITHM, is not an
> implementation or use of the PQC algorithm."

Consequence in one line: altering ML-KEM parameters exits the royalty-free abeyance and re-exposes the
implementer to the underlying patents. This is a constraint that must survive staff turnover.

**Severity:** high — currently one undocumented tweak away from a licensing problem.

---

## Minor refinements — the repo is already substantially right

### R-6. `docs/KEY-DISCLOSURE-LEGAL.md`

Already correct on the UK (2 years, 5-year uplift) and France (3 years, 5 if disclosure would have
prevented a crime). Three refinements only:

- **France** — add the amounts: €270,000, rising to €450,000. Source: Conseil constitutionnel décision
  2018-696 QPC, quoting the text as amended by loi 2016-731.
- **Australia** — the entry says "Up to 10 years … (raised from 2 years)." AustLII's current s.3LA
  shows a **tiered** penalty: 5 years / 300 penalty units, rising to 10 years / 600 penalty units.
  Worth stating the tiering rather than only the ceiling.
- **United States** — add the live biometric split, which post-dates the doc: *United States v. Payne*,
  99 F.4th 495 (9th Cir. 2024), compelled thumbprint **not** testimonial, against *United States v.
  Brown*, 125 F.4th 1186 (D.C. Cir. 2025), **testimonial**. No SCOTUS merits ruling. This materially
  changes the threat model for users who unlock biometrically.

All `[COUNSEL-REVIEW]`. **Severity:** low-medium; the doc is sound, these sharpen it.

---

## Dissolved — no repo target, do not "fix"

### N-1. CRC-32 irreducibility — `docs/CRC-SEAM-ADDENDUM.md` is already correct

I originally listed this as the highest-severity correction. **It has no target in the repo.**
`CRC-SEAM-ADDENDUM.md` contains no irreducibility claim and no field-structure argument; it reasons
about injectivity and its proven regime directly, which is the correct footing.

The defect is in **research report R27**, which cites Stigge et al.'s false statement that "in the case
of CRC32 the polynomial pCRC(x) is irreducible, so this is even a field." Fix it there, in the corpus.
The repo needs no change and is, on this point, better than the report it came from — worth recording
as a positive finding rather than silently dropping.

### N-2. XCB date, ePrint 2024/1554, UC San Diego

All three live in the research reports, not the tree. `grep -ri "san diego" .` over the repo returns
nothing. The one live propagation risk is
`prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` line 21, which would write the refuted attribution *into* the
repo if run unpatched — that remains task T0-1 and is a prompt fix, not a repo fix.
