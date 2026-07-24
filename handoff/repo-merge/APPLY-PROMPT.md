# Claude Code task — apply verified research corrections to the tree

**Repo:** `vc-repo`, branch off `master` (`3ec5ec1` or later).
**Gate:** `verification/build_and_verify.sh --strict` exits 0, **0 SKIP**, anchors intact (Shamir
`a8b0cbb7`), negative control still fails. This session is documentation-only — the suite should be
untouched. Run it before and after anyway.

Corrections from external-claims verification passes 1–3. **Every target below was verified by reading
the file first** — several corrections from the original register were dropped because the repo turned
out to be already correct. Do not add those back.

Companion files: `CORRECTIONS-VERIFIED.md` (full reasoning per item),
`ROADMAP-CLAUDE-DELTAS.md` (exact blocks to splice), `docs/VERIFIED-CLAIMS.md` (new file to add).

---

## 1. NEW FILE — `docs/VERIFIED-CLAIMS.md`

Add the supplied file verbatim. It is the source-checkable counterpart to `CLAIMS-STATUS.md`: published
papers, standards, licences and statutes that cannot be settled from code. It carries a
"current as of 2026-07-24" header — keep that, and keep the "known-unverified" and "structurally
unresolvable" sections. They are the point.

Link it from `CLAUDE.md`'s verification-methodology section (block supplied in the deltas file).

## 2. `docs/RESEARCH-NOTES.md` — split the wide-block reasoning

The **AEZ / FAST / XCB / EME2** "don't build" entry currently attributes the verdict to "Patent
encumbrance and/or known side-channel and analysis concerns." The verdict is right; the patent ground
is false for EME2.

Rewrite so each mode carries its own reason: XCB **broken** (2024, two independent CRYPTO 2025 papers;
SISWG initiated a 1619.2 revision to remove XCB-AES). EME2 **security** — ~2^(n/2) birthday bound plus
data-dependent multiply side channel (Mancillas-López et al., ICISS 2009); **no granted patent ever
covered EME/EME2/CMC**, the only filing (US 2004/0131182, Rogaway, Regents of the University of
California) was abandoned in 2007. AEZ — CAESAR round-3, missed the 2019 final portfolio, published
key-recovery attacks; patent-free, which is the only defensible claim for it.

Do **not** change any verdict. Only the reasoning is wrong.

## 3. `docs/PQ-HYBRID-SPEC.md` — record why the parameters are fixed

There is currently no licence note at all. Add a short subsection quoting NIST's PQC licence, US
Portfolio **§2.9**, verbatim (text in `docs/VERIFIED-CLAIMS.md`), and state the consequence in one
line: altering ML-KEM parameters exits the royalty-free abeyance. The existing parameters
(`n=256, q=3329, k=3, eta1=eta2=2, du=10, dv=4`) are correct — do not touch them.

## 4. `docs/ORAM-SPEC.md` — add the limits section

The doc names HIVE and DataLair but carries no cost figures, no break history, and not R13's mandatory
public-write cloak requirement. Add all three (figures and citations in `CORRECTIONS-VERIFIED.md` R-4),
and downgrade the status from flagship to opt-in experimental.

State the throughput comparison honestly: 2.92 MB/s hidden write against dm-crypt's 210.10 MB/s
*public* write, because dm-crypt has no hidden mode — it is not like-for-like.

## 5. `docs/VSS-SPEC.md` — the bech32 gap

The spec is already careful about length: it states the ≤90-char condition, notes larger shares "drop
the formal bound," and proposes SLIP-39-style segmenting. **Keep all of that.**

Two additions. First, BIP-173 has an insertion-deletion weakness independent of length — with a
trailing `p`, inserting or deleting `q` characters immediately before it does not invalidate the
checksum; BIP-350 bech32m fixes this by replacing the final XOR constant 1 with `0x2bc830a3`. The spec
doesn't mention this and it affects short shares too. Second, replace the unquantified "still detect
the overwhelming majority of errors" with the honest statement that **no formal bound applies past 89
characters**, and record that MAC-bearing codes reach ~118 characters.

Do not change the encoder in this pass — that is a code decision pending owner input.

## 6. `docs/KEY-DISCLOSURE-LEGAL.md` — three refinements

This doc is already substantially correct; do not rewrite it. `[COUNSEL-REVIEW]` throughout.

- **France** — add the amounts: €270,000, rising to €450,000 (Cons. const. 2018-696 QPC, quoting the
  text as amended by loi 2016-731).
- **Australia** — the entry gives only the 10-year ceiling. Current s.3LA is **tiered**: 5 years / 300
  penalty units, rising to 10 years / 600 penalty units. State the tiering.
- **United States** — add the biometric circuit split, which post-dates the doc: *United States v.
  Payne*, 99 F.4th 495 (9th Cir. 2024), compelled thumbprint **not** testimonial, against *United
  States v. Brown*, 125 F.4th 1186 (D.C. Cir. 2025), **testimonial**. No SCOTUS merits ruling. This
  matters for users who unlock biometrically.

## 7. `ROADMAP.md` and `CLAUDE.md` — splice the supplied blocks

Blocks are in `ROADMAP-CLAUDE-DELTAS.md`, matched to house style and to the existing section headings
(`DECIDED`, `BACKLOG`, `Known limitations`, `Verification methodology`, `Conventions`).

**Append into the existing sections. Do not create new top-level documents** — the repo already has the
right structure and a parallel set would diverge.

---

## Explicitly NOT in scope

- **Do not "fix" the CRC-32 irreducibility claim in `docs/CRC-SEAM-ADDENDUM.md`.** It isn't there. That
  doc reasons about injectivity and its proven regime directly, which is correct. The false
  irreducibility claim is in research report R27, in the corpus, not in the tree. Verified by reading.
- **Do not search for "UC San Diego" fixes in the repo.** `grep -ri "san diego" .` returns nothing. The
  live risk is `prompts/CLAUDE-CODE-BATCH3-B-DOCS.md` line 21, which is a prompt fix (task T0-1), not a
  repo fix — and it must happen *before* that prompt is run.
- **Do not change `HKF-MIX-V2-SPEC.md`'s zero salt** in this pass. As built it is RFC 5869-legal (salt
  optional, defaults to HashLen zeros) but it forfeits the per-volume independence R27's Rank-1 was
  designed to deliver. Whether that was deliberate is pending an owner decision. When it is settled,
  either bind the salt or add an explicit trade-off note — but do not leave it silent, because silence
  is what made it look like an oversight.
- **Do not touch the verification suite.** Documentation only.

## Verification before pushing

- `--strict` still exits 0, **0 SKIP**, anchors intact, negative control fails.
- `grep -ri "patent encumbrance" docs/` no longer returns the EME2 group.
- `docs/VERIFIED-CLAIMS.md` exists and is linked from `CLAUDE.md`.
- `ROADMAP.md` gained entries in `DECIDED`, `BACKLOG` and `Known limitations` — and **no** new
  top-level file was created.
- `docs/CRC-SEAM-ADDENDUM.md` is unchanged.
