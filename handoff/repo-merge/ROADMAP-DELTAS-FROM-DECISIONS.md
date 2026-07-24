# ROADMAP deltas from DECISIONS-ANSWERED

**Source:** `DECISIONS-ANSWERED.md` (2026-07-23) · **Target:** repo `ROADMAP.md` @ `3ec5ec1`

These are edits to splice into the **existing** `ROADMAP.md` — not a replacement roadmap. Each block
names the section it lands in. The repo owns the roadmap; this only records what the 13 decisions change.

---

## Into `## DESIGN — specced, not yet built`

**HKF-v2 salt binding [D-1].** The as-built v2 mix drops the volume salt from HKDF-Extract; D-1 ruled
this an oversight. Bind the volume salt as R27 Rank-1 specified, restoring per-volume independence.
Because existing v2 volumes derive differently once bound, this is a **derivation-level migration** and
must be handled under the v2 format work [D-10] and examined by the R22 brief. Closes correction R-2.

**Recovery-share encoding → codex32 + bech32m [D-2].** Default export encoding becomes BIP-93 codex32
(error-correcting). Short codes (**≤ 89 characters**) use BIP-350 bech32m. The 89-char boundary is the
point where bech32's 4-error guarantee holds and must be a written constant, not a per-call judgement.
Also add the BIP-173 insertion-deletion note to `docs/VSS-SPEC.md` (independent of length; affects short
shares). Steers correction R-3.

**Wide-block sector mode: HCTR2 + Adiantum, hardware-selected [D-4].** Supersedes the plain HCTR2-vs-XTS
question. Promote **HCTR2 for AES-NI hardware, Adiantum for non-AES-NI hardware**, both implemented on
every platform, mode selected at **volume-creation time** and recorded in a **v2 header field** [D-10].
Adiantum still invokes AES-256 on one 16-byte block per sector, so it does not remove the AES
dependency — see the constant-time-AES item in BACKLOG. Do not gate by runtime detection at mount:
a volume made on AES-NI hardware must open on hardware without it, so the selector is per-volume, not
per-machine. Test the recorded selector against the D-10 deniability constraint (it mildly fingerprints
the creating hardware).

---

## Into `## DESIGN` — new v2-format entry [D-10]

**On-disk v2 format, deniability-preserving.** Format changes are on the table as a **v2 alongside the
compatible v1**, under a hard constraint: **no v2 feature may reduce deniability below v1, or it is
descoped.** Un-prunes authenticated FDE, per-sector MACs, and integrity metadata (all previously blocked
by the no-format-change rule). Provides the home for the D-4 mode selector and the D-1 salt-binding
migration. Every v2 feature carries a deniability-impact line reviewed against the constraint before
build.

---

## Into `## BACKLOG — good ideas from the research, not started`

**Replace bespoke ristretto255/Ed25519 [D-8, confirmed].** Adopt **libsodium ≥ 1.0.21** for ristretto255
and **HACL\*** for Ed25519. Research (2026-07-23, report on file) confirmed no verified ristretto255
exists in C anywhere and HACL\* has none. libsodium must be **≥ 1.0.21** (CVE-2025-69277 fix; the
ristretto255 API was not the affected surface, and the maintainer recommends ristretto255 as the
mitigation for that bug class). Deletes the hand-rolled group arithmetic. Do **not** hand-build ristretto
on HACL\*'s exposed `Hacl_EC_Ed25519` primitives without an independent audit — the ristretto glue would
be new unverified C. Watch: reopen if HACL\*/libcrux ships verified ristretto255.

**Constant-time AES — now on the critical path [D-4 / A-2].** Required by the Adiantum branch's
single-block-per-sector AES-256 call on non-AES-NI hardware. Because it runs once per sector rather than
over the whole sector, it only has to **exist**, not be fast — a bitsliced/constant-time implementation
is acceptable even if slow. Blocks HCTR2/Adiantum promotion [D-4].

**SSD deniability warning [A-1] — treat as blocking for the decoy feature.** TRIM reveals which sectors
are free (breaks the free-space-indistinguishable-from-random assumption); wear-levelling cannot be
disabled and can leave hidden-volume-creation residue in retired pages, plus per-sector write counters
that leak the written region. Detect non-rotational storage and surface an explicit warning at
**decoy-volume creation**, not just in a docs section. Any chaff/uniform-write countermeasure stays on
the confidentiality side of the scope line — uniform write/trim patterns are fine; fabricating a false
activity record is not, and remains DESCOPED.

---

## Into `## BACKLOG` — research-brief ordering [D-7]

Unrun briefs, in run order: **R22** (migration safety — now first; the v2 format and salt migration land
on this seam) · **R20** (mobile PDE — promoted; it is the deniability-over-flash literature, which the
SSD finding makes a desktop concern too) · **R03** · **R06** · **R28** · **R05** · **R04** · **R07**.
Queued, unranked: **R11**, **R23**, **R26** (demoted — D-8 deletes the bespoke code that made
machine-checked proof urgent). **None killed.** Possible **twelfth brief**: constant-time AES, if it
should be researched before implementation.

---

## Into `## DECIDED — advisory conclusions`

- **End state [D-5, D-13]:** public release to a **select few vulnerable / high-risk individuals** —
  not mass distribution, not a prototype. The code must hold under a serious threat model; the audience
  is small and reachable. This is why A-1 (SSD) is treated as blocking rather than cosmetic.
- **Counsel brief [D-6]:** commissioned. Covers compelled-disclosure statutes, Chia VDF patents, OPAQUE
  IPR, the Joye–Libert/FROST question, general FTO, the R-1 wide-block-mode patent question, and the
  R-6 biometric circuit split (*Payne* 9th Cir. 2024 vs *Brown* D.C. Cir. 2025). No legal conclusion is
  asserted as settled in the tree pending this brief.
- **Platform priority [D-9]:** Linux/macOS (C++ path). Note both wide-block modes must still exist on
  every platform a volume might travel to [D-4].
- **Pass 4 [D-11]:** skipped; citations accepted as flagged — **but the flags must survive into published
  docs**, since an unverified-looking-verified citation is worse than an absent one. Known cost: the
  Pass 1 claim class goes unrechecked, and R-1 is a demonstrated instance of that class failing.
- **Write-only ORAM [D-3]:** stays **opt-in experimental** with an honest limits section (throughput,
  break history for HIVE and DataLair, R13's mandatory public-write cloak). Partly settles R-4.
- **Correction R-1 [D-12]:** narrowed. Keep the don't-build verdict and the security grounds; replace
  "no patent problem" with "EME filing abandoned; no patent basis found for the others"; FTO → counsel
  brief.

---

## Into `## DESCOPED — deliberately not built` (reaffirmed, no change)

The scope boundary is unchanged by any of the 13. Fabricating a false record of user activity to deceive
forensic examination stays permanently descoped. The A-1 chaff countermeasure is explicitly **not** a
reopening of this — it defends against a distinguisher; it does not manufacture history.
