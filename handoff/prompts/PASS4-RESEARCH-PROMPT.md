# Prompt — Pass 4 external-claims verification

Paste into a fresh session. Self-contained; no repo zip needed.

---

This is **Pass 4** of an external-claims verification for a hardened private fork of VeraCrypt 1.26.29
(open-source, Apache 2.0 + TrueCrypt License 3.0, targeting journalists and activists; scope is
access-control cryptography — confidentiality, integrity, deniability). Passes 1–3 are complete. This
pass covers only what they could not reach.

**Method rules, hold throughout:**

1. For each claim, report what the **primary source actually says**, with a verdict of CONFIRMED /
   REFUTED / UNVERIFIABLE-from-available-sources. Never offer a plausible guess as a resolution.
   "Unverifiable from available sources this pass" is a correct and expected output for patent status,
   licence terms, and recent vendor statements.
2. Prefer primary sources — the paper, ePrint, RFC, NIST document, statute or patent record itself, not
   a summary of it. Quote short verbatim excerpts where exact wording is load-bearing.
3. Flag conflicts between sources rather than silently picking one.
4. Confirmations count as findings. So do partial confirmations where a conclusion survives but its
   cited justification is wrong.
5. This is engineering research, not legal advice — mark legal items `[COUNSEL-REVIEW]`.
6. **List explicitly whatever you could not reach.** Do not let items drop silently. Passes 1–3 all did
   this and it is why the effort is auditable.

**Work in this order.**

**A — Patents and licences (highest value; all `[COUNSEL-REVIEW]`).**
Cisco **US 7,418,100** — Pass 3 failed to surface the record; Pass 1 logged "Expired – Fee Related,
adjusted natural expiry 2026-09-09" but that is **unconfirmed from a primary record**. Try a direct
Google Patents fetch. · The single **IETF IPR disclosure against RFC 9807 (OPAQUE)** — its existence is
confirmed; retrieve its *terms* (which patent, what licensing commitment). · **Joye–Libert** patent
relevant to FROST/threshold signatures. · **Chia** VDF provisionals — now live because the time-release
delay slot is back in scope. · Assignment specifics for **EP 2,537,284 / US 9,094,189 / US 9,246,675**
to CNRS / Université de Limoges. · **CN108173643 / CN107566121** (Shanghai Hu Min) — any adjudication,
or does it remain an unadjudicated assertion that Kyber/SABER fall within their AKCN mechanism?

**B — Competing on-disk formats.** BitLocker signature and format basics · FileVault2 / APFS encryption
metadata · Cryptomator and gocryptfs format documentation · the EncFS security audit (Taylor Hornby,
2014) findings · licence assignments relevant to reading other formats (cryptsetup GPL, libluksde).

**C — Deniability and freshness.** van Dijk et al., STC 2007 (confirm venue and claims) · Milan Broz on
dm-crypt deniability limits; Ariadne · Android Verified Boot 2.0 rollback protection · TPM 2.0 NV
monotonic counters, including wear and rate limits · RPMB security analyses and breaks · SGX
monotonic-counter deprecation · flash-specific PDE (DEFY, INFUSE) · Anderson–Needham–Shamir and
McDonald–Kuhn StegFS detail · any multi-snapshot deniability results from 2025–26 · and the **exact
per-size recall/FPR cells** from Fredrickson–Barker–Long (arXiv 2110.04618) — Fig. 4's "hidden volumes
in excess of 0.75 GB are always identified successfully" is confirmed, but the specific cells
(0.75 GB recall 0.999 FPR 0.003; 1.0/1.25 GB recall 1.0 FPR 0.004) are not.

**D — Boot and platform.** Measured boot / TPM PCR basics · UEFI Secure Boot shim review process · any
specific claims about VeraCrypt EFI loader signing · Apple Silicon AES instruction availability.

**E — Side channels.** Fixslicing (Adomnicai–Peyrin, TCHES 2021) · dudect (ePrint 2016/1123) · MemJam
(CT-RSA 2018) · Intel DOIT/DOITM and Arm FEAT_DIT / PSTATE.DIT — existence and semantics.

**F — Modes and MACs.** The whole R02 MAC block: VMAC / UMAC / VHASH security status, GCM key-recovery
literature, KMAC256 (SP 800-185), BLAKE3 as a MAC, dm-integrity double-write overhead · FAST (ePrint
2017/849) · HCH · LEA-256 (Korean standard; ISO/IEC 29192-2 inclusion).

**G — KDF and hashing.** Krawczyk LFSR-based hashing (CRYPTO 1994) · OWASP's *current* PBKDF2 iteration
recommendation (Pass 2 only touched the Argon2 memory floor) · NIST SP 800-132 — is a revision published
or in progress?

**H — Currency.** YubiKey developments after firmware 5.7 · FTL-forensics publications 2025–26 · new
key-disclosure case law 2025–26 `[COUNSEL-REVIEW]`.

**Do not spend budget on these — they are unresolvable in principle:** generalising ctgrind results
beyond one machine and toolchain (the 408 / 1000+ counts are explicitly a single-environment
measurement); whether any target user stores on magnetic media; the `[COUNSEL-REVIEW]` items in R24 that
need a lawyer rather than a search; and whether the HKF-v2 zero-salt choice was deliberate, which is
establishable only by asking.

**Deliverable.** Organise by the letters above. For each item: claim as stated → what the source says,
with citation → verdict. Close with (1) a consolidated list of corrections the fork's reports need,
(2) anything that materially changes the plan, and (3) an explicit list of what you could not reach.
Write it to a file with a readable name — not `compass_artifact_…`. Two prior reports in this project
were nearly lost to opaque filenames.
