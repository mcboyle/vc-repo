# OPEN ITEMS — Pass 4 research backlog

Roughly 40 named items remain unverified after passes 1–3. **None of them gate an open design
decision.** This is citation hygiene required before publication, not before implementation.

Verified as genuinely open by hand-checking each of the three pass reports. An automated cross-check
was attempted first and proved unreliable — it counted *mentions* rather than *resolutions*, so items
appearing only inside "could-not-reach" lists scored as covered, accented names (Mancillas-López,
Höltervennhoff) produced false negatives, and wrapped backlog lines produced false positives for MemJam,
DOIT and SP 800-132. Given that this project already has one confirmed error caused by asserting a
negative from a malformed search, everything below was confirmed by reading.

---

## Priority A — patents and licences [COUNSEL-REVIEW]

| Item | Status | Note |
|---|---|---|
| Cisco US 7,418,100 | UNVERIFIABLE | Pass 3 attempted, the patent record did not surface. Pass 1's "Expired – Fee Related, adjusted expiry 2026-09-09" stands **unconfirmed from a primary record**. Not guessed. Retry a direct Google Patents fetch. |
| OPAQUE / RFC 9807 IPR disclosure | PARTIAL | Exactly one disclosure exists (confirmed on the datatracker). Its **terms** were not retrieved. |
| Joye–Libert (FROST / threshold) | OPEN | R25 flags it as needing counsel before FROST work |
| Chia VDF provisionals | OPEN | Live because the VDF delay slot is back in scope |
| EP 2,537,284 / US 9,094,189 / US 9,246,675 | PARTIAL | Named in the NIST licence summary; assignment specifics to CNRS / Université de Limoges unconfirmed |
| CN108173643 / CN107566121 | PARTIAL | Exist; holder asserts Kyber/SABER fall within their AKCN mechanism. Unadjudicated assertion, not a finding. |

## Priority B — competing on-disk formats (R21)

BitLocker signature/format · FileVault2 and APFS metadata · Cryptomator · gocryptfs · EncFS audit
(Hornby 2014) · cryptsetup GPL and libluksde licence assignments

*(LUKS1/LUKS2 constants and TKS1 stripe math were resolved in Pass 2.)*

## Priority C — deniability and freshness (R12, R13)

van Dijk et al. STC 2007 · Ariadne and Milan Broz's dm-crypt deniability writings · Android Verified
Boot 2.0 rollback protection · TPM 2.0 NV monotonic counters (wear and rate limits) · RPMB security
analyses · SGX monotonic-counter deprecation · flash-specific PDE (DEFY, INFUSE) · StegFS lineage
detail · multi-snapshot deniability results 2025–26 · **Fredrickson exact per-size recall/FPR cells**
(PARTIAL — Fig. 4's "always identified above 0.75 GB" is confirmed; the specific cells are not)

## Priority D — boot and platform (R18, R19)

Measured boot / TPM PCR specifics · UEFI Secure Boot shim review process · VeraCrypt EFI loader signing
· Apple Silicon AES instruction availability

*(RISC-V Zvk ratification resolved in Pass 3.)*

## Priority E — side channels (R17)

Fixslicing (TCHES 2021) · dudect (ePrint 2016/1123) · MemJam (CT-RSA 2018) · Intel DOIT/DOITM and Arm
FEAT_DIT semantics · Mancillas-López ICISS 2009 *(resolved Pass 1 — listed here only because an
automated check misfiled it)*

*(Käsper–Schwabe and Hertzbleed resolved.)*

## Priority F — modes and MACs (R01, R02)

The entire R02 MAC block: VMAC / UMAC / VHASH security status, GCM key-recovery literature, KMAC256
(SP 800-185), BLAKE3 as MAC, dm-integrity double-write overhead · FAST (ePrint 2017/849) · HCH ·
LEA-256 (Korean standard, ISO/IEC 29192-2 status)

## Priority G — KDF and hashing (R27)

Krawczyk LFSR-based hashing (CRYPTO 1994) · OWASP current PBKDF2 iteration count *(only the Argon2
memory floor was touched in Pass 2)* · NIST SP 800-132 revision status

*(HKDF/RFC 5869 salt rules and RFC 9106 Argon2 parameters resolved.)*

## Priority H — currency

YubiKey developments after firmware 5.7 · FTL-forensics publications 2025–26 · key-disclosure case law
2025–26 [COUNSEL-REVIEW]

*(HQC status and the EUCLEAK 5.7 fix resolved.)*

---

## Structurally unresolvable — do not spend budget here

Flagged in `VERIFICATION-REPORT.md` §5 as unsettleable in principle:

- R17's ctgrind generalisation beyond one machine and toolchain. The 408 / 1000+ error counts are a
  **single-environment measurement** — one machine, one valgrind, one container, x86-64. The docs
  already state this provenance; it needs no further research, only continued honesty.
- Whether any target user stores on magnetic media (R21's threshold for raising the AF ceiling).
- Every `[COUNSEL-REVIEW]` item in R24 — these need a lawyer, not a search.
- Whether the HKF-v2 zero-salt choice was deliberate. Establishable only by asking, not by reading.
