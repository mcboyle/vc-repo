# VeraCrypt 1.26.29 Hardened Fork — External Claims Verification, Pass 3

Same rules as passes 1–2: report what the primary source says; verdict CONFIRMED / REFUTED /
UNVERIFIABLE; quote where wording is load-bearing; flag legal items [COUNSEL-REVIEW]. This pass
targets the Pass-2 could-not-reach backlog. Sources read directly this pass are cited inline.

## Priority 6 — CRC-32 irreducibility (the load-bearing correction)
Stigge et al. §4.1 DO assert it, verbatim: "in the case of CRC32 the polynomial pCRC(x) is
irreducible, so this is even a field (it's isomorphic to the F2^8 widely used in cryptology)."
FALSE for standard CRC-32 (0xEDB88320 factors over GF(2); 1+x divides it). The paper immediately
gives the correct general condition: x^N invertible iff p_CRC(0)=1 (coprimality), which every CRC
poly satisfies. CRCINV=0x5B358FD3 confirmed.
VERDICT: irreducibility claim REFUTED (asserted and false); CRCINV CONFIRMED; method sound on the
correct condition. R27 injectivity holds; re-word to rest on p_CRC(0)=1 / companion-matrix
invertibility, NOT field structure. Pass 1's conclusion now fully sourced with the exact quote.

## Priority 6 — HKDF / RFC 5869 salt (bears on §4.2)
RFC 5869: salt optional, non-secret; if absent set to HashLen zeros; hard constraint = not
attacker-controlled. VERDICT: CONFIRMED. Zero-salt is legal but forfeits the per-volume
independence R27's Rank-1 relied on, so the §4.2 divergence finding stands (built HKF-v2 does not
deliver R27's factor-reuse fix). Public per-volume salt is not attacker-chosen either way.

## Priority 4 — Käsper–Schwabe (CHES 2009 / ePrint 2009/129)
Abstract verbatim: AES-CTR bitsliced 7.59 cpb (Core 2); table-GCM AEAD 10.68 cpb; constant-time
AES-GCM 21.99 cpb. VERDICT: CONFIRMED.

## Priority 10 (R19) — RISC-V crypto ratification
Zvk vector crypto: public review 23 Jun–23 Jul 2023; ratified v1.0.0 released 2023-10 (commit
1769c26); merged into unprivileged ISA manuals 2024. Zkt scalar crypto ratified 2021. VERDICT:
CONFIRMED (riscv/riscv-crypto repo note; isa-dev announcement). Apple Silicon AES not re-verified.

## Priority 10 (R24) — statutes [COUNSEL-REVIEW]
France CP Art. 434-15-2 (Cons. const. 2018-696 QPC quoting the loi 2016-731 text): 3 yr / €270,000;
aggravated 5 yr / €450,000. Pre-2016 was 3 yr/€45k → 5 yr/€75k. CONFIRMED; upheld constitutional 2018.
Australia Crimes Act 1914 s.3LA (AustLII): current tiered 5 yr / 300 pu, rising to 10 yr / 600 pu
post-TOLA (Assistance and Access Act 2018). Legacy 6-month figure (Cybercrime Act 2001) is
superseded. CONFIRMED current = 5/10 yr; REFUTED for any doc citing 6 months as current.

## Priority 10 (R25) — OPAQUE RFC 9807 IPR + structure
Published Jul 2025, IRTF/CFRG, Informational ("not endorsed by the IETF", "no formal standing");
was draft-irtf-cfrg-opaque-18. Datatracker shows exactly one IPR record. RECOMMENDED configs target
128-bit: ristretto255-SHA512 / HKDF-SHA-512 / Argon2id(m=2^21,t=1,p=4); P256 variant; scrypt
(N=32768,r=8,p=1) variant. §10.11: OPRF key is the secret salt; no extra salt needed.
VERDICT: PARTIALLY CONFIRMED — one disclosure exists (CONFIRMED); its TERMS not retrieved this pass
(UNVERIFIABLE, carry to Pass 4). Argon2id default matches RFC 9106 FIRST RECOMMENDED (Pass 2) —
internally consistent.

## Could not resolve this pass (Pass 4 backlog)
Cisco US 7,418,100 (patent record didn't surface; NOT guessed); OPAQUE disclosure terms; Joye–Libert;
Chia VDF provisionals; EP 2,537,284 / US 9,094,189 / US 9,246,675 assignment; CN108173643 /
CN107566121; BitLocker/FileVault2/APFS formats; Cryptomator/gocryptfs; EncFS audit (Hornby 2014);
van Dijk STC 2007; TPM 2.0 NV counters; RPMB; SGX counter deprecation; flash PDE (DEFY/INFUSE); R18
measured boot / UEFI shim; Apple Silicon AES; MemJam; Intel DOIT/DOITM & Arm FEAT_DIT; FAST
(2017/849); HCH; LEA-256 (ISO/IEC 29192-2); VMAC/UMAC/VHASH; KMAC256 (SP 800-185); BLAKE3-as-MAC;
dm-integrity double-write; Krawczyk LFSR hashing (CRYPTO 1994); OWASP PBKDF2 count; NIST SP 800-132
revision; YubiKey post-EUCLEAK 5.7+; FTL-forensics 2025-26; Fredrickson exact per-size cells (PARTIAL).

## Consolidated corrections (cumulative, passes 1–3)
1. R27/CRC: re-word to p_CRC(0)=1 / companion-matrix invertibility, not irreducibility/field. Cite
   Stigge §4.1 for method + CRCINV=0x5B358FD3, but flag its "is even a field" as an error. [sourced]
2. R01: XCB date → 2 Sep 2024 (P1).
3. R25: UC Davis / Regents of the University of California, not UC San Diego (P1); ML-KEM FIPS-203
   params only, §2.9 verbatim (P2); OPAQUE disclosure exists, read terms before shipping (P3).
4. ePrint 2024/1554: one evolving paper, not two contradictory cites (P1).
5. R24: FR 3yr/€270k (agg 5yr/€450k); AU 5yr/10yr post-TOLA not 6mo; UK RIPA s.53 2yr/5yr uplift (P2);
   US Payne v Brown biometric split (P2). All [COUNSEL-REVIEW].
6. Recovery encoding: SLIP-0039 / codex32 over BIP-39 (P2).
7. HKDF §4.2: zero-salt is RFC-legal but forfeits R27's per-volume independence; divergence stands.

## Plan-level (cumulative)
- ML-KEM param alteration off the table (§2.9) — closed.
- Write-only ORAM not a default (HIVE/DataLair) — closed.
- VDF delay slot IS in scope as coercion defence (R06 brief) — R25 "no applicability" refuted; keep
  Chia patent question open [COUNSEL-REVIEW].
- CRC correction now airtight: the cited source is indeed wrong, and the exact sentence is recorded.
