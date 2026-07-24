# Verified external claims

**Current as of 2026-07-24.** Established against primary sources across external-claims verification
passes 1–3. Everything here is CONFIRMED unless marked otherwise.

**Purpose:** stop future sessions re-deriving settled facts, and stop settled decisions being
relitigated. If a claim is here, cite it and move on. If it isn't, it is either open (see
`RESEARCH-NOTES.md`) or was never checked — do not assume.

Companion to `CLAIMS-STATUS.md`, which covers repo-checkable claims. This file covers the
**source-checkable** ones: published papers, standards, licences, statutes and vendor statements that
cannot be settled by reading code.

---

## Constraints that bind implementation

### ML-KEM parameters are frozen at FIPS 203

NIST's PQC patent licence, US Portfolio, **§2.9, verbatim**:

> "For the sake of clarity, any implementation or use of the LICENSED PATENT by LICENSOR, SUBLICENSEE
> or any of the party that does not meet the definition of the PQC ALGORITHM, including any
> modification, extension, or derivation of the parameters of the PQC ALGORITHM, is not an
> implementation or use of the PQC algorithm."

§1.11 defines the algorithm as CRYSTALS-KYBER *as prescribed by NIST*. §2.3 places enforcement in
royalty-free abeyance. The French portfolio (EP 2,537,284 / US 9,094,189 / FR 2,956,541) qualifies
standards "only to the extent identical with parameters of the standard prescribed by NIST."

**Therefore:** ship ML-KEM-512/768/1024 exactly as standardised. Any parameter tweak exits the safe
harbour. `PQ-HYBRID-SPEC.md`'s stock parameters are correct — keep them that way.

### Recovery-share codes: the bech32 length limit is real

BIP-173 bech32 guarantees detection of any ≤4 character errors **only up to 89 characters** (90-char
cap). Beyond that there is no formal bound. Separately, BIP-173 has an insertion-deletion weakness at
*any* length: with a trailing `p`, inserting or deleting `q` characters immediately before it does not
invalidate the checksum. BIP-350 bech32m fixes this by replacing the final XOR constant 1 with
`0x2bc830a3`.

A 256-bit share encodes to ~65 chars (inside the window); **MAC-bearing codes reach ~118 chars**
(outside it). See `VSS-SPEC.md` and correction R-3.

Alternatives, if moving: **SLIP-0039** — RS1024 over GF(1024), 3 checksum words, MDS, detects any ≤3
errors, 1024-word list. **BIP-93 codex32** — bech32 charset, HRP `ms`, 13-char checksum *corrects* 4
substitutions / 8 erasures / 13 consecutive erasures; purpose-built for long sharing codewords.

### Flash sanitization is unreliable — never promise single-file erase

Wei et al., FAST 2011: "between 4 percent and 75 percent of the files' contents remained on the SATA
SSDs … USB drives … between 0.57 percent and 84.9 percent." One drive retained 1% of original data
after 20 whole-disk overwrites. Rely on FDE plus verifiable ATA/NVMe sanitize commands.

---

## Decisions closed by research — do not relitigate

### Write-only ORAM is not a default

DataLair, PoPETs 2017 Table 1 — hidden write **2.92 MB/s**; dm-crypt public write **210.10 MB/s**;
HIVE hidden write **0.60 MB/s**. (Public-vs-hidden comparison; dm-crypt has no hidden mode.)

Both reference systems were broken. **HIVE** — Paterson & Strefler, ePrint 2014/901, AsiaCCS 2015: RC4
keystream bias in the free-block fill breaks plausible hiding; implementation-specific, design and
proof intact. **DataLair** — Roche, Aviv, Choi & Mayberry, CCS 2017 §6: free-block selection biased
toward free blocks, violating write-only obliviousness; authors acknowledged and proposed a fix.

Revisit only for a peer-reviewed, unbroken construction under ~5× overhead.

### Wide-block mode: HCTR2 stays

Unbroken, in the Linux kernel since 6.0, patent-free by author declaration. **NIST SP 800-197A**
(pre-draft, 6 June 2025) proposes developing "variants of the HCTR2 technique" as the basis for its
Acc128 accordion, citing HCTR2's maturity and deployment.

Caveats: Acc128 is itself only birthday-bound; beyond-birthday candidates (HCTR+, ToSC 2025(3) / ePrint
2024/2053; GEM) remain research-stage. HCTR2 gives **confidentiality only** — tampering is diffused,
not detected.

**XCB is broken** (2024; two independent CRYPTO 2025 papers — Bhati & Andreeva two-query, Wang et al.
full plaintext recovery; SISWG initiated a 1619.2 revision to remove XCB-AES). **EME2: avoid on
security grounds** — ~2^(n/2) birthday bound and a data-dependent multiply side channel
(Mancillas-López et al., ICISS 2009) — **not** patents; no granted patent ever covered EME/EME2/CMC.
**AEZ: don't build** — CAESAR round-3, missed the 2019 final portfolio, published key-recovery attacks
(Fuhr–Leurent–Suder ASIACRYPT 2015; Chaigneau–Gilbert ToSC 2016(1) at ~2^66.5 chosen plaintexts;
Bonnetain quantum SAC 2017). AEZ *is* patent-free — that is the only defensible claim for it.

### The delay/VDF slot is in scope

R25's "VDFs have no applicability to access control" is **refuted from primary source**. Brief R06
frames it explicitly: a recovery slot openable only after a genuine 24–72 hour wall-clock delay, with a
succinct proof, as a coercion defence — "an interrogation with a hard time limit cannot succeed."
Backlog items 01-44, 03-29, 14-13, 14-14. R25 asked only a freedom-to-operate question, which is
different. Chia's application-layer patents remain open `[COUNSEL-REVIEW]`.

---

## Reference values

**Argon2 (RFC 9106)** — FIRST RECOMMENDED: Argon2id, t=1, p=4, m=2²¹ (2 GiB), 128-bit salt, 256-bit
tag. SECOND: Argon2id, t=3, p=4, m=2¹⁶ (64 MiB). Argon2id MUST be supported. Field tension worth
knowing: OWASP recommends a ~46 MiB floor and a 2025 study found 46.6% of Argon2 deployments below it.

**HKDF (RFC 5869)** — salt is optional and non-secret; absent, it is set to HashLen zeros. The binding
constraint is that salt must not be attacker-controlled. Omitting it is legal but forfeits
source-independence. Relevant to `HKF-MIX-V2-SPEC.md`.

**CRC-32** — the polynomial `0xEDB88320` is **reducible** over GF(2) (even term count, so 1+x divides
it). Stigge et al. ("Reversing CRC", HU Berlin SAR-PR-2006-05 §4.1) assert it is irreducible and that
the state ring "is even a field" — **this is false.** Their method survives on the correct condition,
`p_CRC(0)=1`, which makes `x^N` invertible by coprimality. `CRCINV = 0x5B358FD3` is confirmed.
`CRC-SEAM-ADDENDUM.md` does not rely on the false claim and needs no change.

**Käsper–Schwabe (CHES 2009)** — bitsliced AES-CTR 7.59 cpb on Core 2; table-GCM AEAD 10.68 cpb; first
fully constant-time AES-GCM 21.99 cpb.

**EUCLEAK (ePrint 2024/1380)** — non-constant-time modular inversion, "unnoticed for 14 years and about
80 highest-level Common Criteria certification evaluations." All YubiKey 5 Series below firmware 5.7
affected; 5.7 (6 May 2024) moved off the Infineon crypto library. Physical access plus minutes of EM
acquisition. CVE-2024-45678.

**Hertzbleed (USENIX Security 2022)** — CVE-2022-24436 (Intel), CVE-2022-23823 (AMD), CVE-2022-35888
(Ampere). DVFS frequency side channel; no microcode patch planned.

**RISC-V** — Zvk vector crypto ratified 2023 (v1.0.0 released 2023-10, merged into the unprivileged ISA
manuals 2024); Zkt scalar crypto ratified 2021.

**HQC** — selected 11 March 2025 (NIST IR 8545) as the code-based backup to ML-KEM. Draft standard for
comment expected early 2026, finalisation 2027.

**FROST** — RFC 9591, June 2024, IRTF/CFRG Informational. Base Schnorr patent US 4,995,082 expired
19 February 2008 (the 2010 date circulating on Wikipedia is wrong).

**OPAQUE** — RFC 9807, July 2025, IRTF Informational, explicitly "not endorsed by the IETF." Exactly
one IETF IPR disclosure on record — **its terms have not been retrieved; read them before
implementing.** §10.11: the OPRF key acts as the secret salt, so no extra salt is needed.

**Recovery-code human factors** — Höltervennhoff et al., USENIX Security 2024: 281 surveyed users plus
196 Reddit support requests. ~12% believed the provider could restore access without the code; only
~14.8% stored it in more than one location. Design for people who will lose it and have no second copy.

---

## Known-unverified — do not cite as settled

- **Cisco US 7,418,100** status. Logged as "Expired – Fee Related, adjusted expiry 2026-09-09" but
  **not confirmed from a primary patent record.** Moot in practice — XCB is broken regardless.
- **OPAQUE IPR disclosure terms.** Existence confirmed; content unread.
- **Fredrickson per-size recall/FPR cells.** Fig. 4's "hidden volumes in excess of 0.75 GB are always
  identified successfully" is confirmed; the specific cells are not.
- ~40 further items in the Pass 4 backlog. None gate a decision.

## Structurally unresolvable — do not spend budget

- ctgrind results generalised beyond one machine and toolchain. The 408 / 1000+ error counts are a
  single-environment measurement (one machine, one valgrind, one container, x86-64). `CT-HARDENING-R17.md`
  already states this provenance; it needs continued honesty, not more research.
- Whether any target user stores on magnetic media.
- Every `[COUNSEL-REVIEW]` item — these need a lawyer, not a search.
