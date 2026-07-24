# Research notes — the larger BACKLOG tracks

Honest assessment of the five research-grade items in `ROADMAP.md` → BACKLOG, so nothing is lost and
the next session can pick one up with eyes open. For each: what it is, how it fits this fork's scope,
what is **verifiable in a sandbox** vs. needs a real build/device, and rough effort. These are *not*
routine changes — each deserves its own project.

The house rules still apply: build confidentiality / access-control / deniable **storage**; do **not**
build tooling whose function is to manufacture fake forensic evidence (the DESCOPED line in
`ROADMAP.md` and `CLAUDE.md`). Two of the items below sit near that line and are flagged.

---

## 1. ORAM access-pattern hiding — **flagship; core property proven**

The real mitigation for the multi-snapshot attack (the #1 documented limitation). Write-only ORAM
(HIVE/DataLair) makes every write touch the same PRNG-chosen distribution of physical blocks, so
repeat imaging cannot detect hidden-volume activity. **Status: the access-pattern-hiding property is
proven two ways** (`verification/oram_poc.c`, step `[13]`); the block-layer + position-map integration
into the volume layout is the large real-build part. Full write-up in `docs/ORAM-SPEC.md`.
- *In scope:* yes — deniable storage.
- *Sandbox-verifiable:* the core property (done). Integration + a real two-snapshot experiment: no.
- *Effort:* large (research-grade feature, its own project).

## 2. Decoy-fragments-by-default (upstream issue #1072) — **core proven; moved to DESIGN**

Write plausible hidden-volume creation artifacts on **every** volume by default, so the mere presence
of such fragments proves nothing. **Status: the indistinguishability core is proven** — a real hidden
header (`salt || encrypted`) and a decoy fragment (`salt || keystream`) are the same uniform
distribution, so a free-space scanner cannot tell a with-hidden volume from a decoy-only one
(`verification/decoyfrag_poc.c`, step `[14]`). Full write-up in `docs/DECOY-FRAGMENTS-SPEC.md`.
- *In scope:* yes — it stays clean because the fragments carry **no information** (uniform random), the
  opposite of fabricated activity records (which remain DESCOPED).
- *Sandbox-verifiable:* the indistinguishability core (done). The actual SSD/FTL remnant behaviour and
  writing at real hidden-volume offsets: no (needs real flash).
- *Effort:* medium; remaining work is the write-into-volumes integration + SSD validation.

## 3. Mobile (Android/iOS) — PDE for phones

VeraCrypt has no mobile port. Academic PDE-for-mobile work (Mobiflage, MobiGyges, MobiPluto) shows
demand and **flash-specific** attacks (capacity-comparison, fill-to-full) that desktop hidden volumes
do not face. This is a platform port, not a crypto change.
- *In scope:* yes (confidentiality/deniability), but enormous.
- *Sandbox-verifiable:* essentially no — it is OS/storage-stack integration on real devices. Only
  isolated crypto pieces (already covered by this fork) are testable here.
- *Effort:* very large (a separate product). Best treated as a design study first; the flash attacks
  overlap the ORAM/SSD analysis above.

## 4. UEFI/GPT hidden operating system

Upstream hidden-OS creation is MBR/legacy-BIOS only. A UEFI/GPT hidden OS needs bootloader + ESP +
GPT-layout work (a decoy OS and a hidden OS sharing a disk, booted deniably).
- *In scope:* yes (deniable storage), but it is firmware/bootloader engineering.
- *Sandbox-verifiable:* no — it requires real firmware, an ESP, and boot testing. Nothing here reduces
  to a crypto KAT.
- *Effort:* very large, and high-risk (bootloader bugs brick machines). Design study + a real hardware
  test bench before any code.

## 5. TPM / measured boot / Secure Boot signing

VeraCrypt deliberately omits the TPM. Measured boot (sealing a secret to PCRs) and first-class
bootloader signing would harden **evil-maid** resistance beyond the existing bootloader fingerprint
check. Note the deniability tension: sealing to the TPM can make a volume *non-deniable* (its
dependence on this machine's TPM is itself evidence) and *non-portable* — so this suits the
confidentiality/anti-evil-maid use case, not the deniable-volume use case.
- *In scope:* yes (access control / anti-evil-maid), with the deniability caveat above stated to users.
- *Sandbox-verifiable:* the PCR **policy logic** (which PCRs, seal/unseal state machine) could be unit-
  tested with a software TPM (swtpm) if available; the real sealing needs actual TPM hardware. Not
  verifiable in this sandbox as-is.
- *Effort:* medium-large. A `tpm2`/swtpm-based PoC of seal-to-PCR → unseal is the natural first step,
  on a machine with a TPM.

---

## Recommended order for a future session

1. **Finish the already-proven integrations first** (keyslots §9, network-share client, and the
   documented real-build validations) — they turn proven cores into shipping features.
2. **ORAM integration** (§ above) — highest security value; the core is proven, the block layer is the
   work.
3. **Decoy-fragments-by-default** — smallest of the remaining research items and partly verifiable;
   just hold the evidence-fabrication line.
4. **TPM/measured-boot** — valuable for the anti-evil-maid use case; needs real/simulated TPM.
5. **UEFI/GPT hidden-OS** and **Mobile** — large, real-hardware, design-study-first.

---

## Batch-2 research — "don't build" verdicts (recorded so a planner does not re-propose them)

Batch-2 research produced mostly *negative* results. These items were ruled out; each is listed so a
future session does not re-propose a dead line from a stale backlog. One-line reason each; expand from the
cited sources if reconsidering.

**Modes / ciphers**
- **AEZ, FAST, XCB, EME2** (wide-block alternatives to Adiantum/HCTR2) — **don't build.** The verdict
  stands; the grounds are **per-mode security**, not patents (the earlier "patent encumbrance" phrasing
  was wrong and is corrected below):
  - **XCB** — *cryptanalytically broken.* Three plaintext-recovery attacks published (2024–2025); the
    IEEE P1619.2/SISWG working group moved to remove XCB-AES from the 1619.2 standard. Do not build.
  - **EME2** — avoid on **security** grounds, not legal ones: only a ~2^(n/2) birthday-bound security
    guarantee, plus a data-dependent GF multiply that is a side-channel surface (Mancillas-López et al.,
    ICISS 2009).
  - **AEZ** — a CAESAR round-3 candidate that **missed the final portfolio**, with published
    key-recovery attacks. Not a shipping-grade wide-block mode.
  - **FAST** — no specific published break located; it simply adds nothing over the vetted pair, so it
    is not worth the new-code / new-analysis cost.

  Adiantum (no-AES) and HCTR2 (AES-NI) remain the vetted pair already in tree
  (`docs/ADIANTUM-SPEC.md`, `docs/HCTR2-SPEC.md`). AEZ/FAST/EME2 also appear in `IDEAS-BACKLOG.md`; this
  is the disposition.

  **Patent record (corrected, R-1 / D-12).** The earlier claim of "patent encumbrance" over this group
  was overbroad — it generalized a single *abandoned* filing to a group spanning three institutions. No
  granted patent has been found covering EME/EME2/CMC. The only filing located was **US 2004/0131182**
  (naming Rogaway of **UC Davis**; assignee the **Regents of the University of California**), **abandoned
  in 2007** per the IEEE P1619.2/SISWG record. Phrase this as **"no patent basis found,"** not "no patent
  problem" — the affirmative freedom-to-operate question is FTO territory and lives in the counsel brief
  (`docs/COUNSEL-BRIEF.md`), not here.
- **LEA as a no-AES fallback** — **don't build.** Adiantum is the recommended fallback (see HCTR2 spec);
  do not substitute LEA.

**Storage / deniability**
- **StegFS / steganographic filesystems** — **don't build** as a deniability upgrade. Anderson–Needham–
  Shamir lineage; real capacity/reliability costs and no advantage over the free-space model against the
  multi-snapshot attack (`docs/IDEAS-BACKLOG.md` §G). Research-only.
- **Ciphertext dispersal (Rabin IDA / AONT-RS)** — **don't build** expecting stronger secrecy. Weaker
  than the shipped information-theoretic key split, and distributing recognizable shards conflicts with
  deniability (`docs/IDEAS-BACKLOG.md`, dispersal entry; AFRICACRYPT 2017).
- **Free-space chaff as a multi-snapshot defense** — **don't build** for that purpose; it does not defeat
  the change-chain classifier (`docs/IDEAS-BACKLOG.md` §G; MASCOTS 2021).
- **LUKS-compatible on-disk mode** — **don't build.** This project is deliberately fork-only
  (`docs/KEYSLOTS-SPEC.md`); matching LUKS2's on-disk metadata would import a large format surface for no
  security gain and constrain the header-untouched design.

**Recovery / integrity / platform**
- **Guardian / notary "social recovery"** — **don't build.** Distributing recovery authority to third
  parties adds coercion and collusion surface and a deniability tell; the shipped Shamir threshold split
  already covers split-trust recovery without a trusted quorum service.
- **DIF/DIX end-to-end integrity** — **don't build.** Hardware/storage-stack protection-information is
  orthogonal to at-rest confidentiality and needs controller support; the integrity tier (Merkle
  `[19]`, per-sector auth `[21]`) covers the relevant threat in software.
- **UEFI hidden-OS** — **not now** (`[FORMAT] [RESEARCH]`, `docs/IDEAS-BACKLOG.md`): large,
  firmware/bootloader project; design-study-first, not a batch-2 build.
- **Reimplementing BitLocker / FileVault openers** — **don't build.** Out of scope (interop with other
  vendors' formats), large, and unrelated to this fork's confidentiality/deniability goals.

Anything not on this list that a future session wants to build should still be checked against
`ROADMAP.md` DESCOPED and the scope boundary in `docs/IDEAS-BACKLOG.md` first.
