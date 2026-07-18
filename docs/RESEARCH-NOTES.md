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
