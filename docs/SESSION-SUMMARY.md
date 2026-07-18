# Session summary

Work on branch `claude/project-structure-review-5p44w9`. Every crypto-relevant change is proven **two
ways** (independent Python **and** real compiled VeraCrypt objects); every default build stays
byte-for-byte stock; not-sandbox-testable integration is scoped in docs, not written blind.
`verification/build_and_verify.sh` runs **17 green steps**.

## Built + verified (product code, gated)

| feature | gate | anchor / step |
|---|---|---|
| Cross-platform memory-key scrub (ChaCha RAM-encrypt + scrub on unmount/idle/lock/device) | `VC_ENABLE_KEYSCRUB` | `d28b461b…` [6] |
| Safe duress-dismount (dismount all + scrub; duress passphrase, no header change) | `VC_ENABLE_DURESS` | `3d874ea9…` [7] |
| Multiple-keyslots core (record wrap + 3 backends + KDF binding; **constant-time search**) | `VC_ENABLE_KEYSLOTS` | `56434b53…` [8], lifecycle [9] |
| Explicit Argon2id memory/iterations/parallelism | `VC_ENABLE_ARGON2_PARAMS` | RFC-9106 `0d640df5…` [11] |
| Salt-binding for RAW_SECRET (`HMAC(secret, salt)`) | `VC_ENABLE_HKF_SALT_BIND` | `4619ed18…` [12] |

## P0 hardening of existing code (`IDEAS-BACKLOG.md` §P0)

- **Constant-time GF(2⁸) in Shamir** — branchless multiply + `a^254`, equal to the table over all 65536 inputs (§P0.1).
- **Constant-time keyslot search** — always-decrypt `KeyslotUnwrapCT`, fixed-count scan, constant-time select (§P0.2).
- **Anti-forensic key splitting** — LUKS/TKS1 split/merge, any missing stripe defeats recovery; the SSD-remnant answer (§P0.3, step [15], `ddb23937…`).
- **Swap/hibernate/core-dump lockdown** — `mlockall`/`RLIMIT_CORE=0`/`PR_SET_DUMPABLE=0`, runtime-verified (§P0.4, step [6][G]).
- **Zeroization tests** — `VcSecureWipe` across all sizes/alignments, survives `-O2` (§P0.6, step [6][H]).
- **Verifiable Shamir reconstruction** — `shamir_secret_checksum` (CRC-32), detects wrong/short combines; matches `zlib.crc32` (§D, step [5]).

## Specced + core proven (integration is real-build / `[FORMAT]` / `[HW]`)

| item | proven | doc |
|---|---|---|
| Multiple keyslots — design + wrapping | [8]/[9] | `docs/KEYSLOTS-SPEC.md` |
| Network-bound share (McCallum–Relyea) | `cc288fab…` [10] | `docs/NETWORK-SHARE-SPEC.md` |
| Write-only ORAM (multi-snapshot deniability) | `203b068d…` [13] | `docs/ORAM-SPEC.md` |
| Decoy-fragments-by-default (SSD presence) | `47067dd6…` [14] | `docs/DECOY-FRAGMENTS-SPEC.md` |
| Anti-forensic key splitting (SSD remnant) | `ddb23937…` [15] | `docs/AF-SPLIT-SPEC.md` |
| Balloon memory-hard KDF | `635ebeac…` [16] | `docs/BALLOON-SPEC.md` |
| OPRF password hardening (offline-guess resistance) | `ca5691bd…` [17] | `docs/OPRF-SPEC.md` |

## Remaining — real build / real hardware only

- **Keyslots §9** — `KeyslotArea` volume-I/O, mount-time slot search + duress-slot hook, enroll/rotate/revoke CLI, keyslot-area MAC (§P0.5).
- **Network-share / OPRF servers** — real CFRG group (ristretto255/P-256) or 2048-bit MODP, transport, threshold OPRF/PPSS split.
- **ORAM / decoy-fragments / AF-split integration** — block layer, real hidden-volume offsets, stripe layout; validate on real SSDs.
- **End-to-end validations** — KeyScrub OS triggers, duress round-trip, Argon2/salt-bind create↔mount, on real volumes/desktop.
- **Larger research** — mobile PDE, UEFI/GPT hidden-OS, TPM/measured-boot, wide-block modes (HCTR2/Adiantum), per-sector integrity / Merkle, PQ hybrid. See `docs/RESEARCH-NOTES.md` and `docs/IDEAS-BACKLOG.md`.

## Scope boundary — held throughout

Everything built is confidentiality / access-control / integrity / deniable **storage**. The DESCOPED
evidence-fabrication tooling was not built; the "decoy content generator" DESIGN item was flagged as
too close to that line and left alone; decoy-fragments and free-space chaff are kept to
indistinguishable-random artifacts, never fabricated activity.
