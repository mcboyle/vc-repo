# Session summary

Nine increments on branch `claude/project-structure-review-5p44w9`. Every crypto-relevant change is
proven two ways (independent Python **and** real compiled VeraCrypt objects); every default build stays
byte-for-byte stock; not-sandbox-testable integration is scoped in docs, not written blind.
`verification/build_and_verify.sh` runs **13 green steps**.

## Built + verified

| commit | feature | gate | anchor / step |
|---|---|---|---|
| `2fe9051` | Cross-platform memory-key scrub (ChaCha RAM-encrypt + scrub on unmount/idle/lock/device) | `VC_ENABLE_KEYSCRUB` | `d28b461b…` [6] |
| `6929e2d` | Safe duress-dismount (dismount all + scrub; duress passphrase, no header change) | `VC_ENABLE_DURESS` | `3d874ea9…` [7] |
| `044a1e1` | Multiple-keyslots core (record wrap + 3 backends + KDF binding) | `VC_ENABLE_KEYSLOTS` | `56434b53…` [8], lifecycle [9] |
| `943949a` | Explicit Argon2id memory/iterations/parallelism | `VC_ENABLE_ARGON2_PARAMS` | RFC-9106 `0d640df5…` [11] |
| `6f4da92` | Salt-binding for RAW_SECRET (`HMAC(secret, salt)`) | `VC_ENABLE_HKF_SALT_BIND` | `4619ed18…` [12] |

## Specced + core proven (integration is real-build only)

| commit | item | proven | doc |
|---|---|---|---|
| `42bb9d7` | Multiple keyslots — design + wrapping PoC | wrap/unwrap [8] | `docs/KEYSLOTS-SPEC.md` |
| `b52e5d6` | Network-bound share (McCallum–Relyea) | exchange `cc288fab…` [10] | `docs/NETWORK-SHARE-SPEC.md` |
| `cf7c677` | Write-only ORAM (multi-snapshot deniability) | access-pattern hiding `203b068d…` [13] | `docs/ORAM-SPEC.md` |

## Remaining — real build / real hardware only (not sandbox-testable)

- **Keyslots §9** — `KeyslotArea` volume-I/O bindings, mount-time slot search + duress-slot hook, enroll/rotate/revoke CLI.
- **Network-share client** — EC/bignum at production params (P-256/Ed25519 or 2048-bit MODP), transport, enroll/unlock CLI.
- **ORAM integration** — block layer over the hidden-volume extent, position-map storage, FS interaction, a real two-snapshot experiment.
- **End-to-end validations** — KeyScrub OS triggers (logind/udev), duress round-trip, Argon2/salt-bind create↔mount, on real volumes/desktop.
- **Larger research** — decoy-fragments-by-default, mobile PDE, UEFI/GPT hidden-OS, TPM/measured-boot. See `docs/RESEARCH-NOTES.md`.

## Scope boundary — held

Everything built is confidentiality / access-control / deniable **storage**. The DESCOPED
evidence-fabrication tooling was not built; the "decoy content generator" DESIGN item was flagged as
sitting too close to that line and left alone.
