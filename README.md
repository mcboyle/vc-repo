# VeraCrypt — hardened key-derivation fork (EXPERIMENTAL)

A private fork of **VeraCrypt 1.26.29** that adds optional **hardware and threshold factors** to the
key-derivation path, plus a **factor-gated decoy** volume. The goal is to strengthen the part of disk
encryption that is actually the weak link — password entropy — not the cipher.

> **Experimental. Not for real data without review.** It modifies key derivation, so volumes created
> with a factor are **not** interoperable with stock VeraCrypt and are **unrecoverable if the
> factor/shares are lost**. Volumes created without a factor, and existing volumes, are unaffected.
> A build with no `VC_ENABLE_*` flags is behaviourally identical to stock VeraCrypt.

## What's here

| Feature | Status | Docs |
|---|---|---|
| BLAKE2b-512 PRF | done | `docs/BLAKE2b-README.md` |
| SHA3-512 PRF | done | `docs/SHA3-README.md` |
| Hardware 2FA (YubiKey HMAC-SHA1 + FIDO2 hmac-secret) | done | `docs/HARDWARE-2FA.md` |
| Factor-gated decoy (hidden volume needs the token) | done | `docs/DECOY-VOLUME-SPEC.md` |
| Threshold / split-key (Shamir M-of-N) | done | `docs/SPLIT-KEY-SPEC.md` |
| Cross-platform memory scrub, network-bound unlock, keyslots, … | planned | `ROADMAP.md` |

All of it works through **one seam**: an extra secret is mixed into the password *before* PBKDF2 using
VeraCrypt's own keyfile pool method, so there is **no on-disk header-format change**. See `CLAUDE.md`
for the architecture.

## Layout

```
src/            full fork source (VeraCrypt 1.26.29 + the changes below) — buildable as-is
patches/        per-feature diffs vs stock 1.26.29 (+ ALL-changes-vs-1.26.29.patch), for review/reuse
verification/   test harnesses + build_and_verify.sh (self-contained crypto proofs)
docs/           per-feature specs + THREAT-MODEL.md
scripts/        bootstrap (reproduce from stock) + verify wrappers
CLAUDE.md       architecture, conventions, module map, the maintained scope boundary
ROADMAP.md      consolidated idea log: done / design / backlog / decided / descoped
```

## Quick start

```sh
# 1) verify the crypto with no full build needed
cd verification && ./build_and_verify.sh

# 2) build the fork (Linux) — see docs/HARDWARE-2FA.md §Build for the exact flags
sudo apt-get update && sudo apt-get install -y libykpers-1-dev libfido2-dev libwxgtk3.2-dev
cd src && make CFLAGS='-DVC_ENABLE_HKF -DVC_ENABLE_YUBIKEY_HMAC -DVC_ENABLE_FIDO2' \
               CXXFLAGS='-DVC_ENABLE_HKF -DVC_ENABLE_YUBIKEY_HMAC -DVC_ENABLE_FIDO2'

# 3) example: mount with a YubiKey as the second factor
veracrypt --text --hkf-backend yubikey --hkf-yk-slot 2  /path/to/volume  /mnt/point
```

## Continuing with Claude Code

Open the repo and read `CLAUDE.md` first — it has the architecture, the module map, the verification
convention (prove every crypto change against Python **and** real VeraCrypt objects), and the scope
boundary to maintain. `ROADMAP.md` lists the next tasks; the highest-value one is the cross-platform
memory-key scrub.

## License

Fork of VeraCrypt, which is dual-licensed under the Apache License 2.0 and the TrueCrypt License 3.0.
See `NOTICE`. Modifications in this fork are provided under the same terms.
