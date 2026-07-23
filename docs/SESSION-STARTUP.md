# Session startup & handoff — read this first

Single entry point for a fresh Claude Code (or human) session on this repo. It says what the project
is, how to build and verify it, exactly where things stand, and what to do next. Everything it
references is committed.

## 1. What this repo is

A **private fork of VeraCrypt 1.26.29** that hardens the *key-derivation* path with optional
hardware/threshold factors and a factor-gated decoy. It is **defensive** disk-encryption work:
strengthening password entropy (the real weak link), not touching the cipher. Read `CLAUDE.md` for
the architecture and the **scope boundary** (one thing — automated evidence *fabrication* — is
deliberately out of scope and must stay out).

## 2. The one rule that shapes everything: prove it two ways

Every crypto change is proven (a) byte-for-byte against an **independent Python reimplementation**, and
(b) against **real compiled VeraCrypt objects** — and anchored to an **official KAT** where one exists.
Nothing is called done on assertion alone; honest limits are documented, not hidden. The suite is the
receipt.

## 3. Build & verify (commands)

```sh
# --- verification suite (needs only clang/gcc + python3; NO wxWidgets) ---
cd verification && ./build_and_verify.sh          # runs steps [1]..[48], all must pass

# --- real product build (needs wxWidgets; hardware factors need libykpers-1/libfido2) ---
sudo apt-get install -y libwxgtk3.2-dev libykpers-1-dev libfido2-dev libfuse-dev
cd src && make NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1

# --- real-build acceptance (loopback create/mount round-trips; needs a build + root) ---
sudo bash verification/realbuild/acceptance.sh    # see docs/REAL-BUILD-VALIDATION.md
```

The `.claude/hooks/session-start.sh` SessionStart hook installs these best-effort on web sessions;
`.env` documents every build knob. A plain `make` (no flags) stays **byte-for-byte stock**.

## 4. Where things stand (as of branch `claude/project-structure-review-5p44w9`)

**Verification suite: steps [1]–[48], all green.** Feature areas and their status:

| Area | Status | Key refs |
|---|---|---|
| Hardware/threshold key-factor (HKF), factor-gated decoy | core proven; real YubiKey/FIDO2 round-trip = hardware | `docs/HARDWARE-2FA.md`, `[1]`–`[3]` |
| Cross-platform RAM key scrub | proven; OS lock/device triggers = real session | `docs/MEMORY-SCRUB.md`, `[6]` |
| Duress-passphrase safe dismount | crypto proven; wx end-to-end = real build | `docs/DURESS-DISMOUNT-SPEC.md`, `[7]` |
| Multiple keyslots + AF-split + file-backed area I/O | built & proven; C++ mount-path + CLI = real build | `docs/KEYSLOTS-SPEC.md §9`, `[8][9][36][37]` |
| Balloon KDF as a selectable `--hash` | wired & proven; create/mount round-trip = real build | `docs/BALLOON-SPEC.md`, `[38]` |
| Shamir split-key: per-share MAC, bech32 share codes, VSS | proven; dealer-VSS is a parallel prime-field scheme | `docs/VSS-SPEC.md`, `[40][42]`, `[31][32]` |
| Network share (McCallum–Relyea) at full Ed25519 | proven (RFC 8032 KAT); client/transport = real build | `docs/NETWORK-SHARE-SPEC.md`, `[39]` |
| OPRF / threshold-OPRF / VOPRF over ristretto255 | proven (RFC 9496 KAT); server/transport = real build | `docs/OPRF-SPEC.md`, `[43][44][47]` |
| Constant-time screens (Shamir + keyslot), fuzz | proven (self-validating dudect; 44.8k fuzz invariants) | `[41][46][45]` |
| Argon2id explicit params, salt-binding, anti-downgrade, ORAM, decoy-fragments, Merkle, Poly1305, wide-block modes (Adiantum/HCTR2), PQ hybrid, memory-hard (Balloon/scrypt/Catena), VDFs, algorithm survey | proven PoCs | `docs/*-SPEC.md`, `[11]`–`[35]`, `[48]` |

**The honest meta-point:** the verification steps prove the *crypto is correct and matches the
standards*. That is the easy 20% of shipping a feature. The hard 80% — mount-path wiring, CLI, on-disk
format decisions, UX, real-device testing — is what remains under "real-build" below. The from-scratch
EC/group code (Ed25519, ristretto255) is **validation code, not shippable**: it is correct-against-KAT
but *not* constant-time; a deployment uses a vetted library.

## 5. What's left (nothing more is truthfully "sandbox-provable")

Every `[SANDBOX-OK]` backlog item is done; the formal-methods track has a written analysis + plan
(`docs/FORMAL-ANALYSIS.md`) with mechanization pending a computational prover (CryptoVerif/EasyCrypt).
**Everything else needs a real environment:**

- **Tier 2 (rootful Linux VM, no special hardware):** the biggest leverage. Build the fork and run
  `verification/realbuild/acceptance.sh` — loopback create/mount round-trips for Balloon `--hash`,
  Argon2 params, and (once their CLI is wired) keyslots, duress, HKF-simulator. This converts
  "proven core" into "working feature." See `docs/REAL-BUILD-VALIDATION.md` for the item→test map.
- **Tier 3 (physical devices):** YubiKey/FIDO2 USB, logind/udev triggers, TPM sealing.
- **Formal proofs:** a computational prover in a real environment (research-grade effort).

## 6. Conventions (do not break)

- Gate every addition behind `#if defined(VC_ENABLE_*)`; a default build stays byte-for-byte stock.
- Never change the on-disk header format — mix into the password pool instead.
- Match VeraCrypt's per-file style (C for `Common`/`Crypto`, C++ for `Volume`/`Core`/`Main`).
- Keep docs honest: state the multi-snapshot / SSD / imaged-first limitations rather than overselling.
- Add a new verification step for every crypto change and wire it into `build_and_verify.sh`.

## 7. Map of the plans/ideas (all committed)

- `ROADMAP.md` — the numbered, status-tracked plan of every feature.
- `docs/IDEAS-BACKLOG.md` — the idea backlog, tagged `[SANDBOX-OK]` / `[HW]` / `[RESEARCH]`.
- `docs/SESSION-SUMMARY.md` — the anchor/verification-step index (every proven value + where).
- `docs/THREAT-MODEL.md` + `docs/THREAT-CONTROL-MAP.md` — threats, controls, honest limits, API surface.
- `docs/FORMAL-ANALYSIS.md` — security arguments + mechanization plan.
- `docs/AUDIT-GUIDE.md` — reviewer's front door.
- `docs/REAL-BUILD-VALIDATION.md` — the real-build acceptance checklist.
- `docs/*-SPEC.md` — one spec per feature, each with status + honest limits.
- `docs/STARTUP-PROMPT.md` — a paste-ready in-depth prompt to bring a fresh session fully up to speed.
