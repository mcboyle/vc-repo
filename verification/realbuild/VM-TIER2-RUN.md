# VM Tier-2 acceptance — actual run record (2026-07-25)

First execution of the Tier-2 real-build acceptance path on a box that has a kernel
device-mapper. Prior sessions ran only in containers, where all of Tier 2 SKIPs. This
file records **what actually happened**, with the exact commands, so the next reader
re-runs instead of inheriting. See `docs/CANT-CLAIMS-AUDIT.md` for the per-claim verdicts.

## Environment (probed, not assumed)

```
$ [ -e /dev/mapper/control ] && echo yes        # -> yes  (dm-crypt available)
$ ls /dev/loop-control                           # -> present (crw-rw---- root disk 10,237)
$ nproc                                           # -> 16
$ free -g | awk '/Mem:/{print $2}'               # -> 62 (GB total)
$ lsb_release -d                                  # -> Ubuntu 24.04.4 LTS
$ grep -o aes /proc/cpuinfo | head -1            # -> aes   (AES-NI present)
$ uname -r                                        # -> 6.8.0-136-generic
```

**Environment fact worth recording: `sudo` was password-gated by default.** `sudo -n true`
returned "a password is required"; the `mboyle` user is in the `sudo` group but had no
NOPASSWD rule. The task brief asserted the VM "has sudo" — true for an interactive operator,
but a non-interactive agent session cannot use it until a NOPASSWD drop-in exists:

```
echo "mboyle ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/99-mboyle-nopasswd
sudo chmod 440 /etc/sudoers.d/99-mboyle-nopasswd && sudo visudo -c
```

This is itself an instance of the pattern this repo tracks: "sudo is available" was a
partially-true inherited claim; the direct test (`sudo -n true`) is what settled it.

**Environment fact worth recording: installing extra GCC versions breaks `clang++` builds unless the
matching `libstdc++-N-dev` is also installed.** Installing `gcc-14` (to measure `-fstack-usage` frames
across the CI compiler matrix) moved `clang++`'s auto-selected libstdc++ to gcc-14's, which had no
headers — the product build then failed with `'cstddef'/'exception'/'cxxabi.h' file not found`, which
reads like a broken checkout but is a toolchain-selection artifact. Two ways out: install the matching
`libstdc++-14-dev` (advances `clang++` permanently to gcc-14's libstdc++), or remove the extra GCCs to
restore `clang++`'s original gcc-13 selection (`clang++ -v … | grep 'Selected GCC installation'` shows
which it picks). The box here was restored to gcc-13 so the shipped binary and its timing numbers came
from one toolchain; the cross-compiler frame numbers were captured first.

**Environment/methodology fact worth recording: timing a binary while rebuilding that same path produces
~0.01s samples that read as a severe regression.** A background serial pre/post run was probing
`src/Main/veracrypt` while the product was being rebuilt at that path; the PRE binary (built once in a
worktree) stayed stable at ~85s, while POST was overwritten mid-run and produced a **bimodal 0.01–85s
spread and a meaningless 43.63s mean** — a "regression" that was pure apparatus. Three hypotheses about
the *change* (a live `assert` firing, the `-1` sentinel leaking into the serial path, `rec_fits` bailing
early) were all wrong; the cause was the measurement, not the code — the same error class as the
mixed-build Argon2 episode (a symptom read as evidence about the thing under test rather than the
apparatus). Fix, now enforced by `verification/realbuild/keyslot_timing.sh`: **freeze both binaries to
stable paths, sha256-guard them before and after the run (abort if either changed), and capture exit
status alongside wall-clock** so a 0.01s success and a 0.01s crash are never conflated.

## Build (STEP 2)

```
./scripts/build-product.sh NOGUI=1 HKF=1 HKF_SIMULATOR=1 KEYSCRUB=1 DURESS=1 \
    KEYSLOTS=1 SHARECODE=1 SHAMIRMAC=1 FLASH_WARN=1 ARGON2PARAMS=1
```
Exit 0 in ~29s. Stamp written to `src/.build-flags`:
```
-DTC_LINUX -DTC_NO_GUI -DTC_UNIX -DVC_ENABLE_ARGON2_PARAMS -DVC_ENABLE_DURESS
-DVC_ENABLE_FLASH_WARN -DVC_ENABLE_HKF -DVC_ENABLE_HKF_MIX_V2 -DVC_ENABLE_HKF_MIX_V2_SALTBIND
-DVC_ENABLE_HKF_SIMULATOR -DVC_ENABLE_KEYSCRUB -DVC_ENABLE_KEYSLOTS -DVC_ENABLE_SHAMIR_MAC
-DVC_ENABLE_SHARECODE
```
Note: **no `-DVC_ENABLE_BALLOON_KDF`** — the STEP 2 flag line omits `BALLOON=1`. This matters
for the harness (below).

## Positive control FIRST — kernel dm-crypt mount works end to end

Before any negative test, the load-bearing claim was tested directly with a real filesystem:

```
VC=src/Main/veracrypt; W=$(mktemp -d)
sudo $VC --text --create $W/pc.hc --size=10M --password=P --pim=0 --keyfiles="" \
     --encryption=AES --hash=SHA-512 --filesystem=fat --volume-type=normal --random-source=/dev/urandom
sudo $VC --text --mount  $W/pc.hc $W/pc.mnt --password=P --pim=0 --keyfiles="" \
     --protect-hidden=no --slot=1 --non-interactive
```
Observed (all exit 0):
- dm mapping created: `veracrypt1 (252:1)`
- loop bound: `/dev/loop0: (…/pc.hc)`
- filesystem mounted: `/dev/mapper/veracrypt1 on …/pc.mnt type vfat`
- **wrote and read `proof.txt` through the encrypted mount**
- `--dismount` exit 0; `dmsetup ls` and `losetup -a` clean afterward

Repeated a second time as a regression check — identical result. **Kernel dm-crypt mount is
real and repeatable on this box.**

## Individual claim probes (direct tests, generous timeouts)

| Probe | Command shape | Result | Time |
|---|---|---|---|
| kernel dm-crypt round-trip (FAT) | create+mount+write+read+dismount | **PASS** | mount 1s |
| HKF-simulator 2FA positive mount | `--hkf-backend=simulator --hkf-sim-secret=<sec>` correct | **PASS — mounted via kernel** | 1s |
| HKF-simulator wrong-secret reject | wrong `--hkf-sim-secret` | **PASS — rejected** (Incorrect password) | slow* |
| keyslot enroll → open → recover | `--keyslot-add` then `--keyslot-open` | **PASS — recovers exact master key** | fast |
| keyslot wrong passphrase | `--keyslot-open` wrong pass | **PASS — rejected** | fast |
| keyslot **mount-time auto-search** | plain `--mount` with a *keyslot* passphrase | **PASS — mounted via keyslot through kernel dm-crypt** | **87s** |
| duress-register | `--duress-register --new-password=…` | **PASS — well-formed 16B salt + 32B tag** | fast |
| argon2 wrong-memory / wrong-iterations | `--hash=Argon2` wrong params | **PASS — rejected** (via acceptance.sh) | slow* |

\* "slow" = the fallback path characterised below.

## Two real findings the harness surfaced (neither is a crypto defect) — both now FIXED in this branch

After the fixes below, a full `sudo bash verification/realbuild/acceptance.sh` on this box runs green:
**`SUMMARY: pass=27 fail=0 skip=4 pending=2`** (the 4 SKIP are the Tier-3 hardware items + balloon;
the 2 PENDING are the documented duress-dismount-of-mounted-volumes and network-share integrations).
Every check that previously false-FAILed on a real-dm box now PASSes, including Tier 2b (in-process
`Volume::Open`: plain open/reject + factor 2FA).

### 1. acceptance.sh was calibrated to the *container* failure mode, so its positive round-trips FAILed on a real-dm box

`roundtrip()` creates volumes with `--filesystem=none` and mounts them. On a box with **no**
device-mapper (container), the mount fails *at* the dm-crypt step with a device-mapper error;
`classify_mount_log` matches `device-mapper|dmsetup|/dev/mapper/control` → returns 2 → `keyok`
**PASS**. On a box **with** dm-crypt (this VM), the mount succeeds past dm-crypt and then fails
at the *filesystem* step because a `--filesystem=none` volume has no filesystem:

```
Error: mount: …/mnt: wrong fs type, bad option, bad superblock on /dev/mapper/veracrypt4 …
```
That signature matches none of `classify_mount_log`'s patterns → returns 1 → `bad` **FAIL**.

**Net: the harness's `stock` / `argon2` / `hkf-simulator` positive round-trips PASS in a
container and FAIL on a real VM — exactly inverted.** The harness's success criterion *is* the
container failure mode. The volumes are fine (proven by the FAT round-trip above). **Fixed in this
branch:** `classify_mount_log` now also returns 2 (key-correct, dm reached) when the log shows a
`/dev/mapper/veracrypt` mapping — a node that only ever appears for a *correct* key — so the
`--filesystem=none` mount is recognised as a key-level PASS on both a container and a real-dm box.
(No product change; harness only.)

### 2. Wrong-key mounts cost ~46–87s — and the cause is a DELIBERATE constant-time security feature

Measured on this box, on the **pre-parallel (original serial) binary** — this is the baseline that
motivated the change; post-change speedup numbers are produced separately by the guarded
`keyslot_timing.sh` (do not cross-compare rows below with those):

| Operation (pre-parallel serial binary) | Time |
|---|---|
| native-key mount, pinned `--hash=SHA-512` (auto-search NOT triggered) | **1s** (mounts) |
| wrong-password mount → auto-search, pinned `--hash=SHA-512`, PIM pinned | **46s** then rejects |
| wrong-password mount → auto-search, **no** `--hash` (full PRF sweep too) | **>120s** (did not finish) |
| mount via a keyslot passphrase → auto-search succeeds | **87s** then mounts |

CPU/mem sample during a wrong-key mount: **one** thread at 99.8%, 15 cores idle, load 0.71;
RAM used 1409→1400 MB (≈60 GB stays free). So the cost is a **single-threaded, CPU-bound,
negligible-RAM** chain — *not* memory-hard KDFs.

**Root cause (traced to source, not inferred).** When the native header (slot 0) rejects the
password, the fork runs a **mount-time keyslot auto-search** (`src/Volume/Volume.cpp:309-345`)
configured `cfg.kdf = KeyslotKdfSha512; cfg.cost = 500000; cfg.maxSlots = 63`. `KeyslotOpen`
(`src/Common/KeyslotStore.c:228-268`) then runs that **500,000-iteration PBKDF2-SHA512 on all
63 slots** — each with its own salt (`rec + L_SALT`), so they cannot collapse to one
derivation. 63 × ~0.7s ≈ 46s, an exact match. This reconciles every observation: single-core
(serial loop), `--hash`-independent (its own KDF), wrong-native-key-only (auto-search only
fires when slot 0 fails), negligible RAM (PBKDF2).

**This is intentional and load-bearing for security.** KeyslotStore.c:230-236 states it
outright: *"scan a fixed number of slots … run the KDF and MAC on EVERY slot regardless of the
'VCKS' marker, and select the result in constant time with no early return. This leaks neither
which slot matched nor how many are populated."* The full 63× scan is an **anti-forensic /
deniability constant-time property**. Skipping empty slots (e.g. gating on the `VCKS` magic)
would speed it up but would leak, via timing, how many keyslots exist and which matched —
regressing that guarantee. So the "obvious" optimization is off the table by design.

**Hardware does not help** (confirmed by the CPU/mem sample): 60 GB RAM sits unused and 15 of
16 cores are idle — the loop is serial. More vCPUs/RAM, and ESXi VMX knobs
(`sched.cpu.latencySensitivity`, NUMA sizing, hpet, hardware-assisted-virt exposure), change
nothing; only a faster per-core clock would, and only linearly. The only *safe* software
speedup is to **parallelize the N independent derivations across cores while still computing
all of them and selecting in constant time**.

**Update — this parallelization is now IMPLEMENTED** (`docs/KEYSLOT-PARALLEL-SCAN.md`;
`Common/KeyslotStore.c` `KeyslotOpenParallel` + `Volume/KeyslotParallelExecutor.h`). It preserves the
constant-time invariant (all N derived, no early exit, index-order first-match select), keeps the module
allocation-free, is exception-safe across the C boundary (a `std::thread` `EAGAIN` failure falls back to
inline execution — never a false "wrong password"), and is gated by a committed regression test
(`build_and_verify.sh` step [99]) that checks byte-identical VMK recovery + the constant-time property.
Measured on this 16-core VM with the hash-guarded `keyslot_timing.sh` (frozen PRE=origin/master vs POST,
N=5): the wrong-password mount → auto-search drops **47.6s → 5.7s (8.3×)**, while the serial `pf==NULL`
path (`--keyslot-open`, isolated with the correct native password) is **unchanged — PRE 36.98s vs POST
36.86s, Δ0.11s within the 0.45s spread**. (A naive serial measurement using a *wrong* `--password` first
showed 84.6s vs 51.1s — not a regression but the parallel auto-search leaking in via `Core->OpenVolume`;
see `docs/KEYSLOT-PARALLEL-SCAN.md`.)

**Consequence for the harness.** `acceptance.sh` runs several negative mounts (some with no
pinned `--hash`), each paying the 46s+ auto-search, so it cannot finish within a 5-minute
budget on a real-dm box — it ran the first Tier-2 checks then was killed at 5m. The
self-gating logic is correct; the per-negative wall-clock is the issue. A harness-only
mitigation (no product change): give Tier-2 a longer timeout, and/or assert the negatives via
the fast in-process `open_roundtrip.sh` path rather than full kernel mounts.

### 3. `balloon` round-trip FAILs due to a flag-set mismatch, not a defect

acceptance.sh line 122 runs `roundtrip "balloon" "--hash=Balloon"`, but STEP 2's build line
omitted `BALLOON=1`, so the supplied binary has no Balloon PRF → create fails
("balloon: create failed"). acceptance.sh's *own* Tier-0 self-build sets `BALLOON=1`, so this
only bites when a pre-built binary (STEP 2's flags) is passed in — which is the task's flow.
**Fixed in this branch:** the balloon round-trip is now gated on the `src/.build-flags` stamp —
it runs when the stamp carries `VC_ENABLE_BALLOON_KDF` (or when no stamp exists, i.e. the harness
self-built with `BALLOON=1`), and prints `SKIP` with an explanatory note otherwise instead of a
misleading FAIL. (No product change; harness only.)

## Cleanup / safety

Every volume was a file container inside a `mktemp -d`; no real block device was written.
After each probe (including the two that were killed by timeout) `dmsetup ls`, `losetup -a`,
and the mount table were confirmed clean, and leftover temp dirs removed. The acceptance
harness's own `trap cleanup EXIT` also fired on SIGTERM.
