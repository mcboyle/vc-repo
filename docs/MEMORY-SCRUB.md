# Cross-platform memory-key scrub — design & status

**Status: implemented and verified (crypto core); OS event triggers compiled and wired, to be
validated on real hardware.** This closes the gap called out in `docs/THREAT-MODEL.md`: on
Linux/macOS, VeraCrypt's RAM key-encryption and key-erase-on-shutdown are **Windows-driver-only**, so
any secret this fork holds in user space — most importantly the **reconstructed Shamir secret** and
other HardwareKeyFactor material — otherwise sits in the clear in process RAM for the whole session,
exposed to cold-boot and DMA (Thunderbolt/FireWire) capture. Both the factor-gated decoy and the
split-key factor lean on this being closed.

Everything is gated behind `-DVC_ENABLE_KEYSCRUB` (make: `KEYSCRUB=1`); a build without it is
byte-for-byte stock.

## What it protects (and what it can't)

- **In scope — user-space secrets.** The reconstructed Shamir/raw secret, the simulator secret, the
  FIDO2 PIN, and the transient key-derivation buffers this fork creates. Two mitigations are applied:
  they are **erased on an event** (below), and they are kept **encrypted at rest in RAM** between
  uses (below).
- **Out of scope — the mounted master key.** On Linux, once a volume is mounted the master key lives
  in the **kernel device-mapper (dm-crypt)**, not in this process. A user-space change cannot scrub
  it; that would require `dmsetup`/kernel work (a separate, root-only, fragile effort). We document
  this boundary rather than pretend to cover it. Until then, **treat a mounted volume's master key as
  kernel-resident and exposed to a kernel/DMA attacker.**
- **Not a guarantee.** RAM-encryption-at-rest and event scrubbing shrink the window in which a
  plaintext secret is resident; a determined attacker with *live* DMA can still race the moment a
  secret is revealed for use. This raises the bar, it does not close the door.

## Two mechanisms

### 1. Secure wipe + scrub registry (`src/Common/KeyScrub.{c,h}`)

- `VcSecureWipe(p, n)` — zeroes memory with a compiler barrier so the writes survive dead-store
  elimination at `-O2` (verified via a separate alias in the harness).
- A small fixed-size **registry** of live secret regions. Sensitive buffers register themselves;
  `VcScrubAll()` erases every registered region through one call, so an event handler need not know
  where each secret lives. Thread-safe (pthread mutex / Windows critical section).
- `HKFScrubActiveConfig()` (`src/Common/HardwareKeyFactor.c`) wipes the active factor's secret
  fields and detaches the process-wide config pointer.

### 2. RAM encryption at rest (`VcKsRamTransform`, mirrors the Windows scheme)

This reproduces VeraCrypt's own Windows RAM-key-encryption construction
(`Common/Crypto.c::VcProtectMemory`), instantiated for the application and reusing the **in-tree**
primitives (`Crypto/t1ha2.c`, `Crypto/chacha256.c`):

```
hashSeed = (areaBase + encID) ^ hashSeedMask
(hashLow,hashHigh) = t1ha2_atonce128(keyDerivationArea, areaLen, hashSeed)   # hash a large random "decoy" area
key = ChaCha12_whiten([hashLow, hashHigh, hashLow^hashHigh, hashLow+hashHigh])
cipherIV = (areaBase + encID) ^ cipherIVMask
secret ^= ChaCha12_keystream(key, cipherIV)                                   # encrypt the secret in place
```

- A large (1 MiB) **key-derivation area** of random bytes is allocated once and hashed to derive the
  obfuscation key, so a memory image must recover the whole area — and the address-bound `encID`
  term — to decrypt a secret. This is the "decoy key-derivation region like the Windows ChaCha
  scheme" from the roadmap.
- It is a **stream cipher**, hence its own inverse: `VcKsRamProtect`/`VcKsRamUnprotect` are the same
  operation. A secret is unprotected only for the moment it is mixed into the password, then
  re-protected or scrubbed.
- The obfuscation-area seed comes from the kernel CSPRNG (`/dev/urandom`). **It never derives any
  on-disk key material** — it only hides keys at rest in RAM — so it cannot affect volume keys or
  cross-platform key compatibility.

## When secrets are scrubbed (event triggers, `src/Core/KeyScrubEvents.{h,cpp}`)

`KeyScrubManager` routes four events to `ScrubNow()` (= `VcScrubAll()` + `HKFScrubActiveConfig()`):

| Trigger | Wiring | Sandbox-verifiable? |
|---|---|---|
| **unmount** | hooked in `Core/Unix/CoreUnix.cpp::DismountVolume` (and emergency dismount) | yes (in-process) |
| **idle timeout** | background monotonic-clock timer (`--keyscrub-idle SECONDS`) | yes (in-process) |
| **screen lock** | Linux logind `Lock`/`PrepareForSleep` via sd-bus (`VC_KEYSCRUB_LOGIND`); macOS `com.apple.screenIsLocked` | **no — validate on a real session** |
| **new-device-connect** | Linux udev `usb` add events (`VC_KEYSCRUB_UDEV`); macOS IOKit | **no — validate on a real session** |

The screen-lock and new-device monitors are OS integration that cannot be exercised in a sandbox.
They are compiled behind their own macros and, when not compiled in, print a one-line notice at
startup and stay inert. **They must be validated on a real desktop session before being relied on** —
the same honesty applied to the YubiKey/FIDO2 USB round-trip in `docs/HARDWARE-2FA.md`. The idle
timer registers activity on volume operations; a fuller build would also hook UI input.

## Build

```sh
cd src && make KEYSCRUB=1        # links -lpthread; adds the scrub objects + ChaCha/t1ha primitives
# optional real desktop integration (validate on hardware):
#   CXXFLAGS += -DVC_KEYSCRUB_LOGIND   (link -lsystemd)   screen lock on Linux
#   CXXFLAGS += -DVC_KEYSCRUB_UDEV     (link -ludev)      device hotplug on Linux
```

CLI:

```sh
veracrypt --keyscrub --keyscrub-idle 120 --mount ...   # scrub on unmount + after 120s idle (+ lock/device if compiled)
```

## Verification (per the project convention: proven two ways)

Self-contained (`verification/keyscrub_selftest.c` + `keyscrub_reference.py`, wired into
`verification/build_and_verify.sh` step `[6]`):

1. **Independent Python reimplementation.** `keyscrub_reference.py` reimplements t1ha2_atonce128 and
   ChaCha12 and the `VcKsRamTransform` construction from the algorithm alone.
2. **Real compiled VeraCrypt objects.** `keyscrub_selftest.c` links the actual in-tree
   `Crypto/t1ha2.c` and `Crypto/chacha256.c` and drives the real `Common/KeyScrub.c`.

The two are diffed **byte-for-byte** on a fixed vector. Checks:

- secure-wipe zeroes (observed through a separate alias — survives `-O2` dead-store elimination);
- the registry scrubs every registered region on one `VcScrubAll`;
- the RAM transform round-trips (`protect∘protect == identity`) and the protected buffer **does not
  equal** the plaintext (the secret is not left in the clear);
- `HKFScrubActiveConfig` wipes the reconstructed secret and detaches the config;
- the fixed-vector protected output matches the independent Python reference exactly.

**Regression anchor:** fixed-vector protected secret
`d28b461b44d2c93f66a1f50fdbbaef619bf64b3c92413a0dc535b47d3849203f`
(32-byte secret `0x10..0x2f`, 256-byte area `area[i]=(i*181+31)&0xff`,
`hashSeedMask=0x0f1e2d3c4b5a6978`, `cipherIVMask=0x8090a0b0c0d0e0f0`,
`areaBase=0x1122334455667788`, `encID=0xdeadbeef`, little-endian).

### What is NOT verifiable here (stated plainly)

- The **screen-lock and new-device-connect** OS integrations (sd-bus/logind, udev/IOKit) — no desktop
  session or USB hotplug in a sandbox. Compiled and wired; validate on real hardware.
- The **cold-boot / DMA resistance** itself — that is a physical-attack property, not a unit test. We
  verify the mechanism (secrets are encrypted at rest and erased on events), not the physics.
