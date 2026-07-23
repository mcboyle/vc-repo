# Flash-media deniability warning (`FlashProbe`)

**Status: probe module + decoders built and fail-closed, unit-tested in-sandbox (suite step `[83]`);
the creation-path gate and the Windows/macOS device probes are real-build integration.** Research
batch-2 item C3. Gated behind `-DVC_ENABLE_FLASH_WARN`; default builds are byte-for-byte stock.

## Why

Hidden-volume deniability does **not** survive flash. The flash translation layer remaps blocks out of
place; wear-levelling and over-provisioning retain sub-block fragments (including of the hidden-volume
creation) that chip-off recovers; TRIM/discard leaks the free-space map; and sanitisation commands are
unreliable in practice across a wide range of drives. Separately, a *logical* two-snapshot classifier
over changed-block run-lengths detects hidden volumes ≥ 0.75 GB at recall ≈ 1.0 **even on a rotational
disk**. `docs/THREAT-MODEL.md` conceded "weak on flash" in prose, but a user creating a hidden volume on
an SSD walked a path that told them nothing. For a population that may rely on this under coercion, a
doc footnote is not adequate — the warning has to be in the creation/mount path.

## Behaviour — fail closed

On creating (and mounting) a hidden/decoy volume, emit a prominent **"deniability does NOT hold on this
device"** warning unless the target device verifies clean on *all* axes. **Anything unknown or
unverifiable warns** — silence is never treated as safe.

| Axis | Clean (no warn) requires | Source |
|---|---|---|
| Rotational | Linux `/sys/block/<dev>/queue/rotational == "1"`; Windows `IOCTL_STORAGE_QUERY_PROPERTY` seek-penalty = TRUE; macOS: no reliable flag → **always warn** | `FlashProbeRotationalSysfs` / `FlashProbeDevice` |
| No deterministic TRIM in the data path | ATA `IDENTIFY` word 169 bit 0 (TRIM) **clear**, word 69 bit 14 (DRAT) / bit 5 (RZAT) **clear**; NVMe `DLFEAT` bits 2:0 ≠ 001b/010b; Linux `discard_granularity == 0` | `FlashProbeAtaTrim`, `FlashProbeNvmeDlfeat` |
| No thin-provisioning / dedup / SMR / ZNS underneath | positively confirmed absent | real-build (device-mapper/LVM/SMR inspection) |

Even on a clean pass the caller prints `FlashProbeCaveat()`: deniability still fails on a rotational disk
against an adversary who images the device twice.

`USB-bridged, RAID, virtual, or thin-LVM where the underlying media is unverifiable → warn` is the
fail-closed default: `FlashProbeDevice` folds an **UNKNOWN** thin-provisioning axis into the decision, so
it warns unless the platform glue can positively confirm the underlying media.

## What the sandbox verifies (`verification/flash_probe_test.c`, step `[83]`)

- **Linux rotational/discard probe** against injected `/sys` **fixture trees**: `rotational` 0/1,
  `discard_granularity` present/absent/zero, missing attribute file, missing device dir, and a
  path-escape device name — each mapped to the expected warn/clean.
- **ATA / NVMe bit decoding** against synthetic identify buffers, including the reserved/unknown
  encodings and a `NULL` buffer (→ `WARN_UNKNOWN`).
- **The fail-closed contract as a named check** (`FAIL-CLOSED: no unknown/error axis is ever treated as
  clean`): for every axis, an unknown/error result forces a warn through `FlashProbeAggregate`.

The decoders are pure C with no VeraCrypt platform dependency, so they compile in every `flag_matrix`
combination and unit-test standalone.

## Real-build remainder (state the ceiling)

- **Creation-path gate.** `VolumeCreator` / the CLI hidden-volume path calls `FlashProbeDevice(dev)` and,
  when not clean, prints the warning + reasons + `FlashProbeCaveat()` and requires explicit confirmation.
  CLI first; the GUI dialog is a real-build session.
- **Device probes.** The Linux `rotational`/`discard` path is exercised against fixtures here; the ATA/NVMe
  `IDENTIFY` reads (SG_IO / NVMe admin passthrough), the Windows `IOCTL_STORAGE_QUERY_PROPERTY` seek-penalty
  descriptor, and the macOS always-warn path are compile-checked and need a real build against real media.

Honest form: **Linux probe unit-tested against fixtures; Windows/macOS probes compile-checked, need a
real build.**

## Scope

A media-suitability *warning* is confidentiality/deniability hygiene — it tells the user the truth about
what the device can and cannot guarantee. It does not fabricate any record of activity; it is well inside
the project's access-control boundary.
