# Per-slot policy flags — design proposal (ROI-TOP-50 item 15, `[FORMAT]`)

**Status: DESIGN — awaiting review. No code written yet.** This item changes the keyslot *record*
format, so per the project rule ([FORMAT] items) it is proposed here before implementation.

## Goal

Give each keyslot independent, enforceable policy: **read-only**, **max-attempts** (lockout), and
**expiry** (a slot that stops working after a date). This converts behaviour that is currently
global/implicit into per-slot configuration — e.g. a share-recovery slot that is read-only and
expires, or a guest slot that self-locks after N bad tries.

## What exists today

A labeled table slot (`KSB_HEADER`/`KSB_SIDECAR`, stride `KEYSLOT_TABLE_STRIDE = 1024`) stores, per
slot: a per-slot salt, the AEAD tag, and the wrapped ciphertext. The **wrapped payload is
`flags[1] || vmk`** — a single flags byte (only `KEYSLOT_FLAG_DURESS = 0x01` today) plus the master
key, encrypted and authenticated under the passphrase-derived key. Slot flags are therefore *hidden
and authenticated*: you cannot see or forge them without the passphrase.

`KeyslotOpen` is the **constant-time mount path** — it sizes its work from public params (`cost`,
`afStripes`, `vmkLen`), never from record bytes, and does not reveal which slot matched.

## The three policies split into two very different classes

| policy | needs a WRITE on each attempt? | safe to hide in the encrypted payload? |
|-------------|-------------------------------|-----------------------------------------|
| read-only | no | **yes** |
| expiry | no | **yes** |
| max-attempts| **yes** (increment a counter) | **no** — see below |

**read-only and expiry are static** per slot: set once at enrolment, read at open. They belong in the
encrypted payload, where they are authenticated and leak nothing.

**max-attempts is fundamentally different.** A bad-attempt counter must be *incremented on a failed
attempt* — i.e. before the passphrase is known-good. That has three hard problems:

1. **It requires a write on the mount path**, which breaks read-only media, breaks the deniable
   backend (writing reveals the slot exists), and complicates the constant-time guarantee.
2. **It cannot live in the encrypted payload** — you cannot re-wrap under a key you do not have (the
   attempt failed). So the counter must sit in *cleartext* slot metadata, which (a) leaks that the
   slot exists and how contested it is, and (b) is trivially **rolled back** by restoring an old copy
   of the header/sidecar (the multi-snapshot limitation already documented in THREAT-MODEL.md).
3. **Anti-rollback needs external state** (a TPM NV counter, a monotonic secure element, or a
   networked witness) to be meaningful. Without it, lockout is defeated by `cp header.bak header`.

## Proposal

### A. read-only + expiry — extend the wrapped payload (versioned)

Change the payload from `flags[1] || vmk` to a **v2 payload**:

```
v2 payload = ver[1]=0x02 || flags[1] || expiryUnix[8, big-endian, 0 = never] || vmk
```

- `flags` gains `KEYSLOT_FLAG_READONLY = 0x02` (mount refuses to mount rw; maps to the existing
  read-only mount mode).
- `expiryUnix` is an 8-byte big-endian Unix time; `0` means no expiry. At open, if `now > expiry`,
  the slot is treated as non-matching (mount fails as if the passphrase were wrong — no oracle).
- **Back-compat:** the first payload byte disambiguates. Legacy records have `flags[0] ∈ {0x00,0x01}`
  (duress bit) as their first byte; v2 records use a `ver` byte of `0x02` first. Since a legacy
  `flags` byte can itself be `0x02`… **that collides.** To avoid ambiguity we do NOT overload the
  first byte; instead we key the version off the record, not the payload — see A′.

### A′. (Recommended) version the RECORD, not the payload

Add a **1-byte record version** in the slot's *cleartext* metadata region (there is ample room in the
1024-byte stride; today only salt+tag+ct are used). `ver = 1` = legacy `flags[1]||vmk`; `ver = 2` =
`flags[1] || expiryUnix[8] || vmk`. The mount path reads `ver` (public, not secret — it reveals only
the record *format*, not policy) and sizes the unwrap accordingly. This keeps the payload
unambiguous and leaves legacy records byte-identical (`ver` field defaults to 1/!present region left
as random for deniable slots — deniable slots keep v1 only, since they have no cleartext metadata).

**Why this is safe:** `vmkLen` is already a public parameter; making the effective payload length
depend on a public `ver` byte does not weaken the constant-time property (work is still sized from
public inputs, identical for all slots of the same version). read-only and expiry stay authenticated
inside the AEAD.

### B. max-attempts — propose to SPLIT into two deliverables

- **B1 (this item, no rollback protection):** store a cleartext `attempts[2]` counter + `maxAttempts`
  in the record's metadata; increment on failed `KeyslotOpenAt` (admin/interactive path only, NOT the
  constant-time `KeyslotOpen` mount path); refuse once exceeded. **Documented honestly** as
  rollback-defeatable and not applied on read-only/deniable backends. This is genuinely useful against
  a casual attacker at a live prompt and worthless against an imaging attacker — we say exactly that.
- **B2 (future, separate item):** bind the counter to a TPM NV monotonic counter / secure element so
  rollback is detected. This is `[HW]` and belongs with the TPM factor work, not here.

I recommend shipping **A′ + B1** under item 15, with B1's limitations stated plainly, and filing B2
as a roadmap follow-up. Alternatively, if you would rather not add a rollback-defeatable control at
all, we ship **A′ only** (read-only + expiry, both robust) and drop max-attempts to B2.

## On-disk / compatibility summary

- New: a 1-byte `ver` + optional `attempts[2]`/`maxAttempts[1]` in the **cleartext** slot metadata
  (labeled backends only); an 8-byte `expiryUnix` inside the **encrypted** v2 payload.
- Legacy (`ver=1`) records: **open unchanged, byte-for-byte**. No forced migration; re-enrol to get v2.
- Deniable backend (`KSB_DENIABLE`): **v1 only** (no cleartext metadata by design) — read-only/expiry
  not offered there; documented.
- Default build with `VC_ENABLE_KEYSLOTS` off: **completely unaffected**.
- Gated additionally behind `VC_ENABLE_KEYSLOT_POLICY` so even a keyslots build is opt-in until proven.

## Verification plan (per project convention)

1. Independent Python re-implementation of the v2 payload encode/decode + policy evaluation, diffed
   byte-for-byte against the real compiled `KeyslotStore.c`.
2. Behavioural harness: enrol read-only/expiring/attempt-limited slots on a real in-memory area; prove
   read-only mounts refuse rw, an expired slot stops opening at `now>expiry`, and a slot locks after
   `maxAttempts`. **Negative controls:** a non-expired slot still opens; a non-read-only slot mounts
   rw; attempt N < max still opens; and a v1 legacy record still opens byte-identically.
3. Rollback demonstration for B1: show that restoring the pre-attempt metadata resets the counter —
   proving (not hiding) the limitation.

## Open questions for review

1. **max-attempts:** ship **B1 now with the rollback caveat**, or **defer entirely to B2** and land
   read-only + expiry only? (I lean B1-with-caveat: useful and honestly bounded.)
2. **expiry semantics on open:** fail *closed and silent* (behave as wrong passphrase — my
   recommendation, no oracle) vs. a distinct "slot expired" error (friendlier, but an oracle that a
   slot exists). Recommendation: silent at the constant-time mount path, explicit at the admin
   `--keyslot-list` path.
3. **clock source for expiry:** wall-clock only, or also refuse if the clock looks rolled back vs. the
   volume's last-modified? (Wall-clock only for v1 of this feature; note the caveat.)
