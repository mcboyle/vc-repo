# Tier-5 [FORMAT] items — design proposals (ROI-TOP-50 items 42, 43, 50)

**Status: DESIGN — awaiting review. No code written for any of these yet.** Each changes on-disk
layout, so per the project rule they are proposed here first. All three would be gated behind their own
`VC_ENABLE_*` macro; a default build, and a keyslots build without the flag, stay byte-for-byte stock.

---

## Item 42 — Authenticate the keyslot area / header MAC `[M][FORMAT]`

> **BUILT (reviewed & approved 2026-07-23):** option **A** (VMK-derived `K_area`), **warn-and-continue**
> on old unauthenticated areas. Implemented in `Common/KeyslotAreaMac.{c,h}` (gated
> `VC_ENABLE_KEYSLOT_AREA_MAC`); verified at suite step `[75]` (`keyslot_areamac_test.c` +
> `keyslot_areamac_reference.py`). Items 43 and 50 below remain design-only. The C++ mount-path call
> and header-slack/sidecar trailer placement are the remaining real-build wiring.

### What is already authenticated (important)

Each keyslot **record** is already an AEAD: `KeyslotWrap` produces a 32-byte tag over the wrapped
payload with the header/salt as AAD, and `KeyslotUnwrapCT` verifies it. So **flipping a bit in any
record makes it fail to open** — per-record integrity exists. What is *not* authenticated:

1. **Area-level structure** — an attacker can delete, truncate, or reorder slots, or splice in an old
   copy of the table (rollback). Each surviving record still verifies; the *set* does not.
2. **The native VeraCrypt header** — it carries an embedded CRC-32 of the keys + a magic checked after
   XTS decryption, so random tampering shows up as a decryption failure, but there is no keyed MAC.
3. **The volume body** — XTS, malleable per-sector. This is the large `[L][FORMAT]` per-sector-auth
   gap; item 42 is explicitly the *cheap down-payment*, not that.

### Proposal (scope: the keyslot area)

Add an **area authentication tag** covering the whole keyslot table, stored in a reserved trailer of
the area (labeled backends only; the deniable backend must stay markerless and is out of scope):

```
areaMac = HMAC-SHA256(K_area, "VCKSAREA1" || slotCount || slot[0] || slot[1] || … || slot[n-1])
```

- **Key `K_area`.** It cannot be verified without a secret (else an attacker could recompute it). Two
  options for review:
  - (A) derive `K_area` from any slot's unwrap: when a slot opens, it already recovers the VMK;
    derive `K_area = HKDF(VMK, "keyslot-area-mac")`. The area MAC is then checked *after* a successful
    open. Detects post-hoc tampering/rollback of the table, keyed to the real volume key. **No new
    stored secret.** (Recommended.)
  - (B) store `K_area` wrapped in a dedicated slot. More flexible, but adds a stored key and a
    chicken-and-egg at first mount.
- **Placement.** A 32-byte tag + 4-byte `slotCount` in the area trailer, after the last slot stride.
  Header backend: fits in the header slack below 64K. Sidecar: appended. Bumps an area-format
  version byte (new; there is currently no area-level version, only per-record `ver`).
- **Rollback.** The MAC binds `slotCount`, so truncation/splice of an old shorter table is detected;
  full rollback to an older *complete* table is still possible without external monotonic state
  (documented — same limit as elsewhere; a TPM NV counter is the future defense).

### Compatibility & verification
- Old areas (no trailer) → treated as "unauthenticated area", a warning, not a hard failure, so
  existing volumes keep opening. `VC_ENABLE_KEYSLOT_AREA_MAC` gates the whole thing.
- Verify two ways: HMAC-SHA256 area tag vs an independent Python reference (byte-for-byte), plus a
  behavioural harness — a tampered/truncated/reordered table is detected, an intact one verifies.
  **Negative control:** flipping one slot byte or dropping a slot must fail the area MAC while the
  untampered area passes.

### Open questions
1. Key derivation **(A) VMK-derived** vs **(B) stored wrapped key**? (Lean A.)
2. Old unauthenticated areas: **warn-and-continue** vs **require opt-in acknowledgement**? (Lean warn.)

---

## Item 43 — Encrypted volume labels `[S][FORMAT]`

> **BUILT (reviewed & approved 2026-07-23):** fixed-48-in-64 padded record. Implemented in
> `Common/VolumeLabel.{c,h}` (gated `VC_ENABLE_VOLUME_LABEL`); verified at suite step `[76]`
> (`volume_label_test.c` + `volume_label_reference.py`). Only item 50 below remains design-only.

### Goal
A human-readable label ("work-laptop-backup") the owner can list, without leaking it to an examiner who
images the disk. VeraCrypt has no volume-name field on purpose (deniability). We want the *name* private.

### Proposal
Store the label as a **small AEAD record in the keyslot area**, reusing the exact keyslot record
machinery (it is already indistinguishable-from-random): a labeled slot whose payload is
`"LBL1" || utf8-label[≤48]` instead of a VMK, wrapped under the same passphrase-derived key. Listing a
label = opening that record; without the passphrase it is random bytes, so it leaks nothing.

- **No new on-disk primitive** — it is a keyslot record with a payload type byte. The "format" change
  is only a payload discriminator (`flags` high bit or a payload magic) so `KeyslotOpen` can tell a
  label record from a VMK record.
- Length-padded to a fixed size (e.g. 64 bytes) so the label's *length* does not leak either.
- Deniable backend: supported (bare record), since it is markerless already.

### Compatibility & verification
- Gated `VC_ENABLE_VOLUME_LABEL`. Records without a label are unaffected; a volume simply has no label.
- Verify: byte-for-byte payload layout vs Python + a behavioural harness (set → list → the label
  round-trips; a wrong passphrase yields nothing; the ciphertext is indistinguishable-random).
  **Negative control:** the label bytes never appear in the clear on the medium (grep, like item 14).

### Open question
Fixed max length 48 vs 64 vs variable-padded-to-bucket? (Lean fixed 48 in a 64-byte padded record.)

---

## Item 50 — Atomic, power-loss-resilient header writes `[M][FORMAT]`

> **BUILT (reviewed & approved 2026-07-23):** 8-byte generation counter; keyslot-area A/B rides the
> existing backup-header mirroring. Implemented in `Common/AtomicHeader.{c,h}` (gated
> `VC_ENABLE_ATOMIC_HEADER`); verified at suite step `[77]` (`atomic_header_test.c` +
> `atomic_header_reference.py`) — torn-write recovery proven; true power-loss stays real-build-only.
> All three Tier-5 [FORMAT] items (42, 43, 50) are now built.

### Problem
VeraCrypt keeps a primary header and a backup header (at the end of the volume). A crash *between*
writing the two during a password/keyfile change can leave both stale-or-torn, bricking the volume.
Keyslot add/rotate/revoke has the same exposure for the keyslot area.

### Proposal (A/B + generation, no new on-disk region for the native header)
Use the **existing primary+backup header pair as an A/B slot** plus a monotonic **generation counter**
and a commit tag:

```
each header copy gains (inside the already-reserved/authenticated region):
    gen[8]  (monotonic)   ||   commitTag = HMAC(K, headerBytesWithoutTag || gen)
write order: write the INACTIVE copy fully (data+gen+tag), fsync, THEN it becomes newest by gen.
mount/open: pick the copy with the greatest gen whose commitTag verifies; if the newest is torn
            (tag fails), fall back to the older valid one.
```

- Torn write of one copy is always recoverable from the other (classic A/B). `gen` disambiguates which
  is newest; `commitTag` makes "fully written" atomic (a half-written copy fails its tag).
- For the **keyslot area**, the same scheme over a double-buffered area (two area copies) — a rotate
  writes the inactive copy then flips the newest-gen pointer.
- Requires `fsync`/`FlushFileBuffers` ordering (already available in the volume I/O layer).

### Compatibility & verification
- Gated `VC_ENABLE_ATOMIC_HEADER`. Reuses the backup-header region; `gen`+tag live in reserved bytes,
  so a volume created without the flag is unchanged and still opens.
- **Not fully sandbox-testable** (true power-loss needs real hardware / a fault-injection block
  device). What *is* testable and what I'd build: a harness that simulates torn writes over an
  in-memory medium (truncate/corrupt one copy at every offset) and asserts the recovery logic always
  selects a valid, newest-committed copy; plus the gen/commit-tag layout vs a Python reference.
  **Negative control:** corrupting the *chosen* copy's tag must force fallback to the other; corrupting
  both must fail closed (refuse to mount) rather than mount stale/garbage.

### Open questions
1. Generation counter width and wrap handling (8 bytes = never wraps in practice — fine?).
2. Should the keyslot-area A/B double the area footprint, or ride on the existing backup-header
   mirroring already noted as a remaining task in `docs/KEYSLOTS-SPEC.md §9`?

---

## Summary for review

| item | on-disk change | new stored secret? | sandbox-verifiable | recommend |
|------|----------------|--------------------|--------------------|-----------|
| 42 area/header MAC | +area trailer (tag+count+ver) | no (VMK-derived, opt A) | yes (tamper detect + KAT) | build opt A |
| 43 encrypted label | payload discriminator in a keyslot record | no | yes (round-trip + no-leak) | build, fixed-48 |
| 50 atomic writes | +gen+commitTag in reserved header bytes | no (reuse volume key) | partly (torn-write sim; real power-loss not) | build the sim, flag the gap |

Pick which to implement and answer the open questions, and I'll build them one at a time with the usual
two-way verification + negative controls.
