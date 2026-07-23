# Keyslot-area MAC — authenticate the slot table before unwrap

**Status: MAC construction proven; wiring waits on the keyslot volume-I/O bindings.** Addresses
`IDEAS-BACKLOG.md` §P0.5 ("Authenticate the keyslot area", item 5) and is the **first concrete consumer
of the proven Poly1305 primitive** (`docs/POLY1305-SPEC.md`, step `[18]`).

## The gap it closes

The multiple-keyslots work (`docs/KEYSLOTS-SPEC.md`) stores a table of independently-wrapped copies of
the master key (VMK). XTS gives that table **no integrity**: an attacker who can write to the disk can
flip bits in a slot record, truncate the table, or drop a slot, and the mount path consumes it
silently. Each wrapped slot already carries an HMAC selector that fails *closed* on a bad slot, but that
does not authenticate the **table as a whole** — its length, slot count, ordering, or the surrounding
header bytes. A single MAC over the whole area turns any such modification into a detected error
*before any unwrap is attempted*.

## Construction (RFC 8439 MAC half — one-time key per write)

```
mac_key      = KDF(VMK, "keyslot-area-mac")         # 32 bytes, never on disk
nonce        = fresh per write                      # 8 bytes, stored in clear beside the tag
one_time_key = ChaCha20(mac_key, nonce, counter=0)[0..32]
tag          = Poly1305(one_time_key, area_bytes)   # 16 bytes, stored with the area
verify:      recompute tag; constant-time compare; refuse the volume on mismatch
```

- **ChaCha20** is VeraCrypt's in-tree `Crypto/chacha256.c` (the DJB 8-byte-nonce / 64-bit-counter
  variant); the PoC drives the real object and its zero-key block-0 equals the published ChaCha20 KAT
  `76b8e0ada0f13d90…`.
- **Poly1305** is the step-`[18]` radix-2⁶ implementation, shared via `verification/poly1305.h`.
- **One-time-key discipline is the whole reason for the nonce.** Poly1305 is a *one-time* MAC: reusing
  an `(r,s)` pair across two different areas leaks `r` and lets an attacker forge. A fresh nonce per
  write derives a fresh `one_time_key`, exactly as ChaCha20-Poly1305 does. The nonce is not secret;
  it is stored in the clear next to the tag.
- **No on-disk format change to the volume body.** This is a MAC *over* the existing keyslot area plus
  a small `(nonce, tag)` trailer in the keyslot region — it does not touch the encrypted payload or the
  native VeraCrypt header, so it stays inside the fork's no-header-change rule for the volume proper.

## What the PoC proves (`verification/keyslot_mac_poc.c` + `keyslot_mac_reference.py`, step `[20]`)

Proven the two ways the fork requires — the C PoC drives the **real in-tree ChaCha20 + Poly1305**; an
independent Python reference (pure-python ChaCha20 + big-integer Poly1305) reproduces every value
byte-for-byte over 9 vectors (anchor tag `446592f2…` for a 4-slot × 96-byte area):

- **ChaCha zero-key KAT** — `76b8e0ada0f13d90…`, the published ChaCha20 vector (independent authority).
- **Accept valid** — recomputing the tag over the untampered area matches.
- **Reject tamper** — flipping one bit anywhere in the area changes the tag; constant-time compare fails.
- **Reject truncation** — dropping the last slot changes the tag; the shortened area is refused.
- **Reject wrong key** — a MAC key off by one bit yields a different tag (the key genuinely binds).
- **Nonce binds** — a different nonce yields a different tag (fresh `(r,s)` per write; no reuse).

The verifier's compare is **constant-time** (`ct_eq16`), so a tag mismatch leaks no timing signal.

## Integration & honest notes

- **Depends on the keyslot volume-I/O bindings.** The MAC math is done; what remains is where the
  `(nonce, tag)` trailer lives in each `KeyslotArea` backend (`KSB_HEADER` / `KSB_SIDECAR` /
  `KSB_DENIABLE`) and calling the check at mount **before** the slot search. That is the same real-build
  work tracked in `docs/KEYSLOTS-SPEC.md §9`; this MAC slots directly into it.
- **`mac_key` derivation must be domain-separated.** Derive it from the VMK under a distinct label so it
  is independent of any slot-wrap key; never reuse a wrapping key as the MAC key.
- **Deniable backend caveat.** For `KSB_DENIABLE` (bare records at a passphrase-derived offset), a
  visible `(nonce, tag)` trailer is itself an artifact; the MAC there must live inside the
  passphrase-derived, indistinguishable-from-random region or be recomputed, not stored in a labeled
  slot. Flagged for the deniable-backend integration, not solved here.
- **Detects modification, not rollback.** Like the Merkle work, a MAC catches tampering but not *replay*
  of a whole older `(area, nonce, tag)` triple. Pair with the monotonic-counter item (§A) if
  snapshot-replay is in the threat model.
- **Scope.** Authenticating the access-control table is integrity/access-control infrastructure — well
  inside the project's boundary.
