# Anti-forensic (AF) key splitting — design & status

**Status: core proven; keyslot-format integration remains (real-build, `[FORMAT]`).** The concrete
answer to the **SSD-remnant** caveat that `docs/THREAT-MODEL.md` and every keyslot doc has so far only
*documented*: on flash, wear-leveling / out-of-place writes can leave a **partial** copy of a keyslot's
wrapped key behind after it was "overwritten". AF splitting (LUKS / Clemens Fruhwirth's TKS1) makes a
partial remnant worthless. `IDEAS-BACKLOG.md` §P0.3.

## Mechanism

Before a keyslot's wrapped key is stored, diffuse it across **s stripes** so that recovering the key
needs **all s** of them:

```
split:  buf = 0
        for i in 0..s-2:  stripe[i] = random(n);  buf = diffuse(buf XOR stripe[i])
        stripe[s-1] = key XOR buf                 # store stripe[0..s-1]  (s*n bytes)
merge:  buf = 0
        for i in 0..s-2:  buf = diffuse(buf XOR stripe[i])
        key = stripe[s-1] XOR buf
diffuse(x): SHA-256 each 32-byte section of x with its big-endian section index prepended (LUKS AF).
```

Every stripe except the last is fresh randomness; the last folds in the key. Because the diffusion
mixes each stripe into `buf` before the key is added, **any missing or corrupted stripe leaves `buf`
(and thus the recovered value) uniformly random** — a remnant of some-but-not-all stripes reveals
nothing about the key. To erase a slot you now must lose only *one* stripe, not the whole record, for
the key to be unrecoverable — a far weaker requirement of the (unreliable) flash erase.

## What the PoC proves (`verification/afsplit_poc.c` + `afsplit_reference.py`, step `[15]`)

Proven two ways — the C PoC drives the **real in-tree SHA-256 (`Sha2.c`)**, an independent Python
reference (hashlib) reproduces it **byte-for-byte** (deterministic `xorshift64*` PRNG for the stripes;
split-hash anchor `ddb23937…`):

- **Round-trip** — `merge(split(key)) == key` (n = 128, s = 4).
- **Partial recovery is defeated** — zeroing *any one* of the s stripes makes `merge` produce
  something `!= key`; the final stripe alone (`key XOR buf`) is also `!= key`. All s stripes are
  required.

## Integration (`[FORMAT]`, real-build)

Wire AFsplit into the keyslot record: store `s` stripes (s·vmk bytes) in place of the single wrapped
payload, split on enroll and merge on open. `s` is a public per-slot field; a typical LUKS value is
s = 4000 for a sector-sized stripe area, trading slot size for remnant resistance. This enlarges the
keyslot record, so it composes with (and is gated the same way as) the keyslots feature. The record
layout change and the write/erase discipline against a real SSD are the remaining, not-sandbox-testable
work.

## Honest limits

- **Remnant resistance, not a guarantee.** AF splitting means a *partial* remnant is worthless; it does
  not control where the FTL actually writes, and a drive that preserved *all* stripes somewhere gains
  the attacker nothing beyond a normal copy. It raises the bar against the realistic partial-remnant
  case that plain overwriting fails.
- **Complements, does not replace.** Pairs with decoy-fragments (hide *presence*) and ORAM (hide
  *usage*); AF splitting hardens *erasure/remnants* of the key material itself.
- **Storage cost.** s× the wrapped-key size per slot.
