# Anti-forensic (AF) key splitting — design & status

**Status: core proven (`[15]`); keyslot-format integration built & proven (`[36]`); real-flash
validation remains.** The concrete
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

## Integration (`[FORMAT]`) — built & proven (step `[36]`)

The shipping module is `src/Common/AfSplit.{c,h}` (gated `VC_ENABLE_KEYSLOTS`, the feature it composes
with): the PoC algorithm generalized to arbitrary payload lengths — a trailing partial diffuse section
takes the digest prefix, as cryptsetup's `af.c` does. `KeyslotStore.c` wires it into the record:

- `KeyslotStoreCfg.afStripes = s` (0/1 = off — **byte-identical legacy records**; s ≥ 2 splits).
- Enroll: payload `flags[1]||vmk` → `AfSplit` into s stripes → the stripe blob is wrapped, so
  `ct` grows from `plen` to `s·plen` (still ChaCha20 + HMAC-SHA256-tagged). Open: unwrap → `AfMerge`.
- **Labeled records** become `ver=2` and carry `s` in the (tag-authenticated) `rsv` field —
  informational, like the stored `cost`. **Bare (deniable) records stay field-free.** The operative
  `s` always comes from the public config, so the constant-time search's per-slot work stays fixed
  and is never sized from possibly-random record bytes.
- `s` is bounded by the record stride: `46 + s·plen + 32 ≤ 1024` labeled (s ≤ 14 at vmk = 64);
  an oversized `s` is rejected up front. LUKS-scale s = 4000 needs a larger per-slot area — that
  stride growth is future work, not this format.

Proven two ways in step `[36]` (`verification/keyslotaf_test.c` driving the real compiled
`AfSplit.c + Keyslot.c + KeyslotStore.c` vs. the independent `keyslotaf_reference.py`): the full
labeled-v2 and bare record bytes match the reference byte-for-byte (bare-record anchor `76b60553…`),
round-trips recover VMK + flags, a zeroed stripe region defeats the open (partial-remnant answer at
record level), cfg/record stripe-count mismatches are rejected both ways, AF and legacy records
coexist in one table, and the AF lifecycle (add/open/revoke/duress flag) passes. The remaining
not-sandbox-testable work is only the write/erase discipline against a real SSD.

## Honest limits

- **Remnant resistance, not a guarantee.** AF splitting means a *partial* remnant is worthless; it does
  not control where the FTL actually writes, and a drive that preserved *all* stripes somewhere gains
  the attacker nothing beyond a normal copy. It raises the bar against the realistic partial-remnant
  case that plain overwriting fails.
- **Complements, does not replace.** Pairs with decoy-fragments (hide *presence*) and ORAM (hide
  *usage*); AF splitting hardens *erasure/remnants* of the key material itself.
- **Storage cost.** s× the wrapped-key size per slot.
