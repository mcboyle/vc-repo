# Balloon hashing — memory-hard KDF candidate

**Status: algorithm proven (`[16]`); wired as a selectable mountable PRF and proven (`[38]`);
real-volume round-trip remains.** A candidate to sit alongside
Argon2id in the KDF seam (`IDEAS-BACKLOG.md` §C — "memory-hard alternatives to benchmark against
Argon2id"). Balloon (Boneh, Corrigan-Gibbs, Schechter, 2016) is a **provably memory-hard** password
hash whose only primitive is a **standard cryptographic hash** — here VeraCrypt's in-tree SHA-256 — so
it adds KDF diversity without a bespoke permutation.

## Why a second memory-hard KDF

- **Diversity / hedge.** Argon2id is excellent, but a second, independent memory-hard construction
  (different design, different primitive) hedges against a future weakness in one of them. The project
  already ships several PRFs for exactly this reason.
- **Standard-hash foundation.** Balloon's security reduces to the underlying hash; no new cryptographic
  assumption beyond SHA-256, which the fork already trusts and has compiled/verified.
- **Explicit cost knobs.** Space cost (number of blocks) and time cost (rounds) are separate, explicit
  inputs — the same philosophy as the explicit-Argon2-parameters work (`docs/ARGON2-PARAMS-SPEC.md`).

## Algorithm (single lane, `delta = 3`)

```
n = s_cost blocks of one SHA-256 digest each; cnt = monotonic counter; delta = 3.
Expand:  buf[0] = H(cnt++ || password || salt)
         buf[m] = H(cnt++ || buf[m-1])                       for m = 1..n-1
Mix (t_cost rounds), for each m:
         buf[m] = H(cnt++ || buf[(m-1) mod n] || buf[m])     # previous block + self
         for i in 0..delta-1:
            other  = int( H(cnt++ || t || m || i || salt) ) mod n
            buf[m] = H(cnt++ || buf[m] || buf[other])        # delta pseudo-random dependencies
Extract: buf[n-1]
```

All integers are 8-byte little-endian. Memory-hardness comes from the Mix phase's `delta` data-dependent
reads across the whole `n`-block buffer each round: computing the output without keeping the buffer in
memory forces re-derivation at large time cost (the space–time trade-off the security proof bounds).

## What the PoC proves (`verification/balloon_poc.c` + `balloon_reference.py`, step `[16]`)

Proven two ways — the C PoC drives the **real in-tree SHA-256 (`Sha2.c`)**, an independent Python
reference (`hashlib`) reproduces it **byte-for-byte** (anchor `635ebeac…` for `s=16, t=3`,
`password="correct horse battery staple"`, `salt[i]=(i*5+1)&0xff`):

- **Deterministic** — same `(password, salt, s_cost, t_cost)` → same output.
- **Salt / space / time dependence** — changing the salt, the space cost, or the time cost each change
  the output, so all three inputs genuinely feed the derivation.

PoC parameters are tiny (`s=16` blocks = 512 bytes) for a fast KAT; production values are megabytes of
space and enough rounds to hit a target time budget.

## Integration & honest notes

- **Selectable PRF — built (step `[38]`, gated `-DVC_ENABLE_BALLOON_KDF`).** The wiring follows the
  Argon2 precedent exactly: a `BALLOON` id in the `Crypto.h` PRF enum (non-boot; a stock build is
  byte-identical), `derive_key_balloon (pwd, salt, tcost, spaceKib, dk, dklen, pAbort)` in
  `Common/Pkcs5.c` (heap block buffer; abort → rc −2 with dk zeroed, fail-closed like Argon2;
  `dklen ≤ 32` returns the Balloon output K directly — the `[16]`-anchored core — and longer
  outputs expand K as `block_i = SHA-256(K‖BE32(i)‖salt)`), a fixed
  `BALLOON_HEADER_KEYDATA_SIZE = 192` like Argon2's, dispatch cases in `Volumes.c` (mount + create)
  and `EncryptionThreadPool.c`, `BalloonSetParamsOverride`/`BalloonGetResolvedParams`
  (PIM → rounds `3+(pim−1)/5`, space `min(1024+(pim−1)·512, 65536)` KiB — deliberately shallower
  than Argon2's curve because Balloon-SHA256 is hash-bound), and the `Pkcs5Balloon` class in
  `Volume/Pkcs5Kdf.{h,cpp}` (pim-form derivation like `Pkcs5Argon2`; excluded from hash→KDF
  matching so it never shadows `Pkcs5HmacSha256`). Proven two ways in step `[38]`: the **real
  compiled `Pkcs5.c` TU** vs. an independent Python that first re-derives the `[16]` anchor
  (`635ebeac…`), REF-diffing dk32/dk64/dk192 and the resolver/override. The mount/create round-trip
  on a real volume (`--hash Balloon`) is the remaining real-build validation.
- **Benchmark before shipping.** The point of the item is *comparison*: measure Balloon vs Argon2id at
  equal time budgets on target hardware before recommending either. This PoC establishes correctness,
  not a performance verdict.
- **Not a replacement.** Argon2id remains the default; Balloon is an independent option for
  diversity/defence-in-depth, and (like every KDF here) is only as strong as the space/time costs the
  user picks.
