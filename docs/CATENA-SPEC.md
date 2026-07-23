# Catena-BRG memory-hard KDF core — survey entry

**Status: BRG memory-hard core proven two ways; not the full keyed Catena, and not wired as a mountable
PRF.** A third memory-hard option surveyed alongside **Balloon** (`docs/BALLOON-SPEC.md`, step `[16]`,
now a mountable PRF at step `[38]`) and **scrypt** (step `[34]`), addressing `IDEAS-BACKLOG.md`
"memory-hard alternatives to benchmark against Argon2id".

## What it is

Catena (Forler–Lucks–Wenzel, PHC finalist) is a framework parameterised by a memory-hard graph
function. The **BRG** (bit-reversal graph) instance is the one proven here, over the in-tree SHA-256:

```
n = 2^g                                  # g = "garlic": memory = n 32-byte blocks
v[0]   = H(LE64(0) || pwd || salt)
v[i]   = H(LE64(i) || v[i-1])            for i = 1..n-1        # sequential fill
repeat lambda times:                     # lambda BRG passes (depth)
    r[0] = H(v[n-1] || v[brg(0)])
    r[i] = H(r[i-1] || v[brg(i)])        for i = 1..n-1
    v = r
output = v[n-1]
```

`brg(i)` is the bit-reversal of `i` as a `g`-bit index. The bit-reversal permutation is what makes the
pass **memory-hard**: producing `r[i]` needs `v[brg(i)]`, and the reversal scatters those reads across
the whole array, so an attacker cannot process it in small working memory. The chain `r[i-1] → r[i]`
keeps each pass sequential (no intra-pass parallelism).

## What the PoC proves (`verification/catena_poc.c` + `catena_reference.py`, step `[48]`)

Proven two ways: the C PoC drives the **real in-tree SHA-256 (`Sha2.c`)** and an independent Python
(hashlib) reproduces it **byte-for-byte** for `(g=8, lambda=3)`, `(g=8, lambda=1)`, `(g=10, lambda=3)`.
Also checked: deterministic, and salt-/garlic-/lambda-dependent (each changes the output).

## Honest limits

- **Core, not the full KDF.** This is the BRG memory-hard *core*. The full Catena adds a keyed tweak
  (domain/mode/salt-length binding), an output-length KDF wrapper, and the *client-independent update*
  feature (server-side rehash without the password). Those are not implemented; the construction here
  is not byte-compatible with the Catena reference and is not a standards-compliance claim.
- **Not wired as a mountable PRF.** Unlike Balloon (step `[38]`), this stays a verification-only PoC.
  If chosen for the KDF seam it would follow the same `derive_key_*` wiring, gated like the others.
- **Benchmark before choosing.** As with Balloon, the point is *comparison* — measure against Argon2id
  at equal time budgets on target hardware before recommending any alternative.
