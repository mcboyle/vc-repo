# Explicit Argon2id parameters — design & status

**Status: implemented and verified.** VeraCrypt 1.26.29 shipped Argon2id but shoehorns its cost
parameters into the single **PIM** value — `get_argon2_params()` derives memory and iterations from PIM
and `derive_key_argon2()` **hard-codes parallelism to 1**. This exposes memory, iterations, and
parallelism as **explicit inputs** with sane high-risk defaults, in the same KDF seam the rest of this
project works in. Gated behind `-DVC_ENABLE_ARGON2_PARAMS` (`make ARGON2PARAMS=1`); a build without it
is byte-for-byte stock (the stock `Pkcs5.o` is bit-identical, verified).

## Why

- **PIM is one knob for three parameters.** Argon2id's resistance is tuned by memory (the dominant
  cost against GPU/ASIC), time (iterations), and parallelism (lanes). Collapsing them into PIM means
  you cannot, say, ask for 2 GiB with 4 lanes and few iterations — the shape best against parallel
  hardware. Parallelism in particular is stuck at 1.
- **Same seam, no header change.** Like PIM, the parameters are **not stored** in the header; the user
  supplies them. Nothing about the on-disk format changes.

## Mechanism

No change to the Argon2 algorithm — only to how its parameters are chosen (`Common/Pkcs5.c`, gated):

- `Argon2SetParamsOverride(active, memCostKiB, iterations, parallelism)` — a process-wide override the
  CLI sets before a create/mount (mirrors `HKFSetActiveConfig`).
- `Argon2GetResolvedParams(pim, &t, &m, &p)` — returns the override when active, else the stock PIM
  formula with parallelism 1. Used in `get_pkcs5_iteration_count()`'s `ARGON2` case for memory/time.
- `Argon2GetParallelism()` — the effective parallelism, substituted at the single `argon2id_hash_raw`
  call site in place of the hard-coded `1`.

CLI:

```sh
# create with 1 GiB / 4 iterations / 4 lanes (defaults if the flag is given but a value omitted):
veracrypt -c --hash argon2id --argon2-memory 1024 --argon2-iterations 4 --argon2-parallelism 4 ...
# MOUNT MUST REPEAT THE SAME THREE (they are not stored, exactly like PIM):
veracrypt --argon2-memory 1024 --argon2-iterations 4 --argon2-parallelism 4 --mount ...
```

If any one `--argon2-*` flag is given, the others default to **1024 MiB, 4 iterations, 4 lanes** (a
sane high-risk baseline). A floor is enforced (memory ≥ 8 KiB, iterations ≥ 1, parallelism ≥ 1).

## Compatibility (important)

Because the parameters are not stored, a volume created with explicit parameters **only opens when the
same parameters are supplied again** — there is no auto-detection, exactly as with PIM. A volume
created with `--argon2-parallelism 4` and mounted without it derives a different key and will not open.
This is deliberate (no header-format change) and must be communicated to users: **record your Argon2
parameters alongside how you record your PIM.**

## Verification (proven two ways, per the project convention)

Self-contained (`verification/argon2_params_test.c` + `argon2_params_reference.py`, wired into
`build_and_verify.sh` step `[11]`):

1. **The Argon2 algorithm is anchored to the published RFC 9106 Argon2id test vector.** The harness
   drives the REAL in-tree `argon2id_ctx` (password/salt/secret/associated-data all fixed bytes,
   memory 32 KiB, iterations 3, **parallelism 4**) and reproduces the RFC tag
   `0d640df5…6b01e659` exactly — an independent published KAT that also confirms parallelism > 1 works.
2. **The override plumbs parallelism.** With the override at `p=1`, `derive_key_argon2` matches a direct
   `argon2id_hash_raw(…, 1)` (i.e. stock behaviour); at `p=4` it matches `argon2id_hash_raw(…, 4)`; and
   `p=1` vs `p=4` derive **different** keys — proving parallelism genuinely flows through and changes
   the derived key rather than being ignored.
3. **The resolver matches an independent Python reimplementation** of the PIM formula + override
   selection, diffed byte-for-byte across a range of PIM values and one override case.

The stock (no-flag) `Pkcs5.o` is additionally shown byte-for-byte identical to the baseline object, so
the default build is provably unchanged.

### Not sandbox-testable

The CLI option layer is gated and compiles, but driving an actual `veracrypt` create/mount with these
flags needs the wx application and a real volume — validate the round-trip (create with explicit
params → mount with the same params → opens; mount without → fails) on a real build.
