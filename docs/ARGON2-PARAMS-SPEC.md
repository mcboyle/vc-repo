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

## Certification posture — a friction note, not a reason to change the KDF

The fork's HKDF/KMAC adoption and its fixed FIPS 203 ML-KEM parameters improve certification posture, but
**Argon2id sits outside the current SP 800-132 storage-KDF baseline** until NIST completes its revision —
which is a *decided but not yet drafted* revision. This is recorded so a future reader does not confuse
"best engineering choice" with "easiest certification story."

**This is not an argument to move off Argon2id.** Argon2id stays; both independent audits confirm it. The
note exists only to flag the certification friction honestly, not to reopen the KDF choice — the memory-
hardness Argon2id buys against password guessing is the security property that matters here, and no
SP 800-132-baseline KDF provides it.

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

### Create → open round-trip: verified in-sandbox

This section previously read *"Not sandbox-testable"*. That was inherited, never tested, and wrong — see
`docs/CANT-CLAIMS-AUDIT.md`. The round-trip runs here and is CI-gated.

A volume is created with the real CLI (`--hash=Argon2id --argon2-memory 16 --argon2-iterations 3
--argon2-parallelism 4`) and then opened **in-process** through the real `Volume::Open` by
`verification/realbuild/open_roundtrip.sh` — no kernel dm-crypt needed, because the parameters are
exercised by header-key derivation, not by mounting. Since the parameters are *not stored in the header*,
the round-trip is the only thing that can distinguish "the parameters shape the volume key" from "the
parameters are silently ignored":

| probe | expected | result |
|---|---|---|
| same params — **positive control** | opens, non-trivial master key | opens (256-byte master key) |
| wrong memory (32768 vs 16384 KiB) | reject | PasswordIncorrect |
| wrong iterations (4 vs 3) | reject | PasswordIncorrect |
| wrong parallelism (1 vs 4) | reject | PasswordIncorrect |
| no override at all (PIM default) | reject | PasswordIncorrect |
| right params, wrong password | reject | PasswordIncorrect |

The positive control runs first on purpose: if it fails, every negative below it rejects for free and
proves nothing. (That ordering is what caught a mixed-feature-flag build masquerading as a crypto failure
— the harness now refuses to run against archives whose `src/.build-flags` stamp disagrees with its own.)

Still out of reach here: the **kernel dm-crypt mount** itself, which needs a VM.
