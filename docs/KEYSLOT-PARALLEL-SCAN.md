# Parallelising the mount-time keyslot auto-search

## What and why

The mount-time keyslot auto-search (`Common/KeyslotStore.c` `KeyslotOpen`, driven from
`Volume/Volume.cpp` when the native header rejects the password) runs a
**500 000-iteration PBKDF2-SHA512 on every one of the table's `maxSlots` (63) slots**, by design:
a constant-time scan that derives all N slots with no early return so it leaks neither which slot
matched nor how many are populated (LUKS trade-off; see the comment at `KeyslotOpen`). On the VM this
cost **~46–87 s single-core** for any wrong-key/auto-search open, on a 16-core box with 15 cores idle —
measured, and the reason `verification/realbuild/acceptance.sh` blew its 5-minute budget on the negative
paths. It is the one item the VM run surfaced as a live, measured defect rather than a doc gap.

Parallelising the N independent per-slot derivations is the *only* safe speedup: the security property
is "derive all N, N public", so bounding or magic-gating the scan (skipping empty slots) is off the
table — it would leak occupancy via timing. Running the same N derivations concurrently changes only
wall-clock.

## The invariant (what must not change)

> **Every slot is derived exactly once; the count N depends only on the public config, never on the
> data; the first match in index order is selected in constant time with no early return.** Wall-clock
> therefore depends only on N and the machine — never on *which* slot matched.

## Design

`KeyslotOpen(...)` is unchanged behaviourally; a new `KeyslotOpenParallel(..., pf)` takes a parallel-for
executor. `KeyslotOpen` calls it with `pf == NULL`, which is **byte-for-byte the original serial loop**.
Only the mount auto-search (`Volume.cpp`) passes a real executor.

- **Phase 1 (serial):** read a batch of records. `area->read` is not assumed thread-safe, and the I/O is
  microseconds against a ~0.7 s/slot KDF, so it stays serial.
- **Phase 2 (parallel):** run the batch's pure `KeyslotUnwrapCT` (stack + caller buffers only, no shared
  state — verified) through `pf`, which must run **every** index with no early exit.
- **Phase 3 (serial):** fold the batch into the accumulator with the **same constant-time mask-select the
  serial loop uses**, in index order — so the first match in index order wins, batch boundaries included.

**Batched** (`KS_PARALLEL_BATCH = 16`) so peak automatic memory is fixed at `BATCH·2·STRIDE` regardless of
table size — measured **~33 KB** (`-fstack-usage`, worst of gcc-12/13/14 + clang at the ship flags
`-O2 -fno-strict-aliasing`: 33 104 B), safe on musl's 128 KB default thread stack (a one-shot 63-slot
design would have been ~132 KB and overflowed it). No dynamic allocation — the module keeps its
zero-allocation / always-wiped property and the serial scratch's swappable-stack posture (no new heap
surface for VMK candidate material). The parallel helper is `noinline`, so the serial `pf==NULL` path's
frame is unchanged (measured 3.8 KB, vs the helper's 33 KB on the parallel path only).

### Exception safety (the load-bearing part)

The executor (`Volume/KeyslotParallelExecutor.h` `VolumeKeyslotParallelFor`) is called through a **C**
function pointer from `KeyslotStore.c` (compiled as C, no unwind tables). `std::thread`'s ctor throws
`std::system_error` on `EAGAIN` (RLIMIT_NPROC / cgroup `pids.max` / OOM). This code's **first version had
three exception-safety bugs, each of which read correctly on inspection** — which is exactly why "verify
by code inspection" is not sufficient here and a real test exists (below). The handled failure modes:

1. an exception propagating across the C frames → **UB**, and slots left unrun → the scan finds no match →
   `KeyslotOpen` returns 0 = **"wrong password" for a correct passphrase** (a data-loss-shaped bug). Fixed:
   the executor is `noexcept` and `catch(...)`s, then runs any uncovered index inline.
2. a joinable `std::thread` destructing → `std::terminate`. Fixed: the join loop is **outside** the try, so
   a mid-loop throw cannot skip it.
3. `push_back` reallocating and throwing after a thread was constructed → same `terminate`. Fixed:
   `reserve()` upfront, so no reallocation can occur.

Belt-and-suspenders in the scan itself: `mret[]` is pre-seeded to a `-1` sentinel and the reduce masks
`m<0 → 0`, so even a contract-violating executor degrades a skipped slot to "no match" — never a wrong-key
selection — with a debug `assert` tripwire making the violation loud in debug builds.

## Verification (committed as `build_and_verify.sh` step [99]; scoped to what was measured)

`verification/keyslot_parallel_timing_test.cpp` drives the **actual** `VolumeKeyslotParallelFor` (extracted
into its own header precisely so the product executor is testable, not a replica) over an in-memory area:

- **Correctness / indexing:** VMK recovered at slot 0 **and** the last slot is byte-identical to the
  enrolled VMK (an `i*ct` indexing regression is invisible at slot 0; the last slot is across batch
  boundaries).
- **Exception-safety positive control (deterministic, no resource games):** a `VC_KS_PAR_TEST_HOOK` forces
  the spawn boundary at 0 (all inline), 1, and a partial value; the correct VMK still opens at each — the
  error path must **OPEN**, not merely not-crash.
- **Constant-time scan property:** `match@slot0` vs `match@slotLast`, N=40 interleaved, `CLOCK_MONOTONIC`,
  thread-noise dominated by the KDF cost. Latest: Δmean **2.3 ms** vs a **52 ms** noise floor (ratio 0.04)
  — no position dependence resolvable at ~ms. This is the sub-ms gate dudect ([46]) cannot provide.

Two supporting product measurements. Each names its OPERATION, BINARY, and TOOLCHAIN (three distinct
serial costs exist here — conflating them is how "51.75 ≈ 46" once got written down; see below), and both
are produced by the committed, hash-guarded harness `verification/realbuild/keyslot_timing.sh` (freezes
both binaries by sha256 before/after; aborts if either changed mid-run):

- **Speedup — operation: wrong-password MOUNT → keyslot auto-search (`KeyslotOpenParallel`); binaries:
  frozen PRE=origin/master vs POST=this change; toolchain: clang-18 + gcc-13 libstdc++; 63 slots, N=5,
  hash-guarded.** PRE **mean 47.585 s** (spread 0.435 s) → POST **mean 5.719 s** (spread 0.268 s) —
  **8.3× faster** on a 16-core box; both reject with "Incorrect password" (rc=1). Reproduce:
  `keyslot_timing.sh <pre> <post> autosearch 5 62`.
- **Constant-time, real-mount resolution — `match@0` vs `match@62`:** an earlier-binary check showed
  Δ0.13 s against a 0.5–0.86 s mount noise floor, i.e. **no position dependence detectable at ~0.5 s
  resolution** — it does not prove equality and cannot see a sub-100 ms leak. The step-[99] microbenchmark
  (Δ2.3 ms vs 52 ms, final toolchain) is the finer gate; this real-mount row is only a coarse corroborator.
- **Serial `pf==NULL` path unchanged — operation: `--keyslot-open` full 63-slot serial scan
  (`KeyslotOpen`, `pf==NULL`), isolated with the correct native `--password`; frozen PRE vs POST; final
  toolchain; N=5, hash-guarded.** PRE **mean 36.975 s** (spread 0.451 s) vs POST **mean 36.862 s** (spread
  0.372 s) — Δ0.11 s, **well inside the spread ⇒ no regression** for existing CLI / Windows / verification
  callers. Reproduce: `keyslot_timing.sh <pre> <post> serialopen 5 62`.

Three distinct serial costs, never to be cross-compared: **native-key mount ~1 s** (bypasses the
auto-search entirely); **wrong-password mount auto-search ~46 s serial → parallel** (the speedup);
**`--keyslot-open` full 63-slot scan ~85 s** (63 × ~1.3 s PBKDF2-SHA512 at cost 500 000). The
mid-development "51.75 s ≈ 46 s" comparison was **apples-to-oranges from the start** — 51.75 s was a
`--keyslot-open` serial scan and 46 s was a mount auto-search, different operations on different binaries —
and is retired, not reassuring.

**Measurement confound found and corrected (understand the number before writing it down).** A first
attempt to measure "serial unchanged" via `--keyslot-open` with a *wrong* `--password` showed PRE 84.6 s
vs POST 51.1 s — a 40 % gap on a path that is byte-for-byte identical (verified against origin/master).
That was **not** a regression: the `--keyslot-open` handler first calls `Core->OpenVolume(--password)`
(`UserInterface.cpp:341`), which on a wrong password runs `Volume::Open`'s *own* mount-time auto-search —
now parallel in POST (~6 s) vs serial in PRE (~44 s) — *before* the handler's direct serial `KeyslotOpen`
scan (~44 s, identical in both). So 84 ≈ 44+40 (PRE) and 51 ≈ 6+44 (POST): the delta is the parallelised
auto-search *correctly* firing inside `OpenVolume`, leaking into a measurement meant to isolate the serial
path. Fix: `serialopen` mode uses the **correct** native `--password` (so `OpenVolume` accepts the native
header fast and skips its auto-search) with a wrong `--new-password`, isolating the pure serial `pf==NULL`
scan. (This is itself extra evidence the parallelisation works — the speedup shows up even via the
`--keyslot-open` recovery path.)
