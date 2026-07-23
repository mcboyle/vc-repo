# Constant-time hardening — measured ground truth for R17

*Research batch-3 R17 scaffold. This records what the current tree actually does about software-crypto
side channels, measured, so the incoming R17 report can be checked against evidence rather than taken at
face value (the batch-2 lesson). It is not the report; it is the baseline the report should confirm or
contradict.*

## The defect that motivated R17 (fixed, PR #7)

`verification/hctr2_poc.c`'s `gf_dot()` (the GF(2¹²⁸) multiply behind HCTR2's POLYVAL) branched on secret
data in two places — a bit of the polynomial accumulator and the low bit of the reduction state. Both
operands are secret (the POLYVAL key is `AES_k(0¹²⁸)`). The code *avoided* lookup tables and introduced a
branch/timing channel instead. Fixed with arithmetic masking (`m = 0 - bit; x ^= value & m`), fixed
iteration count, no tables — mirroring `src/Common/Shamir.c`'s GF(2⁸) approach. The project's convention
existed and was correct; it simply had not been carried into a second implementation of the same idea.

## Q1 — does masking-mirroring-Shamir survive the compiler? **Measured: yes, at -O2/-O3/LTO on gcc+clang.**

Two independent lines of evidence.

**(a) Static branch classification.** Disassembling the masked `gf_dot` (`objdump -d`) shows the only
conditional jumps are **loop control** — `cmp $0x80,%esi; je` (counter vs 128) and the limb-loop
counter — and, on clang, `cmov` for the `s ? (b>>(64-s)) : 0` guard where `s = i & 63` is the **public**
loop index. No conditional branch targets a secret-derived value. `-O2 -flto` fully unrolls the
fixed-count loops, leaving zero conditional jumps.

**(b) ctgrind / valgrind-memcheck white-box check** (`verification/ct_ctgrind_test.c`,
`ct_ctgrind_check.sh`). The secret operands are marked *undefined* (`VALGRIND_MAKE_MEM_UNDEFINED`); under
memcheck, any branch or memory index on a secret-derived bit raises "Conditional jump or move depends on
uninitialised value." Both subjects are the **real** primitives, reached by `#include`, not a hand-copy:
`gf_mul`/`gf_inv` from `src/Common/Shamir.c` and `gf_dot` from `verification/hctr2_poc.c` (via
`HCTR2_NO_MAIN`, the same include technique as `hctr2_dudect_test.c`) — so the check cannot silently
validate a stale copy if `gf_dot` is edited. Result:

| opt level | gcc | clang |
|---|---|---|
| `-O2` | 0 errors | 0 errors |
| `-O3` | 0 errors | 0 errors |
| `-O2 -flto` | 0 errors | 0 errors |

The check is **self-validating**: the same poisoning over a deliberately-branchy leaky copy (kept local to
the harness) raises 3–9 errors at every level, so a 0 on the real code is a real signal, not a silent
no-op. **Conclusion: the masking is not reintroduced as a branch at the optimization levels the suite
builds with, on either compiler.** This does *not* rule out microarchitectural leakage that survives
branch-free code (data-cache banking, execution-port contention, variable-latency instructions) —
memcheck and dudect are both blind to that; see Q3/Q4.

**Provenance — single environment.** The numbers above are one measurement: **one machine, one valgrind
version (3.22.0), one container**. The self-validating leaky control is what makes a 0 trustworthy (the
tool demonstrably catches a real leak in the same run), but this is not a cross-platform or
cross-toolchain survey. This doc exists to be checked against an external R17 report; overstating a
single-environment result would defeat that purpose. Re-run `verification/ct_ctgrind_check.sh` on another
host/valgrind to widen it.

## Q2 — finding the *next* instance of "a second implementation of an idea done right elsewhere"

The defect class is duplication that diverges in constant-time-ness, not a one-off. A systematic sweep for
the current tree:

- **Enumerate the finite-field / bignum / conditional-select sites** and check each for the masked idiom
  vs a branch. Grep seeds that actually hit this tree: `>> .* & 1` (bit extraction), `0ULL - `/`0U - `
  (mask construction — its *absence* near a secret-bit test is the smell), `if .*& 1`, `while (b)` /
  `while (.*)` loops whose bound is a secret, `?` ternaries on secret-derived values, and table indexing
  `\[[a-z].*\]` where the index is secret.
- **Pair every "constant-time" claim with a screen.** The four dudect screens (`shamir_`, `keyslot_`,
  `duress_`, `hctr2_dudect_test.c`) and now this ctgrind check are the enforced ones; any *new* primitive
  that touches secrets should get one before it is called constant-time. The gap that let `gf_dot` through
  was exactly that it had no screen while `Shamir.c` did.
- **Diff sibling implementations.** Where the same operation exists twice (GF multiply in `Shamir.c` vs
  `gf_dot`; any future promotion of a PoC into `src/`), the promotion checklist should require the ct
  screen to move with the code — the HCTR2-into-`src/` promotion is the immediate case and is gated on
  exactly this.

## Q3 — is dudect the right gate, and what does it miss?

- **dudect** (Reparaz–Balasch–Yarom) is a *black-box statistical timing* screen: it needs no source
  annotation, runs anywhere, and catches leakage regardless of cause — but it cannot say *which*
  instruction leaks, needs many samples, and is noisy in a shared VM (Q4).
- **ctgrind / ct-verif / dataflow tools** are *white-box*: they pinpoint the leaking branch/index and give
  a deterministic pass/fail, but only for the leakage they model (control flow + memory addressing), and
  need the secret annotated. This scaffold **adds ctgrind** (`ct_ctgrind_test.c`) as the complementary
  tool — it found nothing on the real code, which is the useful confirming result.
- **Realistic cost in a privilege-free container:** ctgrind = valgrind + `<valgrind/memcheck.h>`, no
  special privileges, but valgrind is not guaranteed present and runs ~10–50× slower — so it is kept as an
  **on-demand check** (`ct_ctgrind_check.sh`), deliberately *not* a hard `--strict` step (a valgrind-absent
  container would otherwise turn into a strict failure). Formal tools (ct-verif/Binsec/haybale) prove more
  but cost real integration effort and are out of scope for a container gate. This is itself an answer to
  the brief's cost question: dudect stays the always-on gate; ctgrind is the on-demand deepener.

## Q4 — what does a passing dudect screen justify about a real deployment?

Little, on its own, about *target* hardware — and the docs already treat it that way. dudect here is
measured in a shared virtualized environment; a pass is **evidence of the absence of a large timing
signal in this environment**, not a proof of constant-time execution on the user's CPU (different
microarchitecture, different cache/port behaviour, SMT neighbours). The honest claim the tree should make
— and this scaffold recommends the report confirm — is: *"branch-free by construction (static +
ctgrind-confirmed at -O2/-O3/LTO), with a dudect screen that shows no timing signal in CI; constant-time
behaviour on specific target hardware is not claimed and would need on-device measurement."* The relative
(not absolute) dudect criterion the screens use is what keeps the CI verdict stable across machines; it
does not extend the claim to the user's machine.

## For the R17 report

Treat the above as the baseline. "This project's existing convention is adequate, here is the evidence"
is an acceptable conclusion (the brief says so) — and the measured ctgrind result is evidence for it. The
open questions the report can still add value on: microarchitectural leakage that survives branch-free
code (which neither dudect nor ctgrind here covers), and whether any *other* current site carries the
duplicate-divergence defect (Q2's sweep is a method, not a finished audit).
