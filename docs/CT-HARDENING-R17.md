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
  need the secret annotated. This scaffold **adds ctgrind** (`ct_ctgrind_test.c`): it confirms the masked
  field arithmetic + the keyslot compare are clean, and — pointed at the table AES fallback — localizes a
  real leak (see the A1 section below), which is exactly the white-box value dudect cannot give.
- **Realistic cost in a privilege-free container:** ctgrind = valgrind + `<valgrind/memcheck.h>`, no
  special privileges, but valgrind is not guaranteed present and runs ~10–50× slower. Formal tools
  (ct-verif/Binsec/haybale) prove more but cost real integration effort and are out of scope for a
  container gate.

### The two senses of "gate" — reconciled (do not "fix" this later)

R17 says *"promote ctgrind/TIMECOP to your primary constant-time gate"*; this project keeps **dudect** as
the `--strict` step. **These are not in conflict — they answer different questions under one word:**

- **Which tool runs in `--strict`:** **dudect.** valgrind is not guaranteed present in a privilege-free
  container, and wiring it into the always-on gate would turn its absence into a failure or a silent skip.
  Given this project's history with silent skips, that is the right call. This composition is **settled and
  is not being reversed** — ctgrind stays the on-demand check (`ct_ctgrind_check.sh`).
- **Which tool's verdict is *authoritative for the claim*:** **ctgrind.** Taint-tracking is
  environment-independent and localizes the leak; dudect measures wall-clock timing in a shared VM and
  proves the least (Q4). So the project's constant-time *claims* rest on the **ctgrind** result, with the
  dudect screen cited as always-on corroboration — R17 endorses this distinction as "correct and
  important." "Primary gate" (R17) = *authoritative verdict*; "always-on gate" (this repo) = *what runs in
  `--strict`*. Both statements stand.

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

## A1 — the table AES fallback measured under ctgrind (a positive finding)

The masked field arithmetic is proven clean; the **cipher underneath was unexamined**. `src/Crypto/Aestab.c`
is Brian Gladman's table-based AES (the `ft_tab`/`fl_tab`/`it_tab` class), and `src/Common/Crypto.c` runs
it on any machine without AES-NI **and** whenever a user disables hardware encryption
(`HasAESNI() && !HwEncryptionDisabled`). Table-driven AES indexes memory with key/plaintext-derived data
by construction — the *original* cache-timing target (Bernstein 2005; Osvik–Shamir–Tromer 2006; MemJam,
CT-RSA 2018). `ct_ctgrind_test.c` now makes it a **subject**: poison the key (key schedule + round tables)
and, separately, the plaintext, through the real `Aescrypt.c` + `Aeskey.c` + `Aestab.c`.

**Result — positive, as expected.** memcheck flags secret-dependent memory addressing at every level:

| opt level | gcc | clang | flagged functions |
|---|---|---|---|
| `-O2` | 408 | 408 | `aes_encrypt`, `aes_decrypt`, `aes_encrypt_key256`, `aes_decrypt_key256` |
| `-O3` | 408 | 1000+ | same |
| `-O2 -flto` | 408 | 408 | same (LTO inlines into `main`) |

A **positive result is the finding, not a harness failure** — ctgrind is supposed to flag table AES. The
value is converting "presumably leaky" into *measured, localized, quantified*: hundreds of distinct
secret-dependent table accesses, confined to the four AES functions, on both compilers at every level.
The masked primitives and `KeyslotConstTimeEqual` in the same binary stay at **0** — so this is a property
of the AES fallback, not of the harness.

**The honest consequence (belongs in the doc regardless of how it reads):** **the constant-time claims
this project makes apply to its field arithmetic (`gf_mul`/`gf_inv`/`gf_dot`) and keyslot logic
(`KeyslotConstTimeEqual`), NOT to the table-based AES fallback (`Aescrypt.c`/`Aestab.c`).** On hardware
with AES-NI the shipping path uses the hardware instructions (constant-time by the CPU) and the table path
does not run; but on a machine without AES-NI, or with hardware encryption disabled, the table path is
cache-timing-vulnerable. This directly bears on **HCTR2 promotion into `src/`**: HCTR2 is AES-based, so it
inherits this on the no-AES-NI path — the clean `gf_dot` result says nothing about the cipher underneath.

**Not fixed here, deliberately.** No AES source was modified (this session measures). R17 is explicit:
*do not build a bespoke bitsliced AES* — the S-box circuit is easy to get subtly wrong; if replacement is
ever warranted the answer is adopting a vetted constant-time implementation (BearSSL `aes_ct`,
BoringSSL/RustCrypto lineage), a separate and larger decision. **Other AES sources noted:**
`src/Crypto/AesSmall.c` is a byte-oriented AES ("only 8-bit byte operations") — smaller footprint but a
256-byte S-box indexed by secret data is still a cache-timing surface, not a table-free win;
`src/Crypto/Aes_hw_armv8.c` is the ARMv8 hardware path (`arm_neon.h` crypto extension), constant-time by
hardware and not exercised in this x86 container.

## For the R17 report

Treat the above as the baseline. "This project's existing convention is adequate, here is the evidence"
is an acceptable conclusion for the *field arithmetic and keyslot logic* (the brief says so) — the measured
ctgrind result is evidence for it — but the **table AES fallback is measurably not constant-time**, and
that qualifier now travels with every constant-time claim in the tree. Open questions the report can still
add value on: microarchitectural leakage that survives branch-free code (which neither dudect nor ctgrind
here covers), the AES-fallback decision (accept-and-document vs adopt a vetted `aes_ct`), and whether any
*other* current site carries the duplicate-divergence defect (Q2's sweep is a method, not a finished audit;
A3's blessed-module guard now enforces it going forward).

## Environment ceiling (stated plainly)

Every measurement here is **one container, one valgrind version (3.22.0), gcc + clang, x86-64** — the
triples available in this sandbox. R17's Stage 2 asks for the ctgrind sweep across *every release target
triple* (ARM, the AES-NI vs no-AES-NI split on real silicon, each shipped compiler); **that is not this
session** and remains an open gap. The self-validating controls (leak caught; masked primitives clean;
AES flagged) make the single-environment verdict trustworthy, but not a cross-triple survey.
