# Prompt for the vc-repo Claude Code session — PR #10 review fixes

Paste the block below into the session that owns PR #10.

---

PR #10 was independently reviewed against a fresh clone. The substance is sound and it should merge —
the guard, the harness extension, the driver polarity and the A1/A4 doc work all check out. One item
needs fixing first because it over-claims, and there are four cheap nits. Please do these on the same
branch and push; no design changes.

## 1. BLOCKING — `scripts/ct-primitive-guard.sh` over-claims what the guard does

The failure message currently ends with:

> This is the mechanism that would have caught the original `gf_dot` branch defect automatically.

That is not true, and it was tested. Reproduction:

1. Re-introduce a branch on secret data inside `gf_dot` in `verification/hctr2_poc.c` — e.g. insert
   `if ((a[i >> 6] >> (i & 63)) & 1) { }` before the existing masked line.
2. Run `./scripts/ct-primitive-guard.sh`.
3. Result: **`OK`, exit 0.** The original defect is not caught, because `hctr2_poc.c` is on `GF_BLESSED`.

The guard is a **location** guard — "does this operation live in a blessed module?" — not a
**correctness** guard. Branchiness is caught by ctgrind/dudect, not by this script. Once a file is on the
allowlist it is exempt, so the guard cannot detect a regression *inside* a blessed file.

What the guard genuinely would have done is flag `hctr2_poc.c`'s `gf_dot` as unblessed **at the moment the
file was introduced**, forcing a review before it was allowlisted. That is real value; it is just a
different claim.

**Do this:** reword the closing message to claim only that. Suggested:

```
echo "This is the mechanism that would have forced a review of the second gf_dot when it was introduced."
```

Also add one sentence to the header comment making the scope explicit — something like: *this guard checks
**where** a constant-time-sensitive primitive is defined, not **whether** the implementation is
constant-time; a regression inside an already-blessed file is caught by ctgrind/dudect, not here.*

**Do NOT** try to make the guard detect branchiness. That is ctgrind/dudect's job and R17 is explicit that
this guard's purpose is the duplicate-implementation defect class. The fix here is honest wording, not
more machinery. The reason this matters: `CT-HARDENING-R17.md` is otherwise scrupulous about stating
claims only at the level each tool licenses (Q4, and the new A4 section), and an over-claiming guard
message cuts against exactly that discipline.

## 2. Tighten the `leaky` exemption to the identifier (cheap)

`grep -viE 'leaky'` exempts any matched line containing the word anywhere, so a genuine unblessed
definition with the word in a trailing comment is silently exempt. Confirmed:

```c
unsigned char gf_mul (unsigned char a, unsigned char b) { /* not leaky at all */ return a^b; }
```

is not flagged. Scope the exclusion to the function identifier (`_leaky` / `leaky_` in the name) rather
than the whole line. Keep the false-negative-preferring posture — just close the accidental bypass.

## 3. Make the self-test cover `scan()`, not just the heuristic

`--self-test` exercises `find_defs_abs` only. A bug in `scan()` or `is_blessed()` would pass the self-test
and then silently pass everything. This was checked manually — planting an unblessed `gf_mul` in a new
`src/Common/` file *is* caught, exit 1 — so the logic is correct today; the point is to make that
permanent. Add a case that drives the real `scan()` path against a planted file (and cleans up after
itself, including if the script exits early).

## 4. `scan()` exit-status wraparound (trivial)

`scan()` returns the violation count as an exit status, so ≥256 violating files would wrap to 0. Return a
boolean instead.

## 5. Comment nit in `verification/ct_ctgrind_test.c` (trivial)

The A2 block calls `b[31] ^= 0x01` the "worst case for an early-out." That is the worst case for *timing*
(dudect); under taint-tracking the leaky compare branches on secret data at `i = 0` regardless of where
the difference sits. The choice is still good — it maximizes the leaky error count — so keep the code and
fix the rationale.

## Verification before pushing

- `./scripts/ct-primitive-guard.sh --self-test` passes, and the new scan-path case passes.
- `./scripts/ct-primitive-guard.sh` still clean on the tree.
- Planting an unblessed `gf_mul` in a new file still fails with exit 1 (guard keeps its teeth).
- `verification/ct_ctgrind_check.sh` unchanged in behaviour: REAL = 0, LEAKY > 0, AES > 0 recorded as the
  expected finding, AES = 0 still treated as a harness failure.
- `--strict` still **82/82, 0 SKIP**, anchors intact (Shamir `a8b0cbb7`), negative control still fails.

Items 1 and 5 are comment/message-only. Items 2–4 touch guard logic, so re-run the guard checks above and
confirm the scan stays clean.

## Not in scope for this pass

Two things surfaced in the same review but belong to other work, not to PR #10:

- The A1 finding's consequence for **HCTR2 promotion into `src/`** — HCTR2 is AES-based, so it inherits
  the measured table-AES leak on the no-AES-NI path (`Crypto.c:1179`,
  `HasAESNI() && !HwEncryptionDisabled`). The doc already says this; it belongs in the HCTR2 promotion
  decision, not here.
- The 408 / 1000+ error counts remain a **single-environment measurement** (one machine, one valgrind, one
  container, x86-64). The doc already states that provenance. No change needed.
