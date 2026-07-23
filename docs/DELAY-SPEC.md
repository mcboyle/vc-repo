# Sloth verifiable delay function — coercion cooling-off

**Status: algorithm proven two ways; the volume-factor wiring is real-build.** Addresses
`IDEAS-BACKLOG.md` "Delay functions" row (RSW time-lock, Sloth, VDFs) — a factor that imposes a fixed,
unshortenable wall-clock delay to unlock.

## The gap it closes

A coercer who seizes the media and the passphrase can decrypt immediately. A *delay* factor changes the
economics: unlocking requires a computation that takes a fixed real time no amount of hardware can
shorten, giving a cooling-off window (and making rubber-hose attacks visibly slow). The primitive must
be **sequential** (unparallelizable) to compute yet **fast to verify**, or the honest holder pays the
delay twice.

## Construction (Sloth — Lenstra & Wesolowski, 2015)

Over a prime `p ≡ 3 (mod 4)`, iterate a square-root permutation `T` times:

```
rho(x): b = [x is a QR];  base = x if b else -x   (mod p)      # exactly one of x,-x is a QR
        y = base^((p+1)/4) mod p                                # y^2 = base
        if parity(y) != b: y = p - y                            # encode the branch bit in y's parity
forward (slow):  x_{i+1} = rho(x_i)          — one modexp per step
verify  (fast):  x_i = rho^{-1}(x_{i+1})     — one squaring per step: b=parity(y), base=y^2, x=base if b else -base
```

Encoding the QR-branch bit in the root's parity makes `rho` a true bijection whose inverse is a single
squaring, so verification is ~one modmul per step against a full modexp per step to compute — the
asymmetry that defines a VDF.

## What the PoC proves (`verification/sloth_poc.c` + `sloth_reference.py`, step `[30]`)

No standard KAT exists for Sloth, so the proof is the fork's dual-implementation rule plus the defining
property: `sloth_poc.c` (a 256-bit fixed-width bignum — schoolbook `mulmod`, 5-limb long-division
reduction, square-and-multiply `powmod`) and `sloth_reference.py` (Python bigint) agree **byte-for-byte**
on the T=500 chain output (`1f884ff5…`); `verify()` recovers the seed through the fast path
(`verify_recovers_seed`); a different step count changes the output (`steps_matter`); and a tampered
output fails to recover the seed (`tamper_detected`).

## Integration & honest notes

- **Wall-clock calibration is the real-build step.** T must be tuned to a target delay on reference
  hardware; the sequential-squaring assumption is only as strong as the fastest modexp an adversary can
  build (ASIC headroom), so pick T with margin and document the hardware baseline.
- **Composes as a factor, not a replacement.** Sloth gates a mixed-in secret (chain the volume factor's
  input through the delay) — it does not encrypt anything itself.
- **Undersized PoC prime.** 256 bits is a PoC parameter; production uses a large safe prime (or an RSA
  modulus for the RSW time-lock variant, which additionally hides the group order).
- **Scope.** A time-delay on the user's own unlock — access-control, inside the project boundary.
