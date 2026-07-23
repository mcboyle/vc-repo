#!/usr/bin/env python3
# Independent Sloth VDF reference (docs/DELAY-SPEC.md, IDEAS-BACKLOG.md "Delay
# functions" row). Sloth (Lenstra & Wesolowski, "A random zoo: sloth, unicorn,
# and trx", 2015) is a verifiable delay function: computing it takes T inherently
# SEQUENTIAL modular square-root steps (each a full modexp), but VERIFYING takes
# T cheap squarings — so a coercer cannot parallelize their way past the delay,
# yet the holder checks it instantly. This is the "coercion cooling-off" the
# backlog wants: a volume factor that costs a fixed wall-clock time to unlock,
# unshortenable even with a datacenter.
#
# Over a prime p ≡ 3 (mod 4), the square-root permutation is:
#   rho(x) = tau( sqrt(x) ), sqrt(x) = x^((p+1)/4) if x is a QR else (-x)^((p+1)/4);
#   tau flips the low bit to make rho a bijection (so it inverts exactly).
# Forward step = one modexp (slow); inverse step = one squaring (fast).
#
# No standard KAT exists for Sloth; the proof is (1) byte-identical agreement
# between this reference and sloth_poc.c, and (2) the defining invertibility:
# verify() reproduces the seed from the output in T fast steps. Stdlib only.
import sys

# 256-bit prime, p ≡ 3 (mod 4)  (undersized for production; a PoC parameter)
P = 0x800000000000000000000000000000000000000000000000000000000000005f

def _is_qr(x, p):
    return pow(x, (p - 1) // 2, p) == 1

def _sqrt_perm(x, p):
    # A true bijection of Z_p (p ≡ 3 mod 4). Exactly one of x, -x is a QR
    # (since -1 is a non-residue). Take the square root of whichever is a QR,
    # and set the root's PARITY to the branch bit so the inverse can recover it.
    b = 1 if _is_qr(x, p) else 0
    base = x % p if b else (-x) % p          # base is always a QR
    y = pow(base, (p + 1) // 4, p)           # y*y == base (mod p)
    if (y & 1) != b:
        y = (p - y) % p
    return y

def _sqrt_perm_inv(y, p):
    # Fast inverse: one squaring. Recover the branch bit from y's parity,
    # square to get base, then undo the conditional negation.
    b = y & 1
    base = (y * y) % p
    return base if b else (-base) % p

def sloth(seed, steps, p=P):
    x = seed % p
    for _ in range(steps):
        x = _sqrt_perm(x, p)
    return x

def sloth_verify(output, steps, p=P):
    # T fast squarings recover the seed (each undoing one sqrt-perm step)
    x = output % p
    for _ in range(steps):
        x = _sqrt_perm_inv(x, p)
    return x

if __name__ == "__main__":
    seed = 0x1234567890ABCDEF1122334455667788AABBCCDDEEFF00998877665544332211
    STEPS = 500
    out = sloth(seed, STEPS)
    print("REF sloth_out %064x" % out)
    rec = sloth_verify(out, STEPS)
    print("REF verify_recovers_seed " + ("YES" if rec == seed % P else "NO"))
    # determinism
    print("REF deterministic " + ("YES" if sloth(seed, STEPS) == out else "NO"))
    # a different step count gives a different output (delay is real)
    print("REF steps_matter " + ("YES" if sloth(seed, STEPS + 1) != out else "NO"))
    # tampering the output => verify does not recover the seed
    bad = out ^ 1
    print("REF tamper_detected " + ("YES" if sloth_verify(bad, STEPS) != seed % P else "NO"))
    sys.exit(0 if rec == seed % P else 1)
