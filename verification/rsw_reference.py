#!/usr/bin/env python3
# Independent RSW time-lock reference (docs/DELAY-SPEC.md, IDEAS-BACKLOG.md
# "Delay functions" row). Rivest-Shamir-Wagner 1996: the original time-lock
# puzzle. The opener must compute x^(2^T) mod N by T SEQUENTIAL squarings --
# unparallelizable. The party who KNOWS the factorization of N = p*q has a
# trapdoor: e = 2^T mod phi(N), then x^e is two modexps regardless of T. So the
# volume owner (who keeps p,q at enrollment) can rewrap instantly while an
# adversary -- or the owner after discarding the factors -- pays the full delay.
# Complements Sloth (step [30]): Sloth = verify-fast, RSW = create-fast.
#
# No standard KAT; proof = byte-identical agreement with rsw_poc.c + the
# defining identity (trapdoor == sequential) + wrong-trapdoor divergence.
import sys

Pp = 0x800000000000000000000000000012b7
Qp = 0x800000000000000000000000000cb003
N = Pp * Qp
PHI = (Pp - 1) * (Qp - 1)
T = 1000

def sequential(x, t=T):
    x %= N
    for _ in range(t):
        x = (x * x) % N
    return x

def trapdoor(x, phi=PHI, t=T):
    e = pow(2, t, phi)
    return pow(x % N, e, N)

if __name__ == "__main__":
    seed = 0x1234567890ABCDEF1122334455667788AABBCCDDEEFF00998877665544332211
    slow = sequential(seed)
    fast = trapdoor(seed)
    print("REF rsw_out %064x" % slow)
    print("REF trapdoor_matches_sequential " + ("YES" if fast == slow else "NO"))
    print("REF deterministic " + ("YES" if sequential(seed) == slow else "NO"))
    print("REF steps_matter " + ("YES" if sequential(seed, T + 1) != slow else "NO"))
    # a wrong trapdoor (wrong phi, i.e. wrong factorization) diverges
    print("REF wrong_trapdoor_detected " + ("YES" if trapdoor(seed, PHI - 2) != slow else "NO"))
    sys.exit(0 if fast == slow else 1)
