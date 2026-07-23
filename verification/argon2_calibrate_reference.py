#!/usr/bin/env python3
"""argon2_calibrate_reference.py — independent reference for the Argon2 auto-calibration policy
(ROI-TOP-50 item 10).

The calibration policy is deterministic and timing-free: iterations = floor(targetMs*1000 /
perIterMicros), clamped to [floorIters, capIters], with a per-iteration cost of 0 guarded to 1.
This reimplements it and prints one 'REF ...' line per grid point; the C harness prints the same
lines from the real Pkcs5.c Argon2IterationsForBudget and the suite diffs them byte-for-byte.
"""
FLOOR = 3
CAP   = 1 << 20

def iters_for_budget(target_ms, per_iter_us, floor=FLOOR, cap=CAP):
    if per_iter_us == 0: per_iter_us = 1
    if floor == 0: floor = 1
    if cap < floor: cap = floor
    it = (target_ms * 1000) // per_iter_us
    if it < floor: it = floor
    if it > cap:   it = cap
    return it

def main():
    target_ms = [0, 1, 25, 50, 100, 250, 500, 1000, 5000, 60000]
    per_iter  = [1, 100, 1000, 5000, 20000, 200000]     # microseconds per Argon2 pass
    for t in target_ms:
        for p in per_iter:
            print(f"REF {t} {p} {FLOOR} {CAP} {iters_for_budget(t, p)}")

if __name__ == "__main__":
    main()
