#!/usr/bin/env python3
"""volume_label_reference.py — independent reference for the encrypted-label framing (ROI item 43).

The only NEW logic in item 43 is the payload framing (the AEAD is the already-anchored KeyslotWrap).
This reimplements the framing independently:  plaintext[64] = b"LBL1" || len[1] || label || zero-pad.
It emits one 'FRAME <idx> <pt_hex>' line per fixed test label; the C harness emits the same from the
real VolumeLabelFrame and the suite diffs them byte-for-byte.
"""
import sys

# Fixed label set — MUST match the C harness order/content exactly.
LABELS = [
    b"",
    b"a",
    b"work-laptop-backup",
    b"A" * 48,                                   # max length
    bytes([0xc3, 0xa9, 0xce, 0xb4, 0x2d, 0x37]), # "é δ -7" (non-ASCII UTF-8)
]
PT = 64
MAGIC = b"LBL1"

def frame(label):
    assert 0 <= len(label) <= 48
    body = MAGIC + bytes([len(label)]) + label
    return body + b"\x00" * (PT - len(body))

def main():
    for i, lab in enumerate(LABELS):
        print("FRAME", i, frame(lab).hex())
    return 0

if __name__ == "__main__":
    sys.exit(main())
