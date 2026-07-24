#!/usr/bin/env python3
"""
codex32_reference.py — independent reference for the codex32 (BIP-93) recovery-share encoding (step [92]).

Layer 1 of the two-way convention, diffed against codex32_test.c (which drives the REAL compiled
Common/ShareCode.c). The ms32 error-correcting checksum (regular 13-symbol + long 15-symbol) and the
5<->8 bit packing are reimplemented here from the BIP-93 spec, independent of ShareCode.c. This file
also asserts, against the OFFICIAL BIP-93 published test vectors, that the checksum + packing decode the
published strings to their published master seeds — the independent authority leg.

Note on scope: codex32 payloads are not canonical on the trailing pad bits (<=4 bits, discarded on
decode per BIP-93), so this encoder zero-pads — a valid codex32 encoding that decodes to the same seed
as the official (non-zero-pad) vectors, but is not byte-identical to them. The REF encode lines below
are therefore diffed against the C encoder (which zero-pads identically); the OFFICIAL vectors are
exercised through decode + seed-recovery (below), the same way codex32_test.c anchors them.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

MS32_CONST = 0x10CE0795C2FD1E62A
MS32_LONG_CONST = 0x43381E570BF4798AB26


def ms32_polymod(values):
    GEN = [0x19DC500CE73FDE210, 0x1BFAE00DEF77FE529, 0x1FBD920FFFE7BEE52,
           0x1739640BDEEE3FDAD, 0x07729A039CFC75F5A]
    residue = 0x23181B3
    for v in values:
        b = residue >> 60
        residue = (residue & 0x0FFFFFFFFFFFFFFF) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue


def ms32_long_polymod(values):
    GEN = [0x3D59D273535EA62D897, 0x7A9BECB6361C6C51507, 0x543F9B7E6C38D8A2A0E,
           0x0C577EAECCF1990D13C, 0x1887F74F8DC71B10651]
    residue = 0x23181B3
    for v in values:
        b = residue >> 70
        residue = (residue & 0x3FFFFFFFFFFFFFFFFF) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue


def create_checksum(data):
    if len(data) > 80:
        pm = ms32_long_polymod(data + [0] * 15) ^ MS32_LONG_CONST
        return [(pm >> 5 * (14 - i)) & 31 for i in range(15)]
    pm = ms32_polymod(data + [0] * 13) ^ MS32_CONST
    return [(pm >> 5 * (12 - i)) & 31 for i in range(13)]


def verify_checksum(data):
    if len(data) >= 96:
        return ms32_long_polymod(data) == MS32_LONG_CONST
    if len(data) <= 93:
        return ms32_polymod(data) == MS32_CONST
    return False


def to5(data):
    acc = 0
    bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)   # zero-pad the final group
    return out


def from5_trunc(symbols):
    acc = 0
    bits = 0
    out = bytearray()
    for s in symbols:
        acc = (acc << 5) | s
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)   # discard the final <=4 pad bits


def encode(k, ident, share_index, payload):
    data = [CHARSET.index(str(k))] + [CHARSET.index(c) for c in ident] \
        + [CHARSET.index(share_index)] + to5(payload)
    combined = data + create_checksum(data)
    return "ms1" + "".join(CHARSET[d] for d in combined)


def decode(s):
    s = s.lower()
    assert s[:3] == "ms1"
    data = [CHARSET.index(c) for c in s[3:]]
    assert verify_checksum(data), "checksum"
    csum = 15 if len(data) >= 96 else 13
    body = data[:-csum]
    k = int(CHARSET[body[0]]) if CHARSET[body[0]].isdigit() else None
    ident = "".join(CHARSET[b] for b in body[1:5])
    share_index = CHARSET[body[5]]
    seed = from5_trunc(body[6:])
    return k, ident, share_index, seed


def main():
    # deterministic REF set (diffed against the C encoder, which zero-pads identically)
    sets = [
        (0, "test", "s", bytes(range(16))),                       # 128-bit, regular checksum
        (3, "clv3", "c", bytes((0x40 + i) & 0xFF for i in range(32))),  # 256-bit, regular
        (5, "0c8v", "s", bytes((i * 7 + 3) & 0xFF for i in range(64))),  # 512-bit, long checksum
    ]
    for k, ident, idx, seed in sets:
        print("REF codex32 k=%d id=%s idx=%s = %s" % (k, ident, idx, encode(k, ident, idx, seed)))

    # OFFICIAL BIP-93 vectors: decode + seed recovery (the independent authority leg)
    tv1 = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"
    k, ident, idx, seed = decode(tv1)
    assert seed.hex() == "318c6318c6318c6318c6318c6318c631", seed.hex()
    assert (k, ident, idx) == (0, "test", "s")
    print("REF official_tv1_seed = %s" % seed.hex())

    tv5 = ("MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8"
           "WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK")
    k, ident, idx, seed = decode(tv5)
    assert seed.hex() == ("dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104"
                          "c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9"), seed.hex()
    print("REF official_tv5_seed = %s" % seed.hex())


if __name__ == "__main__":
    main()
