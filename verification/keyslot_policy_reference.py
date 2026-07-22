#!/usr/bin/env python3
# keyslot_policy_reference.py — independent (layer-1) reference for the v2 policy payload layout.
#
# The v2 keyslot payload is  flags[1] || expiryUnix[8, big-endian] || vmk.  This script computes the
# REF lines for the fixed slot the C harness (keyslot_policy_test.c) enrolls and reads back, so
# build_and_verify.sh can diff them byte-for-byte. It intentionally shares NO code with the C module.

REF_FLAGS  = 0x02                       # KEYSLOT_FLAG_READONLY
REF_EXPIRY = 0x0000000064abcdef
VMK_LEN    = 64
VMK        = bytes((0x40 + i) & 0xff for i in range(VMK_LEN))

print("REF flags=%02x" % (REF_FLAGS & 0xff))
print("REF expiry=" + REF_EXPIRY.to_bytes(8, "big").hex())
print("REF vmk=" + VMK.hex())
