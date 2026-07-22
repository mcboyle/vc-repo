/*
 * SelfTest — power-on / on-mount known-answer tests for the fork's crypto primitives (ROI item 15/17).
 *
 * VeraCrypt already KAT-tests its ciphers at startup (EncryptionTest). This adds the same discipline
 * for the primitives THIS fork relies on when deriving a factored/keyslot header — run them at the
 * moment they matter (mount) so a miscompiled or corrupted build fails closed instead of silently
 * producing wrong keys. Gated behind VC_ENABLE_SELFTEST; a default build does not compile it.
 */
#ifndef TC_HEADER_Common_SelfTest
#define TC_HEADER_Common_SelfTest

#include "Tcdefs.h"

#if defined(VC_ENABLE_SELFTEST)

#if defined(__cplusplus)
extern "C" {
#endif

/* Bits set in the return value of VcForkSelfTest for each primitive that FAILED its KAT. */
#define VC_SELFTEST_SHA3_512  0x01   /* SHA3-512 PRF (FIPS-202)          */
#define VC_SELFTEST_SHA256    0x02   /* SHA-256 (duress/HKF HMAC base)   */
#define VC_SELFTEST_T1HA2     0x04   /* t1ha2 (KeyScrub RAM transform)   */

/* Run all fork-primitive KATs. Returns 0 if every test passed, or a bitmask of VC_SELFTEST_* bits for
   the ones that failed. Callers (mount path) MUST refuse to proceed on a non-zero result. */
int VcForkSelfTest (void);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_SELFTEST */

#endif /* TC_HEADER_Common_SelfTest */
