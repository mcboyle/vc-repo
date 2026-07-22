/*
 * SelfTest — see SelfTest.h. Known-answer tests for the fork's crypto primitives, run at mount.
 */
#include "SelfTest.h"

#if defined(VC_ENABLE_SELFTEST)

#include <string.h>
#include "Crypto/Sha3.h"
#include "Crypto/Sha2.h"
#include "Crypto/t1ha.h"

/* SHA3-512("") — FIPS 202 known-answer value. */
static const unsigned char KAT_SHA3_512_EMPTY[64] = {
	0xa6,0x9f,0x73,0xcc,0xa2,0x3a,0x9a,0xc5,0xc8,0xb5,0x67,0xdc,0x18,0x5a,0x75,0x6e,
	0x97,0xc9,0x82,0x16,0x4f,0xe2,0x58,0x59,0xe0,0xd1,0xdc,0xc1,0x47,0x5c,0x80,0xa6,
	0x15,0xb2,0x12,0x3a,0xf1,0xf5,0xf9,0x4c,0x11,0xe3,0xe9,0x40,0x2c,0x3a,0xc5,0x58,
	0xf5,0x00,0x19,0x9d,0x95,0xb6,0xd3,0xe3,0x01,0x75,0x85,0x86,0x28,0x1d,0xcd,0x26
};

/* SHA-256("abc") — FIPS 180-4 known-answer value. */
static const unsigned char KAT_SHA256_ABC[32] = {
	0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};

/* t1ha2 regression anchor: t1ha2_atonce("VeraCrypt fork self-test KAT vector", 35, 0). Not a published
   KAT (t1ha has none), but a fixed input->output that detects a broken/miscompiled t1ha at mount.
   Cross-checked identical on GCC and clang. */
#define KAT_T1HA2_ANCHOR  ((uint64) UINT64_C(0x63dc293cc960a875))
static const char KAT_T1HA2_INPUT[] = "VeraCrypt fork self-test KAT vector";

/* The negative control (-DVC_SELFTEST_CORRUPT) perturbs the first expected byte of one KAT so the
   self-test MUST report a failure — proving the check is not vacuous. */
#if defined(VC_SELFTEST_CORRUPT)
#define CORRUPT_SHA3_BYTE0 (KAT_SHA3_512_EMPTY[0] ^ 0xff)
#else
#define CORRUPT_SHA3_BYTE0 (KAT_SHA3_512_EMPTY[0])
#endif

int VcForkSelfTest (void)
{
	int fail = 0;

	/* SHA3-512("") */
	{
		SHA3_CTX c;
		unsigned char md[SHA3_512_DIGESTSIZE];
		sha3_512_init (&c);
		sha3_512_update (&c, (const unsigned char *) "", 0);
		sha3_512_final (&c, md);
		if (md[0] != CORRUPT_SHA3_BYTE0 || memcmp (md + 1, KAT_SHA3_512_EMPTY + 1, sizeof (md) - 1) != 0)
			fail |= VC_SELFTEST_SHA3_512;
	}

	/* SHA-256("abc") */
	{
		unsigned char md[32];
		sha256 (md, (const unsigned char *) "abc", 3);
		if (memcmp (md, KAT_SHA256_ABC, sizeof (md)) != 0)
			fail |= VC_SELFTEST_SHA256;
	}

	/* t1ha2 anchor */
	{
		uint64 h = t1ha2_atonce (KAT_T1HA2_INPUT, sizeof (KAT_T1HA2_INPUT) - 1, 0);
		if (h != KAT_T1HA2_ANCHOR)
			fail |= VC_SELFTEST_T1HA2;
	}

	return fail;
}

#endif /* VC_ENABLE_SELFTEST */
