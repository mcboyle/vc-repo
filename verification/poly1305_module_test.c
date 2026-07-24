/*
 * poly1305_module_test.c — the SHIPPABLE Poly1305 (src/Crypto/Poly1305.c) vs the RFC 8439 KATs and the
 * proven verification-local reference (T2-4c). Step [18] proved the header-only PoC against the RFC
 * vectors + an independent python bigint; this proves the src/ module the Adiantum mode will call, by
 * LINKING the real Poly1305.o (built -DVC_ENABLE_POLY1305) — same technique as the AesCt/V2Format module
 * tests. Two ways: (1) the published RFC 8439 §2.5.2 + A.3 known-answer vectors (an authority independent
 * of the code), and (2) byte-for-byte agreement with the independent verification/poly1305.h reference
 * over many random key/length inputs.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "Crypto/Poly1305.h"            /* the real shippable object: void Poly1305(...) */
#include "poly1305.h"                   /* the proven independent reference: static void poly1305(...) */

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-54s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }
static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

static uint64_t xs = 0x243f6a8885a308d3ull;
static unsigned char rnd (void) { xs ^= xs << 13; xs ^= xs >> 7; xs ^= xs << 17; return (unsigned char) xs; }

int main (void)
{
	unsigned char tag[16];

	/* (1a) RFC 8439 §2.5.2 */
	{
		const char *m = "Cryptographic Forum Research Group";
		static const unsigned char kk[32] = {
			0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
			0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
		static const unsigned char want[16] = {
			0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9 };
		Poly1305 (tag, (const unsigned char *)m, strlen (m), kk);
		printf ("REF rfc_2.5.2 "); hex (tag, 16); printf ("\n");
		check ("shippable Poly1305: RFC 8439 §2.5.2 (a8061dc1..)", memcmp (tag, want, 16) == 0);
	}

	/* (1b) RFC 8439 A.3 #1: all-zero key, 64-byte zero message -> zero tag */
	{
		unsigned char key[32], msg[64], zero[16];
		memset (key, 0, 32); memset (msg, 0, 64); memset (zero, 0, 16);
		Poly1305 (tag, msg, 64, key);
		check ("shippable Poly1305: RFC 8439 A.3 #1 (zero key -> zero tag)", memcmp (tag, zero, 16) == 0);
	}

	/* (1c) RFC 8439 A.3 #2: r=0, s=36e5..863e -> tag == s */
	{
		const char *m =
			"Any submission to the IETF intended by the Contributor for publication "
			"as all or part of an IETF Internet-Draft or RFC and any statement made "
			"within the context of an IETF activity is considered an \"IETF "
			"Contribution\". Such statements include oral statements in IETF "
			"sessions, as well as written and electronic communications made at any "
			"time or place, which are addressed to";
		static const unsigned char ss[16] = {
			0x36,0xe5,0xf6,0xb5,0xc5,0xe0,0x60,0x70,0xf0,0xef,0xca,0x96,0x22,0x7a,0x86,0x3e };
		unsigned char key[32];
		memset (key, 0, 16); memcpy (key + 16, ss, 16);
		Poly1305 (tag, (const unsigned char *)m, strlen (m), key);
		check ("shippable Poly1305: RFC 8439 A.3 #2 (tag == s)", memcmp (tag, ss, 16) == 0);
	}

	/* (2) agreement with the independent verification/poly1305.h reference over random inputs */
	{
		int t, mism = 0;
		for (t = 0; t < 4096; t++)
		{
			unsigned char key[32], msg[300], a[16], b[16];
			size_t len = (size_t)(rnd () | ((size_t)(rnd () & 1) << 8));   /* 0..511, but cap below */
			size_t i;
			if (len > sizeof msg) len = sizeof msg;
			for (i = 0; i < 32; i++) key[i] = rnd ();
			for (i = 0; i < len; i++) msg[i] = rnd ();
			Poly1305 (a, msg, len, key);   /* real shippable object */
			poly1305 (b, msg, len, key);   /* independent reference */
			if (memcmp (a, b, 16) != 0) mism++;
		}
		printf ("REF agree_reference 4096 %d\n", mism);
		check ("shippable Poly1305 == verification reference (4096 random inputs)", mism == 0);
	}

	printf ("\n%s\n", all_pass ? "POLY1305 MODULE TESTS PASSED (real src/Crypto/Poly1305.o)" : "POLY1305 MODULE TESTS FAILED");
	return all_pass ? 0 : 1;
}
