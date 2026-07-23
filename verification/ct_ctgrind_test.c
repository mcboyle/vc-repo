/*
 * ct_ctgrind_test.c — ctgrind-style constant-time check for the project's masked secret-dependent
 * primitives, using valgrind/memcheck (research batch-3 R17 scaffold).
 *
 * dudect (steps [41]/[.. ]/[82]) is a black-box *timing* screen; it cannot see WHICH instruction leaks,
 * and it measures in a shared VM. This is the complementary white-box check R17 Q1/Q3 ask about: mark the
 * SECRET operands as "undefined" (VALGRIND_MAKE_MEM_UNDEFINED) and run the primitive under memcheck. If
 * the compiled code branches on, or indexes memory with, any secret-derived bit, memcheck reports
 * "Conditional jump or move depends on uninitialised value" / "use of uninitialised value" — so a CLEAN
 * run is direct evidence that the arithmetic masking survived the compiler with no secret-dependent
 * control flow (the exact failure mode — cmov-not-guaranteed, -O2/-O3 divergence, LTO — R17 raises).
 *
 * This binary is SELF-VALIDATING like the dudect screens: it runs the check on (a) the REAL masked
 * primitives and (b) a deliberately branchy leaky copy. Under valgrind the harness asserts memcheck
 * FLAGS the leaky one and CLEARS the real ones; the driver (ct_ctgrind_check.sh) greps valgrind's error
 * count. Built WITHOUT valgrind it still runs (the client requests are no-ops) and just self-checks
 * functional agreement.
 *
 * Subjects, selected by argv[1]:
 *   (none)  — REAL masked primitives + KeyslotConstTimeEqual (A2): must be CLEAN (0 errors).
 *   "leaky" — deliberately-branchy copies incl. an early-out compare: must be FLAGGED (>0).
 *   "aes"   — table AES (A1): poison the key and (separately) the plaintext, run the REAL
 *             Aescrypt/Aeskey/Aestab. A POSITIVE result is the EXPECTED FINDING — table AES indexes
 *             memory with key/plaintext-derived data by construction (Bernstein 2005; Osvik-Shamir-
 *             Tromer 2006), so ctgrind is supposed to flag it. Converts "presumably leaky" into
 *             measured + localized. The driver records the count and which functions leaked; it does
 *             NOT treat this as a failure of the masked primitives.
 *
 * Includes the REAL static primitives from their shipping/PoC sources — Shamir.c (gf_mul/gf_inv) and
 * hctr2_poc.c (gf_dot, via HCTR2_NO_MAIN) — the same include technique the dudect harnesses use
 * (hctr2_dudect_test.c), so the check tracks the real gf_dot and cannot silently validate a stale copy.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if defined(CT_USE_VALGRIND)
#  include <valgrind/memcheck.h>
#  define SECRET(p, n)  VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#  define PUBLIC(p, n)  VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#  define SECRET(p, n)  ((void)0)
#  define PUBLIC(p, n)  ((void)0)
#endif

#include "Shamir.c"   /* real static gf_mul / gf_inv (branchless, masked) */

#define HCTR2_NO_MAIN
#include "hctr2_poc.c"   /* real static gf_dot (+ u256) — same technique as hctr2_dudect_test.c; needs
                            the AES objects linked (Aescrypt/Aeskey/Aestab.o — see ct_ctgrind_check.sh) */

/* ---- deliberately-branchy leaky copies (secret-dependent control flow); u256 comes from hctr2_poc.c ---- */
static unsigned char gf_mul_leaky (unsigned char a, unsigned char b) {
	unsigned char p = 0;
	while (b) { if (b & 1) p ^= a;                       /* branch on secret b */
		{ unsigned hi = a & 0x80; a = (unsigned char)((a << 1) & 0xff); if (hi) a ^= 0x1b; }
		b = (unsigned char)(b >> 1); }
	return p;
}
static void gf_dot_leaky (const uint64_t a[2], const uint64_t b[2], uint64_t out[2]) {
	u256 c; int i, limb; memset (&c, 0, sizeof c);
	for (i = 0; i < 128; i++) {
		if ((a[i >> 6] >> (i & 63)) & 1) {               /* branch on secret a */
			int w = i >> 6, s = i & 63;
			c.w[w]     ^= b[0] << s;
			c.w[w + 1] ^= (s ? (b[0] >> (64 - s)) : 0) ^ (b[1] << s);
			c.w[w + 2] ^= s ? (b[1] >> (64 - s)) : 0;
		}
	}
	for (i = 0; i < 128; i++) {
		if (c.w[0] & 1) { c.w[0] ^= 1ULL; c.w[1] ^= (1ULL<<57)|(1ULL<<62)|(1ULL<<63); c.w[2] ^= 1ULL; }
		for (limb = 0; limb < 3; limb++) c.w[limb] = (c.w[limb] >> 1) | (c.w[limb + 1] << 63);
		c.w[3] >>= 1;
	}
	out[0] = c.w[0]; out[1] = c.w[1];
}

/* A2 — the real keyslot constant-time compare (linked from src/Common/Keyslot.c, same as
   keyslot_dudect_test.c) and a deliberately-branchy leaky control (early-out memcmp: branches on the
   first differing secret byte). */
extern int KeyslotConstTimeEqual (const unsigned char *a, const unsigned char *b, int len);
static int ct_eq_leaky (const unsigned char *a, const unsigned char *b, int len) {
	int i; for (i = 0; i < len; i++) { if (a[i] != b[i]) return 0; }   /* branch on secret byte */
	return 1;
}

/* A1 — the AES subject uses the real Aescrypt/Aeskey/Aestab via Crypto/Aes.h (pulled in by
   hctr2_poc.c above; included explicitly for clarity). */
#include "Crypto/Aes.h"

/* volatile sinks so the compiler cannot elide the primitive under test */
static volatile unsigned char g_sink8;
static volatile uint64_t      g_sink64;

/* --- A1: table-AES subject. Poison the KEY (key schedule + round tables index on key-derived data)
   and, separately, the PLAINTEXT (round tables index on plaintext^roundkey), through the REAL
   Aescrypt/Aeskey/Aestab. A POSITIVE (nonzero) memcheck result is the EXPECTED finding — table AES is
   cache-timing-leaky by construction; this converts "presumably leaky" into measured+localized. --- */
static void aes_subject (void)
{
	unsigned char key[32], in[16], out[16];
	aes_encrypt_ctx ec[1];
	aes_decrypt_ctx dc[1];
	int t;
	memset (key, 0x40, sizeof key); memset (in, 0x11, sizeof in);

	/* (1) secret KEY -> key schedule (Aeskey.c) + encrypt round function (Aescrypt.c) index tables */
	for (t = 0; t < 4; t++) {
		SECRET (key, sizeof key);
		aes_encrypt_key256 (key, ec);
		aes_encrypt (in, out, ec);
		PUBLIC (out, sizeof out); g_sink8 ^= out[0];
		aes_decrypt_key256 (key, dc);
		aes_decrypt (in, out, dc);
		PUBLIC (out, sizeof out); g_sink8 ^= out[0];
		PUBLIC (key, sizeof key);
	}
	/* (2) public key, secret PLAINTEXT -> encrypt round tables index on plaintext-derived data */
	memset (key, 0x40, sizeof key);
	aes_encrypt_key256 (key, ec);
	for (t = 0; t < 4; t++) {
		SECRET (in, sizeof in);
		aes_encrypt (in, out, ec);
		PUBLIC (out, sizeof out); g_sink8 ^= out[0];
		PUBLIC (in, sizeof in);
	}
}

int main (int argc, char **argv)
{
	int leaky = (argc > 1 && strcmp (argv[1], "leaky") == 0);
	int aes   = (argc > 1 && strcmp (argv[1], "aes")   == 0);

	if (aes) {                                     /* A1: separate subject; nonzero is the finding */
		aes_subject ();
		printf ("AES (table) exercised under memcheck poisoning\n");
		return 0;
	}

	/* functional agreement first (so the ONLY difference the ct check sees is control flow) */
	{
		int a, b, mism = 0;
		for (a = 0; a < 256; a++) for (b = 0; b < 256; b++)
			if (gf_mul ((unsigned char)a, (unsigned char)b) != gf_mul_leaky ((unsigned char)a, (unsigned char)b)) mism++;
		printf ("gf_mul vs leaky agree on 65536 products = %s\n", mism ? "NO" : "YES");
	}

	/* --- gf_mul / gf_inv over GF(2^8): poison the secret operand, exercise every value --- */
	{
		int i; unsigned char x, y;
		for (i = 0; i < 256; i++) {
			x = (unsigned char) i; y = (unsigned char)(i * 7 + 1);
			SECRET (&x, 1); SECRET (&y, 1);
			g_sink8 = leaky ? gf_mul_leaky (x, y) : gf_mul (x, y);
			g_sink8 = gf_inv (x);              /* gf_inv is fixed-schedule; always the real one */
			PUBLIC (&x, 1); PUBLIC (&y, 1);
		}
	}

	/* --- gf_dot over GF(2^128): poison both 128-bit operands --- */
	{
		uint64_t a[2], b[2], o[2]; int t;
		for (t = 0; t < 64; t++) {
			a[0] = (uint64_t)(t*2654435761u); a[1] = (uint64_t)(t*40503u+7);
			b[0] = (uint64_t)(t*2246822519u); b[1] = (uint64_t)(t*3266489917u+11);
			SECRET (a, sizeof a); SECRET (b, sizeof b);
			if (leaky) gf_dot_leaky (a, b, o); else gf_dot (a, b, o);
			PUBLIC (o, sizeof o);           /* de-poison the output so the sink read is clean */
			g_sink64 ^= o[0] ^ o[1];
		}
	}

	/* --- A2: KeyslotConstTimeEqual (OR-accumulate, data-oblivious) vs a leaky early-out compare.
	   Poison both buffers; the real compare must stay clean, the leaky one must be flagged. --- */
	{
		unsigned char a[32], b[32]; int i, r = 0;
		for (i = 0; i < 32; i++) { a[i] = (unsigned char)(i * 3 + 1); b[i] = (unsigned char)(i * 3 + 1); }
		/* differ in the LAST byte: this is the worst case for TIMING (a dudect early-out leaks most
		   here). Under taint-tracking the leaky compare branches on secret data at i=0 regardless of
		   where the difference sits — the last-byte choice just maximizes the leaky error count. */
		b[31] ^= 0x01;
		SECRET (a, sizeof a); SECRET (b, sizeof b);
		r = leaky ? ct_eq_leaky (a, b, 32) : KeyslotConstTimeEqual (a, b, 32);
		PUBLIC (a, sizeof a); PUBLIC (b, sizeof b);
		g_sink8 ^= (unsigned char) r;
	}

	printf ("%s primitives exercised under memcheck poisoning\n", leaky ? "LEAKY" : "REAL");
	return 0;
}
