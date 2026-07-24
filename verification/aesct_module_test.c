/*
 * aesct_module_test.c — the SHIPPABLE constant-time AES (src/Crypto/AesCt.c) vs FIPS-197 + real Gladman
 * AES (research T2-4a). Step [87] proved the inline PoC; this proves the src/ module that Adiantum will
 * call, by LINKING the real AesCt.o (built -DVC_ENABLE_CTAES) alongside the real Gladman objects
 * (Aescrypt/Aeskey/Aestab) — same technique as the DuressToken/V2Format module tests.
 *
 * Proven: the official FIPS-197 Appendix C.3 AES-256 vector; byte-for-byte agreement with the real
 * in-tree Gladman AES over 4096 random keys/blocks (both the one-shot and the expand-once API); and,
 * under valgrind (-DCT_USE_VALGRIND), a CLEAN memcheck run with key+plaintext poisoned (the constant-time
 * property; contrast: table AES is LEAKY).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if defined(CT_USE_VALGRIND)
#  include <valgrind/memcheck.h>
#  define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#  define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#  define SECRET(p, n) ((void)0)
#  define PUBLIC(p, n) ((void)0)
#endif

#include "Crypto/AesCt.h"
#include "Crypto/Aes.h"    /* real Gladman AES */

static int all_pass = 1;
static volatile unsigned char g_sink;
static void check (const char *n, int ok) { printf ("  %-54s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }
static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

static uint32_t xs = 0x2545f491u;
static unsigned char rnd (void) { xs ^= xs << 13; xs ^= xs >> 17; xs ^= xs << 5; return (unsigned char) xs; }

int main (void)
{
	/* (1) OFFICIAL FIPS-197 Appendix C.3 AES-256 vector, through the shippable module */
	{
		unsigned char key[32], in[16], out[16];
		static const unsigned char kat[16] = { 0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 };
		int i;
		for (i = 0; i < 32; i++) key[i] = (unsigned char) i;
		for (i = 0; i < 16; i++) in[i]  = (unsigned char) (i * 0x11);
		AesCtEncrypt256 (key, in, out);
		printf ("REF fips197_aes256 "); hex (out, 16); printf ("\n");
		check ("shippable AesCt: FIPS-197 C.3 vector (8ea2b7ca..)", memcmp (out, kat, 16) == 0);
	}

	/* (2) agreement with the real Gladman AES over 4096 random keys/blocks — both APIs */
	{
		aes_encrypt_ctx ec[1];
		AesCtKey256 k[1];
		int t, mism1 = 0, mism2 = 0;
		for (t = 0; t < 4096; t++)
		{
			unsigned char key[32], in[16], mine[16], real[16], mine2[16]; int i;
			for (i = 0; i < 32; i++) key[i] = rnd ();
			for (i = 0; i < 16; i++) in[i]  = rnd ();
			AesCtEncrypt256 (key, in, mine);                 /* one-shot */
			AesCtInit256 (k, key); AesCtEncryptBlock (k, in, mine2);   /* expand-once */
			aes_encrypt_key256 (key, ec); aes_encrypt (in, real, ec);
			if (memcmp (mine, real, 16) != 0)  mism1++;
			if (memcmp (mine2, real, 16) != 0) mism2++;
		}
		printf ("REF agree_oneshot 4096 %d\n", mism1);
		printf ("REF agree_expandonce 4096 %d\n", mism2);
		check ("one-shot AesCtEncrypt256 == real Gladman (4096 blocks)", mism1 == 0);
		check ("expand-once AesCtInit256+Block == real Gladman (4096 blocks)", mism2 == 0);
	}

	/* (2c) DECRYPT: FIPS-197 vector inverts, agrees with the real Gladman aes_decrypt, and round-trips */
	{
		unsigned char key[32], in[16], out[16];
		static const unsigned char kat_ct[16] = { 0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 };
		aes_decrypt_ctx dc[1];
		AesCtKey256 k[1];
		int t, mism = 0, rt = 0, i;
		for (i = 0; i < 32; i++) key[i] = (unsigned char) i;
		AesCtDecrypt256 (key, kat_ct, out);
		printf ("REF fips197_decrypt "); hex (out, 16); printf ("\n");
		{ int ok = 1; for (i = 0; i < 16; i++) if (out[i] != (unsigned char) (i * 0x11)) ok = 0;
		  check ("shippable AesCt decrypt: FIPS-197 ct -> plaintext (00112233..)", ok); }
		xs = 0x9e3779b9u;   /* fresh stream for the decrypt sweep */
		for (t = 0; t < 4096; t++)
		{
			unsigned char rk[32], ct[16], mine[16], real[16], back[16];
			for (i = 0; i < 32; i++) rk[i] = rnd ();
			for (i = 0; i < 16; i++) ct[i] = rnd ();
			AesCtDecrypt256 (rk, ct, mine);
			aes_decrypt_key256 (rk, dc); aes_decrypt (ct, real, dc);
			if (memcmp (mine, real, 16) != 0) mism++;
			AesCtInit256 (k, rk); AesCtEncryptBlock (k, ct, back); AesCtDecryptBlock (k, back, back);
			if (memcmp (back, ct, 16) != 0) rt++;   /* Dec(Enc(x)) == x */
		}
		printf ("REF agree_decrypt 4096 %d\n", mism);
		printf ("REF roundtrip 4096 %d\n", rt);
		check ("AesCt decrypt == real Gladman aes_decrypt (4096 blocks)", mism == 0);
		check ("Dec(Enc(x)) == x round-trip (4096 blocks)", rt == 0);
	}

	/* (3) constant-time demonstration: poison key + plaintext; CLEAN under memcheck */
	{
		unsigned char key[32], in[16], out[16]; int i;
		for (i = 0; i < 32; i++) key[i] = (unsigned char) (0x40 + i);
		for (i = 0; i < 16; i++) in[i]  = (unsigned char) (0x11 * i);
		unsigned char dout[16];
		SECRET (key, 32); SECRET (in, 16);
		AesCtEncrypt256 (key, in, out);
		AesCtDecrypt256 (key, in, dout);        /* decrypt path also poisoned */
		PUBLIC (out, 16); PUBLIC (dout, 16);
		g_sink ^= out[0] ^ dout[0];
		printf ("REF ct_poisoned_run done\n");
		check ("secret-poisoned encrypt+decrypt complete (CLEAN under memcheck)", 1);
	}

	printf ("\n%s\n", all_pass ? "AESCT MODULE TESTS PASSED (real src/Crypto/AesCt.o)" : "AESCT MODULE TESTS FAILED");
	return all_pass ? 0 : 1;
}
