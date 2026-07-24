/*
 * codex32_test.c — the REAL Common/ShareCode.c codex32 (BIP-93) encoder/decoder driven end-to-end
 * (build_and_verify.sh step [92]; docs/VSS-SPEC.md, decision D-2 "codex32 default export encoding").
 *
 * Two-way per the project convention: this drives the real compiled ShareCode.c, emitting REF lines
 * (encoded codex32 strings) that codex32_reference.py recomputes independently (a from-the-spec ms32
 * checksum + 5<->8 packing). PASS/FAIL checks additionally anchor to the OFFICIAL BIP-93 published test
 * vectors — decode of the 128-bit "test" secret (regular 13-symbol checksum) and the 512-bit "0C8V"
 * secret (long 15-symbol checksum) recovers their exact published master seeds — and exercise
 * round-trip and single-character error detection (the ms32 checksum's job).
 */
#include <stdio.h>
#include <string.h>
#include "Common/ShareCode.h"

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-56s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }

static int hexparse (const char *s, unsigned char *o)
{ int n = 0; while (s[0] && s[1]) { unsigned int b; char t[3] = { s[0], s[1], 0 }; sscanf (t, "%2x", &b); o[n++] = (unsigned char) b; s += 2; } return n; }

/* official BIP-93 test vectors */
static const char *TV1 = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw";
static const char *TV1_SEED = "318c6318c6318c6318c6318c6318c631";
static const char *TV5 =
	"MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8"
	"WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK";
static const char *TV5_SEED =
	"dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104"
	"c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9";

int main (void)
{
	unsigned char seed[128], pay[128];
	int sl, rc, k, pl;
	char id[4], idx, out[SHARECODE_CODEX32_MAX_LEN];

	/* ---- REF: deterministic encodings (python recomputes byte-for-byte) ---- */
	{
		int i;
		unsigned char a[16], b[32], c[64];
		for (i = 0; i < 16; i++) a[i] = (unsigned char) i;
		for (i = 0; i < 32; i++) b[i] = (unsigned char) (0x40 + i);
		for (i = 0; i < 64; i++) c[i] = (unsigned char) (i * 7 + 3);
		ShareCodeCodex32Encode (0, "test", 's', a, 16, out, sizeof out); printf ("REF codex32 k=0 id=test idx=s = %s\n", out);
		ShareCodeCodex32Encode (3, "clv3", 'c', b, 32, out, sizeof out); printf ("REF codex32 k=3 id=clv3 idx=c = %s\n", out);
		ShareCodeCodex32Encode (5, "0c8v", 's', c, 64, out, sizeof out); printf ("REF codex32 k=5 id=0c8v idx=s = %s\n", out);
	}

	printf ("[checks]\n");

	/* ---- OFFICIAL BIP-93 vector 1 (regular checksum): decode recovers the 128-bit seed ---- */
	sl = hexparse (TV1_SEED, seed);
	rc = ShareCodeCodex32Decode (TV1, &k, id, &idx, pay, sizeof pay, &pl);
	check ("BIP-93 TV1 decode ok", rc == SHARECODE_OK);
	check ("BIP-93 TV1 (k,id,index) == (0,test,s)", k == 0 && memcmp (id, "test", 4) == 0 && idx == 's');
	check ("BIP-93 TV1 recovers the published 128-bit seed", pl == sl && memcmp (pay, seed, (size_t) sl) == 0);

	/* ---- OFFICIAL BIP-93 vector 5 (long checksum): decode recovers the 512-bit seed ---- */
	sl = hexparse (TV5_SEED, seed);
	rc = ShareCodeCodex32Decode (TV5, &k, id, &idx, pay, sizeof pay, &pl);
	check ("BIP-93 TV5 (long checksum) decode ok", rc == SHARECODE_OK);
	check ("BIP-93 TV5 (k,id,index) == (0,0c8v,s)", k == 0 && memcmp (id, "0c8v", 4) == 0 && idx == 's');
	check ("BIP-93 TV5 recovers the published 512-bit seed", pl == sl && memcmp (pay, seed, (size_t) sl) == 0);

	/* ---- round-trip an arbitrary payload through the real encoder+decoder ---- */
	{
		int k2, pl2, i, okv; char id2[4], idx2; unsigned char pay2[128], src[40];
		for (i = 0; i < 40; i++) src[i] = (unsigned char) (0x11 * i + 5);
		rc = ShareCodeCodex32Encode (4, "clu2", 'a', src, 40, out, sizeof out);
		okv = (rc == SHARECODE_OK)
		    && ShareCodeCodex32Decode (out, &k2, id2, &idx2, pay2, sizeof pay2, &pl2) == SHARECODE_OK
		    && k2 == 4 && memcmp (id2, "clu2", 4) == 0 && idx2 == 'a'
		    && pl2 == 40 && memcmp (pay2, src, 40) == 0;
		check ("round-trip encode->decode recovers payload/k/id/index", okv);
	}

	/* ---- single-character error detection on the official TV1 ---- */
	{
		char buf[80]; int pos, clen, missed = 0, tested = 0;
		strcpy (buf, TV1);
		clen = (int) strlen (buf);
		for (pos = 3; pos < clen; pos++)   /* mutate every data+checksum char (after "ms1") */
		{
			static const char *CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
			char orig = buf[pos]; int c;
			for (c = 0; c < 32; c++)
			{
				int k3, pl3; char id3[4], idx3; unsigned char p3[128];
				if (CS[c] == orig) continue;
				buf[pos] = CS[c]; tested++;
				if (ShareCodeCodex32Decode (buf, &k3, id3, &idx3, p3, sizeof p3, &pl3) == SHARECODE_OK) missed++;
			}
			buf[pos] = orig;
		}
		printf ("  single-char substitutions tested = %d, undetected = %d\n", tested, missed);
		check ("all single-char typos in TV1 detected", missed == 0);
	}

	printf ("%s\n", all_pass ? "ALL CODEX32 CHECKS PASSED" : "CODEX32 CHECKS FAILED");
	return all_pass ? 0 : 1;
}
