/*
 * ascon_poc.c — Ascon-Hash256 (docs/HASHES-SPEC.md, IDEAS-BACKLOG.md "Hashes"
 * row). Ascon (Dobraunig, Eichlseder, Mendel, Schläffer) is the NIST Lightweight
 * Cryptography winner, standardized in NIST SP 800-232 (2025). Ascon-Hash256:
 * 320-bit state (5 x 64-bit little-endian words), 12-round permutation, rate 8.
 * A compact hash for constrained/embedded targets in scope.
 *
 * NOT in the VeraCrypt tree, so (like Poly1305/BLAKE3) the proof is the official
 * authority + cross-implementation: the NIST ACVP SP 800-232 vectors
 * (ascon_kats.h) and byte-identical REF output against ascon_reference.py.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ascon_kats.h"

static uint64_t ror64 (uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void ascon_perm (uint64_t S[5], int rounds)
{
	int r, i;
	for (r = 12 - rounds; r < 12; r++) {
		uint64_t T[5];
		S[2] ^= (uint64_t)(0xf0 - r * 0x10 + r);          /* round constant */
		S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1];         /* substitution (chi) */
		for (i = 0; i < 5; i++) T[i] = (~S[i]) & S[(i + 1) % 5];
		for (i = 0; i < 5; i++) S[i] ^= T[(i + 1) % 5];
		S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= ~(uint64_t)0;
		S[0] ^= ror64 (S[0], 19) ^ ror64 (S[0], 28);      /* linear diffusion */
		S[1] ^= ror64 (S[1], 61) ^ ror64 (S[1], 39);
		S[2] ^= ror64 (S[2], 1)  ^ ror64 (S[2], 6);
		S[3] ^= ror64 (S[3], 10) ^ ror64 (S[3], 17);
		S[4] ^= ror64 (S[4], 7)  ^ ror64 (S[4], 41);
	}
}

static uint64_t ld64_le (const unsigned char *p)
{
	uint64_t x = 0; int i;
	for (i = 0; i < 8; i++) x |= (uint64_t) p[i] << (8 * i);
	return x;
}
static void st64_le (uint64_t x, unsigned char *p)
{ int i; for (i = 0; i < 8; i++) p[i] = (unsigned char)(x >> (8 * i)); }

static void ascon_hash256 (const unsigned char *msg, size_t len, unsigned char out[32])
{
	/* IV per SP 800-232: [2,0,0xCC] || taglen(256, 2 bytes LE) || [8,0,0] */
	static const unsigned char iv[8] = { 2, 0, 0xCC, 0x00, 0x01, 8, 0, 0 };
	uint64_t S[5] = { ld64_le (iv), 0, 0, 0, 0 };
	unsigned char blk[8];
	size_t i, full = len - (len % 8);
	ascon_perm (S, 12);
	/* absorb full 8-byte blocks */
	for (i = 0; i < full; i += 8) { S[0] ^= ld64_le (msg + i); ascon_perm (S, 12); }
	/* final partial block with 0x01 padding then zeros */
	memset (blk, 0, 8);
	memcpy (blk, msg + full, len - full);
	blk[len - full] = 0x01;
	S[0] ^= ld64_le (blk); ascon_perm (S, 12);
	/* squeeze 32 bytes (rate 8) */
	for (i = 0; i < 32; i += 8) { st64_le (S[0], out + i); ascon_perm (S, 12); }
}

static int hexval (char c)
{ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c - 'A' + 10; }
static size_t unhex (const char *s, unsigned char *out)
{ size_t n = strlen (s) / 2, i; for (i = 0; i < n; i++) out[i] = (unsigned char)((hexval (s[2*i]) << 4) | hexval (s[2*i+1])); return n; }
static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

static unsigned char msgbuf[16384];

int main (void)
{
	unsigned char md[32], expect[32];
	int i, all = 1;
	for (i = 0; i < ASCON_NKATS; i++) {
		size_t n = unhex (ascon_kats[i][0], msgbuf);
		ascon_hash256 (msgbuf, n, md);
		printf ("REF md_%d ", i); hex (md, 32); printf ("\n");
		unhex (ascon_kats[i][1], expect);
		if (memcmp (md, expect, 32) != 0) all = 0;
	}
	printf ("REF all_match %s\n", all ? "YES" : "NO");
	return all ? 0 : 1;
}
