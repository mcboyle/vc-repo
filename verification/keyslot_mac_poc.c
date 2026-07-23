/*
 * keyslot_mac_poc.c — authenticate the keyslot area with a ChaCha20-Poly1305
 * one-time MAC (docs/KEYSLOT-MAC-SPEC.md; IDEAS-BACKLOG.md P0.5 / item 5).
 *
 * XTS gives no integrity, so a tampered or truncated keyslot table is used
 * silently at mount. This binds the whole area under a key derived from the
 * master key: any modification, truncation, or slot-count change is caught by a
 * constant-time tag check BEFORE any unwrap is attempted.
 *
 * Construction is RFC 8439's MAC half (the first consumer of Poly1305, step 18):
 *     one_time_key = ChaCha20(mac_key, nonce, counter=0)[0..32]   # per-write nonce
 *     tag          = Poly1305(one_time_key, area_bytes)
 * A fresh nonce per write keeps Poly1305's one-time-key discipline (reusing an
 * (r,s) pair across two areas would leak r). The nonce is stored in the clear
 * beside the tag; mac_key never touches disk.
 *
 * Proven the two ways this fork requires:
 *   - drives the REAL in-tree Crypto/chacha256.c for the keystream (block-0 equals
 *     the published ChaCha20 zero-key KAT 76b8e0ad...) and the step-18 Poly1305;
 *   - keyslot_mac_reference.py is independent (pure-python ChaCha20 + bigint
 *     Poly1305) and reproduces every tag byte-for-byte.
 * There is no on-disk format change: this is a MAC over the existing area.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/chacha256.h"
#include "poly1305.h"

/* Derive the 32-byte one-time Poly1305 key: first 32 bytes of the ChaCha20
   keystream under (mac_key, 8-byte nonce), 20 rounds, counter 0. */
static void otk_from_chacha (const unsigned char mac_key[32], const unsigned char nonce[8],
                             unsigned char otk[32])
{
	ChaCha256Ctx c; unsigned char zero[32];
	memset (zero, 0, sizeof zero);
	ChaCha256Init (&c, mac_key, nonce, 20);
	ChaCha256Encrypt (&c, zero, 32, otk);   /* keystream ^ 0 = keystream */
}

/* keyslot-area MAC: 16-byte tag over area[0..len) bound to (mac_key, nonce). */
static void keyslot_area_mac (const unsigned char mac_key[32], const unsigned char nonce[8],
                              const unsigned char *area, size_t len, unsigned char tag[16])
{
	unsigned char otk[32];
	otk_from_chacha (mac_key, nonce, otk);
	poly1305 (tag, area, len, otk);
	memset (otk, 0, sizeof otk);   /* one-time key is single-use */
}

/* constant-time 16-byte compare (verifier side) */
static int ct_eq16 (const unsigned char *a, const unsigned char *b)
{
	unsigned char d = 0; int i;
	for (i = 0; i < 16; i++) d |= (unsigned char) (a[i] ^ b[i]);
	return d == 0;
}

static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

/* a plausible serialized keyslot area: 4 slots x 96 bytes (selector||wrapped VMK||mac) */
#define NSLOT   4
#define SLOTSZ  96
#define AREASZ  (NSLOT * SLOTSZ)

int main (void)
{
	unsigned char mac_key[32], nonce[8], area[AREASZ], tag[16];
	int i;

	for (i = 0; i < 32; i++) mac_key[i] = (unsigned char) (0xA0 + i);
	for (i = 0; i < 8;  i++) nonce[i]   = (unsigned char) (i * 9 + 1);
	for (i = 0; i < AREASZ; i++) area[i] = (unsigned char) ((i * 31 + 7) & 0xff);

	/* published sanity: ChaCha20 block-0 for the zero key equals the known KAT */
	{
		unsigned char zk[32] = {0}, zn[8] = {0}, blk[32];
		otk_from_chacha (zk, zn, blk);
		printf ("REF chacha_zero_kat "); hex (blk, 32); printf ("\n");
	}

	keyslot_area_mac (mac_key, nonce, area, AREASZ, tag);
	printf ("REF mac "); hex (tag, 16); printf ("\n");

	/* verifier accepts the untampered area */
	{
		unsigned char v[16]; keyslot_area_mac (mac_key, nonce, area, AREASZ, v);
		printf ("REF accept_valid %s\n", ct_eq16 (v, tag) ? "YES" : "NO");
	}

	/* tamper: flip one bit anywhere in the area -> tag differs, verifier rejects */
	{
		unsigned char t[AREASZ], v[16];
		memcpy (t, area, AREASZ); t[123] ^= 0x08;
		keyslot_area_mac (mac_key, nonce, t, AREASZ, v);
		printf ("REF tamper_mac "); hex (v, 16); printf ("\n");
		printf ("REF reject_tamper %s\n", !ct_eq16 (v, tag) ? "YES" : "NO");
	}

	/* truncation: drop the last slot -> different tag, verifier rejects */
	{
		unsigned char v[16];
		keyslot_area_mac (mac_key, nonce, area, AREASZ - SLOTSZ, v);
		printf ("REF trunc_mac "); hex (v, 16); printf ("\n");
		printf ("REF reject_trunc %s\n", !ct_eq16 (v, tag) ? "YES" : "NO");
	}

	/* wrong MAC key -> different tag (key genuinely binds) */
	{
		unsigned char wk[32], v[16];
		memcpy (wk, mac_key, 32); wk[0] ^= 0x01;
		keyslot_area_mac (wk, nonce, area, AREASZ, v);
		printf ("REF reject_wrongkey %s\n", !ct_eq16 (v, tag) ? "YES" : "NO");
	}

	/* different nonce -> different tag (fresh (r,s) per write; no reuse) */
	{
		unsigned char nn[8], v[16];
		memcpy (nn, nonce, 8); nn[7] ^= 0x01;
		keyslot_area_mac (mac_key, nn, area, AREASZ, v);
		printf ("REF nonce_binds %s\n", !ct_eq16 (v, tag) ? "YES" : "NO");
	}

	return 0;
}
