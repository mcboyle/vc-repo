/*
 * v2format_module_test.c — SHIPPING v2-format module (src/Common/V2Format.c) vs independent python.
 *
 * The step-[84] PoC proved the v2 format LOGIC (mode discrimination w/ nothing stored + full-volume
 * MAC-table indistinguishability) with keyed-BLAKE3 as a PRF-agnostic reference. This step proves the
 * SHIPPING module — which instantiates the same logic on HMAC-SHA256 over the REAL in-tree Crypto/Sha2.c
 * (no new crypto dependency) — byte-for-byte against an independent python HMAC-SHA256
 * (v2format_module_reference.py). Links the real Sha2 object exactly like the DuressToken step [7].
 *
 * Covers: per-mode domain-separated MAC keys, the per-sector tag over ciphertext, mount-time MODE
 * DISCOVERY that stores nothing (correct mode found; wrong master key -> NONE; a legacy tag -> NONE ->
 * v1 fallthrough), constant-time verify, and the MAC-table layout math (slot width + tail split).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "Common/V2Format.h"

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-52s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }
static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

#define SECTOR 64

int main (void)
{
	unsigned char master[32], master2[32];
	unsigned char ct0[SECTOR];
	unsigned char kmac_h[V2_KEY_LEN], kmac_a[V2_KEY_LEN], tag0[V2_MAC_TAG_LEN];
	int i;

	for (i = 0; i < 32; i++) master[i]  = (unsigned char) ((0x40 + i) & 0xff);
	memcpy (master2, master, 32); master2[0] ^= 0x01;                 /* wrong master key */
	for (i = 0; i < SECTOR; i++) ct0[i] = (unsigned char) ((i * 7 + 3) & 0xff);

	V2FormatDeriveModeKey (master, 32, V2_MODE_HCTR2,    kmac_h);
	V2FormatDeriveModeKey (master, 32, V2_MODE_ADIANTUM, kmac_a);
	V2FormatSectorTag (kmac_h, 0, ct0, SECTOR, tag0);                 /* sector 0 written under hctr2 */

	printf ("REF kmac_hctr2 ");    hex (kmac_h, V2_KEY_LEN); printf ("\n");
	printf ("REF kmac_adiantum "); hex (kmac_a, V2_KEY_LEN); printf ("\n");
	printf ("REF tag0 ");          hex (tag0, V2_MAC_TAG_LEN); printf ("\n");

	{
		V2Mode m_ok    = V2FormatDiscoverMode (master,  32, ct0, SECTOR, tag0);
		V2Mode m_wrong = V2FormatDiscoverMode (master2, 32, ct0, SECTOR, tag0);
		unsigned char legacy[V2_MAC_TAG_LEN];
		V2Mode m_v1;
		memset (legacy, 0xAA, sizeof legacy);                         /* a non-tag (legacy v1) slot */
		m_v1 = V2FormatDiscoverMode (master, 32, ct0, SECTOR, legacy);

		printf ("REF discover_hctr2 %d\n",    (int) m_ok);
		printf ("REF discover_wrongkey %d\n", (int) m_wrong);
		printf ("REF discover_v1 %d\n",       (int) m_v1);
		check ("mode discovered = HCTR2 (nothing stored)",        m_ok    == V2_MODE_HCTR2);
		check ("wrong master key discovers no mode (-> v1)",      m_wrong == V2_MODE_NONE);
		check ("legacy/non-tag slot discovers no mode (-> v1)",   m_v1    == V2_MODE_NONE);
	}
	{
		unsigned char bad[V2_MAC_TAG_LEN];
		memcpy (bad, tag0, V2_MAC_TAG_LEN); bad[0] ^= 0x01;
		check ("verify accepts the real tag",  V2FormatSectorVerify (kmac_h, 0, ct0, SECTOR, tag0));
		check ("verify rejects a flipped tag", !V2FormatSectorVerify (kmac_h, 0, ct0, SECTOR, bad));
		check ("tag under adiantum key differs (anti-downgrade binding)",
		       !V2FormatSectorVerify (kmac_a, 0, ct0, SECTOR, tag0));
	}

	/* MAC-table layout math */
	{
		uint64_t tb = V2FormatMacTableBytes (1000, 512);
		uint64_t usable = 0, off = 0;
		int rc = V2FormatSplitDataArea ((uint64_t) 1000 * 512, 512, &usable, &off);
		uint64_t slot5 = V2FormatSlotOffset (5);
		printf ("REF mactable_1000_512 %llu\n", (unsigned long long) tb);
		printf ("REF split_512000_512 %llu %llu\n", (unsigned long long) usable, (unsigned long long) off);
		printf ("REF slot_5 %llu\n", (unsigned long long) slot5);
		check ("MAC table = ceil(1000*16/512)*512 = 16384", tb == 16384);
		check ("split ok + usable+table fits total", rc == 0
		       && usable + V2FormatMacTableBytes (usable / 512, 512) <= (uint64_t) 1000 * 512
		       && off == usable);
		check ("slot offset(5) = 80", slot5 == 80);
		/* a too-small volume is rejected for v2 */
		check ("volume too small for a table is rejected",
		       V2FormatSplitDataArea (512, 512, &usable, &off) != 0);
	}

	printf ("\n%s\n", all_pass ? "V2 FORMAT MODULE TESTS PASSED (real Sha2 HMAC-SHA256)" : "V2 FORMAT MODULE TESTS FAILED");
	return all_pass ? 0 : 1;
}
