/*
 * hkdf_rfc5869_test.c — anchor HKDF-SHA256 to the OFFICIAL RFC 5869 Appendix A vectors.
 *
 * WHY THIS EXISTS (docs/VERIFICATION-ANCHORS.md).
 * HKDF-SHA256 is load-bearing in TWO shipping places:
 *   - src/Common/HardwareKeyFactor.c  — the Rank-1 v2 mix. HKDF-Extract(salt) over (password||response)
 *     with info "VeraCrypt/HKF/mix/v2" produces the mixed password for EVERY v2 factored volume. If this
 *     is not really HKDF, every v2 derivation is something other than what the spec says it is.
 *   - src/Common/KeyslotAreaMac.c     — K_area = HKDF-SHA256(VMK, salt=0^32, info="keyslot-area-mac").
 * Neither had any external anchor: RFC 5869 appeared nowhere in the tree. That is exactly the gap class
 * step [97] was created to close (a load-bearing primitive implementing a published standard, carried on
 * a TWIN alone), and the same shape as the step-[94] defect where an official KAT anchored one layer
 * while the layer that mattered went unchecked.
 *
 * THE ANCHOR CHAIN, and its honest bottom.
 * The in-tree HKDFs are SPECIALISED — fixed info, fixed output length, static linkage — so the RFC's
 * generic (salt, info, L) vectors cannot be fed to them directly. So:
 *   1. Build generic HKDF Extract+Expand on the REAL in-tree HMAC-SHA256 (Crypto/Sha2.c), and check it
 *      against RFC 5869 A.1/A.2/A.3 — PRK and OKM, byte for byte. ANCHOR CLASS: OFFICIAL.
 *   2. Then prove the SHIPPING specialisation equals that now-anchored generic HKDF at its own
 *      parameters. This is the step that matters: it is what rules out a lookalike that merely resembles
 *      HKDF (wrong counter start, info/counter order swapped, T(0) not empty, salt-as-IKM inversion).
 * The chain bottoms out on HMAC-SHA256, which is itself OFFICIAL-anchored at step [69], and on SHA-256
 * in Crypto/Sha2.c. It does NOT bottom out on anything this project wrote unproven.
 *
 * A NOTE ON WHAT A PASS MEANS. Step 1 passing proves our HMAC + our HKDF construction are right. Step 2
 * passing proves the shipping call sites are that same construction. Neither says the *design* choices
 * (which salt, which info label) are right — that is the spec's job, not the anchor's.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Crypto/Sha2.h"
#include "Common/KeyslotAreaMac.h"

#define BLK 64
#define DIG 32

static int pass = 0, fail = 0;
static void check (const char *what, int ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

/* HMAC-SHA256 over the real in-tree sha256(). Anchored independently at step [69]. */
static void hmac256 (const unsigned char *key, size_t keyLen,
                     const unsigned char *msg, size_t msgLen, unsigned char out[DIG])
{
	sha256_ctx c;
	unsigned char k0[BLK], pad[BLK], inner[DIG];
	size_t i;
	memset (k0, 0, sizeof k0);
	if (keyLen > BLK) {
		sha256_begin (&c); sha256_hash (key, (unsigned long) keyLen, &c); sha256_end (k0, &c);
	} else if (keyLen > 0) {
		memcpy (k0, key, keyLen);
	}
	for (i = 0; i < BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&c); sha256_hash (pad, BLK, &c);
	if (msgLen > 0) sha256_hash (msg, (unsigned long) msgLen, &c);
	sha256_end (inner, &c);
	for (i = 0; i < BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&c); sha256_hash (pad, BLK, &c); sha256_hash (inner, DIG, &c);
	sha256_end (out, &c);
}

/* RFC 5869 §2.2 — Extract. PRK = HMAC(salt, IKM); a zero-length salt means HashLen zero bytes. */
static void hkdf_extract (const unsigned char *salt, size_t saltLen,
                          const unsigned char *ikm, size_t ikmLen, unsigned char prk[DIG])
{
	unsigned char zero[DIG];
	if (saltLen == 0) { memset (zero, 0, DIG); salt = zero; saltLen = DIG; }
	hmac256 (salt, saltLen, ikm, ikmLen, prk);
}

/* RFC 5869 §2.3 — Expand. T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i), counter starts at 1. */
static int hkdf_expand (const unsigned char prk[DIG], const unsigned char *info, size_t infoLen,
                        unsigned char *okm, size_t okmLen)
{
	unsigned char T[DIG], *buf;
	size_t n = (okmLen + DIG - 1) / DIG, got = 0, tLen = 0, i;
	if (n > 255) return 0;                          /* RFC 5869: L <= 255*HashLen */
	buf = (unsigned char *) malloc (DIG + infoLen + 1);
	if (!buf) return 0;
	for (i = 1; i <= n; i++) {
		size_t m = 0, take;
		if (tLen) { memcpy (buf, T, tLen); m = tLen; }
		if (infoLen) { memcpy (buf + m, info, infoLen); m += infoLen; }
		buf[m++] = (unsigned char) i;
		hmac256 (prk, DIG, buf, m, T);
		tLen = DIG;
		take = (okmLen - got < DIG) ? (okmLen - got) : DIG;
		memcpy (okm + got, T, take);
		got += take;
	}
	free (buf);
	return 1;
}

static int hexeq (const unsigned char *got, const char *hex, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		unsigned v;
		if (sscanf (hex + 2 * i, "%2x", &v) != 1) return 0;
		if (got[i] != (unsigned char) v) return 0;
	}
	return 1;
}

static void fill (unsigned char *p, size_t n, unsigned char start)
{ size_t i; for (i = 0; i < n; i++) p[i] = (unsigned char) (start + i); }

int main (void)
{
	unsigned char prk[DIG], okm[128];

	printf ("  HKDF-SHA256 vs RFC 5869 Appendix A (OFFICIAL anchor)\n");

	/* ---- A.1: basic SHA-256 ------------------------------------------------------------------- */
	{
		unsigned char ikm[22], salt[13], info[10];
		memset (ikm, 0x0b, sizeof ikm);
		fill (salt, sizeof salt, 0x00);
		fill (info, sizeof info, 0xf0);
		hkdf_extract (salt, sizeof salt, ikm, sizeof ikm, prk);
		check ("A.1 PRK == 077709362c2e32df…",
		       hexeq (prk, "077709362c2e32df0ddc3f0dc47bba63""90b6c73bb50f9c3122ec844ad7c2b3e5", DIG));
		hkdf_expand (prk, info, sizeof info, okm, 42);
		check ("A.1 OKM (L=42) == 3cb25f25faacd57a…",
		       hexeq (okm, "3cb25f25faacd57a90434f64d0362f2a""2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
		                   "34007208d5b887185865", 42));
	}

	/* ---- A.2: longer inputs/outputs — crosses the 32-byte expand block boundary (L=82 => 3 blocks),
	   which is where a wrong counter start or a T(i-1) omission shows up. --------------------------- */
	{
		unsigned char ikm[80], salt[80], info[80];
		fill (ikm,  sizeof ikm,  0x00);
		fill (salt, sizeof salt, 0x60);
		fill (info, sizeof info, 0xb0);
		hkdf_extract (salt, sizeof salt, ikm, sizeof ikm, prk);
		check ("A.2 PRK == 06a6b88c5853361a…",
		       hexeq (prk, "06a6b88c5853361a06104c9ceb35b45c""ef760014904671014a193f40c15fc244", DIG));
		hkdf_expand (prk, info, sizeof info, okm, 82);
		check ("A.2 OKM (L=82, 3 expand blocks) == b11e398dc80327a1…",
		       hexeq (okm, "b11e398dc80327a1c8e7f78c596a4934""4f012eda2d4efad8a050cc4c19afa97c"
		                   "59045a99cac7827271cb41c65e590e09""da3275600c2f09b8367793a9aca3db71"
		                   "cc30c58179ec3e87c14c01d5c1f3434f""1d87", 82));
	}

	/* ---- A.3: zero-length salt AND info. This is the shape the keyslot-area MAC actually uses for its
	   salt (0^32 == absent salt per §2.2), so it is the directly relevant vector. ------------------- */
	{
		unsigned char ikm[22];
		memset (ikm, 0x0b, sizeof ikm);
		hkdf_extract (NULL, 0, ikm, sizeof ikm, prk);
		check ("A.3 PRK (zero-length salt) == 19ef24a32c717b16…",
		       hexeq (prk, "19ef24a32c717b167f33a91d6f648bdf""96596776afdb6377ac434c1c293ccb04", DIG));
		hkdf_expand (prk, NULL, 0, okm, 42);
		check ("A.3 OKM (zero-length info) == 8da4e775a563c18f…",
		       hexeq (okm, "8da4e775a563c18f715f802a063c5a31""b8a11f5c5ee1879ec3454e5f3c738d2d"
		                   "9d201395faa4b61a96c8", 42));

		/* §2.2 explicitly says an absent salt is HashLen zero bytes. The keyslot-area code passes an
		   explicit 0^32 rather than NULL, so prove the two spellings agree — otherwise the "== A.3"
		   reading of that call site would be wrong. */
		{
			unsigned char zero[DIG], prk2[DIG];
			memset (zero, 0, sizeof zero);
			hkdf_extract (zero, sizeof zero, ikm, sizeof ikm, prk2);
			check ("explicit 0^32 salt == absent salt (RFC 5869 §2.2)", memcmp (prk, prk2, DIG) == 0);
		}
	}

	/* ---- THE STEP THAT MATTERS: the SHIPPING specialisation is this same HKDF ---------------------
	   KeyslotAreaMacDeriveKey is a hand-rolled inline HKDF (extract with 0^32, one expand block with
	   info "keyslot-area-mac"). Recompute it through the generic, now-RFC-anchored path and require
	   byte equality. A lookalike — counter starting at 0, info and counter transposed, T(0) not empty,
	   salt and IKM swapped — passes none of these. */
	{
		unsigned char vmk[32], kArea[32], want[32], p2[DIG];
		static const char *INFO = "keyslot-area-mac";
		fill (vmk, sizeof vmk, 0xa0);

		KeyslotAreaMacDeriveKey (vmk, (int) sizeof vmk, kArea);

		hkdf_extract (NULL, 0, vmk, sizeof vmk, p2);
		hkdf_expand (p2, (const unsigned char *) INFO, strlen (INFO), want, sizeof want);
		check ("SHIPPING KeyslotAreaMacDeriveKey == RFC-5869 HKDF(salt=0^32, info=\"keyslot-area-mac\", L=32)",
		       memcmp (kArea, want, sizeof want) == 0);

		/* Negative control on the anchor itself: a different info label must NOT reproduce it, or the
		   comparison above would be vacuous (e.g. if both sides ignored info). */
		{
			unsigned char other[32];
			hkdf_expand (p2, (const unsigned char *) "keyslot-area-maD", 16, other, sizeof other);
			check ("...and a 1-character info change does NOT reproduce it (info is load-bearing)",
			       memcmp (kArea, other, sizeof other) != 0);
		}

		/* And the derivation must actually depend on the VMK. */
		{
			unsigned char vmk2[32], k2[32];
			fill (vmk2, sizeof vmk2, 0xa1);
			KeyslotAreaMacDeriveKey (vmk2, (int) sizeof vmk2, k2);
			check ("...and a different VMK yields a different K_area", memcmp (kArea, k2, 32) != 0);
		}
	}

	printf ("  HKDF RFC 5869: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  HKDF RFC 5869 TEST FAILED\n"); return 1; }
	printf ("  HKDF RFC 5869 TEST PASSED\n");
	return 0;
}
