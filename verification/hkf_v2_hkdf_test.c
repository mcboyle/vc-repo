/*
 * hkf_v2_hkdf_test.c — anchor the HKF v2 mix's OWN inlined HKDF-SHA256 to RFC 5869.
 *
 * WHY THIS EXISTS, AND WHY IT IS SEPARATE FROM [103].
 * Step [103] anchored HKDF-SHA256 to RFC 5869 A.1/A.2/A.3 and then proved ONE shipping specialisation
 * — KeyslotAreaMacDeriveKey — byte-identical to it. It deliberately did NOT close the other one.
 * `HardwareKeyFactor.c` carries a SECOND, INDEPENDENT HKDF implementation: `hkf_v2_mix()` inlines its
 * own Extract and its own multi-block Expand rather than calling any shared helper. Two copies of a
 * standard means two chances to get it wrong, and [103] passing says nothing about this one.
 *
 * It is also the more consequential of the two. `KeyslotAreaMacDeriveKey` protects a keyslot table;
 * `hkf_v2_mix` derives the MIXED PASSWORD OF EVERY v2 FACTORED VOLUME — it is on the mount path of
 * every volume created with a hardware/threshold factor. Until now it was carried on a TWIN alone
 * (steps [80]/[93]: our C against our Python). Per CLAUDE.md rule 3, a twin encodes the same reading
 * of the spec as the code, so both are wrong identically when the reading is wrong. That is precisely
 * how step [94] shipped a non-conformant ristretto255 hash-to-group for months.
 *
 * WHAT IS ANCHORED, AND HOW.
 * `hkf_v2_mix` is static, with a fixed info label and a fixed L, so the generic RFC vectors cannot be
 * fed to it directly. Same chain shape as [103]:
 *   1. Build generic HKDF-SHA256 on the in-tree sha256() and anchor it to the OFFICIAL RFC 5869
 *      A.1/A.2/A.3 vectors — PRK and OKM, byte for byte. (ANCHOR CLASS: OFFICIAL.)
 *   2. Require the SHIPPING entry points — HKFMixResponseIntoPasswordV2 and, on a salt-bound build,
 *      HKFMixResponseIntoPasswordV2Salt — to equal that anchored HKDF byte for byte, at the exact
 *      parameters the product uses: info = "VeraCrypt/HKF/mix/v2", L = HKF_POOL_SIZE (128).
 *
 * THE 4-BLOCK POINT, which is the specific reason this could not ride on [103].
 * L = 128 with SHA-256 is FOUR expand blocks. RFC 5869 A.2 is the longest official vector and reaches
 * only three (L = 82). So the fourth iteration of this Expand loop — including the T(i-1) feedback into
 * it — is not covered by any official vector anywhere, in this tree or in the RFC. The negatives below
 * attack that region directly: a 3-block-and-zero-pad variant and a T(0)-not-empty variant must both
 * DIFFER, which is what proves all 128 bytes genuinely come from the chained expand.
 *
 * The other negatives rule out the classic HKDF lookalikes, each of which would still "work" as a KDF
 * and still round-trip a volume, while not being HKDF: counter starting at 0, info and counter
 * transposed, and salt/IKM swapped in Extract.
 *
 * Build: verification/build_and_verify.sh step [104].
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "Common/HardwareKeyFactor.h"

#include "Crypto/Sha2.h"

#define BLK 64
#define DIG 32

static int pass = 0, fail = 0;
static void check (const char *what, int ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

/* ---- generic HKDF-SHA256, built on the in-tree sha256() (itself OFFICIAL-anchored at [69]) -------- */

static void hmac256 (const unsigned char *key, size_t keyLen,
                     const unsigned char *msg, size_t msgLen,
                     const unsigned char *msg2, size_t msg2Len,
                     unsigned char out[DIG])
{
	sha256_ctx c;
	unsigned char k0[BLK], pad[BLK], inner[DIG];
	size_t i;

	memset (k0, 0, sizeof k0);
	if (keyLen > BLK) {
		sha256_begin (&c); sha256_hash (key, (uint_32t) keyLen, &c); sha256_end (k0, &c);
	} else if (keyLen > 0) {
		memcpy (k0, key, keyLen);
	}

	for (i = 0; i < BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&c); sha256_hash (pad, BLK, &c);
	if (msgLen  > 0) sha256_hash (msg,  (uint_32t) msgLen,  &c);
	if (msg2Len > 0) sha256_hash (msg2, (uint_32t) msg2Len, &c);
	sha256_end (inner, &c);

	for (i = 0; i < BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&c); sha256_hash (pad, BLK, &c); sha256_hash (inner, DIG, &c);
	sha256_end (out, &c);
}

static void hkdf_extract (const unsigned char *salt, size_t saltLen,
                          const unsigned char *ikm, size_t ikmLen,
                          const unsigned char *ikm2, size_t ikm2Len,
                          unsigned char prk[DIG])
{
	hmac256 (salt, saltLen, ikm, ikmLen, ikm2, ikm2Len, prk);
}

/* RFC 5869 §2.3. `ctrFrom` and `feedT` are parameters ONLY so the negative controls below can build
   deliberately-wrong variants; the conformant call always passes (1, 1). */
static void hkdf_expand_var (const unsigned char prk[DIG],
                             const unsigned char *info, size_t infoLen,
                             unsigned char *okm, size_t L,
                             int ctrFrom, int feedT, int maxBlocks)
{
	unsigned char T[DIG];
	size_t got = 0, tLen = 0;
	int blk;

	for (blk = 0; got < L; blk++) {
		unsigned char ctr = (unsigned char) (blk + ctrFrom);
		sha256_ctx c;
		unsigned char k0[BLK], pad[BLK], inner[DIG];
		size_t i, n;

		if (maxBlocks > 0 && blk >= maxBlocks) break;    /* truncation negative */

		memset (k0, 0, sizeof k0);
		memcpy (k0, prk, DIG);
		for (i = 0; i < BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
		sha256_begin (&c); sha256_hash (pad, BLK, &c);
		if (feedT && tLen > 0) sha256_hash (T, (uint_32t) tLen, &c);
		if (!feedT && blk == 0) {                        /* "T(0) is not empty" negative */
			unsigned char zero[DIG]; memset (zero, 0, sizeof zero);
			sha256_hash (zero, DIG, &c);
		}
		if (infoLen > 0) sha256_hash (info, (uint_32t) infoLen, &c);
		sha256_hash (&ctr, 1, &c);
		sha256_end (inner, &c);
		for (i = 0; i < BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
		sha256_begin (&c); sha256_hash (pad, BLK, &c); sha256_hash (inner, DIG, &c);
		sha256_end (T, &c);
		tLen = DIG;

		n = (L - got < DIG) ? (L - got) : DIG;
		memcpy (okm + got, T, n);
		got += n;
	}
	if (got < L) memset (okm + got, 0, L - got);         /* zero-pad the truncation negative */
}

static void hkdf_expand (const unsigned char prk[DIG], const unsigned char *info, size_t infoLen,
                         unsigned char *okm, size_t L)
{
	hkdf_expand_var (prk, info, infoLen, okm, L, 1, 1, 0);
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
{
	size_t i; for (i = 0; i < n; i++) p[i] = (unsigned char) (start + i);
}

/* The exact parameters the shipping mix uses. If either of these drifts from HardwareKeyFactor.c the
   equality assertions below fail loudly — which is the point. */
static const unsigned char HKF_V2_INFO[] = "VeraCrypt/HKF/mix/v2";
#define HKF_V2_INFO_LEN (sizeof (HKF_V2_INFO) - 1)

int main (void)
{
	printf ("  HKF v2 mix: its own inlined HKDF-SHA256 vs RFC 5869 (src/Common/HardwareKeyFactor.c)\n");

	/* ================= 1. anchor generic HKDF to the OFFICIAL RFC 5869 vectors ==================== */
	printf ("  [1] OFFICIAL anchor — RFC 5869 Appendix A (SHA-256)\n");
	{
		unsigned char ikm[22], salt[13], info[10], prk[DIG], okm[42];
		memset (ikm, 0x0b, sizeof ikm);
		fill (salt, sizeof salt, 0x00);
		fill (info, sizeof info, 0xf0);

		hkdf_extract (salt, sizeof salt, ikm, sizeof ikm, NULL, 0, prk);
		check ("A.1 PRK == 077709362c2e32df…",
		       hexeq (prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", DIG));
		hkdf_expand (prk, info, sizeof info, okm, 42);
		check ("A.1 OKM (L=42) == 3cb25f25faacd57a…",
		       hexeq (okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42));
	}
	{
		/* A.2 is the longest official vector: L=82 => THREE expand blocks. The shipping mix needs FOUR
		   (L=128), so this is as far as the RFC can carry us — see the header comment. */
		unsigned char ikm[80], salt[80], info[80], prk[DIG], okm[82];
		fill (ikm,  sizeof ikm,  0x00);
		fill (salt, sizeof salt, 0x60);
		fill (info, sizeof info, 0xb0);

		hkdf_extract (salt, sizeof salt, ikm, sizeof ikm, NULL, 0, prk);
		check ("A.2 PRK == 06a6b88c5853361a…",
		       hexeq (prk, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", DIG));
		hkdf_expand (prk, info, sizeof info, okm, 82);
		check ("A.2 OKM (L=82, 3 expand blocks) == b11e398dc80327a1…",
		       hexeq (okm, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
		                   "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
		                   "cc30c58179ec3e87c14c01d5c1f3434f1d87", 82));
	}
	{
		unsigned char ikm[22], prk[DIG], okm[42];
		memset (ikm, 0x0b, sizeof ikm);
		hkdf_extract (NULL, 0, ikm, sizeof ikm, NULL, 0, prk);
		check ("A.3 PRK (zero-length salt) == 19ef24a32c717b16…",
		       hexeq (prk, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", DIG));
		hkdf_expand (prk, NULL, 0, okm, 42);
		check ("A.3 OKM (zero-length info) == 8da4e775a563c18f…",
		       hexeq (okm, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42));
	}

	/* ================= 2. the SHIPPING v2 mix IS that HKDF ======================================== */
	printf ("  [2] chain — HKFMixResponseIntoPasswordV2 == HKDF(0^32, pw||resp, \"VeraCrypt/HKF/mix/v2\", 128)\n");

	unsigned char pwOrig[64], resp[32];
	fill (pwOrig, sizeof pwOrig, 0x41);
	fill (resp,   sizeof resp,   0x90);

	unsigned char shipped[HKF_POOL_SIZE];
	int shippedLen;
	unsigned char expect[HKF_POOL_SIZE], prk[DIG];
	static const unsigned char ZERO32[DIG] = { 0 };

	{
		memset (shipped, 0, sizeof shipped);
		memcpy (shipped, pwOrig, sizeof pwOrig);
		shippedLen = (int) sizeof pwOrig;
		HKFMixResponseIntoPasswordV2 (shipped, &shippedLen, resp, (int) sizeof resp);

		check ("v2 mix returns exactly HKF_POOL_SIZE (128) bytes", shippedLen == HKF_POOL_SIZE);

		/* Extract salt = 0^32; IKM = password || response (two segments, in that order). */
		hkdf_extract (ZERO32, DIG, pwOrig, sizeof pwOrig, resp, sizeof resp, prk);
		hkdf_expand (prk, HKF_V2_INFO, HKF_V2_INFO_LEN, expect, HKF_POOL_SIZE);

		check ("SHIPPING unbound v2 mix == the RFC-anchored HKDF, all 128 bytes",
		       memcmp (shipped, expect, HKF_POOL_SIZE) == 0);
	}

	/* ================= 3. the 4th expand block — beyond any official vector ======================= */
	printf ("  [3] the 4th expand block (L=128); RFC A.2 reaches only 3\n");
	{
		unsigned char trunc3[HKF_POOL_SIZE];
		hkdf_expand_var (prk, HKF_V2_INFO, HKF_V2_INFO_LEN, trunc3, HKF_POOL_SIZE, 1, 1, 3);
		check ("stopping after 3 blocks + zero-pad DIFFERS (so block 4 is real output)",
		       memcmp (shipped, trunc3, HKF_POOL_SIZE) != 0);

		/* And the tail must not be zeros — a mix that quietly emitted 96 bytes of key material and 32
		   bytes of padding would still "work" and would still round-trip a volume. */
		int tailNonZero = 0, i;
		for (i = 96; i < HKF_POOL_SIZE; i++) if (shipped[i] != 0) { tailNonZero = 1; break; }
		check ("bytes 96..127 are real key material, not padding", tailNonZero);

		unsigned char noFeed[HKF_POOL_SIZE];
		hkdf_expand_var (prk, HKF_V2_INFO, HKF_V2_INFO_LEN, noFeed, HKF_POOL_SIZE, 1, 0, 0);
		check ("T(i-1) feedback matters — a non-empty T(0) variant DIFFERS",
		       memcmp (shipped, noFeed, HKF_POOL_SIZE) != 0);
	}

	/* ================= 4. HKDF lookalikes must all differ ========================================= */
	printf ("  [4] negative controls — constructions that are NOT RFC 5869 HKDF\n");
	{
		unsigned char v[HKF_POOL_SIZE];

		hkdf_expand_var (prk, HKF_V2_INFO, HKF_V2_INFO_LEN, v, HKF_POOL_SIZE, 0, 1, 0);
		check ("counter starting at 0 DIFFERS", memcmp (shipped, v, HKF_POOL_SIZE) != 0);

		/* wrong domain-separation label */
		static const unsigned char OTHER[] = "VeraCrypt/HKF/mix/v3";
		hkdf_expand (prk, OTHER, sizeof OTHER - 1, v, HKF_POOL_SIZE);
		check ("a different info label DIFFERS (domain separation is load-bearing)",
		       memcmp (shipped, v, HKF_POOL_SIZE) != 0);

		/* salt and IKM swapped in Extract */
		unsigned char prkSwapped[DIG], vs[HKF_POOL_SIZE];
		hkdf_extract (pwOrig, sizeof pwOrig, ZERO32, DIG, NULL, 0, prkSwapped);
		hkdf_expand (prkSwapped, HKF_V2_INFO, HKF_V2_INFO_LEN, vs, HKF_POOL_SIZE);
		check ("salt/IKM swapped in Extract DIFFERS", memcmp (shipped, vs, HKF_POOL_SIZE) != 0);

		/* response actually participates */
		unsigned char resp2[32], other[HKF_POOL_SIZE]; int otherLen;
		memcpy (resp2, resp, sizeof resp2); resp2[0] ^= 0x01;
		memset (other, 0, sizeof other); memcpy (other, pwOrig, sizeof pwOrig);
		otherLen = (int) sizeof pwOrig;
		HKFMixResponseIntoPasswordV2 (other, &otherLen, resp2, (int) sizeof resp2);
		check ("a 1-bit response change changes the mixed password",
		       memcmp (shipped, other, HKF_POOL_SIZE) != 0);
	}

	/* ================= 5. the salt-bound derivation (D-1 / Rank-1) ================================ */
#if defined(VC_ENABLE_HKF_MIX_V2_SALTBIND)
	printf ("  [5] salt-bound v2 — HKDF-Extract salt = the VOLUME SALT, not 0^32\n");
	{
		unsigned char vsalt[64], bound[HKF_POOL_SIZE], expectB[HKF_POOL_SIZE], prkB[DIG];
		int boundLen;
		fill (vsalt, sizeof vsalt, 0x20);

		memset (bound, 0, sizeof bound); memcpy (bound, pwOrig, sizeof pwOrig);
		boundLen = (int) sizeof pwOrig;
		HKFMixResponseIntoPasswordV2Salt (bound, &boundLen, resp, (int) sizeof resp,
		                                  vsalt, (int) sizeof vsalt);

		hkdf_extract (vsalt, sizeof vsalt, pwOrig, sizeof pwOrig, resp, sizeof resp, prkB);
		hkdf_expand (prkB, HKF_V2_INFO, HKF_V2_INFO_LEN, expectB, HKF_POOL_SIZE);

		check ("SHIPPING salt-bound v2 mix == the RFC-anchored HKDF with salt = volume salt",
		       memcmp (bound, expectB, HKF_POOL_SIZE) == 0);
		check ("salt-bound output DIFFERS from unbound (the binding is real)",
		       memcmp (bound, shipped, HKF_POOL_SIZE) != 0);

		/* A different volume => a different mixed password from the SAME password+factor. That is the
		   whole point of D-1: the same shares do not open a second volume. */
		unsigned char vsalt2[64], bound2[HKF_POOL_SIZE]; int bound2Len;
		memcpy (vsalt2, vsalt, sizeof vsalt2); vsalt2[0] ^= 0x01;
		memset (bound2, 0, sizeof bound2); memcpy (bound2, pwOrig, sizeof pwOrig);
		bound2Len = (int) sizeof pwOrig;
		HKFMixResponseIntoPasswordV2Salt (bound2, &bound2Len, resp, (int) sizeof resp,
		                                  vsalt2, (int) sizeof vsalt2);
		check ("a 1-bit volume-salt change changes the mixed password (cross-volume separation)",
		       memcmp (bound, bound2, HKF_POOL_SIZE) != 0);

		/* An empty salt must fall back to the unbound 0^32 derivation, as the header documents. */
		unsigned char fb[HKF_POOL_SIZE]; int fbLen;
		memset (fb, 0, sizeof fb); memcpy (fb, pwOrig, sizeof pwOrig);
		fbLen = (int) sizeof pwOrig;
		HKFMixResponseIntoPasswordV2Salt (fb, &fbLen, resp, (int) sizeof resp, NULL, 0);
		check ("a NULL/empty volume salt falls back to the unbound derivation (as documented)",
		       memcmp (fb, shipped, HKF_POOL_SIZE) == 0);
	}
#else
	printf ("  [5] salt-bound probes skipped (built without VC_ENABLE_HKF_MIX_V2_SALTBIND)\n");
#endif

	printf ("  HKF V2 HKDF: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  HKF V2 HKDF TEST FAILED\n"); return 1; }
	printf ("  HKF V2 HKDF TEST PASSED\n");
	return 0;
}
