/*
 * V2Format.c — see V2Format.h. Shippable core of the v2 on-disk format (T1-1), gated VC_ENABLE_V2FORMAT.
 * PRF = HMAC-SHA256 over the in-tree Crypto/Sha2.c (no new crypto dependency). C, VeraCrypt style.
 */

#include "V2Format.h"

#if defined(VC_ENABLE_V2FORMAT)

#include <string.h>
#include "Crypto/Sha2.h"     /* sha256_begin / sha256_hash / sha256_end */

#define V2_SHA256_BLOCK  64
#define V2_SHA256_DIGEST 32

static void v2_wipe (volatile unsigned char *p, size_t n) { while (n--) *p++ = 0; }

/* full-width HMAC-SHA256 (ipad/opad), digest into out32 — same construction as DuressToken.c */
static void v2_hmac_sha256 (const unsigned char *key, int keyLen,
                            const unsigned char *msg, size_t msgLen,
                            unsigned char out32[V2_SHA256_DIGEST])
{
	sha256_ctx    ctx;
	unsigned char k0[V2_SHA256_BLOCK];
	unsigned char pad[V2_SHA256_BLOCK];
	unsigned char inner[V2_SHA256_DIGEST];
	int i;

	if (keyLen > V2_SHA256_BLOCK)
	{
		sha256_begin (&ctx);
		sha256_hash (key, (unsigned int) keyLen, &ctx);
		sha256_end (k0, &ctx);
		memset (k0 + V2_SHA256_DIGEST, 0, V2_SHA256_BLOCK - V2_SHA256_DIGEST);
	}
	else
	{
		if (keyLen > 0)
			memcpy (k0, key, (size_t) keyLen);
		memset (k0 + (keyLen > 0 ? keyLen : 0), 0, V2_SHA256_BLOCK - (keyLen > 0 ? keyLen : 0));
	}

	for (i = 0; i < V2_SHA256_BLOCK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&ctx);
	sha256_hash (pad, V2_SHA256_BLOCK, &ctx);
	if (msgLen > 0)
		sha256_hash (msg, (unsigned int) msgLen, &ctx);
	sha256_end (inner, &ctx);

	for (i = 0; i < V2_SHA256_BLOCK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&ctx);
	sha256_hash (pad, V2_SHA256_BLOCK, &ctx);
	sha256_hash (inner, V2_SHA256_DIGEST, &ctx);
	sha256_end (out32, &ctx);

	v2_wipe (k0, sizeof k0);
	v2_wipe (pad, sizeof pad);
	v2_wipe (inner, sizeof inner);
}

static void v2_le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

const char *V2FormatModeLabel (V2Mode mode)
{
	switch (mode)
	{
	case V2_MODE_HCTR2:    return "VeraCrypt/v2/mac/hctr2";
	case V2_MODE_ADIANTUM: return "VeraCrypt/v2/mac/adiantum";
	default:               return "";
	}
}

void V2FormatDeriveModeKey (const unsigned char *masterKey, int masterKeyLen, V2Mode mode,
                            unsigned char outKey[V2_KEY_LEN])
{
	const char *label = V2FormatModeLabel (mode);
	unsigned char digest[V2_SHA256_DIGEST];
	/* K_mac[mode] = HMAC-SHA256(masterKey, label); take the full 32-byte digest (V2_KEY_LEN == 32). */
	v2_hmac_sha256 (masterKey, masterKeyLen, (const unsigned char *) label, strlen (label), digest);
	memcpy (outKey, digest, V2_KEY_LEN);
	v2_wipe (digest, sizeof digest);
}

void V2FormatSectorTag (const unsigned char macKey[V2_KEY_LEN], uint64_t index,
                        const unsigned char *ct, size_t ctLen, unsigned char tag[V2_MAC_TAG_LEN])
{
	/* tag = HMAC-SHA256(macKey, le64(index) || ct)[0..16]. le64(index) is prepended INSIDE the PRF so a
	   (ciphertext,tag) pair cannot be relocated to a different sector. */
	sha256_ctx    ctx;
	unsigned char k0[V2_SHA256_BLOCK], pad[V2_SHA256_BLOCK];
	unsigned char inner[V2_SHA256_DIGEST], full[V2_SHA256_DIGEST], le[8];
	int i;

	memcpy (k0, macKey, V2_KEY_LEN);
	memset (k0 + V2_KEY_LEN, 0, V2_SHA256_BLOCK - V2_KEY_LEN);
	v2_le64 (index, le);

	for (i = 0; i < V2_SHA256_BLOCK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&ctx);
	sha256_hash (pad, V2_SHA256_BLOCK, &ctx);
	sha256_hash (le, 8, &ctx);
	if (ctLen > 0)
		sha256_hash (ct, (unsigned int) ctLen, &ctx);
	sha256_end (inner, &ctx);

	for (i = 0; i < V2_SHA256_BLOCK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&ctx);
	sha256_hash (pad, V2_SHA256_BLOCK, &ctx);
	sha256_hash (inner, V2_SHA256_DIGEST, &ctx);
	sha256_end (full, &ctx);

	memcpy (tag, full, V2_MAC_TAG_LEN);       /* truncate the 256-bit HMAC to a 128-bit tag */
	v2_wipe (k0, sizeof k0); v2_wipe (pad, sizeof pad);
	v2_wipe (inner, sizeof inner); v2_wipe (full, sizeof full);
}

/* constant-time compare: OR-accumulate the XOR of every byte, no early-out (blessed in ct-primitive-guard). */
static int v2_ct_eq (const unsigned char *a, const unsigned char *b, int n)
{
	unsigned char d = 0;
	int i;
	for (i = 0; i < n; i++)
		d |= (unsigned char) (a[i] ^ b[i]);
	return d == 0;
}

int V2FormatSectorVerify (const unsigned char macKey[V2_KEY_LEN], uint64_t index,
                          const unsigned char *ct, size_t ctLen, const unsigned char tag[V2_MAC_TAG_LEN])
{
	unsigned char t[V2_MAC_TAG_LEN];
	int eq;
	V2FormatSectorTag (macKey, index, ct, ctLen, t);
	eq = v2_ct_eq (t, tag, V2_MAC_TAG_LEN);
	v2_wipe (t, sizeof t);
	return eq;
}

V2Mode V2FormatDiscoverMode (const unsigned char *masterKey, int masterKeyLen,
                             const unsigned char *sector0Ct, size_t ctLen,
                             const unsigned char storedTag[V2_MAC_TAG_LEN])
{
	static const V2Mode modes[2] = { V2_MODE_HCTR2, V2_MODE_ADIANTUM };
	V2Mode found = V2_MODE_NONE;
	int i;
	/* Try every mode's key (no early return on match, so the number of HMACs is independent of which
	   mode — or none — verifies; a wrong master key matches none and returns V2_MODE_NONE, as v1). */
	for (i = 0; i < 2; i++)
	{
		unsigned char kmac[V2_KEY_LEN];
		V2FormatDeriveModeKey (masterKey, masterKeyLen, modes[i], kmac);
		if (V2FormatSectorVerify (kmac, 0, sector0Ct, ctLen, storedTag))
			found = modes[i];
		v2_wipe (kmac, sizeof kmac);
	}
	return found;
}

/* ---- MAC-table layout ---- */

uint64_t V2FormatMacTableBytes (uint64_t dataSectors, uint32_t sectorSize)
{
	uint64_t raw = dataSectors * (uint64_t) V2_MAC_TAG_LEN;    /* one 16-byte slot per data sector */
	uint64_t ss  = (sectorSize == 0) ? 512u : sectorSize;
	return ((raw + ss - 1) / ss) * ss;                        /* round up to a whole sector */
}

int V2FormatSplitDataArea (uint64_t totalDataBytes, uint32_t sectorSize,
                           uint64_t *usableBytesOut, uint64_t *tableOffsetOut)
{
	uint64_t ss = (sectorSize == 0) ? 512u : sectorSize;
	uint64_t totalSectors, usableSectors, tableBytes, usableBytes;
	if (totalDataBytes < 2u * ss)                    /* need at least one usable + one table sector */
		return 1;
	totalSectors = totalDataBytes / ss;
	/* Solve for the largest U such that U + ceil(U*16/ss) <= totalSectors. 16 <= ss so the table is a
	   small fraction; iterate down from an upper bound (at most a couple of steps). */
	usableSectors = totalSectors;
	for (;;)
	{
		uint64_t tblSectors = (usableSectors * (uint64_t) V2_MAC_TAG_LEN + ss - 1) / ss;
		if (usableSectors + tblSectors <= totalSectors)
			break;
		if (usableSectors == 0)
			return 1;
		usableSectors--;
	}
	if (usableSectors == 0)
		return 1;
	tableBytes  = V2FormatMacTableBytes (usableSectors, sectorSize);
	usableBytes = usableSectors * ss;
	if (usableBytesOut)  *usableBytesOut  = usableBytes;
	if (tableOffsetOut)  *tableOffsetOut  = usableBytes;      /* table sits immediately AFTER usable data */
	(void) tableBytes;
	return 0;
}

uint64_t V2FormatSlotOffset (uint64_t index)
{
	return index * (uint64_t) V2_MAC_TAG_LEN;
}

#endif /* VC_ENABLE_V2FORMAT */
