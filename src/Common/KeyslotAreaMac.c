/*
 * KeyslotAreaMac — see KeyslotAreaMac.h. HMAC-SHA256 area tag + HKDF-SHA256 key derivation over the
 * in-tree Sha2. Self-contained (no dependency on the other modules' internal HMAC).
 */
#include "KeyslotAreaMac.h"

#if defined(VC_ENABLE_KEYSLOT_AREA_MAC) && defined(VC_ENABLE_KEYSLOTS)

#include <string.h>
#include "Crypto/Sha2.h"

#define SHA256_BLOCK 64
#define SHA256_DIGEST 32

static void kam_hmac (const unsigned char *key, int keyLen,
                      const unsigned char *msg, size_t msgLen, unsigned char out[SHA256_DIGEST])
{
	sha256_ctx c;
	unsigned char k0[SHA256_BLOCK], pad[SHA256_BLOCK], inner[SHA256_DIGEST];
	int i;
	if (keyLen > SHA256_BLOCK) {
		sha256_begin (&c); sha256_hash (key, (uint_32t) keyLen, &c); sha256_end (k0, &c);
		memset (k0 + SHA256_DIGEST, 0, SHA256_BLOCK - SHA256_DIGEST);
	} else {
		if (keyLen > 0) memcpy (k0, key, (size_t) keyLen);
		memset (k0 + (keyLen > 0 ? keyLen : 0), 0, SHA256_BLOCK - (keyLen > 0 ? keyLen : 0));
	}
	for (i = 0; i < SHA256_BLOCK; i++) pad[i] = k0[i] ^ 0x36;
	sha256_begin (&c); sha256_hash (pad, SHA256_BLOCK, &c);
	if (msgLen > 0) sha256_hash (msg, (uint_32t) msgLen, &c);
	sha256_end (inner, &c);
	for (i = 0; i < SHA256_BLOCK; i++) pad[i] = k0[i] ^ 0x5c;
	sha256_begin (&c); sha256_hash (pad, SHA256_BLOCK, &c); sha256_hash (inner, SHA256_DIGEST, &c);
	sha256_end (out, &c);
}

/* HKDF-SHA256 with empty salt, single 32-byte output block. */
void KeyslotAreaMacDeriveKey (const unsigned char *vmk, int vmkLen, unsigned char kArea[32])
{
	static const unsigned char zeroSalt[SHA256_DIGEST] = {0};
	const char *info = "keyslot-area-mac";
	unsigned char prk[SHA256_DIGEST];
	unsigned char t1in[64];
	size_t infoLen = strlen (info), n = 0;
	/* extract: PRK = HMAC(salt=0^32, IKM=vmk) */
	kam_hmac (zeroSalt, SHA256_DIGEST, vmk, (size_t) vmkLen, prk);
	/* expand: T(1) = HMAC(PRK, info || 0x01) */
	memcpy (t1in, info, infoLen); n = infoLen;
	t1in[n++] = 0x01;
	kam_hmac (prk, SHA256_DIGEST, t1in, n, kArea);
	memset (prk, 0, sizeof prk);
	memset (t1in, 0, sizeof t1in);
}

static void put_u32_be (unsigned char *p, uint32 v)
{ p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16); p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char) v; }
static uint32 get_u32_be (const unsigned char *p)
{ return ((uint32) p[0] << 24) | ((uint32) p[1] << 16) | ((uint32) p[2] << 8) | (uint32) p[3]; }

/* Count occupied labeled slots ("VCKS" magic) within [0, regionLen) at KEYSLOT_TABLE_STRIDE boundaries. */
static uint32 count_slots (KeyslotArea *area, uint64 regionLen)
{
	uint64 off; uint32 n = 0; unsigned char m[4];
	for (off = 0; off + KEYSLOT_TABLE_STRIDE <= regionLen; off += KEYSLOT_TABLE_STRIDE) {
		if (area->read (area->ctx, off, m, 4) != 0) break;
		if (memcmp (m, "VCKS", 4) == 0) n++;
	}
	return n;
}

int KeyslotAreaMacCompute (KeyslotArea *area, uint64 regionLen,
                           const unsigned char kArea[32], unsigned char out[32])
{
	/* MAC = HMAC(K_area, "VCKSAREA1" || u32_be(slotCount) || region-bytes). Streamed via a
	   two-pass HMAC would need a stream API; the region is small (a keyslot area), so hash it as
	   magic||count first, then the region in a running HMAC using the block construction directly. */
	sha256_ctx c;
	unsigned char k0[SHA256_BLOCK], ipad[SHA256_BLOCK], opad[SHA256_BLOCK], inner[SHA256_DIGEST];
	unsigned char hdr[KAM_TRAILER_MAGICLEN + 4], buf[KEYSLOT_TABLE_STRIDE];
	uint32 slots = count_slots (area, regionLen);
	uint64 off; int i;

	memcpy (k0, kArea, SHA256_DIGEST); memset (k0 + SHA256_DIGEST, 0, SHA256_BLOCK - SHA256_DIGEST);
	for (i = 0; i < SHA256_BLOCK; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }

	memcpy (hdr, KAM_TRAILER_MAGIC, KAM_TRAILER_MAGICLEN);
	put_u32_be (hdr + KAM_TRAILER_MAGICLEN, slots);

	sha256_begin (&c);
	sha256_hash (ipad, SHA256_BLOCK, &c);
	sha256_hash (hdr, sizeof hdr, &c);
	for (off = 0; off < regionLen; ) {
		uint64 n = regionLen - off; if (n > sizeof buf) n = sizeof buf;
		if (area->read (area->ctx, off, buf, (size_t) n) != 0) { memset (k0,0,sizeof k0); return KAM_ERR_IO; }
		sha256_hash (buf, (uint_32t) n, &c);
		off += n;
	}
	sha256_end (inner, &c);
	sha256_begin (&c); sha256_hash (opad, SHA256_BLOCK, &c); sha256_hash (inner, SHA256_DIGEST, &c);
	sha256_end (out, &c);
	memset (k0, 0, sizeof k0); memset (ipad, 0, sizeof ipad); memset (opad, 0, sizeof opad);
	return KAM_OK;
}

int KeyslotAreaMacWrite (KeyslotArea *area, uint64 regionLen, uint64 trailerOff,
                         const unsigned char kArea[32])
{
	unsigned char trailer[KAM_TRAILER_SIZE], tag[32];
	uint32 slots = count_slots (area, regionLen);
	int rc = KeyslotAreaMacCompute (area, regionLen, kArea, tag);
	if (rc != KAM_OK) return rc;
	memcpy (trailer, KAM_TRAILER_MAGIC, KAM_TRAILER_MAGICLEN);
	trailer[KAM_TRAILER_MAGICLEN] = KAM_TRAILER_VER;
	put_u32_be (trailer + KAM_TRAILER_MAGICLEN + 1, slots);
	memcpy (trailer + KAM_TRAILER_MAGICLEN + 1 + 4, tag, 32);
	if (area->write (area->ctx, trailerOff, trailer, sizeof trailer) != 0) return KAM_ERR_IO;
	return KAM_OK;
}

int KeyslotAreaMacVerify (KeyslotArea *area, uint64 regionLen, uint64 trailerOff,
                          const unsigned char kArea[32])
{
	unsigned char trailer[KAM_TRAILER_SIZE], tag[32];
	int rc;
	if (area->read (area->ctx, trailerOff, trailer, sizeof trailer) != 0) return KAM_ERR_IO;
	if (memcmp (trailer, KAM_TRAILER_MAGIC, KAM_TRAILER_MAGICLEN) != 0) return KAM_NO_TRAILER;
	if (trailer[KAM_TRAILER_MAGICLEN] != KAM_TRAILER_VER) return KAM_NO_TRAILER;
	rc = KeyslotAreaMacCompute (area, regionLen, kArea, tag);
	if (rc != KAM_OK) return rc;
	/* the stored slotCount must also match what we recomputed (bound into the tag already, but check
	   explicitly so a mismatch is reported as tamper rather than a silent tag miss) */
	if (get_u32_be (trailer + KAM_TRAILER_MAGICLEN + 1) != count_slots (area, regionLen)) return KAM_TAMPERED;
	if (memcmp (trailer + KAM_TRAILER_MAGICLEN + 1 + 4, tag, 32) != 0) return KAM_TAMPERED;
	return KAM_OK;
}

#endif /* VC_ENABLE_KEYSLOT_AREA_MAC && VC_ENABLE_KEYSLOTS */
