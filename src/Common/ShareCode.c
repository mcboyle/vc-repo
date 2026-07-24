/*
 * ShareCode — see ShareCode.h. bech32m (BIP-350) over the same BIP-173 machinery: the 32-char charset,
 * the 5-term BCH generator, hrp-expand, polymod, and 8->5 bit conversion, over the fixed hrp "vcs". The
 * only difference from plain bech32 is the checksum XOR constant: bech32m uses 0x2bc830a3 in place of 1,
 * which BIP-350 published to remove bech32's residual insertion/deletion weakness (decision D-2).
 */

#include "ShareCode.h"

#if defined(VC_ENABLE_SHARECODE)

#include <string.h>

static const char *SC_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const char *SC_HRP = "vcs";
#define SC_HRP_LEN 3

/* bech32m final-XOR constant (BIP-350); plain bech32 (BIP-173) used 1. */
#define SC_BECH32M_CONST 0x2bc830a3u

static const uint32 SC_GEN[5] = { 0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u };

static int sc_charval (char c)   /* charset index, or -1 */
{
	int i;
	for (i = 0; i < 32; i++)
		if (SC_CHARSET[i] == c) return i;
	return -1;
}

static uint32 sc_polymod (const unsigned char *values, int n)
{
	uint32 chk = 1;
	int i, j;
	for (i = 0; i < n; i++)
	{
		uint32 b = chk >> 25;
		chk = ((chk & 0x1ffffffu) << 5) ^ (uint32) values[i];
		for (j = 0; j < 5; j++)
			if ((b >> j) & 1u) chk ^= SC_GEN[j];
	}
	return chk;
}

/* hrp-expand("vcs") into out (2*len+1 = 7 symbols); returns the count */
static int sc_hrp_expand (unsigned char *out)
{
	int i, n = 0;
	for (i = 0; i < SC_HRP_LEN; i++) out[n++] = (unsigned char) (SC_HRP[i] >> 5);
	out[n++] = 0;
	for (i = 0; i < SC_HRP_LEN; i++) out[n++] = (unsigned char) (SC_HRP[i] & 31);
	return n;
}

/* 8-bit bytes -> 5-bit groups (pad with zero bits). Returns number of groups, or -1 on overflow. */
static int sc_to5 (const unsigned char *data, int n, unsigned char *out, int outCap)
{
	uint32 acc = 0;
	int bits = 0, count = 0, i;
	for (i = 0; i < n; i++)
	{
		acc = (acc << 8) | data[i];
		bits += 8;
		while (bits >= 5)
		{
			bits -= 5;
			if (count >= outCap) return -1;
			out[count++] = (unsigned char) ((acc >> bits) & 31);
		}
	}
	if (bits > 0)
	{
		if (count >= outCap) return -1;
		out[count++] = (unsigned char) ((acc << (5 - bits)) & 31);
	}
	return count;
}

/* 5-bit groups -> 8-bit bytes; rejects a non-zero final pad (canonical). Returns byte count or -1. */
static int sc_from5 (const unsigned char *data, int n, unsigned char *out, int outCap)
{
	uint32 acc = 0;
	int bits = 0, count = 0, i;
	for (i = 0; i < n; i++)
	{
		acc = (acc << 5) | data[i];
		bits += 5;
		while (bits >= 8)
		{
			bits -= 8;
			if (count >= outCap) return -1;
			out[count++] = (unsigned char) ((acc >> bits) & 0xff);
		}
	}
	if (bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0)
		return -1;   /* leftover bits must be zero pad */
	return count;
}

int ShareCodeEncode (const ShamirShare *share, const unsigned char *mac, char *out, int outCap)
{
	unsigned char payload[3 + SHAMIR_MAX_SECRET + SHARECODE_MAC_SIZE];
	unsigned char five[8 * sizeof (payload) / 5 + 2];
	unsigned char chkin[7 + sizeof (five) + 6];
	int plen = 0, n5, hn, i, pos, total;
	uint32 pm;

	if (!share || !out || share->len < 1 || share->len > SHAMIR_MAX_SECRET)
		return SHARECODE_ERR_PARAM;

	payload[plen++] = (unsigned char) SHARECODE_VERSION;
	payload[plen++] = share->x;
	payload[plen++] = (unsigned char) share->len;
	memcpy (payload + plen, share->y, share->len); plen += share->len;
	if (mac) { memcpy (payload + plen, mac, SHARECODE_MAC_SIZE); plen += SHARECODE_MAC_SIZE; }

	n5 = sc_to5 (payload, plen, five, (int) sizeof (five));
	if (n5 < 0) return SHARECODE_ERR_PARAM;

	/* checksum = polymod(hrp_expand || data || 000000) ^ bech32m_const */
	hn = sc_hrp_expand (chkin);
	memcpy (chkin + hn, five, (size_t) n5);
	for (i = 0; i < 6; i++) chkin[hn + n5 + i] = 0;
	pm = sc_polymod (chkin, hn + n5 + 6) ^ SC_BECH32M_CONST;

	/* "vcs1" || data chars || 6 checksum chars || NUL */
	total = SC_HRP_LEN + 1 + n5 + 6 + 1;
	if (total > outCap) return SHARECODE_ERR_PARAM;
	pos = 0;
	memcpy (out, SC_HRP, SC_HRP_LEN); pos += SC_HRP_LEN;
	out[pos++] = '1';
	for (i = 0; i < n5; i++) out[pos++] = SC_CHARSET[five[i]];
	for (i = 0; i < 6; i++) out[pos++] = SC_CHARSET[(pm >> (5 * (5 - i))) & 31];
	out[pos] = '\0';
	{ volatile unsigned char *p = payload; size_t z = sizeof (payload); while (z--) *p++ = 0; }
	return SHARECODE_OK;
}

int ShareCodeDecode (const char *str, ShamirShare *share, unsigned char *macOut, int *hasMac)
{
	unsigned char five[SHARECODE_MAX_LEN];
	unsigned char chkin[7 + SHARECODE_MAX_LEN];
	unsigned char payload[3 + SHAMIR_MAX_SECRET + SHARECODE_MAC_SIZE];
	int slen, dataLen, i, hn, n5, pn, macLen;

	if (!str || !share) return SHARECODE_ERR_PARAM;
	slen = (int) strlen (str);
	if (slen < SC_HRP_LEN + 1 + 6 || slen > SHARECODE_MAX_LEN) return SHARECODE_ERR_FORMAT;
	if (memcmp (str, SC_HRP, SC_HRP_LEN) != 0 || str[SC_HRP_LEN] != '1') return SHARECODE_ERR_FORMAT;

	dataLen = slen - (SC_HRP_LEN + 1);              /* data + 6 checksum chars */
	for (i = 0; i < dataLen; i++)
	{
		int v = sc_charval (str[SC_HRP_LEN + 1 + i]);
		if (v < 0) return SHARECODE_ERR_FORMAT;
		five[i] = (unsigned char) v;
	}

	/* verify: polymod(hrp_expand || data(incl checksum)) == bech32m_const */
	hn = sc_hrp_expand (chkin);
	memcpy (chkin + hn, five, (size_t) dataLen);
	if (sc_polymod (chkin, hn + dataLen) != SC_BECH32M_CONST)
		return SHARECODE_ERR_CHECKSUM;

	n5 = dataLen - 6;                               /* strip the checksum groups */
	pn = sc_from5 (five, n5, payload, (int) sizeof (payload));
	if (pn < 3) return SHARECODE_ERR_FORMAT;
	if (payload[0] != SHARECODE_VERSION) return SHARECODE_ERR_FORMAT;

	share->x = payload[1];
	share->len = payload[2];
	if (share->len < 1 || share->len > SHAMIR_MAX_SECRET) return SHARECODE_ERR_FORMAT;
	if (3 + share->len > pn) return SHARECODE_ERR_FORMAT;
	memcpy (share->y, payload + 3, (size_t) share->len);

	macLen = pn - (3 + share->len);
	if (macLen == SHARECODE_MAC_SIZE)
	{
		if (macOut) memcpy (macOut, payload + 3 + share->len, SHARECODE_MAC_SIZE);
		if (hasMac) *hasMac = 1;
	}
	else if (macLen == 0)
	{
		if (hasMac) *hasMac = 0;
	}
	else
	{
		return SHARECODE_ERR_FORMAT;
	}
	{ volatile unsigned char *p = payload; size_t z = sizeof (payload); while (z--) *p++ = 0; }
	return SHARECODE_OK;
}

/* ================= codex32 (BIP-93): ms32 error-correcting checksum + envelope =======================
 *
 * ms32 is a BCH code over GF(32) with a register wider than 64 bits — 65 bits for the regular (13-symbol)
 * checksum, ~76 bits for the long (15-symbol) one — so the residue is carried in an explicit two-word
 * {hi,lo} pair (no __int128 dependency; portable to every target). The generator/constant values and the
 * initial residue 0x23181b3 (which folds in the fixed "ms" HRP) are the BIP-93 reference values verbatim.
 */

typedef struct { uint64 hi, lo; } sc_u128;

/* regular checksum (13 symbols): 65-bit register */
static const sc_u128 MS32_GEN[5] = {
	{ 0x1u, 0x9dc500ce73fde210ULL }, { 0x1u, 0xbfae00def77fe529ULL },
	{ 0x1u, 0xfbd920fffe7bee52ULL }, { 0x1u, 0x739640bdeee3fdadULL },
	{ 0x0u, 0x7729a039cfc75f5aULL }
};
#define MS32_CONST_HI  0x1u
#define MS32_CONST_LO  0x0ce0795c2fd1e62aULL

/* long checksum (15 symbols): ~76-bit register */
static const sc_u128 MS32_GEN_LONG[5] = {
	{ 0x3d5u, 0x9d273535ea62d897ULL }, { 0x7a9u, 0xbecb6361c6c51507ULL },
	{ 0x543u, 0xf9b7e6c38d8a2a0eULL }, { 0x0c5u, 0x77eaeccf1990d13cULL },
	{ 0x188u, 0x7f74f8dc71b10651ULL }
};
#define MS32_LONG_CONST_HI  0x433u
#define MS32_LONG_CONST_LO  0x81e570bf4798ab26ULL

#define MS32_CSUM_SHORT  13
#define MS32_CSUM_LONG   15
#define MS32_LONG_DATA_THRESHOLD  80   /* data part (excl. checksum) longer than this -> long checksum */

/* symbol values -> ms32 residue (two-word). isLong selects register width / generator / mask. */
static sc_u128 ms32_polymod (const unsigned char *v, int n, int isLong)
{
	sc_u128 r;
	const sc_u128 *GEN = isLong ? MS32_GEN_LONG : MS32_GEN;
	int topshift = isLong ? 70 : 60;
	uint64 mask_hi = isLong ? 0x3fULL : 0x0ULL;
	uint64 mask_lo = isLong ? 0xffffffffffffffffULL : 0x0fffffffffffffffULL;
	int i, j;
	r.hi = 0; r.lo = 0x23181b3ULL;
	for (i = 0; i < n; i++)
	{
		uint64 b, mlo, mhi;
		if (topshift >= 64) b = (r.hi >> (topshift - 64)) & 31u;
		else                b = ((r.hi << (64 - topshift)) | (r.lo >> topshift)) & 31u;
		mlo = r.lo & mask_lo; mhi = r.hi & mask_hi;
		r.hi = (mhi << 5) | (mlo >> 59);
		r.lo = (mlo << 5);
		r.lo ^= v[i];
		for (j = 0; j < 5; j++)
			if ((b >> j) & 1u) { r.hi ^= GEN[j].hi; r.lo ^= GEN[j].lo; }
	}
	return r;
}

/* extract the 5-bit group at bit position p from a two-word residue */
static unsigned int ms32_extract5 (sc_u128 r, int p)
{
	if (p >= 64) return (unsigned int) ((r.hi >> (p - 64)) & 31u);
	if (p > 59)  return (unsigned int) (((r.lo >> p) | (r.hi << (64 - p))) & 31u);
	return (unsigned int) ((r.lo >> p) & 31u);
}

/* lowercase a single ASCII char */
static char sc_tolower (char c) { return (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c; }

/* 5-bit groups -> 8-bit bytes, codex32 style: DISCARD the final incomplete group (BIP-93: "Any
   incomplete group at the end MUST be 4 bits or less, and is discarded") rather than requiring the
   pad bits to be zero — codex32 payloads are not canonical on those trailing bits. Returns byte
   count, or -1 if a full (>=5-bit) leftover group remains (malformed). */
static int sc_from5_trunc (const unsigned char *data, int n, unsigned char *out, int outCap)
{
	uint32 acc = 0;
	int bits = 0, count = 0, i;
	for (i = 0; i < n; i++)
	{
		acc = (acc << 5) | data[i];
		bits += 5;
		while (bits >= 8)
		{
			bits -= 8;
			if (count >= outCap) return -1;
			out[count++] = (unsigned char) ((acc >> bits) & 0xff);
		}
	}
	if (bits >= 5) return -1;   /* a whole leftover symbol => malformed */
	return count;
}

int ShareCodeCodex32Encode (int k, const char id[4], char shareIndex,
                            const unsigned char *payload, int payloadLen, char *out, int outCap)
{
	unsigned char data[SHARECODE_CODEX32_MAX_LEN];
	unsigned char work[SHARECODE_CODEX32_MAX_LEN];
	int ndata = 0, n5, i, v, isLong, csumLen, total, pos;
	sc_u128 pm;

	if (!id || !payload || !out || payloadLen < 1) return SHARECODE_ERR_PARAM;
	if (!(k == 0 || (k >= 2 && k <= 9))) return SHARECODE_ERR_PARAM;   /* k==1 invalid (BIP-93) */

	v = sc_charval ((char) ('0' + k)); if (v < 0) return SHARECODE_ERR_PARAM;
	data[ndata++] = (unsigned char) v;
	for (i = 0; i < 4; i++) { v = sc_charval (sc_tolower (id[i])); if (v < 0) return SHARECODE_ERR_PARAM; data[ndata++] = (unsigned char) v; }
	v = sc_charval (sc_tolower (shareIndex)); if (v < 0) return SHARECODE_ERR_PARAM; data[ndata++] = (unsigned char) v;

	n5 = sc_to5 (payload, payloadLen, data + ndata, SHARECODE_CODEX32_MAX_LEN - ndata);
	if (n5 < 0) return SHARECODE_ERR_PARAM;
	ndata += n5;

	isLong = ndata > MS32_LONG_DATA_THRESHOLD;
	csumLen = isLong ? MS32_CSUM_LONG : MS32_CSUM_SHORT;
	if (ndata + csumLen > SHARECODE_CODEX32_MAX_LEN) return SHARECODE_ERR_PARAM;

	memcpy (work, data, (size_t) ndata);
	for (i = 0; i < csumLen; i++) work[ndata + i] = 0;
	pm = ms32_polymod (work, ndata + csumLen, isLong);
	if (isLong) { pm.hi ^= MS32_LONG_CONST_HI; pm.lo ^= MS32_LONG_CONST_LO; }
	else        { pm.hi ^= MS32_CONST_HI;      pm.lo ^= MS32_CONST_LO; }

	total = 2 + 1 + ndata + csumLen + 1;   /* "ms" + "1" + data + checksum + NUL */
	if (total > outCap) return SHARECODE_ERR_PARAM;
	pos = 0; out[pos++] = 'm'; out[pos++] = 's'; out[pos++] = '1';
	for (i = 0; i < ndata; i++) out[pos++] = SC_CHARSET[data[i]];
	for (i = 0; i < csumLen; i++) out[pos++] = SC_CHARSET[ms32_extract5 (pm, 5 * (csumLen - 1 - i))];
	out[pos] = '\0';
	return SHARECODE_OK;
}

int ShareCodeCodex32Decode (const char *str, int *k, char id[4], char *shareIndex,
                            unsigned char *payload, int payloadCap, int *payloadLen)
{
	unsigned char data[SHARECODE_CODEX32_MAX_LEN];
	int slen, dlen, isLong, csumLen, i, v, npay5, pn, kv;
	sc_u128 chk;

	if (!str) return SHARECODE_ERR_PARAM;
	slen = (int) strlen (str);
	if (slen < 3 || slen > SHARECODE_CODEX32_MAX_LEN - 1) return SHARECODE_ERR_FORMAT;
	if (sc_tolower (str[0]) != 'm' || sc_tolower (str[1]) != 's' || str[2] != '1') return SHARECODE_ERR_FORMAT;

	dlen = slen - 3;
	if (dlen > SHARECODE_CODEX32_MAX_LEN) return SHARECODE_ERR_FORMAT;
	isLong = dlen >= 96;
	csumLen = isLong ? MS32_CSUM_LONG : MS32_CSUM_SHORT;
	if (dlen < 6 + 1 + csumLen) return SHARECODE_ERR_FORMAT;   /* k+id+index + >=1 payload + checksum */

	for (i = 0; i < dlen; i++)
	{
		v = sc_charval (sc_tolower (str[3 + i]));
		if (v < 0) return SHARECODE_ERR_FORMAT;
		data[i] = (unsigned char) v;
	}

	chk = ms32_polymod (data, dlen, isLong);
	if (isLong) { if (chk.hi != MS32_LONG_CONST_HI || chk.lo != MS32_LONG_CONST_LO) return SHARECODE_ERR_CHECKSUM; }
	else        { if (chk.hi != MS32_CONST_HI      || chk.lo != MS32_CONST_LO)      return SHARECODE_ERR_CHECKSUM; }

	kv = (unsigned char) sc_tolower (str[3]);
	if (kv < '0' || kv > '9' || kv == '1') return SHARECODE_ERR_FORMAT;
	if (k) *k = kv - '0';
	if (id) for (i = 0; i < 4; i++) id[i] = sc_tolower (str[3 + 1 + i]);
	if (shareIndex) *shareIndex = sc_tolower (str[3 + 5]);

	npay5 = dlen - csumLen - 6;
	pn = sc_from5_trunc (data + 6, npay5, payload, payloadCap);
	if (pn < 1) return SHARECODE_ERR_FORMAT;
	if (payloadLen) *payloadLen = pn;
	return SHARECODE_OK;
}

#endif /* VC_ENABLE_SHARECODE */
