/*
 * ShareCode — see ShareCode.h. Straight BIP-173 bech32: the 32-char charset, the 5-term BCH
 * generator, hrp-expand, polymod, and 8->5 bit conversion, over the fixed hrp "vcs".
 */

#include "ShareCode.h"

#if defined(VC_ENABLE_SHARECODE)

#include <string.h>

static const char *SC_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const char *SC_HRP = "vcs";
#define SC_HRP_LEN 3

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

	/* checksum = polymod(hrp_expand || data || 000000) ^ 1 */
	hn = sc_hrp_expand (chkin);
	memcpy (chkin + hn, five, (size_t) n5);
	for (i = 0; i < 6; i++) chkin[hn + n5 + i] = 0;
	pm = sc_polymod (chkin, hn + n5 + 6) ^ 1u;

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

	/* verify: polymod(hrp_expand || data(incl checksum)) == 1 */
	hn = sc_hrp_expand (chkin);
	memcpy (chkin + hn, five, (size_t) dataLen);
	if (sc_polymod (chkin, hn + dataLen) != 1u)
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

#endif /* VC_ENABLE_SHARECODE */
