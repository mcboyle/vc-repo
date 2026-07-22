/*
 * KeyslotStore — see KeyslotStore.h. Three backends over one KeyslotArea.
 *
 * Labeled record (KSB_HEADER / KSB_SIDECAR), within a KEYSLOT_TABLE_STRIDE slot:
 *     magic[4]="VCKS" ver[1] kdf[1] rsv[2] cost[4] plen[2] salt[32] ct[plen] tag[32] <random pad>
 *   occupancy is the plaintext magic; aad (authenticated by the tag) = the 46 header+salt bytes.
 *
 * Anti-forensic records (cfg->afStripes = s >= 2, docs/AF-SPLIT-SPEC.md): the payload is AF-split
 * into s stripes before wrapping, so ct grows to s*plen and a partial remnant of a slot yields
 * nothing. Labeled AF records carry ver=2 and s in the (authenticated) rsv field; like 'cost', the
 * stored copy is informational — the operative value is the public config, so the constant-time
 * search's per-slot work is fixed and never sized from record bytes. Bare records stay field-free.
 *
 * Bare record (KSB_DENIABLE), within a slot located from the passphrase:
 *     salt[32] ct[plen] tag[32]   — no plaintext markers, indistinguishable from random free-space.
 *   aad = "VCKSbare" || salt. The slot index is H(passphrase) mod nSlots, so distinct passphrases
 *   take distinct slots (collisions handled as documented in docs/KEYSLOTS-SPEC.md §3b).
 *
 * The wrapped payload is flags[1] || vmk, so slot flags are encrypted, not marked in the clear.
 */

#include "KeyslotStore.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include <string.h>
#include "AfSplit.h"
#include "Crypto/Sha2.h"

/* labeled header field offsets */
#define L_MAGIC 0
#define L_VER   4
#define L_KDF   5
#define L_RSV   6
#define L_COST  8
#define L_PLEN  12
#define L_SALT  14
#define L_CT    (L_SALT + KEYSLOT_SALT_SIZE)   /* 46 */
#define L_AAD_LEN L_CT                          /* magic..salt authenticated */

/* bare record offsets */
#define B_SALT 0
#define B_CT   (B_SALT + KEYSLOT_SALT_SIZE)     /* 32 */

static const unsigned char KS_BARE_DOMAIN[8] = { 'V','C','K','S','b','a','r','e' };

static void ks_wipe (volatile unsigned char *p, size_t n) { while (n--) *p++ = 0; }
static void put_u16 (unsigned char *p, unsigned v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); }
static void put_u32 (unsigned char *p, unsigned v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }

static int is_labeled (KeyslotBackend b) { return b == KSB_HEADER || b == KSB_SIDECAR; }

#if defined(VC_ENABLE_KEYSLOT_POLICY)
#define KS_EXPIRY_BYTES 8                          /* v2 payload inserts expiryUnix[8] after flags[1] */
static void put_u64_be (unsigned char *p, uint64 v)
{
	int i; for (i = 7; i >= 0; i--) { p[i] = (unsigned char) (v & 0xff); v >>= 8; }
}
static uint64 get_u64_be (const unsigned char *p)
{
	uint64 v = 0; int i; for (i = 0; i < 8; i++) v = (v << 8) | p[i]; return v;
}
#endif
/* v1 payload = flags[1] || vmk ; v2 (policy) payload = flags[1] || expiryUnix[8] || vmk */
static int plen_of (const KeyslotStoreCfg *cfg)
{
#if defined(VC_ENABLE_KEYSLOT_POLICY)
	if (cfg->policy) return cfg->vmkLen + 1 + KS_EXPIRY_BYTES;
#endif
	return cfg->vmkLen + 1;
}
/* max payload buffer size (holds either version). */
#define KS_PAYLOAD_MAX (KEYSLOT_VMK_MAX + 1 + 8)

/* AF stripe count s (public, like cost); 0/1 = off. ct_of = the wrapped blob length s*plen. */
static int af_of (const KeyslotStoreCfg *cfg) { return (cfg->afStripes >= 2) ? cfg->afStripes : 1; }
static int ct_of (const KeyslotStoreCfg *cfg) { return plen_of (cfg) * af_of (cfg); }

#if defined(VC_ENABLE_KEYSLOT_POLICY)
/* Cleartext policy trailer in the slot's random pad (after ct+tag): "KP" || maxAttempts || attempts.
   Necessarily UNAUTHENTICATED (the counter must change without the key) — hence rollback-defeatable,
   as documented. Only written/read for labeled policy slots. */
#define KS_POL_MARK0 'K'
#define KS_POL_MARK1 'P'
static int ks_pol_off (const KeyslotStoreCfg *cfg) { return L_CT + ct_of (cfg) + KEYSLOT_TAG_SIZE; }
static int ks_pol_fits (const KeyslotStoreCfg *cfg) { return ks_pol_off (cfg) + 4 <= KEYSLOT_TABLE_STRIDE; }
#endif

static int rec_fits (const KeyslotStoreCfg *cfg)
{
	int base = is_labeled (cfg->backend) ? L_CT : B_CT;
	return base + ct_of (cfg) + KEYSLOT_TAG_SIZE <= KEYSLOT_TABLE_STRIDE;
}

static uint64 n_slots (const KeyslotStoreCfg *cfg, KeyslotArea *area)
{
	uint64 bySize = area->size (area->ctx) / KEYSLOT_TABLE_STRIDE;
	uint64 byCfg  = (cfg->maxSlots > 0) ? (uint64) cfg->maxSlots : bySize;
	return (bySize < byCfg) ? bySize : byCfg;
}

/* deniable slot index = H("VCKSloc" || pass) mod nSlots */
static uint64 deniable_index (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                              const unsigned char *pass, int passLen)
{
	unsigned char h[32], buf[7 + 512];
	uint64 idx, ns = n_slots (cfg, area);
	int n = 0, i;
	const char *dom = "VCKSloc";
	if (ns == 0) return 0;
	for (i = 0; i < 7; i++) buf[n++] = (unsigned char) dom[i];
	if (passLen > 512) passLen = 512;
	memcpy (buf + n, pass, passLen); n += passLen;
	sha256 (h, buf, (unsigned int) n);
	idx = ((uint64) h[0] | ((uint64) h[1] << 8) | ((uint64) h[2] << 16) | ((uint64) h[3] << 24)) % ns;
	ks_wipe (buf, sizeof (buf));
	return idx;
}

/* ---- add ---- */

static int labeled_first_free (const KeyslotStoreCfg *cfg, KeyslotArea *area)
{
	unsigned char hdr[L_CT];
	uint64 i, ns = n_slots (cfg, area);
	for (i = 0; i < ns; i++)
	{
		if (area->read (area->ctx, i * KEYSLOT_TABLE_STRIDE, hdr, sizeof (hdr)) != 0)
			return -1;
		if (memcmp (hdr, "VCKS", 4) != 0)
			return (int) i;
	}
	return -1;
}

int KeyslotAdd (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                const unsigned char *pass, int passLen, int flags,
                const unsigned char *vmk)
{
	int plen = plen_of (cfg), s = af_of (cfg), ct = ct_of (cfg);
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	unsigned char payload[KS_PAYLOAD_MAX];
	unsigned char blob[KEYSLOT_TABLE_STRIDE];
	unsigned char salt[KEYSLOT_SALT_SIZE];
	int idx;
	uint64 off;

	if (cfg->vmkLen <= 0 || cfg->vmkLen > KEYSLOT_VMK_MAX || !rec_fits (cfg))
		return -1;

	cfg->randBytes (salt, sizeof (salt));
	payload[0] = (unsigned char) flags;
	memcpy (payload + 1, vmk, cfg->vmkLen);

	/* fill the whole slot with random first, so unused tail bytes are indistinguishable from fill */
	cfg->randBytes (rec, sizeof (rec));

	/* AF-split the payload into s stripes (s == 1 is the identity), then wrap the stripe blob */
	if (AfSplit (payload, plen, s, cfg->randBytes, blob) != 0)
	{
		ks_wipe (payload, sizeof (payload));
		return -1;
	}

	if (is_labeled (cfg->backend))
	{
		unsigned char aad[L_CT];
		idx = labeled_first_free (cfg, area);
		if (idx < 0)
		{
			ks_wipe (payload, sizeof (payload));
			ks_wipe (blob, sizeof (blob));
			return -1;
		}
		off = (uint64) idx * KEYSLOT_TABLE_STRIDE;

		memcpy (rec + L_MAGIC, "VCKS", 4);
		rec[L_VER] = (unsigned char) ((s >= 2) ? 2 : 1);
		rec[L_KDF] = 1;
		if (s >= 2)
			put_u16 (rec + L_RSV, (unsigned) s);   /* authenticated via the aad; informational like cost */
		else
		{
			rec[L_RSV] = 0; rec[L_RSV + 1] = 0;
		}
		put_u32 (rec + L_COST, cfg->cost);
		put_u16 (rec + L_PLEN, (unsigned) plen);
		memcpy (rec + L_SALT, salt, KEYSLOT_SALT_SIZE);
		memcpy (aad, rec, L_AAD_LEN);
		KeyslotWrap (cfg->kdf, cfg->cost, pass, passLen, salt, KEYSLOT_SALT_SIZE,
		             aad, L_AAD_LEN, blob, ct, rec + L_CT, rec + L_CT + ct);
	}
	else /* KSB_DENIABLE */
	{
		unsigned char aad[8 + KEYSLOT_SALT_SIZE];
		idx = (int) deniable_index (cfg, area, pass, passLen);
		off = (uint64) idx * KEYSLOT_TABLE_STRIDE;
		memcpy (rec + B_SALT, salt, KEYSLOT_SALT_SIZE);
		memcpy (aad, KS_BARE_DOMAIN, 8);
		memcpy (aad + 8, salt, KEYSLOT_SALT_SIZE);
		KeyslotWrap (cfg->kdf, cfg->cost, pass, passLen, salt, KEYSLOT_SALT_SIZE,
		             aad, sizeof (aad), blob, ct, rec + B_CT, rec + B_CT + ct);
	}

	if (area->write (area->ctx, off, rec, sizeof (rec)) != 0)
		idx = -1;

	ks_wipe (payload, sizeof (payload));
	ks_wipe (blob, sizeof (blob));
	ks_wipe (rec, sizeof (rec));
	ks_wipe (salt, sizeof (salt));
	return idx;
}

/* ---- open ---- */


int KeyslotOpen (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                 const unsigned char *pass, int passLen,
                 unsigned char *vmkOut, int *flagsOut)
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	int plen = plen_of (cfg), s = af_of (cfg), ct = ct_of (cfg);

	if (!rec_fits (cfg))
		return 0;

	if (is_labeled (cfg->backend))
	{
		/* Constant-time slot search: scan a fixed number of slots (the config's table size, a public
		   value), run the KDF and MAC on EVERY slot regardless of the "VCKS" marker, and select the
		   result in constant time with no early return. This leaks neither which slot matched nor how
		   many are populated. The KDF cost, payload length and AF stripe count come from the config
		   (public), never from the possibly-random slot bytes, so the per-slot work is fixed and a
		   garbage slot cannot force a huge iteration count. Cost: one KDF per table slot per open (the
		   LUKS trade-off). The AF merge runs once on the selected stripe blob, after the scan. */
		unsigned char aad[L_AAD_LEN];
		unsigned char tmp[KEYSLOT_TABLE_STRIDE], selp[KEYSLOT_TABLE_STRIDE];
		unsigned char payload[KS_PAYLOAD_MAX];
		uint64 i, ns = n_slots (cfg, area);
		int found = 0, b;

		memset (selp, 0, sizeof (selp));
		for (i = 0; i < ns; i++)
		{
			int m, sel; unsigned char mask;
			if (area->read (area->ctx, i * KEYSLOT_TABLE_STRIDE, rec, sizeof (rec)) != 0)
				continue;
			memcpy (aad, rec, L_AAD_LEN);
			m = KeyslotUnwrapCT (cfg->kdf, cfg->cost, pass, passLen, rec + L_SALT, KEYSLOT_SALT_SIZE,
			                     aad, L_AAD_LEN, rec + L_CT, ct, rec + L_CT + ct, tmp);
			sel  = m & (found ^ 1);                       /* take the first match only */
			mask = (unsigned char) (0u - (unsigned) sel);
			for (b = 0; b < ct; b++)
				selp[b] = (unsigned char) ((selp[b] & ~mask) | (tmp[b] & mask));
			found |= m;
		}
		if (found)
		{
			AfMerge (selp, plen, s, payload);
			if (flagsOut) *flagsOut = payload[0];
			memcpy (vmkOut, payload + 1, cfg->vmkLen);
			ks_wipe (payload, sizeof (payload));
		}
		ks_wipe (tmp, sizeof (tmp));
		ks_wipe (selp, sizeof (selp));
		ks_wipe (rec, sizeof (rec));
		return found;
	}
	else /* KSB_DENIABLE: the passphrase-derived slot (a single always-decrypt unwrap) */
	{
		unsigned char aad[8 + KEYSLOT_SALT_SIZE], blob[KEYSLOT_TABLE_STRIDE];
		unsigned char payload[KS_PAYLOAD_MAX];
		uint64 off = deniable_index (cfg, area, pass, passLen) * KEYSLOT_TABLE_STRIDE;
		int ok;
		if (area->read (area->ctx, off, rec, sizeof (rec)) != 0)
			return 0;
		memcpy (aad, KS_BARE_DOMAIN, 8);
		memcpy (aad + 8, rec + B_SALT, KEYSLOT_SALT_SIZE);
		ok = KeyslotUnwrapCT (cfg->kdf, cfg->cost, pass, passLen, rec + B_SALT, KEYSLOT_SALT_SIZE,
		                      aad, sizeof (aad), rec + B_CT, ct, rec + B_CT + ct, blob);
		if (ok)
		{
			AfMerge (blob, plen, s, payload);
			if (flagsOut) *flagsOut = payload[0];
			memcpy (vmkOut, payload + 1, cfg->vmkLen);
		}
		ks_wipe (payload, sizeof (payload));
		ks_wipe (blob, sizeof (blob));
		ks_wipe (rec, sizeof (rec));
		return ok;
	}
}

/* ---- indexed open (admin-side; rotate/list-owned) ---- */

/* Open EXACTLY labeled-table slot 'index' with 'pass'. Unlike KeyslotOpen (the mount path, which is
   constant-time and hides which slot matched), this deliberately reveals per-index success so an admin
   holding the passphrase can locate the slot to revoke during rotation. Returns 1 and fills vmkOut on a
   match, 0 otherwise (empty slot / wrong pass / out of range). Labeled backends only. */
int KeyslotOpenAt (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index,
                   const unsigned char *pass, int passLen,
                   unsigned char *vmkOut, int *flagsOut)
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	unsigned char aad[L_AAD_LEN], tmp[KEYSLOT_TABLE_STRIDE];
	unsigned char payload[KS_PAYLOAD_MAX];
	int plen = plen_of (cfg), s = af_of (cfg), ct = ct_of (cfg), m;

	if (!is_labeled (cfg->backend) || !rec_fits (cfg))
		return 0;
	if (index < 0 || (uint64) index >= n_slots (cfg, area))
		return 0;
	if (area->read (area->ctx, (uint64) index * KEYSLOT_TABLE_STRIDE, rec, sizeof (rec)) != 0)
		return 0;
	if (memcmp (rec, "VCKS", 4) != 0)
		return 0;   /* empty/random slot */

	memcpy (aad, rec, L_AAD_LEN);
	m = KeyslotUnwrapCT (cfg->kdf, cfg->cost, pass, passLen, rec + L_SALT, KEYSLOT_SALT_SIZE,
	                     aad, L_AAD_LEN, rec + L_CT, ct, rec + L_CT + ct, tmp);
	if (m)
	{
		AfMerge (tmp, plen, s, payload);
		if (flagsOut) *flagsOut = payload[0];
		memcpy (vmkOut, payload + 1, cfg->vmkLen);
	}
	ks_wipe (payload, sizeof (payload));
	ks_wipe (tmp, sizeof (tmp));
	ks_wipe (rec, sizeof (rec));
	return m;
}

/* ---- revoke / count ---- */

int KeyslotRevoke (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index)
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	if (index < 0 || (uint64) index >= n_slots (cfg, area))
		return -1;
	cfg->randBytes (rec, sizeof (rec));   /* overwrite with fresh random: no residual wrapping */
	return area->write (area->ctx, (uint64) index * KEYSLOT_TABLE_STRIDE, rec, sizeof (rec));
}

#if defined(VC_ENABLE_KEYSLOT_SHRED)
int KeyslotShred (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index,
                  unsigned char attestation[32])
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	unsigned char hOld[32], hNew[32];
	unsigned char msg[10 + 4 + 32 + 32];
	uint64 off;

	if (index < 0 || (uint64) index >= n_slots (cfg, area))
		return -1;
	off = (uint64) index * KEYSLOT_TABLE_STRIDE;

	if (area->read (area->ctx, off, rec, sizeof (rec)) != 0)      /* hash the slot BEFORE */
		return -1;
	sha256 (hOld, rec, sizeof (rec));

	cfg->randBytes (rec, sizeof (rec));                            /* overwrite the ENTIRE stride */
	if (area->write (area->ctx, off, rec, sizeof (rec)) != 0)
		return -1;

	if (area->read (area->ctx, off, rec, sizeof (rec)) != 0)      /* read back what ACTUALLY landed */
		return -1;
	sha256 (hNew, rec, sizeof (rec));

	/* attestation = SHA256("VCKSSHRED1" || index_be32 || H(before) || H(after)) */
	memcpy (msg, "VCKSSHRED1", 10);
	msg[10] = (unsigned char) (index >> 24); msg[11] = (unsigned char) (index >> 16);
	msg[12] = (unsigned char) (index >> 8);  msg[13] = (unsigned char) index;
	memcpy (msg + 14, hOld, 32);
	memcpy (msg + 46, hNew, 32);
	sha256 (attestation, msg, sizeof (msg));

	ks_wipe (rec, sizeof (rec));
	return 0;
}
#endif

int KeyslotCount (const KeyslotStoreCfg *cfg, KeyslotArea *area)
{
	unsigned char hdr[4];
	uint64 i, ns;
	int count = 0;
	if (!is_labeled (cfg->backend))
		return 0;   /* deniable slots are not enumerable without their passphrase, by design */
	ns = n_slots (cfg, area);
	for (i = 0; i < ns; i++)
	{
		if (area->read (area->ctx, i * KEYSLOT_TABLE_STRIDE, hdr, sizeof (hdr)) != 0)
			continue;
		if (memcmp (hdr, "VCKS", 4) == 0)
			count++;
	}
	return count;
}

#if defined(VC_ENABLE_KEYSLOT_POLICY)
/* ---- per-slot policy (ROI item 15; docs/KEYSLOT-POLICY-DESIGN.md) ---- */

int KeyslotAddPolicy (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                      const unsigned char *pass, int passLen, int flags,
                      const unsigned char *vmk, uint64 expiryUnix, int maxAttempts)
{
	int plen = plen_of (cfg), s = af_of (cfg), ct = ct_of (cfg), p;
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	unsigned char payload[KS_PAYLOAD_MAX];
	unsigned char blob[KEYSLOT_TABLE_STRIDE];
	unsigned char salt[KEYSLOT_SALT_SIZE];
	unsigned char aad[L_CT];
	int idx;
	uint64 off;

	if (!cfg->policy || !is_labeled (cfg->backend))          /* policy: v2 + labeled backends only */
		return -1;
	if (cfg->vmkLen <= 0 || cfg->vmkLen > KEYSLOT_VMK_MAX || !rec_fits (cfg) || !ks_pol_fits (cfg))
		return -1;
	if (maxAttempts < 0 || maxAttempts > 255)
		return -1;

	cfg->randBytes (salt, sizeof (salt));
	/* v2 payload: flags[1] || expiryUnix[8] || vmk (read-only bit lives in flags, authenticated+hidden) */
	payload[0] = (unsigned char) flags;
	put_u64_be (payload + 1, expiryUnix);
	memcpy (payload + 1 + KS_EXPIRY_BYTES, vmk, cfg->vmkLen);

	cfg->randBytes (rec, sizeof (rec));                       /* random-fill the whole slot first */

	if (AfSplit (payload, plen, s, cfg->randBytes, blob) != 0)
	{
		ks_wipe (payload, sizeof (payload));
		return -1;
	}

	idx = labeled_first_free (cfg, area);
	if (idx < 0)
	{
		ks_wipe (payload, sizeof (payload));
		ks_wipe (blob, sizeof (blob));
		return -1;
	}
	off = (uint64) idx * KEYSLOT_TABLE_STRIDE;

	memcpy (rec + L_MAGIC, "VCKS", 4);
	rec[L_VER] = (unsigned char) ((s >= 2) ? 2 : 1);
	rec[L_KDF] = 1;
	if (s >= 2) put_u16 (rec + L_RSV, (unsigned) s);
	else { rec[L_RSV] = 0; rec[L_RSV + 1] = 0; }
	put_u32 (rec + L_COST, cfg->cost);
	put_u16 (rec + L_PLEN, (unsigned) plen);
	memcpy (rec + L_SALT, salt, KEYSLOT_SALT_SIZE);
	memcpy (aad, rec, L_AAD_LEN);
	KeyslotWrap (cfg->kdf, cfg->cost, pass, passLen, salt, KEYSLOT_SALT_SIZE,
	             aad, L_AAD_LEN, blob, ct, rec + L_CT, rec + L_CT + ct);

	/* cleartext policy trailer in the pad (unauthenticated; rollback-defeatable, as documented) */
	p = ks_pol_off (cfg);
	rec[p] = KS_POL_MARK0; rec[p + 1] = KS_POL_MARK1;
	rec[p + 2] = (unsigned char) maxAttempts; rec[p + 3] = 0;   /* attempts starts at 0 */

	if (area->write (area->ctx, off, rec, sizeof (rec)) != 0)
		idx = -1;

	ks_wipe (payload, sizeof (payload));
	ks_wipe (blob, sizeof (blob));
	ks_wipe (rec, sizeof (rec));
	ks_wipe (salt, sizeof (salt));
	return idx;
}

int KeyslotOpenPolicy (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                       const unsigned char *pass, int passLen, uint64 nowUnix,
                       unsigned char *vmkOut, int *flagsOut, uint64 *expiryOut)
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE], aad[L_AAD_LEN];
	unsigned char tmp[KEYSLOT_TABLE_STRIDE], selp[KEYSLOT_TABLE_STRIDE];
	unsigned char payload[KS_PAYLOAD_MAX];
	int plen = plen_of (cfg), s = af_of (cfg), ct = ct_of (cfg);
	uint64 i, ns;
	int found = 0, b, rc = 0;

	if (!cfg->policy || !is_labeled (cfg->backend) || !rec_fits (cfg))
		return 0;
	ns = n_slots (cfg, area);
	memset (selp, 0, sizeof (selp));
	for (i = 0; i < ns; i++)                                  /* same constant-time scan as KeyslotOpen */
	{
		int m, sel; unsigned char mask;
		if (area->read (area->ctx, i * KEYSLOT_TABLE_STRIDE, rec, sizeof (rec)) != 0)
			continue;
		memcpy (aad, rec, L_AAD_LEN);
		m = KeyslotUnwrapCT (cfg->kdf, cfg->cost, pass, passLen, rec + L_SALT, KEYSLOT_SALT_SIZE,
		                     aad, L_AAD_LEN, rec + L_CT, ct, rec + L_CT + ct, tmp);
		sel  = m & (found ^ 1);
		mask = (unsigned char) (0u - (unsigned) sel);
		for (b = 0; b < ct; b++)
			selp[b] = (unsigned char) ((selp[b] & ~mask) | (tmp[b] & mask));
		found |= m;
	}
	if (found)
	{
		uint64 expiry;
		AfMerge (selp, plen, s, payload);
		expiry = get_u64_be (payload + 1);
		if (nowUnix != 0 && expiry != 0 && nowUnix > expiry)
			rc = 0;                                          /* expired: silent, as if no match */
		else
		{
			if (flagsOut)  *flagsOut  = payload[0];
			if (expiryOut) *expiryOut = expiry;
			memcpy (vmkOut, payload + 1 + KS_EXPIRY_BYTES, cfg->vmkLen);
			rc = 1;
		}
		ks_wipe (payload, sizeof (payload));
	}
	ks_wipe (tmp, sizeof (tmp));
	ks_wipe (selp, sizeof (selp));
	ks_wipe (rec, sizeof (rec));
	return rc;
}

int KeyslotOpenAtPolicy (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index,
                         const unsigned char *pass, int passLen, uint64 nowUnix,
                         unsigned char *vmkOut, int *flagsOut,
                         int *attemptsOut, int *maxAttemptsOut)
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE], aad[L_AAD_LEN], tmp[KEYSLOT_TABLE_STRIDE];
	unsigned char payload[KS_PAYLOAD_MAX];
	int plen = plen_of (cfg), s = af_of (cfg), ct = ct_of (cfg), m, p, maxA, attA, rc;
	uint64 off;

	if (!cfg->policy || !is_labeled (cfg->backend) || !rec_fits (cfg) || !ks_pol_fits (cfg))
		return 0;
	if (index < 0 || (uint64) index >= n_slots (cfg, area))
		return 0;
	off = (uint64) index * KEYSLOT_TABLE_STRIDE;
	if (area->read (area->ctx, off, rec, sizeof (rec)) != 0)
		return 0;
	if (memcmp (rec, "VCKS", 4) != 0)
		return 0;                                            /* empty/random slot */

	p = ks_pol_off (cfg);
	if (rec[p] == KS_POL_MARK0 && rec[p + 1] == KS_POL_MARK1) { maxA = rec[p + 2]; attA = rec[p + 3]; }
	else { maxA = 0; attA = 0; }
	if (maxAttemptsOut) *maxAttemptsOut = maxA;

	if (maxA > 0 && attA >= maxA)                            /* locked out — refuse without trying */
	{
		if (attemptsOut) *attemptsOut = attA;
		ks_wipe (rec, sizeof (rec));
		return KEYSLOT_LOCKED;
	}

	memcpy (aad, rec, L_AAD_LEN);
	m = KeyslotUnwrapCT (cfg->kdf, cfg->cost, pass, passLen, rec + L_SALT, KEYSLOT_SALT_SIZE,
	                     aad, L_AAD_LEN, rec + L_CT, ct, rec + L_CT + ct, tmp);
	if (!m)                                                  /* wrong pass: increment + write back */
	{
		if (rec[p] == KS_POL_MARK0 && rec[p + 1] == KS_POL_MARK1 && attA < 255)
		{
			attA++;
			rec[p + 3] = (unsigned char) attA;
			(void) area->write (area->ctx, off, rec, sizeof (rec));
		}
		if (attemptsOut) *attemptsOut = attA;
		ks_wipe (tmp, sizeof (tmp));
		ks_wipe (rec, sizeof (rec));
		return 0;
	}

	AfMerge (tmp, plen, s, payload);
	{
		uint64 expiry = get_u64_be (payload + 1);
		if (nowUnix != 0 && expiry != 0 && nowUnix > expiry)
			rc = 0;                                          /* correct pass but expired: silent */
		else
		{
			if (flagsOut) *flagsOut = payload[0];
			memcpy (vmkOut, payload + 1 + KS_EXPIRY_BYTES, cfg->vmkLen);
			rc = 1;
			if (rec[p] == KS_POL_MARK0 && rec[p + 1] == KS_POL_MARK1 && attA != 0)
			{
				rec[p + 3] = 0;                              /* reset the counter on success */
				(void) area->write (area->ctx, off, rec, sizeof (rec));
				attA = 0;
			}
		}
	}
	if (attemptsOut) *attemptsOut = attA;
	ks_wipe (payload, sizeof (payload));
	ks_wipe (tmp, sizeof (tmp));
	ks_wipe (rec, sizeof (rec));
	return rc;
}
#endif /* VC_ENABLE_KEYSLOT_POLICY */

#endif /* VC_ENABLE_KEYSLOTS */
