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

static int plen_of (const KeyslotStoreCfg *cfg) { return cfg->vmkLen + 1; }   /* flags[1] || vmk */

/* AF stripe count s (public, like cost); 0/1 = off. ct_of = the wrapped blob length s*plen. */
static int af_of (const KeyslotStoreCfg *cfg) { return (cfg->afStripes >= 2) ? cfg->afStripes : 1; }
static int ct_of (const KeyslotStoreCfg *cfg) { return plen_of (cfg) * af_of (cfg); }

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
	unsigned char payload[KEYSLOT_VMK_MAX + 1];
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
		unsigned char payload[KEYSLOT_VMK_MAX + 1];
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
		unsigned char payload[KEYSLOT_VMK_MAX + 1];
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
	unsigned char payload[KEYSLOT_VMK_MAX + 1];
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

#endif /* VC_ENABLE_KEYSLOTS */
