/*
 * differential_test.c — randomized / boundary robustness testing of the split-key + recovery core
 * (build_and_verify.sh step [45]; IDEAS-BACKLOG §"Randomized differential testing").
 *
 * Beyond the fixed KATs: a deterministic seeded fuzzer drives the REAL compiled Shamir.c +
 * ShamirMac.c + ShareCode.c + Keyslot.c + KeyslotStore.c + AfSplit.c over thousands of randomized and
 * boundary configurations (degenerate thresholds t=2 and t=n, duplicate share x-coords, zero/oversized
 * and boundary secret lengths, random add/open/revoke keyslot sequences, ShareCode corruption),
 * asserting invariants hold and nothing crashes or silently returns a wrong answer. The PRNG is
 * seeded, so the pass/fail verdict is reproducible even though the inputs are "random".
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Shamir.h"
#include "Common/ShamirMac.h"
#include "Common/ShareCode.h"
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* deterministic PRNG */
static uint64_t g_rng = 0xD1FFE0D1FFE0D1FFULL;
static uint32_t rnd (void) { uint64_t x = g_rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; g_rng = x; return (uint32_t) (x >> 32); }
static int rrange (int lo, int hi) { return lo + (int) (rnd() % (uint32_t) (hi - lo + 1)); }   /* inclusive */

static int all_pass = 1;
static long checks = 0;
static void expect (const char *name, int ok) { checks++; if (!ok) { all_pass = 0; printf ("  FAIL: %s\n", name); } }

/* ---- test KDF for keyslots: PBKDF2-HMAC-SHA256 over real Sha2.c ---- */
#define BLK 64
#define DIG 32
static void hmac256 (const unsigned char *k, int kl, const unsigned char *m, int ml, unsigned char o[DIG])
{
	sha256_ctx c; unsigned char k0[BLK], p[BLK], in[DIG]; int i;
	if (kl > BLK) { sha256_begin(&c); sha256_hash(k,(unsigned)kl,&c); sha256_end(k0,&c); memset(k0+DIG,0,BLK-DIG); }
	else { if (kl>0) memcpy(k0,k,kl); memset(k0+kl,0,BLK-kl); }
	for (i=0;i<BLK;i++) p[i]=k0[i]^0x36;
	sha256_begin(&c); sha256_hash(p,BLK,&c); if (ml>0) sha256_hash(m,(unsigned)ml,&c); sha256_end(in,&c);
	for (i=0;i<BLK;i++) p[i]=k0[i]^0x5c;
	sha256_begin(&c); sha256_hash(p,BLK,&c); sha256_hash(in,DIG,&c); sha256_end(o,&c);
}
static void test_kdf (const unsigned char *pw, int pwl, const unsigned char *salt, int sl,
                      unsigned int iters, unsigned char *out, int outLen)
{
	int blocks=(outLen+DIG-1)/DIG, blk, i; unsigned char T[DIG],U[DIG],sb[128+4];
	for (blk=1; blk<=blocks; blk++) {
		unsigned int j; int kk;
		memcpy(sb,salt,sl); sb[sl]=(unsigned char)(blk>>24); sb[sl+1]=(unsigned char)(blk>>16);
		sb[sl+2]=(unsigned char)(blk>>8); sb[sl+3]=(unsigned char)blk;
		hmac256(pw,pwl,sb,sl+4,U); memcpy(T,U,DIG);
		for (j=1;j<iters;j++){ hmac256(pw,pwl,U,DIG,U); for(kk=0;kk<DIG;kk++) T[kk]^=U[kk]; }
		{ int off=(blk-1)*DIG, n=(outLen-off<DIG)?(outLen-off):DIG; for(i=0;i<n;i++) out[off+i]=T[i]; }
	}
}
static void kdf_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++) p[i]=(unsigned char)rnd(); }

/* ---- Shamir differential ---- */
static void fuzz_shamir (int rounds)
{
	int it;
	for (it = 0; it < rounds; it++)
	{
		int len = rrange (1, SHAMIR_MAX_SECRET);
		int n   = rrange (2, SHAMIR_MAX_SHARES);
		int t   = rrange (2, n);
		unsigned char secret[SHAMIR_MAX_SECRET], rndbuf[(SHAMIR_MAX_SHARES) * SHAMIR_MAX_SECRET];
		ShamirShare sh[SHAMIR_MAX_SHARES], sub[SHAMIR_MAX_SHARES];
		unsigned char out[SHAMIR_MAX_SECRET]; int outLen, i, j;
		unsigned int csSecret;

		for (i = 0; i < len; i++) secret[i] = (unsigned char) rnd();
		for (i = 0; i < (t - 1) * len; i++) rndbuf[i] = (unsigned char) rnd();
		expect ("split ok", shamir_split (secret, len, t, n, rndbuf, sh) == SHAMIR_OK);
		csSecret = shamir_secret_checksum (secret, len);

		/* all n shares reconstruct */
		expect ("combine all==secret", shamir_combine (sh, n, out, &outLen) == SHAMIR_OK && outLen == len && memcmp (out, secret, len) == 0);

		/* a random t-subset reconstructs (Fisher-Yates pick t of n) */
		{
			int idx[SHAMIR_MAX_SHARES];
			for (i = 0; i < n; i++) idx[i] = i;
			for (i = 0; i < t; i++) { int r = rrange (i, n - 1), tmp = idx[i]; idx[i] = idx[r]; idx[r] = tmp; sub[i] = sh[idx[i]]; }
			expect ("t-subset==secret", shamir_combine (sub, t, out, &outLen) == SHAMIR_OK && memcmp (out, secret, len) == 0);
			expect ("t-subset checksum ok", shamir_secret_checksum (out, outLen) == csSecret);
		}

		/* below threshold: a (t-1)-subset yields a detectably-wrong secret (len>=4 => collision ~2^-32) */
		if (t >= 3 && len >= 4)
		{
			for (i = 0; i < t - 1; i++) sub[i] = sh[i];
			if (shamir_combine (sub, t - 1, out, &outLen) == SHAMIR_OK)
				expect ("below-threshold differs", memcmp (out, secret, len) != 0 && shamir_secret_checksum (out, outLen) != csSecret);
		}

		/* duplicate x-coords rejected */
		{
			for (i = 0; i < t; i++) sub[i] = sh[i];
			sub[t - 1].x = sub[0].x;                       /* force a collision */
			expect ("dup x rejected", shamir_combine (sub, t, out, &outLen) == SHAMIR_ERR_PARAM);
		}

		/* keyed per-share MAC survives a random tamper */
		{
			unsigned char macKey[SHAMIR_MAC_KEY_SIZE], tag[SHAMIR_MAC_TAG_SIZE]; int pos, biti;
			ShamirShare bad;
			for (i = 0; i < SHAMIR_MAC_KEY_SIZE; i++) macKey[i] = (unsigned char) rnd();
			j = rrange (0, n - 1);
			ShamirShareMac (macKey, &sh[j], tag);
			expect ("mac verifies honest", ShamirShareVerify (macKey, &sh[j], tag) == 1);
			bad = sh[j]; pos = rrange (0, len - 1); biti = rrange (0, 7); bad.y[pos] ^= (unsigned char) (1u << biti);
			expect ("mac rejects tampered", ShamirShareVerify (macKey, &bad, tag) == 0);
		}
	}

	/* degenerate + invalid parameters (fixed, not random) */
	{
		unsigned char secret[8] = { 1,2,3,4,5,6,7,8 }, rndbuf[64], out[8]; int outLen; ShamirShare sh[16];
		int i; for (i = 0; i < 64; i++) rndbuf[i] = (unsigned char) (i * 3 + 1);
		expect ("t=2,n=2 ok", shamir_split (secret, 8, 2, 2, rndbuf, sh) == SHAMIR_OK
		        && shamir_combine (sh, 2, out, &outLen) == SHAMIR_OK && memcmp (out, secret, 8) == 0);
		expect ("t=n=16 ok", shamir_split (secret, 8, 16, 16, rndbuf, sh) == SHAMIR_OK
		        && shamir_combine (sh, 16, out, &outLen) == SHAMIR_OK && memcmp (out, secret, 8) == 0);
		expect ("len=0 rejected",  shamir_split (secret, 0, 2, 3, rndbuf, sh) == SHAMIR_ERR_PARAM);
		expect ("len>max rejected", shamir_split (secret, SHAMIR_MAX_SECRET + 1, 2, 3, rndbuf, sh) == SHAMIR_ERR_PARAM);
		expect ("t<2 rejected",     shamir_split (secret, 8, 1, 3, rndbuf, sh) == SHAMIR_ERR_PARAM);
		expect ("n<t rejected",     shamir_split (secret, 8, 4, 3, rndbuf, sh) == SHAMIR_ERR_PARAM);
		expect ("n>max rejected",   shamir_split (secret, 8, 2, SHAMIR_MAX_SHARES + 1, rndbuf, sh) == SHAMIR_ERR_PARAM);
	}
}

/* ---- ShareCode differential ---- */
static void fuzz_sharecode (int rounds)
{
	int it;
	for (it = 0; it < rounds; it++)
	{
		ShamirShare sh, dec; unsigned char mac[SHARECODE_MAC_SIZE], macOut[SHARECODE_MAC_SIZE];
		char code[SHARECODE_MAX_LEN]; int len, i, withMac, hasMac, clen, pos, r;

		len = rrange (1, SHAMIR_MAX_SECRET);
		sh.x = (unsigned char) rrange (1, 255); sh.len = len;
		for (i = 0; i < len; i++) sh.y[i] = (unsigned char) rnd();
		for (i = 0; i < SHARECODE_MAC_SIZE; i++) mac[i] = (unsigned char) rnd();
		withMac = rrange (0, 1);

		if (ShareCodeEncode (&sh, withMac ? mac : NULL, code, sizeof (code)) != SHARECODE_OK) { expect ("encode ok", 0); continue; }
		hasMac = -1;
		expect ("roundtrip decode", ShareCodeDecode (code, &dec, macOut, &hasMac) == SHARECODE_OK
		        && dec.x == sh.x && dec.len == sh.len && memcmp (dec.y, sh.y, len) == 0
		        && hasMac == withMac && (!withMac || memcmp (macOut, mac, SHARECODE_MAC_SIZE) == 0));

		/* single random character substitution must be detected */
		clen = (int) strlen (code); pos = rrange (4, clen - 1);
		{
			static const char *CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
			char orig = code[pos], sub;
			do { r = rrange (0, 31); sub = CS[r]; } while (sub == orig);
			code[pos] = sub;
			expect ("1-char typo detected", ShareCodeDecode (code, &dec, macOut, &hasMac) != SHARECODE_OK);
			code[pos] = orig;
		}
	}

	/* garbage strings must be rejected cleanly, never crash */
	{
		ShamirShare dec; unsigned char macOut[SHARECODE_MAC_SIZE]; int hasMac, i;
		char buf[64];
		const char *garbage[] = { "", "vcs1", "xyz1qqqqqq", "vcs1!!!!!!", "vcs10000000000000000" };
		for (i = 0; i < 5; i++)
			expect ("garbage rejected", ShareCodeDecode (garbage[i], &dec, macOut, &hasMac) != SHARECODE_OK);
		for (i = 0; i < 20; i++)   /* random noise */
		{
			int j, m = rrange (1, 60); for (j = 0; j < m; j++) buf[j] = (char) (32 + rnd() % 95); buf[m] = 0;
			(void) ShareCodeDecode (buf, &dec, macOut, &hasMac);   /* just must not crash */
			expect ("random noise no crash", 1);
		}
	}
}

/* ---- Keyslot differential (random add/open/revoke over an in-memory area) ---- */
#define KAREA_SLOTS 32
#define KVMK 48
static void fuzz_keyslots (int rounds)
{
	static unsigned char area_buf[KAREA_SLOTS * KEYSLOT_TABLE_STRIDE];
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char vmk[KVMK], out[KVMK];
	int live[KAREA_SLOTS], liveFlags[KAREA_SLOTS], it, i;
	char passes[KAREA_SLOTS][16];

	area.read  = NULL; /* set below */
	{
		/* closures via file-scope statics are awkward in C; use simple globals */
	}
	for (i = 0; i < KVMK; i++) vmk[i] = (unsigned char) (0x30 + i);

	/* area callbacks over area_buf */
	extern int  ks_rd (void*, uint64, unsigned char*, size_t);
	extern int  ks_wr (void*, uint64, const unsigned char*, size_t);
	extern uint64 ks_sz (void*);
	area.read = ks_rd; area.write = ks_wr; area.size = ks_sz; area.ctx = area_buf;

	memset (&cfg, 0, sizeof (cfg));
	cfg.kdf = test_kdf; cfg.cost = 64; cfg.vmkLen = KVMK; cfg.maxSlots = KAREA_SLOTS; cfg.randBytes = kdf_rand;
	cfg.backend = KSB_HEADER;
	memset (area_buf, 0, sizeof (area_buf));
	for (i = 0; i < KAREA_SLOTS; i++) { live[i] = 0; }

	for (it = 0; it < rounds; it++)
	{
		int op = rrange (0, 2);
		if (op == 0)   /* add */
		{
			int flags = rrange (0, 1) ? KEYSLOT_FLAG_DURESS : 0, af = rrange (0, 1) ? 4 : 0, idx, plen;
			char pass[16]; int pl = rrange (4, 12), j;
			KeyslotStoreCfg c2 = cfg; c2.afStripes = af;
			for (j = 0; j < pl; j++) pass[j] = (char) ('a' + rnd() % 26); pass[pl] = 0;
			/* AF stride guard: skip if it wouldn't fit */
			plen = KVMK + 1; if (af >= 2 && 46 + af * plen + 32 > KEYSLOT_TABLE_STRIDE) continue;
			idx = KeyslotAdd (&c2, &area, (const unsigned char*) pass, pl, flags, vmk);
			if (idx >= 0) { live[idx] = 1 + af; liveFlags[idx] = flags; strcpy (passes[idx], pass);
				expect ("added slot opens", KeyslotOpen (&c2, &area, (const unsigned char*) pass, pl, out, &i) && !memcmp (out, vmk, KVMK) && i == flags); }
		}
		else if (op == 1)   /* open a live slot with the wrong then right passphrase */
		{
			int cand = rrange (0, KAREA_SLOTS - 1), flg;
			if (live[cand])
			{
				KeyslotStoreCfg c2 = cfg; c2.afStripes = (live[cand] == 5) ? 4 : 0;
				int pl = (int) strlen (passes[cand]);
				expect ("live opens", KeyslotOpen (&c2, &area, (const unsigned char*) passes[cand], pl, out, &flg)
				        && !memcmp (out, vmk, KVMK) && flg == liveFlags[cand]);
				expect ("wrong pass fails", !KeyslotOpen (&c2, &area, (const unsigned char*) "not-the-pass", 12, out, &flg));
			}
		}
		else   /* revoke */
		{
			int cand = rrange (0, KAREA_SLOTS - 1);
			if (live[cand]) { expect ("revoke ok", KeyslotRevoke (&cfg, &area, cand) == 0);
				{ KeyslotStoreCfg c2 = cfg; c2.afStripes = (live[cand]==5)?4:0; int flg;
				  expect ("revoked no longer opens", !KeyslotOpen (&c2, &area, (const unsigned char*) passes[cand], (int) strlen (passes[cand]), out, &flg)); }
				live[cand] = 0; }
		}
	}
}

/* area callbacks (file scope so fuzz_keyslots can take their address) */
int ks_rd (void *c, uint64 off, unsigned char *b, size_t n) { if (off + n > (uint64) KAREA_SLOTS * KEYSLOT_TABLE_STRIDE) return -1; memcpy (b, (unsigned char*) c + off, n); return 0; }
int ks_wr (void *c, uint64 off, const unsigned char *b, size_t n) { if (off + n > (uint64) KAREA_SLOTS * KEYSLOT_TABLE_STRIDE) return -1; memcpy ((unsigned char*) c + off, b, n); return 0; }
uint64 ks_sz (void *c) { (void) c; return (uint64) KAREA_SLOTS * KEYSLOT_TABLE_STRIDE; }

int main (void)
{
	printf ("[differential/fuzz over the real split-key + recovery modules]\n");
	fuzz_shamir (4000);
	fuzz_sharecode (4000);
	fuzz_keyslots (4000);
	printf ("  ran %ld invariant checks\n", checks);
	printf ("%s\n", all_pass ? "ALL DIFFERENTIAL CHECKS PASSED" : "DIFFERENTIAL CHECKS FAILED");
	return all_pass ? 0 : 1;
}
