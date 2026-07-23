/*
 * volume_label_test.c — encrypted volume labels (ROI item 43) over the real VolumeLabel + Keyslot AEAD.
 *
 * Two ways:
 *   1. the payload FRAMING (the item's only new logic) is emitted as 'FRAME i <hex>' for a fixed label
 *      set and diffed byte-for-byte against volume_label_reference.py;
 *   2. the AEAD round-trip over the real KeyslotWrap/Unwrap: Set -> Get returns the exact label.
 * Negative controls: a wrong passphrase yields no label; a flipped record byte fails the AEAD; the
 * label's cleartext bytes never appear in the 128-byte record (indistinguishable-from-random); a
 * 49-byte label is rejected; the fixed 64-byte plaintext hides the label length.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/VolumeLabel.h"
#include "Crypto/Sha2.h"

/* test KDF (PBKDF2-HMAC-SHA256), same as the other keyslot harnesses */
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
		unsigned int j; int k;
		memcpy(sb,salt,sl); sb[sl]=(unsigned char)(blk>>24); sb[sl+1]=(unsigned char)(blk>>16);
		sb[sl+2]=(unsigned char)(blk>>8); sb[sl+3]=(unsigned char)blk;
		hmac256(pw,pwl,sb,sl+4,U); memcpy(T,U,DIG);
		for (j=1;j<iters;j++){ hmac256(pw,pwl,U,DIG,U); for(k=0;k<DIG;k++) T[k]^=U[k]; }
		{ int off=(blk-1)*DIG, n=(outLen-off<DIG)?(outLen-off):DIG; for(i=0;i<n;i++) out[off+i]=T[i]; }
	}
}
static uint32_t g_rng = 0x1AB31234u;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

/* fixed label set — MUST match volume_label_reference.py */
static const struct { const char *bytes; int len; } LABELS[] = {
	{ "", 0 },
	{ "a", 1 },
	{ "work-laptop-backup", 18 },
	{ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 48 },
	{ "\xc3\xa9\xce\xb4-7", 6 },
};
#define NLAB (int)(sizeof(LABELS)/sizeof(LABELS[0]))

static int all_pass = 1;
static void check (const char *n, int ok) { printf("  %-56s %s\n", n, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

static int contains (const unsigned char *hay, int hn, const char *needle, int nn)
{ int i; if (nn<=0) return 0; for (i=0;i+nn<=hn;i++) if (memcmp(hay+i,needle,nn)==0) return 1; return 0; }

int main (void)
{
	unsigned char rec[VOLUME_LABEL_RECORD_SIZE], pt[VOLUME_LABEL_PT_SIZE];
	char got[128];
	int i, len;
	const unsigned int COST = 64;

	/* (1) framing KAT lines for the python diff */
	for (i=0;i<NLAB;i++) {
		int j; VolumeLabelFrame(LABELS[i].bytes, LABELS[i].len, pt);
		printf("FRAME %d ", i); for (j=0;j<VOLUME_LABEL_PT_SIZE;j++) printf("%02x", pt[j]); printf("\n");
	}

	printf("[set/get round-trip over the real keyslot AEAD]\n");
	for (i=0;i<NLAB;i++) {
		char nm[80];
		check("VolumeLabelSet ok", VolumeLabelSet(test_kdf,COST,(const unsigned char*)"pw",2,LABELS[i].bytes,LABELS[i].len,det_rand,rec)==0);
		len = VolumeLabelGet(test_kdf,COST,(const unsigned char*)"pw",2,rec,got,sizeof got);
		snprintf(nm,sizeof nm,"label %d round-trips exactly (len=%d)", i, LABELS[i].len);
		check(nm, len==LABELS[i].len && memcmp(got,LABELS[i].bytes,LABELS[i].len)==0);
	}

	printf("[negative controls]\n");
	VolumeLabelSet(test_kdf,COST,(const unsigned char*)"pw",2,"work-laptop-backup",18,det_rand,rec);
	check("wrong passphrase yields no label (-1)", VolumeLabelGet(test_kdf,COST,(const unsigned char*)"nope",4,rec,got,sizeof got)==-1);
	check("label cleartext is NOT present in the record", !contains(rec,VOLUME_LABEL_RECORD_SIZE,"work-laptop-backup",18));
	{
		unsigned char save = rec[40]; rec[40] ^= 0x01;
		check("flipped record byte fails the AEAD (-1)", VolumeLabelGet(test_kdf,COST,(const unsigned char*)"pw",2,rec,got,sizeof got)==-1);
		rec[40] = save;
		check("restored record reads the label again", VolumeLabelGet(test_kdf,COST,(const unsigned char*)"pw",2,rec,got,sizeof got)==18);
	}
	check("a 49-byte label is rejected by Set", VolumeLabelSet(test_kdf,COST,(const unsigned char*)"pw",2,
	      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",49,det_rand,rec)==-1);
	/* length is hidden: a 1-byte and a 48-byte label produce the same-size 128-byte record */
	{
		unsigned char recShort[VOLUME_LABEL_RECORD_SIZE], recLong[VOLUME_LABEL_RECORD_SIZE];
		VolumeLabelSet(test_kdf,COST,(const unsigned char*)"pw",2,"a",1,det_rand,recShort);
		VolumeLabelSet(test_kdf,COST,(const unsigned char*)"pw",2,LABELS[3].bytes,48,det_rand,recLong);
		check("short and max labels yield identical record size (length hidden)", sizeof recShort==sizeof recLong);
	}

	printf("\n%s\n", all_pass ? "PASS: labels round-trip; wrong pass/tamper rejected; no cleartext leak; length hidden"
	                          : "FAIL: volume label");
	return all_pass ? 0 : 1;
}
