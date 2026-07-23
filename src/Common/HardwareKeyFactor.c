/*
 * HardwareKeyFactor — see HardwareKeyFactor.h for the design.
 *
 * The response->password mixing replicates Common/Keyfiles.c byte-for-byte (rolling CRC-32 into a
 * 128-byte pool via modular addition, then pool added into the password). Backends are compiled in
 * only when their -DVC_ENABLE_* macro is set.
 */

#include "HardwareKeyFactor.h"
#include <string.h>
#if defined(VC_ENABLE_HKF_LEN_CONDITION) || defined(VC_ENABLE_HKF_MIX_V2)
#include "Crypto/Sha2.h"   /* sha256() for §6 length conditioning and the Rank-1 v2 HKDF mix */
#endif

/* ------------------------------------------------------------------ *
 *  CRC-32 (standard, polynomial 0xEDB88320) — identical to Common/Crc *
 * ------------------------------------------------------------------ */

static unsigned int hkf_crc_tab[256];
static int hkf_crc_ready = 0;

static void hkf_crc_init (void)
{
	unsigned int c;
	int n, k;
	for (n = 0; n < 256; n++)
	{
		c = (unsigned int) n;
		for (k = 0; k < 8; k++)
			c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
		hkf_crc_tab[n] = c;
	}
	hkf_crc_ready = 1;
}

#define HKF_UPDC32(octet, crc) (hkf_crc_tab[(((crc) ^ (unsigned char)(octet)) & 0xff)] ^ ((crc) >> 8))

void HKFMixResponseIntoPassword (unsigned char *password, int *password_len,
                                 const unsigned char *response, int response_len)
{
	unsigned char pool[HKF_POOL_SIZE];
	unsigned int crc = 0xffffffffu;
	unsigned int writePos = 0;
	int i;

	if (!hkf_crc_ready)
		hkf_crc_init();

	memset (pool, 0, sizeof (pool));

	/* Same rolling-CRC pool construction as KeyFileProcess(): modular add of the 4 CRC bytes. */
	for (i = 0; i < response_len; i++)
	{
		crc = HKF_UPDC32 (response[i], crc);
		pool[writePos++] += (unsigned char) (crc >> 24);
		pool[writePos++] += (unsigned char) (crc >> 16);
		pool[writePos++] += (unsigned char) (crc >> 8);
		pool[writePos++] += (unsigned char) (crc);
		if (writePos >= HKF_POOL_SIZE)
			writePos = 0;
	}

	/* Same application as KeyFilesApply(): add pool into the password, extend length to the pool. */
	for (i = 0; i < HKF_POOL_SIZE; i++)
	{
		if (i < *password_len)
			password[i] += pool[i];
		else
			password[i] = pool[i];
	}
	if (*password_len < HKF_POOL_SIZE)
		*password_len = HKF_POOL_SIZE;

	{
		volatile unsigned char *p = pool;
		size_t n = sizeof (pool);
		while (n--) *p++ = 0;
	}
}

#if defined(VC_ENABLE_HKF_MIX_V2)
/* --- Rank-1 v2 mixing: HKDF-SHA256 over (password || response), domain-separated ------------------ */

#define HKF_HMAC_BLOCK  64
#define HKF_HMAC_DIGEST 32

/* HMAC-SHA256 over up to two message segments, using the in-tree sha256(). */
static void hkf_v2_hmac (const unsigned char *key, int keyLen,
                         const unsigned char *m1, int l1, const unsigned char *m2, int l2,
                         unsigned char out[HKF_HMAC_DIGEST])
{
	sha256_ctx c;
	unsigned char k0[HKF_HMAC_BLOCK], pad[HKF_HMAC_BLOCK], inner[HKF_HMAC_DIGEST];
	int i;
	if (keyLen > HKF_HMAC_BLOCK) {
		sha256_begin (&c); sha256_hash (key, (uint_32t) keyLen, &c); sha256_end (k0, &c);
		memset (k0 + HKF_HMAC_DIGEST, 0, HKF_HMAC_BLOCK - HKF_HMAC_DIGEST);
	} else {
		if (keyLen > 0) memcpy (k0, key, (size_t) keyLen);
		memset (k0 + (keyLen > 0 ? keyLen : 0), 0, HKF_HMAC_BLOCK - (keyLen > 0 ? keyLen : 0));
	}
	for (i = 0; i < HKF_HMAC_BLOCK; i++) pad[i] = (unsigned char)(k0[i] ^ 0x36);
	sha256_begin (&c); sha256_hash (pad, HKF_HMAC_BLOCK, &c);
	if (l1 > 0) sha256_hash (m1, (uint_32t) l1, &c);
	if (l2 > 0) sha256_hash (m2, (uint_32t) l2, &c);
	sha256_end (inner, &c);
	for (i = 0; i < HKF_HMAC_BLOCK; i++) pad[i] = (unsigned char)(k0[i] ^ 0x5c);
	sha256_begin (&c); sha256_hash (pad, HKF_HMAC_BLOCK, &c); sha256_hash (inner, HKF_HMAC_DIGEST, &c);
	sha256_end (out, &c);
	{ volatile unsigned char *p = k0; size_t n = sizeof k0; while (n--) *p++ = 0; }
}

void HKFMixResponseIntoPasswordV2 (unsigned char *password, int *password_len,
                                   const unsigned char *response, int response_len)
{
	/* Domain-separated HKDF info label (subsumes item 97's cSHAKE labels). */
	static const unsigned char HKF_V2_INFO[] = "VeraCrypt/HKF/mix/v2";
	static const unsigned char HKF_V2_ZERO_SALT[HKF_HMAC_DIGEST] = { 0 };
	unsigned char prk[HKF_HMAC_DIGEST];
	unsigned char okm[HKF_POOL_SIZE];
	unsigned char T[HKF_HMAC_DIGEST];
	int infoLen = (int) sizeof (HKF_V2_INFO) - 1;      /* drop the NUL terminator */
	int blocks = (HKF_POOL_SIZE + HKF_HMAC_DIGEST - 1) / HKF_HMAC_DIGEST;
	int blk, pw = *password_len, got = 0, tLen = 0;

	/* Extract: PRK = HMAC(salt=0^32, IKM = password || response). */
	hkf_v2_hmac (HKF_V2_ZERO_SALT, HKF_HMAC_DIGEST, password, pw, response, response_len, prk);

	/* Expand: T(i) = HMAC(PRK, T(i-1) || info || i); OKM = T(1) || T(2) || ... truncated to L. */
	for (blk = 1; blk <= blocks; blk++) {
		unsigned char ctr = (unsigned char) blk;
		sha256_ctx c;
		unsigned char k0[HKF_HMAC_BLOCK], pad[HKF_HMAC_BLOCK], inner[HKF_HMAC_DIGEST];
		int i, n;
		/* HMAC(PRK, [T] || info || ctr) — inline to feed three segments */
		memcpy (k0, prk, HKF_HMAC_DIGEST); memset (k0 + HKF_HMAC_DIGEST, 0, HKF_HMAC_BLOCK - HKF_HMAC_DIGEST);
		for (i = 0; i < HKF_HMAC_BLOCK; i++) pad[i] = (unsigned char)(k0[i] ^ 0x36);
		sha256_begin (&c); sha256_hash (pad, HKF_HMAC_BLOCK, &c);
		if (tLen > 0) sha256_hash (T, (uint_32t) tLen, &c);
		sha256_hash (HKF_V2_INFO, (uint_32t) infoLen, &c);
		sha256_hash (&ctr, 1, &c);
		sha256_end (inner, &c);
		for (i = 0; i < HKF_HMAC_BLOCK; i++) pad[i] = (unsigned char)(k0[i] ^ 0x5c);
		sha256_begin (&c); sha256_hash (pad, HKF_HMAC_BLOCK, &c); sha256_hash (inner, HKF_HMAC_DIGEST, &c);
		sha256_end (T, &c);
		tLen = HKF_HMAC_DIGEST;
		n = (HKF_POOL_SIZE - got < HKF_HMAC_DIGEST) ? (HKF_POOL_SIZE - got) : HKF_HMAC_DIGEST;
		for (i = 0; i < n; i++) okm[got + i] = T[i];
		got += n;
		{ volatile unsigned char *p = k0; size_t z = sizeof k0; while (z--) *p++ = 0; }
	}

	memcpy (password, okm, HKF_POOL_SIZE);
	*password_len = HKF_POOL_SIZE;

	{ volatile unsigned char *p = prk; size_t z = sizeof prk; while (z--) *p++ = 0; }
	{ volatile unsigned char *p = T;   size_t z = sizeof T;   while (z--) *p++ = 0; }
	{ volatile unsigned char *p = okm; size_t z = sizeof okm; while (z--) *p++ = 0; }
}

void HKFMixResponseIntoPasswordVer (int version, unsigned char *password, int *password_len,
                                    const unsigned char *response, int response_len)
{
	if (version == HKF_MIX_V2)
		HKFMixResponseIntoPasswordV2 (password, password_len, response, response_len);
	else
		HKFMixResponseIntoPassword (password, password_len, response, response_len);
}

int HKFComputeActiveResponse (const unsigned char *salt, int salt_len,
                              unsigned char *respOut, int *rlenOut)
{
	const HKFConfig *cfg = g_hkfActiveConfig;
	*rlenOut = 0;
	if (!cfg || cfg->backend == HKF_BACKEND_NONE)
		return HKF_OK;                       /* factor disabled: caller does a single unmixed pass */
	return HKFComputeResponse (cfg, salt, salt_len, respOut, rlenOut);
}

int HKFApplyIfConfiguredVer (int version, unsigned char *userKey, int *keyLength,
                             const unsigned char *salt, int salt_len)
{
	unsigned char resp[HKF_MAX_RESPONSE];
	int rlen = 0, rc = HKFComputeActiveResponse (salt, salt_len, resp, &rlen);
	if (rc != HKF_OK)
		return rc;                           /* token missing/failed: caller aborts */
	if (rlen > 0)
		HKFMixResponseIntoPasswordVer (version, userKey, keyLength, resp, rlen);
	{ volatile unsigned char *p = resp; size_t n = sizeof (resp); while (n--) *p++ = 0; }
	return HKF_OK;
}
#endif /* VC_ENABLE_HKF_MIX_V2 */

/* ================================================================== *
 *  Software simulator (TESTING ONLY): self-contained SHA-1 + HMAC     *
 * ================================================================== */
#if defined(VC_ENABLE_HKF_SIMULATOR)

/* The simulator is fully self-contained (its own SHA-1 and SHA-256) so it needs no other object files.
   The production FIDO2 backend below uses VeraCrypt's own sha256() instead. */

/* --- compact SHA-256 (simulator only) --- */
typedef struct { unsigned int h[8]; unsigned long long len; unsigned char buf[64]; int idx; } hkf_sha256_ctx;

static const unsigned int hkf_k256[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

static unsigned int hkf_ror (unsigned int v, int b) { return (v >> b) | (v << (32 - b)); }

static void hkf_sha256_block (hkf_sha256_ctx *c, const unsigned char *p)
{
	unsigned int w[64], a,b,cc,d,e,f,g,h,t1,t2; int i;
	for (i = 0; i < 16; i++)
		w[i] = ((unsigned int)p[i*4]<<24)|((unsigned int)p[i*4+1]<<16)|((unsigned int)p[i*4+2]<<8)|((unsigned int)p[i*4+3]);
	for (i = 16; i < 64; i++)
	{
		unsigned int s0 = hkf_ror(w[i-15],7) ^ hkf_ror(w[i-15],18) ^ (w[i-15]>>3);
		unsigned int s1 = hkf_ror(w[i-2],17) ^ hkf_ror(w[i-2],19) ^ (w[i-2]>>10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
	for (i = 0; i < 64; i++)
	{
		unsigned int S1 = hkf_ror(e,6)^hkf_ror(e,11)^hkf_ror(e,25);
		unsigned int ch = (e & f) ^ ((~e) & g);
		t1 = h + S1 + ch + hkf_k256[i] + w[i];
		unsigned int S0 = hkf_ror(a,2)^hkf_ror(a,13)^hkf_ror(a,22);
		unsigned int maj = (a & b) ^ (a & cc) ^ (b & cc);
		t2 = S0 + maj;
		h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
	}
	c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}

static void hkf_sha256_init (hkf_sha256_ctx *c)
{
	c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
	c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;
	c->len=0; c->idx=0;
}
static void hkf_sha256_update (hkf_sha256_ctx *c, const unsigned char *p, size_t n)
{
	c->len += (unsigned long long) n * 8;
	while (n--) { c->buf[c->idx++] = *p++; if (c->idx==64){ hkf_sha256_block(c,c->buf); c->idx=0; } }
}
static void hkf_sha256_final (hkf_sha256_ctx *c, unsigned char out[32])
{
	unsigned long long bits=c->len; int i; unsigned char pad=0x80;
	hkf_sha256_update(c,&pad,1); pad=0;
	while (c->idx!=56) hkf_sha256_update(c,&pad,1);
	for (i=7;i>=0;i--){ unsigned char b=(unsigned char)(bits>>(i*8)); hkf_sha256_update(c,&b,1); }
	for (i=0;i<8;i++){ out[i*4]=(unsigned char)(c->h[i]>>24); out[i*4+1]=(unsigned char)(c->h[i]>>16); out[i*4+2]=(unsigned char)(c->h[i]>>8); out[i*4+3]=(unsigned char)c->h[i]; }
}
static void hkf_sha256_oneshot (unsigned char out[32], const unsigned char *in, int n)
{
	hkf_sha256_ctx c; hkf_sha256_init(&c); hkf_sha256_update(&c,in,(size_t)n); hkf_sha256_final(&c,out);
}

/* --- compact SHA-1 (used only by the simulator; production never computes HMAC-SHA1 on the host) --- */
typedef struct { unsigned int h[5]; unsigned long long len; unsigned char buf[64]; int idx; } hkf_sha1_ctx;

static unsigned int hkf_rol (unsigned int v, int b) { return (v << b) | (v >> (32 - b)); }

static void hkf_sha1_block (hkf_sha1_ctx *c, const unsigned char *p)
{
	unsigned int w[80], a, b, cc, d, e, i, f, k, t;
	for (i = 0; i < 16; i++)
		w[i] = ((unsigned int) p[i*4] << 24) | ((unsigned int) p[i*4+1] << 16) |
		       ((unsigned int) p[i*4+2] << 8) | ((unsigned int) p[i*4+3]);
	for (i = 16; i < 80; i++)
		w[i] = hkf_rol (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
	for (i = 0; i < 80; i++)
	{
		if      (i < 20) { f = (b & cc) | ((~b) & d);            k = 0x5A827999u; }
		else if (i < 40) { f = b ^ cc ^ d;                       k = 0x6ED9EBA1u; }
		else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);    k = 0x8F1BBCDCu; }
		else             { f = b ^ cc ^ d;                       k = 0xCA62C1D6u; }
		t = hkf_rol (a, 5) + f + e + k + w[i];
		e = d; d = cc; cc = hkf_rol (b, 30); b = a; a = t;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void hkf_sha1_init (hkf_sha1_ctx *c)
{
	c->h[0]=0x67452301u; c->h[1]=0xEFCDAB89u; c->h[2]=0x98BADCFEu; c->h[3]=0x10325476u; c->h[4]=0xC3D2E1F0u;
	c->len = 0; c->idx = 0;
}

static void hkf_sha1_update (hkf_sha1_ctx *c, const unsigned char *p, size_t n)
{
	c->len += (unsigned long long) n * 8;
	while (n--)
	{
		c->buf[c->idx++] = *p++;
		if (c->idx == 64) { hkf_sha1_block (c, c->buf); c->idx = 0; }
	}
}

static void hkf_sha1_final (hkf_sha1_ctx *c, unsigned char out[20])
{
	unsigned long long bits = c->len;
	int i;
	unsigned char pad = 0x80;
	hkf_sha1_update (c, &pad, 1);
	pad = 0;
	while (c->idx != 56) hkf_sha1_update (c, &pad, 1);
	for (i = 7; i >= 0; i--) { unsigned char b = (unsigned char)(bits >> (i*8)); hkf_sha1_update (c, &b, 1); }
	for (i = 0; i < 5; i++)
	{
		out[i*4]   = (unsigned char)(c->h[i] >> 24);
		out[i*4+1] = (unsigned char)(c->h[i] >> 16);
		out[i*4+2] = (unsigned char)(c->h[i] >> 8);
		out[i*4+3] = (unsigned char)(c->h[i]);
	}
}

static void hkf_hmac_sha1 (const unsigned char *key, int klen,
                           const unsigned char *msg, int mlen, unsigned char out[20])
{
	unsigned char k[64], ipad[64], opad[64], kd[20], inner[20];
	hkf_sha1_ctx c;
	int i;
	if (klen > 64) { hkf_sha1_init (&c); hkf_sha1_update (&c, key, (size_t) klen); hkf_sha1_final (&c, kd); key = kd; klen = 20; }
	memset (k, 0, 64); memcpy (k, key, (size_t) klen);
	for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
	hkf_sha1_init (&c); hkf_sha1_update (&c, ipad, 64); hkf_sha1_update (&c, msg, (size_t) mlen); hkf_sha1_final (&c, inner);
	hkf_sha1_init (&c); hkf_sha1_update (&c, opad, 64); hkf_sha1_update (&c, inner, 20); hkf_sha1_final (&c, out);
}

static void hkf_hmac_sha256 (const unsigned char *key, int klen,
                             const unsigned char *msg, int mlen, unsigned char out[32])
{
	unsigned char k[64], ipad[64], opad[64], kd[32], inner[32];
	hkf_sha256_ctx c;
	int i;
	if (klen > 64) { hkf_sha256_oneshot (kd, key, klen); key = kd; klen = 32; }
	memset (k, 0, 64); memcpy (k, key, (size_t) klen);
	for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
	hkf_sha256_init (&c); hkf_sha256_update (&c, ipad, 64); hkf_sha256_update (&c, msg, (size_t) mlen); hkf_sha256_final (&c, inner);
	hkf_sha256_init (&c); hkf_sha256_update (&c, opad, 64); hkf_sha256_update (&c, inner, 32); hkf_sha256_final (&c, out);
}

static int HKFSimulatorResponse (const HKFConfig *cfg,
                                 const unsigned char *challenge, int challenge_len,
                                 unsigned char *response_out, int *response_len_out)
{
	if (cfg->simSecretLen <= 0 || cfg->simSecretLen > (int) sizeof (cfg->simSecret))
		return HKF_ERR_CONFIG;

	if (cfg->simMac == 1)
	{
		/* Emulate a YubiKey OTP-slot HMAC-SHA1: response = HMAC-SHA1(secret, challenge). */
		hkf_hmac_sha1 (cfg->simSecret, cfg->simSecretLen, challenge, challenge_len, response_out);
		*response_len_out = 20;
		return HKF_OK;
	}
	else if (cfg->simMac == 2)
	{
		/* Emulate FIDO2 hmac-secret: host feeds a 32-byte salt = SHA256(challenge); device returns
		   HMAC-SHA256(CredRandom, salt). Here CredRandom is modelled by simSecret. */
		unsigned char salt32[32];
		hkf_sha256_oneshot (salt32, challenge, challenge_len);
		hkf_hmac_sha256 (cfg->simSecret, cfg->simSecretLen, salt32, 32, response_out);
		*response_len_out = 32;
		return HKF_OK;
	}
	return HKF_ERR_CONFIG;
}
#endif /* VC_ENABLE_HKF_SIMULATOR */

/* ================================================================== *
 *  YubiKey HMAC-SHA1 challenge-response (libykpers)                    *
 * ================================================================== */
#if defined(VC_ENABLE_YUBIKEY_HMAC)
#include <ykpers-1/ykcore.h>
#include <ykpers-1/ykdef.h>

static int HKFYubiKeyResponse (const HKFConfig *cfg,
                               const unsigned char *challenge, int challenge_len,
                               unsigned char *response_out, int *response_len_out)
{
	YK_KEY *yk = 0;
	unsigned char resp[64];
	uint8_t cmd;
	int rc, ret = HKF_ERR_DEVICE;

	if (!yk_init ())
		return HKF_ERR_DEVICE;

	yk = yk_open_first_key ();
	if (!yk)
	{
		yk_release ();
		return HKF_ERR_NO_DEVICE;
	}

	cmd = (cfg->ykSlot == 2) ? SLOT_CHAL_HMAC2 : SLOT_CHAL_HMAC1;
	memset (resp, 0, sizeof (resp));

	/* HMAC-SHA1 CR: challenge up to 64 bytes in, 20-byte HMAC out (buffer sized 64 per API). */
	rc = yk_challenge_response (yk, cmd, cfg->ykMayBlock,
	                            (unsigned int) challenge_len, challenge,
	                            sizeof (resp), resp);
	if (rc)
	{
		memcpy (response_out, resp, 20);
		*response_len_out = 20;
		ret = HKF_OK;
	}

	{ volatile unsigned char *p = resp; size_t n = sizeof (resp); while (n--) *p++ = 0; }
	yk_close_key (yk);
	yk_release ();
	return ret;
}
#endif /* VC_ENABLE_YUBIKEY_HMAC */

/* ================================================================== *
 *  FIDO2 hmac-secret assertion (libfido2)                             *
 * ================================================================== */
#if defined(VC_ENABLE_FIDO2)
#include <fido.h>
#include "Crypto/Sha2.h"

static int HKFFido2Response (const HKFConfig *cfg,
                             const unsigned char *challenge, int challenge_len,
                             unsigned char *response_out, int *response_len_out)
{
	fido_dev_info_t *devlist = 0;
	fido_dev_t *dev = 0;
	fido_assert_t *assert = 0;
	unsigned char salt32[32];
	unsigned char cdh[32];
	const char *path = 0;
	size_t ndev = 0, hlen;
	const unsigned char *hptr;
	int r, ret = HKF_ERR_DEVICE;

	if (cfg->fidoCredIdLen <= 0 || cfg->fidoRpId[0] == 0)
		return HKF_ERR_CONFIG;

	fido_init (0);

	/* Reduce the 64-byte volume salt to the 32-byte hmac-secret salt the CTAP2 extension requires. */
	sha256 (salt32, challenge, (uint_32t) challenge_len);
	/* Client-data hash is not security-relevant for our use; a fixed value keeps derivation stable. */
	memset (cdh, 0, sizeof (cdh));

	devlist = fido_dev_info_new (8);
	if (!devlist) return HKF_ERR_DEVICE;
	if (fido_dev_info_manifest (devlist, 8, &ndev) != FIDO_OK || ndev == 0) { ret = HKF_ERR_NO_DEVICE; goto done; }
	path = fido_dev_info_path (fido_dev_info_ptr (devlist, 0));

	dev = fido_dev_new ();
	if (!dev || fido_dev_open (dev, path) != FIDO_OK) { ret = HKF_ERR_NO_DEVICE; goto done; }

	assert = fido_assert_new ();
	if (!assert) goto done;

	if (fido_assert_set_rp (assert, cfg->fidoRpId) != FIDO_OK) goto done;
	if (fido_assert_set_clientdata_hash (assert, cdh, sizeof (cdh)) != FIDO_OK) goto done;
	if (fido_assert_allow_cred (assert, cfg->fidoCredId, (size_t) cfg->fidoCredIdLen) != FIDO_OK) goto done;
	if (fido_assert_set_extensions (assert, FIDO_EXT_HMAC_SECRET) != FIDO_OK) goto done;
	if (fido_assert_set_hmac_salt (assert, salt32, sizeof (salt32)) != FIDO_OK) goto done;

	r = fido_dev_get_assert (dev, assert, (cfg->fidoPin[0] ? cfg->fidoPin : 0));
	if (r != FIDO_OK) { ret = HKF_ERR_DEVICE; goto done; }

	hptr = fido_assert_hmac_secret_ptr (assert, 0);
	hlen = fido_assert_hmac_secret_len (assert, 0);
	if (hptr && hlen > 0 && hlen <= HKF_MAX_RESPONSE)
	{
		memcpy (response_out, hptr, hlen);
		*response_len_out = (int) hlen;
		ret = HKF_OK;
	}

done:
	if (assert)  fido_assert_free (&assert);
	if (dev)     { fido_dev_close (dev); fido_dev_free (&dev); }
	if (devlist) fido_dev_info_free (&devlist, 8);
	{ volatile unsigned char *p = salt32; size_t n = sizeof (salt32); while (n--) *p++ = 0; }
	return ret;
}
#endif /* VC_ENABLE_FIDO2 */

/* ================================================================== *
 *  Salt-binding for RAW_SECRET (production HMAC-SHA256 over sha256)   *
 * ================================================================== */

#if defined(VC_ENABLE_HKF_SALT_BIND)
#include "Crypto/Sha2.h"   /* VeraCrypt's real SHA-256 */

/* out = HMAC-SHA256(key = secret, msg = salt). Standard ipad/opad over the in-tree sha256(). */
static void hkf_saltbind_hmac_sha256 (const unsigned char *key, int keyLen,
                                      const unsigned char *msg, int msgLen,
                                      unsigned char out[32])
{
	sha256_ctx    ctx;
	unsigned char k0[64], pad[64], inner[32], keyHash[32];
	int i;

	if (keyLen > 64)
	{
		sha256_begin (&ctx); sha256_hash (key, (uint_32t) keyLen, &ctx); sha256_end (keyHash, &ctx);
		memcpy (k0, keyHash, 32); memset (k0 + 32, 0, 32);
	}
	else
	{
		if (keyLen > 0) memcpy (k0, key, (size_t) keyLen);
		memset (k0 + keyLen, 0, (size_t) (64 - keyLen));
	}

	for (i = 0; i < 64; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&ctx); sha256_hash (pad, 64, &ctx);
	if (msgLen > 0) sha256_hash (msg, (uint_32t) msgLen, &ctx);
	sha256_end (inner, &ctx);

	for (i = 0; i < 64; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&ctx); sha256_hash (pad, 64, &ctx); sha256_hash (inner, 32, &ctx);
	sha256_end (out, &ctx);

	{ volatile unsigned char *p = k0;      size_t n = sizeof (k0);      while (n--) *p++ = 0; }
	{ volatile unsigned char *p = inner;   size_t n = sizeof (inner);   while (n--) *p++ = 0; }
	{ volatile unsigned char *p = keyHash; size_t n = sizeof (keyHash); while (n--) *p++ = 0; }
}
#endif /* VC_ENABLE_HKF_SALT_BIND */

/* ================================================================== *
 *  Dispatcher                                                         *
 * ================================================================== */

static int hkf_dispatch_response (const HKFConfig *cfg,
                                  const unsigned char *challenge, int challenge_len,
                                  unsigned char *response_out, int *response_len_out)
{
	if (!cfg || !challenge || challenge_len <= 0 || !response_out || !response_len_out)
		return HKF_ERR_CONFIG;

	switch (cfg->backend)
	{
	case HKF_BACKEND_YK_HMAC_SHA1:
#if defined(VC_ENABLE_YUBIKEY_HMAC)
		return HKFYubiKeyResponse (cfg, challenge, challenge_len, response_out, response_len_out);
#else
		return HKF_ERR_UNSUPPORTED;
#endif

	case HKF_BACKEND_FIDO2_HMAC_SECRET:
#if defined(VC_ENABLE_FIDO2)
		return HKFFido2Response (cfg, challenge, challenge_len, response_out, response_len_out);
#else
		return HKF_ERR_UNSUPPORTED;
#endif

	case HKF_BACKEND_SIMULATOR:
#if defined(VC_ENABLE_HKF_SIMULATOR)
		return HKFSimulatorResponse (cfg, challenge, challenge_len, response_out, response_len_out);
#else
		return HKF_ERR_UNSUPPORTED;
#endif

	case HKF_BACKEND_RAW_SECRET:
		/* A caller-supplied secret (typically a Shamir reconstruction); mixed like a keyfile. */
		if (cfg->rawSecretLen <= 0 || cfg->rawSecretLen > HKF_MAX_RESPONSE)
			return HKF_ERR_CONFIG;
#if defined(VC_ENABLE_HKF_SALT_BIND)
		if (cfg->rawSecretBindSalt)
		{
			/* Bind the secret to this volume's salt: response = HMAC-SHA256(secret, salt). The same
			   reconstructed secret then yields a different factor on a different volume. */
			hkf_saltbind_hmac_sha256 (cfg->rawSecret, cfg->rawSecretLen, challenge, challenge_len, response_out);
			*response_len_out = 32;
			return HKF_OK;
		}
#endif
		/* Otherwise the salt is not used — the secret is fixed per enrollment. */
		memcpy (response_out, cfg->rawSecret, (size_t) cfg->rawSecretLen);
		*response_len_out = cfg->rawSecretLen;
		return HKF_OK;

	default:
		return HKF_ERR_CONFIG;
	}
}

/*
 * Public entry: dispatch to the backend, then (optionally) length-condition the response.
 *
 * Length conditioning (VC_ENABLE_HKF_LEN_CONDITION — CRC keyfile-pool seam addendum §6). The pool mix
 * writes 4 pool bytes per input byte into a 128-byte pool, so wrap-around — and the additive folding
 * that leaves injectivity unproven — begins at 33 input bytes. Every hardware backend stays <= 32 bytes
 * (YubiKey HMAC-SHA1 = 20, FIDO2 hmac-secret = 32), and so does a salt-bound RAW_SECRET (HMAC-SHA256 =
 * 32); but a raw Shamir-reconstructed RAW_SECRET may be 33..64 bytes (HKF_MAX_RESPONSE = 64) and would
 * wrap. Conditioning anything > 32 bytes to sha256()->32 keeps EVERY backend inside the proven-injective
 * regime structurally, not incidentally. It is a NO-OP for all <= 32-byte responses (hardware backends
 * and salt-bound RAW_SECRET are byte-for-byte unchanged); for a > 32-byte raw RAW_SECRET it changes the
 * derived value, so such a volume must be re-enrolled (or mounted with a version-try loop). Defence in
 * depth — not a substitute for enabling salt-binding by default. See docs/CRC-SEAM-ADDENDUM.md.
 */
int HKFComputeResponse (const HKFConfig *cfg,
                        const unsigned char *challenge, int challenge_len,
                        unsigned char *response_out, int *response_len_out)
{
	int rc = hkf_dispatch_response (cfg, challenge, challenge_len, response_out, response_len_out);
#if defined(VC_ENABLE_HKF_LEN_CONDITION)
	if (rc == HKF_OK && response_len_out && *response_len_out > 32)
	{
		unsigned char h[32];
		sha256 (h, response_out, (uint_32t) *response_len_out);
		memcpy (response_out, h, 32);
		*response_len_out = 32;
		burn (h, sizeof h);
	}
#endif
	return rc;
}

/* Rec 1 (addendum §5): salt-binding on by default for RAW_SECRET, with an explicit opt-out. */
void HKFApplySaltBindDefault (HKFConfig *cfg)
{
#if defined(VC_ENABLE_HKF_SALT_BIND_DEFAULT) && defined(VC_ENABLE_HKF_SALT_BIND)
	if (cfg && cfg->backend == HKF_BACKEND_RAW_SECRET && !cfg->rawSecretNoBindSalt)
		cfg->rawSecretBindSalt = 1;
#else
	(void) cfg;
#endif
}

/* ------------------------------------------------------------------ *
 *  Active-config hook for the mount / format derivation call-sites    *
 * ------------------------------------------------------------------ */

const HKFConfig *g_hkfActiveConfig = 0;

void HKFSetActiveConfig (const HKFConfig *cfg)
{
	g_hkfActiveConfig = cfg;
}

/* Guarded on KEYSCRUB && HKF so this is the *complement* of the KeyScrub.c fallback stub, which is
 * guarded on KEYSCRUB && !HKF. Exactly one definition exists when KEYSCRUB is on (this real one when
 * a hardware/threshold factor is compiled in, the empty stub otherwise), and neither when KEYSCRUB is
 * off. Without the && HKF here the KEYSCRUB-on/HKF-off build defined the symbol twice (see
 * docs/REAL-BUILD-VALIDATION.md guard-complementarity). */
#if defined(VC_ENABLE_KEYSCRUB) && defined(VC_ENABLE_HKF)
void HKFScrubActiveConfig (void)
{
	HKFConfig *cfg = (HKFConfig *) g_hkfActiveConfig;   /* wipe the caller-owned secret storage */
	if (cfg)
	{
		{ volatile unsigned char *p = cfg->rawSecret;  size_t n = sizeof (cfg->rawSecret);  while (n--) *p++ = 0; }
		{ volatile unsigned char *p = cfg->simSecret;  size_t n = sizeof (cfg->simSecret);  while (n--) *p++ = 0; }
		{ volatile unsigned char *p = (volatile unsigned char *) cfg->fidoPin; size_t n = sizeof (cfg->fidoPin); while (n--) *p++ = 0; }
		cfg->rawSecretLen = 0;
		cfg->simSecretLen = 0;
	}
	g_hkfActiveConfig = 0;
}
#endif

int HKFApplyIfConfigured (unsigned char *userKey, int *keyLength,
                          const unsigned char *salt, int salt_len)
{
	const HKFConfig *cfg = g_hkfActiveConfig;
	unsigned char resp[HKF_MAX_RESPONSE];
	int rlen = 0, rc;

	if (!cfg || cfg->backend == HKF_BACKEND_NONE)
		return HKF_OK;                       /* factor disabled: derivation unchanged */

	rc = HKFComputeResponse (cfg, salt, salt_len, resp, &rlen);
	if (rc != HKF_OK)
		return rc;                           /* token missing/failed: caller aborts */

	HKFMixResponseIntoPassword (userKey, keyLength, resp, rlen);

	{ volatile unsigned char *p = resp; size_t n = sizeof (resp); while (n--) *p++ = 0; }
	return HKF_OK;
}

int HKFShouldApply (const HKFConfig *cfg, int layoutIsHidden)
{
	if (!cfg || cfg->backend == HKF_BACKEND_NONE)
		return 0;                            /* no factor configured */
	if (cfg->applyPolicy == HKF_APPLY_HIDDEN_ONLY)
		return layoutIsHidden ? 1 : 0;       /* decoy layout: gate the hidden header only */
	return 1;                                /* HKF_APPLY_ALL */
}
