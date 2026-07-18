/*
 * downgrade_poc.c — header-version + anti-downgrade parameter binding
 * (docs/ANTI-DOWNGRADE-SPEC.md, IDEAS-BACKLOG.md A).
 *
 * An attacker who can edit the header could claim WEAKER KDF/cipher parameters
 * (tiny Argon2 memory, a weak PRF/cipher, an older header version) hoping the
 * victim re-derives under them and cheapens offline attack. Binding a canonical
 * serialization of every negotiated parameter into a MAC keyed from the password
 * makes any such edit produce a different tag, so the volume FAILS CLOSED rather
 * than silently accepting downgraded parameters.
 *
 * Canonical layout is FIXED-WIDTH big-endian (unambiguous -- no field-boundary
 * confusion): version:u16 | prf_id:u16 | cipher_id:u16 | mode_id:u16 |
 * argon_mem_kib:u32 | argon_iters:u32 | argon_parallelism:u8   (17 bytes).
 *
 * HMAC-SHA256 drives the REAL in-tree Crypto/Sha2.c; downgrade_reference.py is
 * independent (hashlib). build_and_verify.sh diffs REF lines byte-for-byte.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

#define DIG 32

/* --- HMAC-SHA256 over the in-tree Sha2.c --- */
static void sha256_1 (const unsigned char *m, size_t n, unsigned char out[DIG])
{ sha256_ctx c; sha256_begin (&c); if (n) sha256_hash (m, (uint_32t) n, &c); sha256_end (out, &c); }

static void hmac_sha256 (const unsigned char *key, size_t klen,
                         const unsigned char *msg, size_t mlen, unsigned char out[DIG])
{
	unsigned char k[64], ipad[64], opad[64], inner[DIG];
	sha256_ctx c; int i;
	memset (k, 0, 64);
	if (klen > 64) sha256_1 (key, klen, k); else memcpy (k, key, klen);
	for (i = 0; i < 64; i++) { ipad[i] = (unsigned char)(k[i] ^ 0x36); opad[i] = (unsigned char)(k[i] ^ 0x5c); }
	sha256_begin (&c); sha256_hash (ipad, 64, &c); if (mlen) sha256_hash ((unsigned char *) msg, (uint_32t) mlen, &c); sha256_end (inner, &c);
	sha256_begin (&c); sha256_hash (opad, 64, &c); sha256_hash (inner, DIG, &c); sha256_end (out, &c);
}

/* --- parameter set + canonical serialization --- */
typedef struct {
	uint16_t version, prf_id, cipher_id, mode_id;
	uint32_t argon_mem_kib, argon_iters;
	uint8_t  argon_parallelism;
} Params;

static void be16 (unsigned char *p, uint16_t v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char) v; }
static void be32 (unsigned char *p, uint32_t v) { p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16); p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char) v; }

static int canon (const Params *p, unsigned char out[17])
{
	be16 (out + 0, p->version); be16 (out + 2, p->prf_id); be16 (out + 4, p->cipher_id); be16 (out + 6, p->mode_id);
	be32 (out + 8, p->argon_mem_kib); be32 (out + 12, p->argon_iters); out[16] = p->argon_parallelism;
	return 17;
}

static void binding_key (const unsigned char *pw, size_t pwlen, const unsigned char *salt, size_t slen, unsigned char bk[DIG])
{ hmac_sha256 (pw, pwlen, salt, slen, bk); }

static void param_tag (const unsigned char *pw, size_t pwlen, const unsigned char *salt, size_t slen,
                       const Params *p, unsigned char tag[DIG])
{ unsigned char bk[DIG], c[17]; binding_key (pw, pwlen, salt, slen, bk); canon (p, c); hmac_sha256 (bk, DIG, c, 17, tag); memset (bk, 0, DIG); }

static int ct_eq (const unsigned char *a, const unsigned char *b, int n)
{ unsigned char d = 0; int i; for (i = 0; i < n; i++) d |= (unsigned char)(a[i] ^ b[i]); return d == 0; }

static int verify (const unsigned char *pw, size_t pwlen, const unsigned char *salt, size_t slen,
                   const Params *p, const unsigned char tag[DIG])
{ unsigned char t[DIG]; param_tag (pw, pwlen, salt, slen, p, t); return ct_eq (t, tag, DIG); }

static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

int main (void)
{
	unsigned char salt[64], tag[DIG], c[17];
	const unsigned char *pw = (const unsigned char *) "correct horse battery staple";
	size_t pwlen = strlen ((const char *) pw);
	Params base = { 2, 3, 1, 2, 1048576u, 3u, 4 };
	int i, all = 1;

	for (i = 0; i < 64; i++) salt[i] = (unsigned char) ((i * 11 + 3) & 0xff);

	param_tag (pw, pwlen, salt, 64, &base, tag);
	printf ("REF param_tag "); hex (tag, DIG); printf ("\n");
	canon (&base, c); printf ("REF canon_base "); hex (c, 17); printf ("\n");
	printf ("REF accept_base %s\n", verify (pw, pwlen, salt, 64, &base, tag) ? "YES" : "NO");

	{
		Params d;
		#define TRY(name, field, val) do { d = base; d.field = (val); \
			int det = !verify (pw, pwlen, salt, 64, &d, tag); all = all && det; \
			printf ("REF detect_%s %s\n", name, det ? "YES" : "NO"); } while (0)
		TRY ("argon_mem",     argon_mem_kib,     8);
		TRY ("argon_iters",   argon_iters,       1);
		TRY ("argon_par",     argon_parallelism, 1);
		TRY ("prf_weaker",    prf_id,            0);
		TRY ("cipher_weaker", cipher_id,         0);
		TRY ("mode_weaker",   mode_id,           0);
		TRY ("version_roll",  version,           1);
		#undef TRY
	}
	printf ("REF all_downgrades_detected %s\n", all ? "YES" : "NO");

	printf ("REF wrongpw_detected %s\n",
	        !verify ((const unsigned char *) "wrong pass", 10, salt, 64, &base, tag) ? "YES" : "NO");

	/* canonical unambiguity: swapping mem<->iters values yields distinct canon bytes */
	{
		Params a = base, b = base; unsigned char ca[17], cb[17];
		a.argon_mem_kib = 3; a.argon_iters = 1048576u;
		b.argon_mem_kib = 1048576u; b.argon_iters = 3;
		canon (&a, ca); canon (&b, cb);
		printf ("REF canon_unambiguous %s\n", !ct_eq (ca, cb, 17) ? "YES" : "NO");
	}
	return 0;
}
