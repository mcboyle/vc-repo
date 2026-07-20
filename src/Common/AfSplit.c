/*
 * AfSplit — see AfSplit.h. The diffusion is the LUKS AF construction: SHA-256 over each 32-byte
 * section with its big-endian section index prepended; a trailing partial section takes the digest
 * prefix (cryptsetup's af.c does the same). Matches verification/afsplit_poc.c for n % 32 == 0 and
 * extends it to arbitrary n; both are diffed against the independent Python reference.
 */

#include "AfSplit.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include <string.h>
#include "Crypto/Sha2.h"

#define AF_DIGEST 32

static void af_wipe (volatile unsigned char *p, size_t n) { while (n--) *p++ = 0; }

static void af_xor (const unsigned char *a, const unsigned char *b, unsigned char *out, int n)
{
	int i;
	for (i = 0; i < n; i++)
		out[i] = (unsigned char) (a[i] ^ b[i]);
}

/* LUKS diffuse: SHA-256 each 32-byte section with its big-endian index prepended; a final partial
   section of r bytes takes the first r bytes of its digest. */
static void af_diffuse (const unsigned char *src, unsigned char *dst, int n)
{
	int i, full = n / AF_DIGEST, rem = n % AF_DIGEST;
	for (i = 0; i < full + (rem ? 1 : 0); i++)
	{
		sha256_ctx c;
		unsigned char iv[4], h[AF_DIGEST];
		int take = (i < full) ? AF_DIGEST : rem;
		iv[0] = (unsigned char) (i >> 24); iv[1] = (unsigned char) (i >> 16);
		iv[2] = (unsigned char) (i >> 8);  iv[3] = (unsigned char) i;
		sha256_begin (&c);
		sha256_hash (iv, 4, &c);
		sha256_hash (src + i * AF_DIGEST, (uint_32t) take, &c);
		sha256_end (h, &c);
		memcpy (dst + i * AF_DIGEST, h, take);
		af_wipe (h, sizeof (h));
	}
}

int AfSplit (const unsigned char *material, int n, int s,
             void (*rng) (unsigned char *, size_t),
             unsigned char *stripes)
{
	unsigned char buf[1024], t[1024];
	int i;

	if (n <= 0 || n > (int) sizeof (buf) || s < 1 || material == NULL || stripes == NULL
	    || (s > 1 && rng == NULL))
		return -1;

	memset (buf, 0, (size_t) n);
	for (i = 0; i < s - 1; i++)
	{
		rng (stripes + (size_t) i * n, (size_t) n);
		af_xor (buf, stripes + (size_t) i * n, t, n);
		af_diffuse (t, buf, n);
	}
	af_xor (material, buf, stripes + (size_t) (s - 1) * n, n);

	af_wipe (buf, sizeof (buf));
	af_wipe (t, sizeof (t));
	return 0;
}

void AfMerge (const unsigned char *stripes, int n, int s, unsigned char *materialOut)
{
	unsigned char buf[1024], t[1024];
	int i;

	if (n <= 0 || n > (int) sizeof (buf) || s < 1)
		return;

	memset (buf, 0, (size_t) n);
	for (i = 0; i < s - 1; i++)
	{
		af_xor (buf, stripes + (size_t) i * n, t, n);
		af_diffuse (t, buf, n);
	}
	af_xor (stripes + (size_t) (s - 1) * n, buf, materialOut, n);

	af_wipe (buf, sizeof (buf));
	af_wipe (t, sizeof (t));
}

#endif /* VC_ENABLE_KEYSLOTS */
