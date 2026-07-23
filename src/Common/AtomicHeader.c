/*
 * AtomicHeader — see AtomicHeader.h. A/B header pair + generation + commit tag over the in-tree Sha2.
 */
#include "AtomicHeader.h"

#if defined(VC_ENABLE_ATOMIC_HEADER)

#include <string.h>
#include "Crypto/Sha2.h"

#define SHA256_BLOCK 64
#define SHA256_DIGEST 32

static void ah_hmac (const unsigned char key[32],
                     const unsigned char *m1, size_t l1, const unsigned char *m2, size_t l2,
                     unsigned char out[SHA256_DIGEST])
{
	sha256_ctx c;
	unsigned char k0[SHA256_BLOCK], pad[SHA256_BLOCK], inner[SHA256_DIGEST];
	int i;
	memcpy (k0, key, 32); memset (k0 + 32, 0, SHA256_BLOCK - 32);
	for (i = 0; i < SHA256_BLOCK; i++) pad[i] = k0[i] ^ 0x36;
	sha256_begin (&c); sha256_hash (pad, SHA256_BLOCK, &c);
	if (l1) sha256_hash (m1, (uint_32t) l1, &c);
	if (l2) sha256_hash (m2, (uint_32t) l2, &c);
	sha256_end (inner, &c);
	for (i = 0; i < SHA256_BLOCK; i++) pad[i] = k0[i] ^ 0x5c;
	sha256_begin (&c); sha256_hash (pad, SHA256_BLOCK, &c); sha256_hash (inner, SHA256_DIGEST, &c);
	sha256_end (out, &c);
}

static void put_gen (unsigned char *p, uint64 g)
{ int i; for (i = 7; i >= 0; i--) { p[i] = (unsigned char)(g & 0xff); g >>= 8; } }
static uint64 read_gen (const unsigned char *p)
{ uint64 g = 0; int i; for (i = 0; i < 8; i++) g = (g << 8) | p[i]; return g; }

/* constant-time-ish tag compare (not secret-dependent branching on the tag content) */
static int tag_equal (const unsigned char *a, const unsigned char *b)
{ int i, d = 0; for (i = 0; i < ATOMIC_HEADER_TAG_SIZE; i++) d |= a[i] ^ b[i]; return d == 0; }

void AtomicHeaderBuild (const unsigned char K[32], const unsigned char *header, int headerLen,
                        uint64 gen, unsigned char *out)
{
	unsigned char genb[ATOMIC_HEADER_GEN_SIZE];
	memmove (out, header, (size_t) headerLen);
	put_gen (genb, gen);
	memcpy (out + headerLen, genb, ATOMIC_HEADER_GEN_SIZE);
	/* commitTag = HMAC(K, header || gen) */
	ah_hmac (K, out, (size_t) headerLen, genb, ATOMIC_HEADER_GEN_SIZE,
	         out + headerLen + ATOMIC_HEADER_GEN_SIZE);
}

int AtomicHeaderValid (const unsigned char K[32], const unsigned char *copy, int headerLen)
{
	unsigned char tag[ATOMIC_HEADER_TAG_SIZE];
	ah_hmac (K, copy, (size_t) headerLen, copy + headerLen, ATOMIC_HEADER_GEN_SIZE, tag);
	return tag_equal (tag, copy + headerLen + ATOMIC_HEADER_GEN_SIZE);
}

uint64 AtomicHeaderGen (const unsigned char *copy, int headerLen)
{ return read_gen (copy + headerLen); }

int AtomicHeaderSelect (const unsigned char K[32],
                        const unsigned char *copyA, const unsigned char *copyB, int headerLen,
                        unsigned char *outHeader, uint64 *outGen)
{
	int va = AtomicHeaderValid (K, copyA, headerLen);
	int vb = AtomicHeaderValid (K, copyB, headerLen);
	int chosen;
	if (!va && !vb) return -1;                                   /* fail closed */
	if (va && !vb) chosen = 0;
	else if (vb && !va) chosen = 1;
	else chosen = (AtomicHeaderGen (copyB, headerLen) > AtomicHeaderGen (copyA, headerLen)) ? 1 : 0;
	{
		const unsigned char *c = chosen ? copyB : copyA;
		if (outHeader) memcpy (outHeader, c, (size_t) headerLen);
		if (outGen) *outGen = AtomicHeaderGen (c, headerLen);
	}
	return chosen;
}

uint64 AtomicHeaderNextGen (const unsigned char K[32],
                            const unsigned char *copyA, const unsigned char *copyB, int headerLen)
{
	uint64 g = 0;
	if (AtomicHeaderValid (K, copyA, headerLen)) { uint64 ga = AtomicHeaderGen (copyA, headerLen); if (ga > g) g = ga; }
	if (AtomicHeaderValid (K, copyB, headerLen)) { uint64 gb = AtomicHeaderGen (copyB, headerLen); if (gb > g) g = gb; }
	return g + 1;
}

#endif /* VC_ENABLE_ATOMIC_HEADER */
