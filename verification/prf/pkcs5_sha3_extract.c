/* ---- HMAC-SHA3-512 and PBKDF2-HMAC-SHA3-512 ----
   Uses the FIPS 202 Keccak primitive in Crypto/Sha3.c. Non-boot PRF only.
   SHA3-512's HMAC block size is its rate = 72 bytes (SHA3_512_BLOCKSIZE); like BLAKE2b this
   exceeds the (PKCS5_SALT_SIZE + 4) scratch buffer, so a dedicated 72-byte pad buffer is used. */
#ifndef TC_WINDOWS_BOOT

typedef struct hmac_sha3_512_ctx_struct
{
	SHA3_CTX ctx;
	SHA3_CTX inner_digest_ctx;	/* pre-computed inner digest context */
	SHA3_CTX outer_digest_ctx;	/* pre-computed outer digest context */
	unsigned char k[PKCS5_SALT_SIZE + 4];	/* holds (salt_len + 4) and also the 64-byte SHA3-512 hash */
	unsigned char u[SHA3_512_DIGESTSIZE];
} hmac_sha3_512_ctx;

static void hmac_sha3_512_internal
(
	unsigned char *d,		/* input data; d is guaranteed to be at least 64 bytes long */
	int ld,			/* length of input data in bytes */
	hmac_sha3_512_ctx* hmac	/* HMAC-SHA3-512 context which holds temporary variables */
)
{
	SHA3_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/
	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (SHA3_CTX));
	sha3_512_update (ctx, d, ld);
	sha3_512_final (ctx, d);	/* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/
	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (SHA3_CTX));
	sha3_512_update (ctx, d, SHA3_512_DIGESTSIZE);
	sha3_512_final (ctx, d);	/* d = outer digest */
}

void hmac_sha3_512
(
	unsigned char *k,	/* secret key */
	int lk,		/* length of the key in bytes */
	unsigned char *d,	/* data */
	int ld		/* length of data in bytes */
)
{
	hmac_sha3_512_ctx hmac;
	SHA3_CTX* ctx;
	unsigned char pad[SHA3_512_BLOCKSIZE];	/* 72-byte HMAC key-pad block */
	int b;
	unsigned char key[SHA3_512_DIGESTSIZE];

	/* If the key is longer than the hash block size, let key = sha3_512(key), per HMAC. */
	if (lk > SHA3_512_BLOCKSIZE)
	{
		SHA3_CTX tctx;

		sha3_512_init (&tctx);
		sha3_512_update (&tctx, k, lk);
		sha3_512_final (&tctx, key);

		k = key;
		lk = SHA3_512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	/* Prevent leaks */
	}

	/**** Precompute HMAC Inner Digest ****/
	ctx = &(hmac.inner_digest_ctx);
	sha3_512_init (ctx);

	for (b = 0; b < lk; ++b)
		pad[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&pad[lk], 0x36, SHA3_512_BLOCKSIZE - lk);

	sha3_512_update (ctx, pad, SHA3_512_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/
	ctx = &(hmac.outer_digest_ctx);
	sha3_512_init (ctx);

	for (b = 0; b < lk; ++b)
		pad[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&pad[lk], 0x5C, SHA3_512_BLOCKSIZE - lk);

	sha3_512_update (ctx, pad, SHA3_512_BLOCKSIZE);

	hmac_sha3_512_internal (d, ld, &hmac);

	/* Prevent leaks */
	burn (&hmac, sizeof(hmac));
	burn (pad, sizeof(pad));
	burn (key, sizeof(key));
}

static void derive_u_sha3_512 (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_sha3_512_ctx* hmac, volatile long *pAbortKeyDerivation)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
	uint32 c;
	int i;

	c = iterations;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */

	/* big-endian block number */
	b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_sha3_512_internal (k, salt_len + 4, hmac);
	memcpy (u, k, SHA3_512_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
		/* CANCELLATION CHECK: check every 1024 iterations */
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return;	/* Abort derivation */

		hmac_sha3_512_internal (k, SHA3_512_DIGESTSIZE, hmac);
		for (i = 0; i < SHA3_512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}

void derive_key_sha3_512 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
	hmac_sha3_512_ctx hmac;
	SHA3_CTX* ctx;
	unsigned char pad[SHA3_512_BLOCKSIZE];	/* 72-byte HMAC key-pad block */
	int b, l, r;
	unsigned char key[SHA3_512_DIGESTSIZE];

	/* If the password is longer than the hash block size, let pwd = sha3_512(pwd), per HMAC. */
	if (pwd_len > SHA3_512_BLOCKSIZE)
	{
		SHA3_CTX tctx;

		sha3_512_init (&tctx);
		sha3_512_update (&tctx, pwd, pwd_len);
		sha3_512_final (&tctx, key);

		pwd = key;
		pwd_len = SHA3_512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	/* Prevent leaks */
	}

	if (dklen % SHA3_512_DIGESTSIZE)
	{
		l = 1 + dklen / SHA3_512_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA3_512_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA3_512_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/
	ctx = &(hmac.inner_digest_ctx);
	sha3_512_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		pad[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&pad[pwd_len], 0x36, SHA3_512_BLOCKSIZE - pwd_len);

	sha3_512_update (ctx, pad, SHA3_512_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/
	ctx = &(hmac.outer_digest_ctx);
	sha3_512_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		pad[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&pad[pwd_len], 0x5C, SHA3_512_BLOCKSIZE - pwd_len);

	sha3_512_update (ctx, pad, SHA3_512_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha3_512 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
		memcpy (dk, hmac.u, SHA3_512_DIGESTSIZE);
		dk += SHA3_512_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha3_512 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
	memcpy (dk, hmac.u, r);

cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (pad, sizeof(pad));
	burn (key, sizeof(key));
}

#endif // TC_WINDOWS_BOOT (SHA3-512)
