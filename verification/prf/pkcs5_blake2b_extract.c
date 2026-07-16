/* ---- HMAC-BLAKE2b-512 and PBKDF2-HMAC-BLAKE2b ----
   Reuses the in-tree BLAKE2b primitive that ships with Argon2 (declared via Crypto.h),
   hence the shared VC_DCS_DISABLE_ARGON2 guard. Non-boot PRF only.
   NOTE: unlike the BLAKE2s HMAC above, the ipad/opad block is BLAKE2B_BLOCKSIZE (128) bytes,
   which does not fit in the (PKCS5_SALT_SIZE + 4) scratch buffer, so a dedicated 128-byte
   pad buffer is used for key padding. */
#if !defined(TC_WINDOWS_BOOT) && !defined(VC_DCS_DISABLE_ARGON2)

typedef struct hmac_blake2b_ctx_struct
{
	blake2b_state ctx;
	blake2b_state inner_digest_ctx;	/* pre-computed inner digest context */
	blake2b_state outer_digest_ctx;	/* pre-computed outer digest context */
	unsigned char k[PKCS5_SALT_SIZE + 4];	/* holds (salt_len + 4) and also the 64-byte BLAKE2b hash */
	unsigned char u[BLAKE2B_DIGESTSIZE];
} hmac_blake2b_ctx;

static void hmac_blake2b_internal
(
	unsigned char *d,		/* input data; d is guaranteed to be at least 64 bytes long */
	int ld,			/* length of input data in bytes */
	hmac_blake2b_ctx* hmac	/* HMAC-BLAKE2b context which holds temporary variables */
)
{
	blake2b_state* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/
	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (blake2b_state));
	blake2b_update (ctx, d, ld);
	blake2b_final (ctx, d, BLAKE2B_DIGESTSIZE);	/* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/
	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (blake2b_state));
	blake2b_update (ctx, d, BLAKE2B_DIGESTSIZE);
	blake2b_final (ctx, d, BLAKE2B_DIGESTSIZE);	/* d = outer digest */
}

void hmac_blake2b
(
	unsigned char *k,	/* secret key */
	int lk,		/* length of the key in bytes */
	unsigned char *d,	/* data */
	int ld		/* length of data in bytes */
)
{
	hmac_blake2b_ctx hmac;
	blake2b_state* ctx;
	unsigned char pad[BLAKE2B_BLOCKSIZE];	/* 128-byte HMAC key-pad block */
	int b;
	unsigned char key[BLAKE2B_DIGESTSIZE];

	/* If the key is longer than the hash block size, let key = blake2b(key), per HMAC. */
	if (lk > BLAKE2B_BLOCKSIZE)
	{
		blake2b_state tctx;

		blake2b_init (&tctx, BLAKE2B_DIGESTSIZE);
		blake2b_update (&tctx, k, lk);
		blake2b_final (&tctx, key, BLAKE2B_DIGESTSIZE);

		k = key;
		lk = BLAKE2B_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	/* Prevent leaks */
	}

	/**** Precompute HMAC Inner Digest ****/
	ctx = &(hmac.inner_digest_ctx);
	blake2b_init (ctx, BLAKE2B_DIGESTSIZE);

	for (b = 0; b < lk; ++b)
		pad[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&pad[lk], 0x36, BLAKE2B_BLOCKSIZE - lk);

	blake2b_update (ctx, pad, BLAKE2B_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/
	ctx = &(hmac.outer_digest_ctx);
	blake2b_init (ctx, BLAKE2B_DIGESTSIZE);

	for (b = 0; b < lk; ++b)
		pad[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&pad[lk], 0x5C, BLAKE2B_BLOCKSIZE - lk);

	blake2b_update (ctx, pad, BLAKE2B_BLOCKSIZE);

	hmac_blake2b_internal (d, ld, &hmac);

	/* Prevent leaks */
	burn (&hmac, sizeof(hmac));
	burn (pad, sizeof(pad));
	burn (key, sizeof(key));
}

static void derive_u_blake2b (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_blake2b_ctx* hmac, volatile long *pAbortKeyDerivation)
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

	hmac_blake2b_internal (k, salt_len + 4, hmac);
	memcpy (u, k, BLAKE2B_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
		/* CANCELLATION CHECK: check every 1024 iterations */
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return;	/* Abort derivation */

		hmac_blake2b_internal (k, BLAKE2B_DIGESTSIZE, hmac);
		for (i = 0; i < BLAKE2B_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}

void derive_key_blake2b (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
	hmac_blake2b_ctx hmac;
	blake2b_state* ctx;
	unsigned char pad[BLAKE2B_BLOCKSIZE];	/* 128-byte HMAC key-pad block */
	int b, l, r;
	unsigned char key[BLAKE2B_DIGESTSIZE];

	/* If the password is longer than the hash block size, let pwd = blake2b(pwd), per HMAC. */
	if (pwd_len > BLAKE2B_BLOCKSIZE)
	{
		blake2b_state tctx;

		blake2b_init (&tctx, BLAKE2B_DIGESTSIZE);
		blake2b_update (&tctx, pwd, pwd_len);
		blake2b_final (&tctx, key, BLAKE2B_DIGESTSIZE);

		pwd = key;
		pwd_len = BLAKE2B_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	/* Prevent leaks */
	}

	if (dklen % BLAKE2B_DIGESTSIZE)
	{
		l = 1 + dklen / BLAKE2B_DIGESTSIZE;
	}
	else
	{
		l = dklen / BLAKE2B_DIGESTSIZE;
	}

	r = dklen - (l - 1) * BLAKE2B_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/
	ctx = &(hmac.inner_digest_ctx);
	blake2b_init (ctx, BLAKE2B_DIGESTSIZE);

	for (b = 0; b < pwd_len; ++b)
		pad[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&pad[pwd_len], 0x36, BLAKE2B_BLOCKSIZE - pwd_len);

	blake2b_update (ctx, pad, BLAKE2B_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/
	ctx = &(hmac.outer_digest_ctx);
	blake2b_init (ctx, BLAKE2B_DIGESTSIZE);

	for (b = 0; b < pwd_len; ++b)
		pad[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&pad[pwd_len], 0x5C, BLAKE2B_BLOCKSIZE - pwd_len);

	blake2b_update (ctx, pad, BLAKE2B_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_blake2b (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
		memcpy (dk, hmac.u, BLAKE2B_DIGESTSIZE);
		dk += BLAKE2B_DIGESTSIZE;
	}

	/* last block */
	derive_u_blake2b (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
	memcpy (dk, hmac.u, r);

cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (pad, sizeof(pad));
	burn (key, sizeof(key));
}

#endif // !defined(TC_WINDOWS_BOOT) && !defined(VC_DCS_DISABLE_ARGON2)
