/*
 * argon2_params_test.c — verification for the explicit Argon2id parameter override.
 *
 * My change only *plumbs* memory/iterations/parallelism through to Argon2id (stock shoehorns them into
 * PIM and fixes parallelism at 1); it does not touch the Argon2 algorithm. So it is verified as:
 *
 *   [RFC]  the REAL in-tree Argon2 reproduces the published RFC 9106 Argon2id test vector (parallelism
 *          4) — the independent anchor for the algorithm itself.
 *   [P]    the override actually plumbs parallelism: with p=1 derive_key_argon2 matches a direct
 *          argon2id_hash_raw(...,1) (and hence stock), with p=4 it matches argon2id_hash_raw(...,4),
 *          and p=1 vs p=4 differ (so parallelism genuinely changes the derived key).
 *   REF    the resolver's PIM formula and override selection — printed as REF lines and diffed
 *          byte-for-byte against the independent argon2_params_reference.py.
 *
 * Links the REAL in-tree Common/Pkcs5.c (with -DVC_ENABLE_ARGON2_PARAMS) and Argon2 sources.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>     /* wchar_t, used by Pkcs5.h declarations */
#include "argon2.h"
#include "Common/Pkcs5.h"

static void hex (const char *l, const unsigned char *p, int n)
{ int i; printf ("%s", l); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }
static int eq (const unsigned char *a, const unsigned char *b, int n) { return memcmp (a, b, n) == 0; }

int main (void)
{
	/* [RFC] RFC 9106 Argon2id KAT via the real argon2id_ctx (password/salt/secret/ad all fixed bytes) */
	{
		unsigned char pwd[32], salt[16], secret[8], ad[12], out[32];
		static const unsigned char RFC[32] = {
			0x0d,0x64,0x0d,0xf5,0x8d,0x78,0x76,0x6c,0x08,0xc0,0x37,0xa3,0x4a,0x8b,0x53,0xc9,
			0xd0,0x1e,0xf0,0x45,0x2d,0x75,0xb6,0x5e,0xb5,0x25,0x20,0xe9,0x6b,0x01,0xe6,0x59 };
		argon2_context ctx; memset (&ctx, 0, sizeof ctx);
		memset (pwd,1,32); memset (salt,2,16); memset (secret,3,8); memset (ad,4,12);
		ctx.out=out; ctx.outlen=32; ctx.pwd=pwd; ctx.pwdlen=32; ctx.salt=salt; ctx.saltlen=16;
		ctx.secret=secret; ctx.secretlen=8; ctx.ad=ad; ctx.adlen=12;
		ctx.t_cost=3; ctx.m_cost=32; ctx.lanes=4; ctx.threads=4; ctx.version=ARGON2_VERSION_13;
		argon2id_ctx (&ctx);
		printf ("[RFC] in-tree Argon2id == RFC 9106 vector (p=4): %s\n", eq (out, RFC, 32) ? "YES" : "NO");
	}

	/* [P] the override plumbs parallelism into derive_key_argon2 */
	{
		unsigned char pwd[16], salt[16], d1[32], d4[32], r1[32], r4[32];
		memset (pwd, 0xAB, 16); memset (salt, 0xCD, 16);

		Argon2SetParamsOverride (1, 64, 3, 1);                 /* m=64 KiB, t=3, p=1 */
		derive_key_argon2 (pwd,16, salt,16, 3, 64, d1, 32, NULL);
		argon2id_hash_raw (3, 64, 1, pwd,16, salt,16, r1, 32, NULL);

		Argon2SetParamsOverride (1, 64, 3, 4);                 /* same but p=4 */
		derive_key_argon2 (pwd,16, salt,16, 3, 64, d4, 32, NULL);
		argon2id_hash_raw (3, 64, 4, pwd,16, salt,16, r4, 32, NULL);
		Argon2SetParamsOverride (0, 0, 0, 1);                  /* clear */

		printf ("[P] p=1 override == argon2id_hash_raw(p=1) (stock-equivalent): %s\n", eq (d1, r1, 32) ? "YES" : "NO");
		printf ("[P] p=4 override == argon2id_hash_raw(p=4): %s\n", eq (d4, r4, 32) ? "YES" : "NO");
		printf ("[P] p=1 and p=4 derive different keys: %s\n", !eq (d1, d4, 32) ? "YES" : "NO");
	}

	/* REF: resolver PIM formula (no override) — diffed against the python reference */
	{
		int pims[] = { 0, 1, 3, 12, 31, 32, 40 };
		unsigned i;
		Argon2SetParamsOverride (0, 0, 0, 1);
		for (i = 0; i < sizeof (pims) / sizeof (pims[0]); i++)
		{
			uint32 it = 0, mc = 0, par = 0;
			int used = Argon2GetResolvedParams (pims[i], &it, &mc, &par);
			printf ("REF resolve pim=%d used=%d t=%u m=%u p=%u\n", pims[i], used, it, mc, par);
		}
		/* and one override case */
		Argon2SetParamsOverride (1, 262144, 5, 8);   /* 256 MiB, 5 iters, 8 lanes */
		{
			uint32 it = 0, mc = 0, par = 0;
			int used = Argon2GetResolvedParams (12, &it, &mc, &par);
			printf ("REF resolve pim=12 used=%d t=%u m=%u p=%u\n", used, it, mc, par);
		}
		Argon2SetParamsOverride (0, 0, 0, 1);
	}

	return 0;
}
