/*
 * keyscrub_selftest.c — self-contained verification for the cross-platform memory-key scrub.
 *
 * Layer 2 of the project's two-way convention: this harness links the REAL in-tree VeraCrypt
 * objects (Crypto/t1ha2.c, Crypto/chacha256.c, Crypto/chachaRng.c) and drives the real
 * Common/KeyScrub.c. Layer 1 is verification/keyscrub_reference.py, an independent Python
 * reimplementation of the same transform; build_and_verify.sh diffs the two "REF" lines below
 * byte-for-byte.
 *
 * Checks:
 *   [A] VcSecureWipe zeroises, observed through a separate alias (survives -O2 dead-store removal).
 *   [B] the scrub registry wipes every registered region on one VcScrubAll call.
 *   [C] VcKsRamTransform on a FIXED vector -> printed "REF" lines (matched against Python).
 *   [D] the transform is its own inverse (protect then protect == identity) and the protected
 *       buffer does not equal the plaintext (the secret is not left in the clear).
 *   [E] the live store path (RNG-seeded 1 MB area) round-trips a secret and then scrubs it.
 *   [L] negative-control liveness (ROI item 2): the secret is asserted PRESENT before and ABSENT
 *       after the wipe, in the same run. Building this TU with -DVC_NEGCTL_NO_WIPE skips the wipe and
 *       the "absent after" assertions must flip to NO — build_and_verify.sh builds both variants and
 *       checks the flip, proving a silent no-op wipe would be caught (the checks are not vacuous).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/KeyScrub.h"
#include "Common/HardwareKeyFactor.h"
#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>   /* getrlimit for the lockdown check */
#endif
#if defined(__linux__)
#include <sys/prctl.h>      /* PR_GET_DUMPABLE for the lockdown check */
#endif

static void print_hex (const char *label, const unsigned char *p, size_t n)
{
	size_t i;
	printf ("%s", label);
	for (i = 0; i < n; i++)
		printf ("%02x", p[i]);
	printf ("\n");
}

/* ---- FIXED test vector, shared verbatim with keyscrub_reference.py ---- */
#define AREA_LEN   256
#define SECRET_LEN 32
static const uint64_t HASH_MASK = UINT64_C(0x0f1e2d3c4b5a6978);
static const uint64_t IV_MASK   = UINT64_C(0x8090a0b0c0d0e0f0);
static const uint64_t AREA_BASE = UINT64_C(0x1122334455667788);
static const uint64_t ENC_ID    = UINT64_C(0x00000000deadbeef);

static void fill_area (unsigned char area[AREA_LEN])
{
	int i;
	for (i = 0; i < AREA_LEN; i++)
		area[i] = (unsigned char) ((i * 181 + 31) & 0xff);
}

static void fill_secret (unsigned char s[SECRET_LEN])
{
	int i;
	for (i = 0; i < SECRET_LEN; i++)
		s[i] = (unsigned char) (0x10 + i);
}

/* dummy RNG for the live store path — deterministic here only so the harness is reproducible */
static void test_rng (unsigned char *p, size_t n)
{
	static uint32_t s = 0x12345678u;
	size_t i;
	for (i = 0; i < n; i++)
	{
		s = s * 1103515245u + 12345u;
		p[i] = (unsigned char) (s >> 24);
	}
}

int main (void)
{
	/* [A] secure wipe */
	{
		unsigned char buf[64];
		volatile unsigned char *alias = buf;
		int i, nonzero = 0;
		for (i = 0; i < 64; i++) buf[i] = (unsigned char) (i + 1);
		VcSecureWipe (buf, sizeof (buf));
		for (i = 0; i < 64; i++) nonzero |= alias[i];
		printf ("[A] secure-wipe zeroed: %s\n", nonzero ? "NO" : "YES");
	}

	/* [B] registry scrub */
	{
		unsigned char a[16], b[8], c[40];
		int i, dirty = 0;
		for (i = 0; i < 16; i++) a[i] = 0xAA;
		for (i = 0; i < 8;  i++) b[i] = 0xBB;
		for (i = 0; i < 40; i++) c[i] = 0xCC;
		VcScrubRegister (a, sizeof (a));
		VcScrubRegister (b, sizeof (b));
		VcScrubRegister (c, sizeof (c));
		printf ("[B] registered regions: %d\n", VcScrubRegionCount ());
		VcScrubAll ();
		for (i = 0; i < 16; i++) dirty |= a[i];
		for (i = 0; i < 8;  i++) dirty |= b[i];
		for (i = 0; i < 40; i++) dirty |= c[i];
		printf ("[B] all registered regions zeroed: %s\n", dirty ? "NO" : "YES");
		VcScrubUnregister (a); VcScrubUnregister (b); VcScrubUnregister (c);
		printf ("[B] regions after unregister: %d\n", VcScrubRegionCount ());
	}

	/* [C] fixed-vector transform -> reproducible "REF" lines for the Python cross-check */
	{
		unsigned char area[AREA_LEN], secret[SECRET_LEN], work[SECRET_LEN];
		fill_area (area);
		fill_secret (secret);
		memcpy (work, secret, SECRET_LEN);
		VcKsRamTransform (area, AREA_LEN, HASH_MASK, IV_MASK, AREA_BASE, ENC_ID, work, SECRET_LEN);
		print_hex ("REF protected = ", work, SECRET_LEN);

		/* [D] inverse + not-in-clear */
		{
			int notclear = memcmp (work, secret, SECRET_LEN) != 0;
			VcKsRamTransform (area, AREA_LEN, HASH_MASK, IV_MASK, AREA_BASE, ENC_ID, work, SECRET_LEN);
			printf ("REF roundtrip identity = %s\n", memcmp (work, secret, SECRET_LEN) == 0 ? "YES" : "NO");
			printf ("REF protected != plaintext = %s\n", notclear ? "YES" : "NO");
		}
	}

	/* [E] live store: RNG-seeded 1 MB area, protect/unprotect round-trip, then scrub */
	{
		unsigned char secret[SECRET_LEN], saved[SECRET_LEN];
		int i, ok, notclear, restored, scrubbed;
		fill_secret (secret);
		memcpy (saved, secret, SECRET_LEN);
		ok = VcKsRamProtectInit (test_rng);
		VcKsRamProtect (secret, SECRET_LEN);
		notclear = memcmp (secret, saved, SECRET_LEN) != 0;
		VcScrubRegister (secret, SECRET_LEN);
		VcKsRamUnprotect (secret, SECRET_LEN);
		restored = memcmp (secret, saved, SECRET_LEN) == 0;
		VcScrubAll ();
		scrubbed = 1;
		for (i = 0; i < SECRET_LEN; i++) if (secret[i]) scrubbed = 0;
		printf ("[E] store init: %s\n", ok ? "YES" : "NO");
		printf ("[E] protected != plaintext: %s\n", notclear ? "YES" : "NO");
		printf ("[E] unprotect restored secret: %s\n", restored ? "YES" : "NO");
		printf ("[E] scrub-on-event cleared secret: %s\n", scrubbed ? "YES" : "NO");
		VcKsRamProtectShutdown ();
	}

	/* [G] memory-hygiene lockdown: core dumps disabled + process non-dumpable (observable here) */
	{
		int bits = VcKeyMemoryLockdown ();
		int core_off = 0, dump_off = 0;
#if defined(__linux__) || defined(__APPLE__)
		{ struct rlimit rl; if (getrlimit (RLIMIT_CORE, &rl) == 0 && rl.rlim_cur == 0) core_off = 1; }
#endif
#if defined(__linux__)
		dump_off = (prctl (PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
#endif
		printf ("[G] lockdown ran (bits=0x%02x): %s\n", bits, "YES");
		printf ("[G] core dumps disabled (RLIMIT_CORE==0): %s\n", core_off ? "YES" : "NO");
		printf ("[G] process non-dumpable (PR_GET_DUMPABLE==0): %s\n", dump_off ? "YES" : "NO");
		printf ("[G] mlockall best-effort (privilege-gated, not asserted): %s\n",
		        (bits & VC_LOCKDOWN_MLOCK) ? "applied" : "skipped");
	}

	/* [J] swap / hibernation exposure detector (ROI item 11). Driven with fixtures so the two states
	 *     are exercised deterministically — this IS the negative control: a system with no swap and no
	 *     hibernation must report clean (0), and the detector must NOT cry wolf; a system with an
	 *     active swap area and suspend-to-disk must report both bits. */
	{
		const char *clean_swaps = "/tmp/ks_fix_swaps_clean";
		const char *swap_swaps  = "/tmp/ks_fix_swaps_active";
		const char *no_hib      = "/tmp/ks_fix_power_nohib";
		const char *hib         = "/tmp/ks_fix_power_hib";
		FILE *f;
		int clean, exposed, tokfp;
		f = fopen (clean_swaps, "w"); fputs ("Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n", f); fclose (f);
		f = fopen (swap_swaps, "w");  fputs ("Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n"
		                                     "/dev/dm-1                               partition\t8388604\t0\t-2\n", f); fclose (f);
		f = fopen (no_hib, "w"); fputs ("freeze mem\n", f); fclose (f);
		f = fopen (hib,    "w"); fputs ("freeze mem disk\n", f); fclose (f);

		clean   = VcSwapHibernateStatusFrom (clean_swaps, no_hib);   /* expect 0 */
		exposed = VcSwapHibernateStatusFrom (swap_swaps,  hib);      /* expect SWAP_ACTIVE|SUPPORTED */
		/* token-exactness: a mode literally named "diskless" must NOT be read as "disk" */
		f = fopen ("/tmp/ks_fix_power_fp", "w"); fputs ("freeze diskless\n", f); fclose (f);
		tokfp = VcSwapHibernateStatusFrom (NULL, "/tmp/ks_fix_power_fp");   /* expect 0 (no SUPPORTED) */

		printf ("[J] no-swap/no-hibernate fixture reports clean: %s\n", clean == 0 ? "YES" : "NO");
		printf ("[J] active-swap fixture flags SWAP_ACTIVE: %s\n",
		        (exposed & VC_HIBERNATE_SWAP_ACTIVE) ? "YES" : "NO");
		printf ("[J] suspend-to-disk fixture flags SUPPORTED: %s\n",
		        (exposed & VC_HIBERNATE_SUPPORTED) ? "YES" : "NO");
		printf ("[J] 'diskless' not misread as hibernation: %s\n",
		        (tokfp & VC_HIBERNATE_SUPPORTED) ? "NO" : "YES");
		remove (clean_swaps); remove (swap_swaps); remove (no_hib); remove (hib); remove ("/tmp/ks_fix_power_fp");
	}

	/* [H] zeroization matrix: VcSecureWipe zeroes every size/alignment and survives -O2 DSE */
	{
		static unsigned char pool[300];
		int sizes[] = { 1, 7, 8, 16, 31, 32, 63, 64, 100, 255 };
		unsigned i, off, allzero = 1;
		for (off = 0; off < 3; off++)
			for (i = 0; i < sizeof (sizes) / sizeof (sizes[0]); i++)
			{
				volatile unsigned char *alias = pool + off;
				int n = sizes[i], j;
				for (j = 0; j < n; j++) pool[off + j] = (unsigned char) (0xA5 ^ j);
				VcSecureWipe (pool + off, (size_t) n);
				for (j = 0; j < n; j++) if (alias[j]) allzero = 0;
			}
		printf ("[H] secure-wipe zeroes all sizes/alignments (survives -O2): %s\n", allzero ? "YES" : "NO");
	}

	/* [F] HKF integration: HKFScrubActiveConfig wipes the reconstructed secret + detaches config */
	{
		static HKFConfig cfg;
		int i, dirty = 0;
		memset (&cfg, 0, sizeof (cfg));
		cfg.backend = HKF_BACKEND_RAW_SECRET;
		for (i = 0; i < 32; i++) cfg.rawSecret[i] = (unsigned char) (0xE0 + i);
		cfg.rawSecretLen = 32;
		HKFSetActiveConfig (&cfg);
		HKFScrubActiveConfig ();
		for (i = 0; i < 32; i++) dirty |= cfg.rawSecret[i];
		printf ("[F] HKF secret wiped: %s\n", dirty ? "NO" : "YES");
		printf ("[F] HKF config detached: %s\n", g_hkfActiveConfig == 0 ? "YES" : "NO");
	}

	/* [L] negative-control liveness (ROI item 2). A zeroization test that only checks "absent after"
	 *     can pass vacuously — if the buffer was already zero, or the compiler elided it, or the wipe
	 *     is a silent no-op. Each pair below asserts the secret is PRESENT *before* and ABSENT *after*
	 *     in the same run, so a wipe that does nothing is caught. Compiling this TU with
	 *     -DVC_NEGCTL_NO_WIPE skips the wipe: the "present before" lines must stay YES (the input was
	 *     real) while the "absent after" lines must flip to NO. build_and_verify.sh builds BOTH
	 *     variants and asserts exactly that flip — proving the checks have teeth. */
	{
#if defined(VC_NEGCTL_NO_WIPE)
		const int wipe_enabled = 0;
#else
		const int wipe_enabled = 1;
#endif
		/* [L1] VcSecureWipe — read the buffer through a volatile alias so -O2 cannot elide it */
		{
			unsigned char s[SECRET_LEN];
			volatile unsigned char *alias = s;
			int i, present = 0, absent = 1;
			fill_secret (s);
			for (i = 0; i < SECRET_LEN; i++) present |= alias[i];
			if (wipe_enabled) VcSecureWipe (s, SECRET_LEN);
			for (i = 0; i < SECRET_LEN; i++) if (alias[i]) absent = 0;
			printf ("[L1] secret present before wipe: %s\n", present ? "YES" : "NO");
			printf ("[L1] secret absent after wipe: %s\n", absent ? "YES" : "NO");
		}
		/* [L2] HKFScrubActiveConfig — the security-critical path (wipes a reconstructed factor secret) */
		{
			static HKFConfig cfg;
			int i, present = 0, absent = 1;
			memset (&cfg, 0, sizeof (cfg));
			cfg.backend = HKF_BACKEND_RAW_SECRET;
			for (i = 0; i < 32; i++) cfg.rawSecret[i] = (unsigned char) (0xE0 + i);
			cfg.rawSecretLen = 32;
			for (i = 0; i < 32; i++) present |= cfg.rawSecret[i];
			HKFSetActiveConfig (&cfg);
			if (wipe_enabled) HKFScrubActiveConfig ();
			for (i = 0; i < 32; i++) if (cfg.rawSecret[i]) absent = 0;
			printf ("[L2] HKF secret present before scrub: %s\n", present ? "YES" : "NO");
			printf ("[L2] HKF secret absent after scrub: %s\n", absent ? "YES" : "NO");
		}
	}

	return 0;
}
