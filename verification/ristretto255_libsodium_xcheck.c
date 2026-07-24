/*
 * ristretto255_libsodium_xcheck.c — THIRD independent oracle for the ristretto255 group (D-8 evidence).
 *
 * WHY (D-8). ROADMAP item D-8 (final) decides the shipped network-share / OPRF group arithmetic will be
 * libsodium's ristretto255, not the bespoke from-scratch code the PoCs use. This harness stands up
 * libsodium as an **RFC-9496-anchored** oracle so the swap can be reasoned about against a standard, and
 * cross-checks the from-scratch group ENCODING against it.
 *
 * WHAT IT PROVES (hard asserts, self-contained — no PoC needed):
 *   (A.1) The basepoint multiples 1B..5B computed with crypto_scalarmult_ristretto255_base reproduce the
 *         RFC 9496 Appendix A.1 encodings exactly. It also prints them as `REF ristretto iB` lines so the
 *         suite step can diff them against oprf_ristretto_poc.c — i.e. from-scratch == libsodium == RFC on
 *         the group-encoding + base-scalarmult layer.
 *   (A.2) The RFC 9496 Appendix A.2 hash-to-group vector (SHA-512 of the canonical label, mapped with
 *         crypto_core_ristretto255_from_hash) reproduces the RFC encoding exactly — establishing libsodium
 *         as the RFC-conformant hash-to-group.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: cross-check the from-scratch OPRF hash-to-group. That comparison
 * SURFACED A DEFECT — see docs/OPRF-SPEC.md "RFC-conformance of hash-to-group" and ROADMAP D-8: the
 * bespoke ristretto255 map + point-add (Elligator hash-to-group) diverges from RFC 9496 / libsodium
 * (A.1 base multiples and scalarmult agree, so the divergence is isolated to the hash-to-group MAP). The
 * PoC's own two-oracle check missed it because its Python twin shares the same convention and it anchored
 * only to A.1. D-8 deletes the bespoke map, so this harness records the finding rather than chasing the
 * Elligator bug; the shipped path will be libsodium, which this harness pins to the RFC.
 *
 * SCOPE. VERIFICATION-only: links libsodium, never the product; the default build gains no dependency.
 * Version note: the D-8 *shipping* pin is libsodium >= 1.0.21 (CVE-2025-69277, which per D-8 did not touch
 * ristretto255). As an ORACLE, any libsodium whose ristretto255 reproduces the RFC A.1 + A.2 KATs above is
 * trustworthy; the harness hard-asserts exactly that and prints the linked version.
 */

#include <stdio.h>
#include <string.h>
#include <sodium.h>

static void tohex (const unsigned char *p, int n, char *out)
{ int i; for (i = 0; i < n; i++) sprintf (out + 2 * i, "%02x", p[i]); }

/* RFC 9496 Appendix A.1 — encodings of 1B .. 5B (multiples of the generator). */
static const char *A1[5] = {
	"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
	"6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
	"94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
	"da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
	"e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e"
};

/* RFC 9496 Appendix A.2 — one hash-to-group vector: from_hash(SHA-512(label)). */
static const char *A2_LABEL    = "Ristretto is traditionally a short shot of espresso coffee";
static const char *A2_EXPECTED = "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46";

int main (void)
{
	if (sodium_init () < 0) { fprintf (stderr, "sodium_init failed\n"); return 2; }
	int fail = 0;
	char hex[65];

	/* (A.1) basepoint multiples — hard KAT + emit REF lines for the from-scratch cross-check. */
	for (int i = 1; i <= 5; i++)
	{
		unsigned char s[32] = {0}, q[32];
		s[0] = (unsigned char) i;
		if (crypto_scalarmult_ristretto255_base (q, s) != 0) { fprintf (stderr, "base mult %d failed\n", i); return 2; }
		tohex (q, 32, hex);
		printf ("REF ristretto %dB = %s\n", i, hex);
		if (strcmp (hex, A1[i - 1]) != 0) { fprintf (stderr, "A.1 KAT FAIL at %dB\n", i); fail = 1; }
	}

	/* (A.2) hash-to-group vector — hard KAT establishing libsodium as the RFC hash-to-group. */
	{
		unsigned char h[64], p[32];
		crypto_hash_sha512 (h, (const unsigned char *) A2_LABEL, strlen (A2_LABEL));
		if (crypto_core_ristretto255_from_hash (p, h) != 0) { fprintf (stderr, "from_hash failed\n"); return 2; }
		tohex (p, 32, hex);
		if (strcmp (hex, A2_EXPECTED) != 0) { fprintf (stderr, "A.2 hash-to-group KAT FAIL: %s\n", hex); fail = 1; }
		else fprintf (stderr, "A.2 hash-to-group KAT OK (%s)\n", hex);
	}

	fprintf (stderr, "libsodium %s — ristretto255 oracle (D-8; shipping pin >= 1.0.21)\n", sodium_version_string ());
	if (fail) { fprintf (stderr, "RISTRETTO255 LIBSODIUM XCHECK: RFC KAT FAILURE\n"); return 1; }
	fprintf (stderr, "RISTRETTO255 LIBSODIUM XCHECK: RFC 9496 A.1 + A.2 reproduced\n");
	return 0;
}
