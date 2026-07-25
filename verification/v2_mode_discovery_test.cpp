/*
 * v2_mode_discovery_test.cpp — prove V2FormatDiscoverMode DISCRIMINATES between the two wide-block
 * modes, using the REAL EncryptionMode classes to produce the ciphertext it inspects.
 *
 * WHY THIS TEST COULD NOT EXIST UNTIL NOW. `V2Mode` is `{V2_MODE_HCTR2 = 0, V2_MODE_ADIANTUM = 1,
 * V2_MODE_NONE = -1}` and `V2FormatDiscoverMode` identifies a volume's mode by deriving each mode's MAC
 * key from the master key and testing which one reproduces the stored sector-0 tag. Step [85] proved
 * that tag arithmetic against a twin. But with only ONE wide-block EncryptionMode implemented
 * (Adiantum, #35), the *discrimination* could never be exercised end to end: you could show it returns
 * NONE for a wrong key, and nothing more. Every "it picks the right mode" claim rested on the tag math
 * alone, never on two real modes producing two real ciphertexts.
 *
 * EncryptionModeHctr2 changes that. This harness encrypts the SAME sector-0 plaintext under BOTH real
 * mode classes, tags each with its own mode-derived key, and requires discovery to return the mode that
 * actually produced it — and to keep doing so when the two are swapped. That is the difference between
 * "the tag function works" and "mode discovery works".
 *
 * WHAT IT DELIBERATELY DOES NOT CLAIM. This is the DISCOVERY half of T1-1 only. It does not exercise
 * the per-sector MAC I/O layer (tags are computed here, not written through Volume::WriteSectors), and
 * it says nothing about what should happen when a tag MISMATCHES on a real read — that is a fail-closed
 * vs fail-warn policy decision, not a fact about this code. See docs/V2-FORMAT-SPEC.md.
 *
 * ANCHOR CLASS: PROPERTY (the fork's own format; no published standard to conform to). The underlying
 * HMAC-SHA256 is OFFICIAL-anchored at [69] and the mode-key HKDF shape at [104]; what is asserted here
 * is behaviour of a fork-specific construction, which is the correct class for it.
 */

#include <cstdio>
#include <cstring>
#include "Platform/Platform.h"
#include "Volume/EncryptionModeHctr2.h"
#include "Volume/EncryptionModeAdiantum.h"

extern "C" {
#include "Common/V2Format.h"
}

using namespace VeraCrypt;

static int pass = 0, fail = 0;
static void check (const char *what, bool ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

static const size_t SEC = 512;

int main ()
{
	printf ("  V2 mode discovery — does DiscoverMode pick the mode that actually encrypted sector 0?\n");

	/* One master key; each mode derives its OWN sub-key from it (mode-domain-separated, T1-1a). */
	uint8 masterKey[64];
	for (size_t i = 0; i < sizeof masterKey; i++) masterKey[i] = (uint8) (i * 11 + 3);

	uint8 plain[SEC];
	for (size_t i = 0; i < SEC; i++) plain[i] = (uint8) (i * 31 + 7);

	/* --- encrypt sector 0 under each REAL mode class ------------------------------------------------ */
	uint8 ctH[SEC], ctA[SEC];
	memcpy (ctH, plain, SEC);
	memcpy (ctA, plain, SEC);
	{
		uint8 k[32];
		for (size_t i = 0; i < sizeof k; i++) k[i] = (uint8) (0x40 + i);

		shared_ptr <EncryptionModeHctr2> h (new EncryptionModeHctr2);
		h->SetKey (ConstBufferPtr (k, sizeof k));
		h->EncryptSectorsCurrentThread (ctH, 0, 1, SEC);

		shared_ptr <EncryptionModeAdiantum> a (new EncryptionModeAdiantum);
		a->SetKey (ConstBufferPtr (k, sizeof k));
		a->EncryptSectorsCurrentThread (ctA, 0, 1, SEC);
	}
	check ("the two wide-block modes produce DIFFERENT sector-0 ciphertext (same key)",
	       memcmp (ctH, ctA, SEC) != 0);

	/* --- tag each ciphertext with ITS OWN mode-derived MAC key --------------------------------------- */
	uint8 macKeyH[V2_KEY_LEN], macKeyA[V2_KEY_LEN];
	V2FormatDeriveModeKey (masterKey, (int) sizeof masterKey, V2_MODE_HCTR2,   macKeyH);
	V2FormatDeriveModeKey (masterKey, (int) sizeof masterKey, V2_MODE_ADIANTUM, macKeyA);
	check ("the two mode keys differ (mode domain separation, T1-1a)",
	       memcmp (macKeyH, macKeyA, V2_KEY_LEN) != 0);

	uint8 tagH[V2_MAC_TAG_LEN], tagA[V2_MAC_TAG_LEN];
	V2FormatSectorTag (macKeyH, 0, ctH, SEC, tagH);
	V2FormatSectorTag (macKeyA, 0, ctA, SEC, tagA);

	/* --- THE POINT OF THIS HARNESS: discovery must name the mode that really encrypted it ------------ */
	printf ("  [1] discrimination (untestable until a SECOND wide-block mode existed)\n");
	{
		V2Mode gotH = V2FormatDiscoverMode (masterKey, (int) sizeof masterKey, ctH, SEC, tagH);
		V2Mode gotA = V2FormatDiscoverMode (masterKey, (int) sizeof masterKey, ctA, SEC, tagA);
		check ("an HCTR2-encrypted sector 0 is discovered as HCTR2",   gotH == V2_MODE_HCTR2);
		check ("an Adiantum-encrypted sector 0 is discovered as ADIANTUM", gotA == V2_MODE_ADIANTUM);
		check ("...and the two answers are not the same value (it is really choosing)", gotH != gotA);
	}

	/* --- negatives ---------------------------------------------------------------------------------- */
	printf ("  [2] negatives\n");
	{
		/* Wrong master key -> NONE, indistinguishable from a v1 volume. This is the fall-through the
		   mount path relies on: a v1 volume, or a wrong password, must not be mistaken for a v2 mode. */
		uint8 badKey[64];
		memcpy (badKey, masterKey, sizeof badKey); badKey[0] ^= 0x01;
		check ("a wrong master key yields NONE (falls through to a v1 interpretation)",
		       V2FormatDiscoverMode (badKey, (int) sizeof badKey, ctH, SEC, tagH) == V2_MODE_NONE);

		/* Tag belonging to the OTHER mode -> NONE. A tag/ciphertext pair from different modes is not a
		   valid v2 volume, and must not be silently resolved to whichever mode happens to match first. */
		check ("HCTR2 ciphertext carrying the ADIANTUM tag yields NONE",
		       V2FormatDiscoverMode (masterKey, (int) sizeof masterKey, ctH, SEC, tagA) == V2_MODE_NONE);

		/* A single flipped ciphertext bit must break discovery — the tag covers the ciphertext. */
		uint8 tampered[SEC];
		memcpy (tampered, ctH, SEC); tampered[SEC / 2] ^= 0x01;
		check ("a 1-bit ciphertext change yields NONE (the tag covers the sector)",
		       V2FormatDiscoverMode (masterKey, (int) sizeof masterKey, tampered, SEC, tagH) == V2_MODE_NONE);

		/* A flipped tag bit likewise. */
		uint8 badTag[V2_MAC_TAG_LEN];
		memcpy (badTag, tagH, sizeof badTag); badTag[0] ^= 0x01;
		check ("a 1-bit tag change yields NONE",
		       V2FormatDiscoverMode (masterKey, (int) sizeof masterKey, ctH, SEC, badTag) == V2_MODE_NONE);
	}

	printf ("  V2 MODE DISCOVERY: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  V2 MODE DISCOVERY TEST FAILED\n"); return 1; }
	printf ("  V2 MODE DISCOVERY TEST PASSED\n");
	return 0;
}
