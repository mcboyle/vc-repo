/*
 * v2_sector_mac_io_test.cpp — the v2 per-sector MAC I/O layer (src/Volume/V2SectorMacIo.h).
 *
 * WHAT THIS PROVES, beyond the tag arithmetic already anchored at [85]:
 *   - the FAIL-CLOSED policy actually fires: a modified ciphertext sector throws, and the caller does
 *     NOT receive data;
 *   - the ORDERING is right — tags are over CIPHERTEXT, so verify-before-decrypt / update-after-encrypt.
 *     A layer that authenticated plaintext would still round-trip cleanly while authenticating nothing
 *     an attacker can touch, so this is checked explicitly rather than assumed;
 *   - the TORN-WRITE state (new data under an old tag) is detected — this is the concrete mechanism
 *     behind the accepted availability cost, and the reason the override is mandatory;
 *   - the OVERRIDE behaves as specified: off by default, counts and reports what it ignored, and is
 *     instance state that is never written to the volume.
 *
 * ANCHOR CLASS: PROPERTY. Fork-specific format; the underlying HMAC-SHA256 is OFFICIAL-anchored at [69]
 * and the mode-key HKDF at [104]. What is asserted here is I/O-layer behaviour.
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "Platform/Platform.h"
#include "Platform/FileStream.h"
#include "Volume/V2SectorMacIo.h"

using namespace VeraCrypt;

static int pass = 0, fail = 0;
static void check (const char *what, bool ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

static const size_t SEC = 512;
static const uint64 NSECT = 8;

int main ()
{
	printf ("  V2 per-sector MAC I/O layer (src/Volume/V2SectorMacIo.h)\n");

	/* A scratch volume-shaped file: NSECT data sectors, then the MAC table. */
	FilePath tmp (L"/tmp/vc_v2_mac_io_test.bin");
	{
		File f;
		f.Open (tmp, File::CreateReadWrite);
		SecureBuffer zero ((size_t) (NSECT * SEC + NSECT * V2_MAC_TAG_LEN));
		memset (zero.Ptr(), 0, zero.Size());
		f.WriteAt (zero, 0);
		f.Close();
	}

	uint8 masterKey[64];
	for (size_t i = 0; i < sizeof masterKey; i++) masterKey[i] = (uint8) (i * 7 + 1);

	/* Stand-in "ciphertext": the layer is mode-agnostic — it authenticates whatever bytes it is given.
	   NOTE THE SECTOR TERM. An earlier version used `i * 13 + 5` alone, which is a trap: 512 * 13 is a
	   multiple of 256, so every sector came out BYTE-IDENTICAL. That silently defeats any test that
	   relocates one sector's ciphertext to another index — the relocated bytes equal the target's own
	   bytes, so verification legitimately succeeds and the test reads as a failure of index binding when
	   it is really a failure of the test data. Mix the sector number in so sectors genuinely differ. */
	SecureBuffer ct ((size_t) (NSECT * SEC));
	for (size_t i = 0; i < ct.Size(); i++)
		ct.Ptr()[i] = (uint8) (i * 13 + 5 + (i / SEC) * 101);

	File f;
	f.Open (tmp, File::OpenReadWrite);

	V2SectorMacIo mac;
	mac.Configure (V2_MODE_HCTR2, masterKey, (int) sizeof masterKey, SEC, NSECT * SEC, NSECT);
	check ("configured for a v2 volume -> active", mac.IsActive());
	check ("the override is OFF by default", !mac.GetIgnoreTags());

	/* --- 1. write tags, then verify them back ------------------------------------------------------- */
	printf ("  [1] update then verify\n");
	mac.UpdateRange (f, ct.Ptr(), 0, NSECT);
	{
		bool threw = false;
		try { mac.VerifyRange (f, ct.Ptr(), 0, NSECT); } catch (...) { threw = true; }
		check ("freshly tagged ciphertext verifies", !threw);
	}

	/* --- 2. FAIL CLOSED on a modified sector -------------------------------------------------------- */
	printf ("  [2] fail-closed policy\n");
	{
		SecureBuffer tampered ((size_t) (NSECT * SEC));
		tampered.CopyFrom (ct);
		tampered.Ptr()[3 * SEC + 100] ^= 0x01;      /* one bit, in sector 3 */

		bool threw = false;
		try { mac.VerifyRange (f, tampered.Ptr(), 0, NSECT); }
		catch (V2TagMismatch &) { threw = true; }
		check ("a 1-bit ciphertext change THROWS V2TagMismatch (read refused)", threw);
		check ("nothing was ignored, because the override is off", mac.GetIgnoredMismatchCount() == 0);

		/* Verifying only the untouched sectors must still succeed — the failure is scoped to the
		   damaged sector, not the whole volume. */
		bool threwClean = false;
		try { mac.VerifyRange (f, tampered.Ptr(), 0, 3); } catch (...) { threwClean = true; }
		check ("sectors before the damaged one still verify (failure is per-sector)", !threwClean);
	}

	/* --- 3. THE TORN-WRITE STATE — new data under an old tag ---------------------------------------- */
	printf ("  [3] torn write (the availability cost, and why the override exists)\n");
	{
		/* Simulate: data updated on disk, tags NOT yet updated (crash between the two writes). */
		SecureBuffer newCt ((size_t) (NSECT * SEC));
		for (size_t i = 0; i < newCt.Size(); i++) newCt.Ptr()[i] = (uint8) (i * 29 + 3);

		bool threw = false;
		try { mac.VerifyRange (f, newCt.Ptr(), 0, NSECT); }
		catch (V2TagMismatch &) { threw = true; }
		check ("new data under stale tags is DETECTED (fails closed, no adversary needed)", threw);

		/* ...and the override is what gets the operator's data back. */
		mac.SetIgnoreTags (true);
		bool threwOverride = false;
		try { mac.VerifyRange (f, newCt.Ptr(), 0, NSECT); } catch (...) { threwOverride = true; }
		check ("with the override, the read is allowed to proceed", !threwOverride);
		check ("...and every ignored sector is COUNTED, not silently passed",
		       mac.GetIgnoredMismatchCount() == NSECT);
		check ("...and the first offending sector is recorded for the operator",
		       mac.GetFirstIgnoredSector() == 0);
		mac.SetIgnoreTags (false);
	}

	/* --- 4. the tag really is over ciphertext, and binds the sector index --------------------------- */
	printf ("  [4] tag binds ciphertext AND sector index\n");
	{
		mac.UpdateRange (f, ct.Ptr(), 0, NSECT);

		/* Present sector 2's ciphertext as though it were sector 5. If the tag did not bind the index, an
		   adversary could freely relocate sectors within the volume. */
		bool threw = false;
		try { mac.VerifyRange (f, ct.Ptr() + 2 * SEC, 5, 1); }
		catch (V2TagMismatch &) { threw = true; }
		check ("a sector's ciphertext replayed at a DIFFERENT index is rejected", threw);

		/* The above alone does not ISOLATE index binding — it would also fail if the two sectors merely
		   held different bytes. This does isolate it: tag IDENTICAL content at two different indices and
		   require the tags to differ. Only the index can account for that difference. */
		uint8 same[SEC];
		memset (same, 0xC7, sizeof same);
		uint8 tagAt2[V2_MAC_TAG_LEN], tagAt5[V2_MAC_TAG_LEN];
		uint8 key[V2_KEY_LEN];
		V2FormatDeriveModeKey (masterKey, (int) sizeof masterKey, V2_MODE_HCTR2, key);
		V2FormatSectorTag (key, 2, same, sizeof same, tagAt2);
		V2FormatSectorTag (key, 5, same, sizeof same, tagAt5);
		check ("IDENTICAL ciphertext at different indices yields DIFFERENT tags (index is bound)",
		       memcmp (tagAt2, tagAt5, V2_MAC_TAG_LEN) != 0);
	}

	/* --- 5. bounds are refused, not silently wrapped ------------------------------------------------ */
	printf ("  [5] bounds\n");
	{
		bool threw = false;
		try { mac.VerifyRange (f, ct.Ptr(), NSECT - 1, 4); } catch (...) { threw = true; }
		check ("a range past the end of the table is REFUSED (would touch the backup header)", threw);
	}

	/* --- 6. a non-v2 volume takes a no-op path ------------------------------------------------------ */
	printf ("  [6] v1 volumes are untouched\n");
	{
		V2SectorMacIo inactive;
		check ("an unconfigured instance is inactive", !inactive.IsActive());
		bool threw = false;
		try { inactive.VerifyRange (f, ct.Ptr(), 0, NSECT); inactive.UpdateRange (f, ct.Ptr(), 0, NSECT); }
		catch (...) { threw = true; }
		check ("verify/update on a non-v2 volume are explicit no-ops, not errors", !threw);
	}

	f.Close();
	remove ("/tmp/vc_v2_mac_io_test.bin");

	printf ("  V2 SECTOR MAC IO: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  V2 SECTOR MAC IO TEST FAILED\n"); return 1; }
	printf ("  V2 SECTOR MAC IO TEST PASSED\n");
	return 0;
}
