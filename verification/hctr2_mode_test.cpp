/*
 * hctr2_mode_test.cpp — module test for the EncryptionMode shim, src/Volume/EncryptionModeHctr2.
 *
 * WHAT THIS ADDS THAT [91] DOES NOT. Step [91] proves the Hctr2 ALGORITHM against all 18 official
 * google/hctr2 KATs. It says nothing about the EncryptionMode subclass, which is where the shim can
 * go wrong in ways the KATs cannot see: a wrong tweak convention, a SectorOffset that is ignored, a
 * sector/data-unit size confusion, or an in-place aliasing bug. Those are integration faults, so this
 * is a PROPERTY test over the real class, not another KAT run.
 *
 * The single most important assertion here is the WIDE-BLOCK one. It is the entire reason to prefer
 * Hctr2 over XTS in this fork, and it is exactly the property a shim can silently lose (e.g. by
 * calling the primitive per 16-byte block instead of per sector). Under XTS, flipping one plaintext
 * byte changes ONE 16-byte ciphertext block; under a correct Hctr2 sector mode it must randomise the
 * WHOLE sector. The test measures that, rather than asserting it in a comment.
 *
 * Build: verification/build_and_verify.sh step [103].
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "Platform/Platform.h"
#include "Volume/EncryptionModeHctr2.h"

using namespace VeraCrypt;

static int pass = 0, fail = 0;

static void check (const char *what, bool ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

static size_t diff_bytes (const uint8 *a, const uint8 *b, size_t n)
{
	size_t d = 0;
	for (size_t i = 0; i < n; i++) if (a[i] != b[i]) d++;
	return d;
}

static shared_ptr <EncryptionModeHctr2> MakeMode (uint8 keyByte)
{
	shared_ptr <EncryptionModeHctr2> m (new EncryptionModeHctr2);
	uint8 key[EncryptionModeHctr2::Hctr2KeySize];
	for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8) (keyByte + i * 7);
	m->SetKey (ConstBufferPtr (key, sizeof key));
	return m;
}

int main ()
{
	printf ("  EncryptionModeHctr2 shim test (src/Volume/EncryptionModeHctr2.cpp)\n");

	const size_t SEC = 512;
	shared_ptr <EncryptionModeHctr2> mode = MakeMode (0x11);

	check ("key is set after SetKey", mode->IsKeySet());
	check ("GetKeySize() == 32 (Hctr2's own key, not a sum over Ciphers)", mode->GetKeySize() == 32);
	check ("GetName() == \"HCTR2\"", mode->GetName() == L"HCTR2");
	check ("GetNew() returns a fresh, unkeyed instance", mode->GetNew() && !mode->GetNew()->IsKeySet());

	/* --- 1. round-trip through the class ---------------------------------------------------------- */
	printf ("  [1] sector round-trip\n");
	{
		uint8 pt[SEC * 4], ct[SEC * 4], rt[SEC * 4];
		for (size_t i = 0; i < sizeof pt; i++) pt[i] = (uint8) (i * 31 + 7);
		memcpy (ct, pt, sizeof pt);

		mode->EncryptSectorsCurrentThread (ct, 0, 4, SEC);
		check ("encryption changes the data", memcmp (ct, pt, sizeof pt) != 0);

		memcpy (rt, ct, sizeof ct);
		mode->DecryptSectorsCurrentThread (rt, 0, 4, SEC);
		check ("decrypt(encrypt(x)) == x over 4 sectors", memcmp (rt, pt, sizeof pt) == 0);
	}

	/* --- 2. THE WIDE-BLOCK PROPERTY — the reason this mode exists ---------------------------------- */
	printf ("  [2] wide-block diffusion (the property XTS does NOT have)\n");
	{
		uint8 a[SEC], b[SEC];
		for (size_t i = 0; i < SEC; i++) a[i] = (uint8) (i);
		memcpy (b, a, SEC);
		b[SEC / 2] ^= 0x01;                       /* one bit, in the middle of the sector */

		mode->EncryptSectorsCurrentThread (a, 5, 1, SEC);
		mode->EncryptSectorsCurrentThread (b, 5, 1, SEC);

		const size_t d = diff_bytes (a, b, SEC);
		printf ("    one plaintext bit flipped -> %zu of %zu ciphertext bytes differ\n", d, SEC);
		/* A narrow-block mode would change only the containing 16-byte block. Random diffusion changes
		   ~255/256 of the bytes; require a large majority so this cannot pass by luck. */
		check ("a 1-bit plaintext change randomises the WHOLE sector (>90% of bytes)", d > (SEC * 9) / 10);
		check ("...and is not confined to a 16-byte block (as XTS would be)", d > 16);
	}

	/* --- 3. the tweak actually binds the sector index ---------------------------------------------- */
	printf ("  [3] sector index is bound into the ciphertext\n");
	{
		uint8 s0[SEC], s1[SEC];
		for (size_t i = 0; i < SEC; i++) { s0[i] = 0xA5; s1[i] = 0xA5; }
		mode->EncryptSectorsCurrentThread (s0, 0, 1, SEC);
		mode->EncryptSectorsCurrentThread (s1, 1, 1, SEC);
		check ("identical plaintext at different sector indices -> different ciphertext",
		       memcmp (s0, s1, SEC) != 0);
	}

	/* --- 4. SectorOffset participates (a shim that ignores it would still round-trip) --------------- */
	printf ("  [4] SectorOffset is honoured\n");
	{
		uint8 x[SEC], y[SEC];
		shared_ptr <EncryptionModeHctr2> shifted = MakeMode (0x11);
		shifted->SetSectorOffset (100);

		for (size_t i = 0; i < SEC; i++) { x[i] = 0x5C; y[i] = 0x5C; }
		mode->EncryptSectorsCurrentThread (x, 0, 1, SEC);       /* offset 0, sector 0   */
		shifted->EncryptSectorsCurrentThread (y, 0, 1, SEC);    /* offset 100, sector 0 */
		check ("the same sector under a different SectorOffset encrypts differently",
		       memcmp (x, y, SEC) != 0);

		/* ...and it is the SUM that matters: offset 100 + sector 0 == offset 0 + sector 100. */
		uint8 z[SEC];
		for (size_t i = 0; i < SEC; i++) z[i] = 0x5C;
		mode->EncryptSectorsCurrentThread (z, 100, 1, SEC);
		check ("offset 100 + sector 0 == offset 0 + sector 100 (tweak is the sum)",
		       memcmp (y, z, SEC) == 0);
	}

	/* --- 5. a different key gives different ciphertext ---------------------------------------------- */
	printf ("  [5] key separation\n");
	{
		uint8 k1[SEC], k2[SEC];
		shared_ptr <EncryptionModeHctr2> other = MakeMode (0x77);
		for (size_t i = 0; i < SEC; i++) { k1[i] = 0x3B; k2[i] = 0x3B; }
		mode->EncryptSectorsCurrentThread (k1, 9, 1, SEC);
		other->EncryptSectorsCurrentThread (k2, 9, 1, SEC);
		check ("a different key yields different ciphertext", memcmp (k1, k2, SEC) != 0);

		/* Cross-key decryption must not silently return plaintext. */
		uint8 crossed[SEC];
		memcpy (crossed, k1, SEC);
		other->DecryptSectorsCurrentThread (crossed, 9, 1, SEC);
		bool allSame = true;
		for (size_t i = 0; i < SEC; i++) if (crossed[i] != 0x3B) { allSame = false; break; }
		check ("decrypting under the WRONG key does not recover the plaintext", !allSame);
	}

	/* --- 6. buffer (header-style) path, and refusal of a partial unit -------------------------------- */
	printf ("  [6] buffer path + partial-unit refusal\n");
	{
		uint8 buf[512 * 2], orig[512 * 2];
		for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8) (i * 13 + 5);
		memcpy (orig, buf, sizeof buf);
		mode->Encrypt (buf, sizeof buf);
		mode->Decrypt (buf, sizeof buf);
		check ("Encrypt/Decrypt buffer round-trip over whole data units", memcmp (buf, orig, sizeof buf) == 0);

		/* Wide-block cannot process a partial unit; it must refuse rather than emit a truncated result
		   that would later decrypt to garbage and look like a wrong key. */
		bool threw = false;
		try { mode->Encrypt (buf, 300); } catch (...) { threw = true; }
		check ("a non-multiple-of-unit length is REFUSED, not silently truncated", threw);

		bool threwSector = false;
		try { mode->EncryptSectorsCurrentThread (buf, 0, 1, HCTR2_MAX_SECTOR + 512); }
		catch (...) { threwSector = true; }
		check ("an oversized sector is REFUSED (cannot be split without changing the property)", threwSector);
	}

	/* --- 7. an unkeyed instance must not encrypt ------------------------------------------------------ */
	printf ("  [7] unkeyed instance\n");
	{
		EncryptionModeHctr2 fresh;
		uint8 b[SEC]; memset (b, 0, sizeof b);
		bool threw = false;
		try { fresh.EncryptSectorsCurrentThread (b, 0, 1, SEC); } catch (...) { threw = true; }
		check ("encrypting without a key throws", threw);
	}

	printf ("  HCTR2 MODE: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  HCTR2 MODE SHIM TEST FAILED\n"); return 1; }
	printf ("  HCTR2 MODE SHIM TEST PASSED\n");
	return 0;
}
