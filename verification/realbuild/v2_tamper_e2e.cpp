/*
 v2_tamper_e2e.cpp — the END-TO-END proof that v2 tamper detection is actually armed on a real volume.

 WHY THIS EXISTS, AND WHAT IT CAUGHT
 verification/v2_sector_mac_io_test.cpp proves V2SectorMacIo in ISOLATION: hand it ciphertext and a file,
 and it tags, verifies, fails closed and counts overrides correctly. That test passes whether or not the
 layer is ever reached by a real mount. It was passing 15/15 while the shipping feature was inert, for
 THREE independent reasons, none of which any component test could see:

   1. DOUBLE-SHRUNK DATA AREA. VolumeLayoutV2Normal::GetDataSize() returns the header's STORED
      VolumeDataSize, which CreateVolume had already reduced to the split's usable prefix. The population
      code split it a second time and put the table inside user data.
   2. THE TABLE REGION WAS NEVER RESERVED. For a non-quick Normal volume the backup header is written at
      the current SEQUENTIAL file position, which the format loop leaves at the end of the usable data —
      exactly where the table begins. The backup header landed on top of the first 131072 bytes of tags
      and the finished container came out short by the whole table.
   3. MISMATCHED MAC-KEY LENGTH. VolumeHeader::GetMasterKeys() returns the entire 256-byte master-key
      FIELD (sized for the largest cascade), while VolumeCreator derives from the key it actually
      generated — EA->GetKeySize() * 2, i.e. 64 bytes for AES-XTS. Different HKDF input, so every tag
      differed and discovery matched nothing.

 Each failure mode is silent in the same way: V2FormatDiscoverMode returns NONE, V2Mac stays inert, and
 the volume opens as v1 with authentication ABSENT. Nothing throws and nothing is logged. Only driving
 create -> mount -> write -> read on one real volume catches this, because each side is internally
 self-consistent and only their COMPOSITION is wrong.

 That is the general lesson this harness encodes: a unit test proves a component; only an end-to-end test
 proves the component is CONNECTED. For a security control, "not connected" and "absent" are the same
 thing, and both look exactly like "passing".

 THE FLOW (driven by v2_tamper_e2e.sh, one command per invocation)
   create (CLI, --v2-format) -> probe: the volume is recognised as v2
                             -> write a known sector, read it back: authenticated I/O round-trips
                             -> tamper: flip one bit of CIPHERTEXT on disk, outside the volume abstraction
                             -> read: REFUSED (V2TagMismatch); the caller gets no plaintext
                             -> read with the operator override: allowed, and the ignore is COUNTED

 ANCHOR CLASS: PROPERTY. Fork-specific format. The primitives underneath are anchored elsewhere
 (HMAC-SHA256 OFFICIAL at [69], the mode-key HKDF at [104]); what is asserted here is that the shipping
 create and mount paths agree and that the fail-closed policy reaches a real caller.

 USAGE
   v2_tamper_e2e <command> <volume> <password> [args]
 Every command exits 0 on the expected outcome and non-zero otherwise; the shell driver holds the
 expectations, the same division of labour open_roundtrip.cpp uses.
*/

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

#include "Platform/Platform.h"
#include "Platform/FileStream.h"
#include "Volume/Volume.h"
#include "Volume/VolumePassword.h"

using namespace VeraCrypt;
using namespace std;

static shared_ptr<VolumePassword> MakePassword (const string &s)
{
	return shared_ptr<VolumePassword> (new VolumePassword ((const uint8 *) s.data(), s.size()));
}

/* Open with the same defaults open_roundtrip.cpp uses. KDF is left unpinned unless VC_OPEN_KDF is set,
   so the driver can keep opens fast by naming the hash the volume was created with. */
static void OpenVolume (Volume &vol, const string &path, const string &password)
{
	shared_ptr <Pkcs5Kdf> kdf;
	const char *kdfName = getenv ("VC_OPEN_KDF");
	if (kdfName && *kdfName)
		kdf = Pkcs5Kdf::GetAlgorithm (StringConverter::ToWide (string (kdfName)));

	vol.Open (VolumePath (StringConverter::ToWide (path)), true, MakePassword (password), 0, kdf,
	          shared_ptr <KeyfileList> (), false);
}

static uint64 DataOffsetOf (const Volume &vol)
{
	return vol.GetLayout()->GetDataOffset (vol.GetHostSize());
}

int main (int argc, char **argv)
{
	if (argc < 4)
	{
		fprintf (stderr, "usage: %s <command> <volume> <password> [args]\n", argv[0]);
		return 2;
	}

	const string cmd  = argv[1];
	const string path = argv[2];
	const string pw   = argv[3];

	try
	{
#if !defined(VC_ENABLE_V2FORMAT)
		fprintf (stderr, "built without VC_ENABLE_V2FORMAT — this harness requires V2FORMAT=1\n");
		return 3;
#else
		/* ---- probe: is this volume recognised as v2 by the REAL mount path? ------------------------
		   This is the single assertion the whole defect hid behind. It is deliberately the first thing
		   the driver checks, before any tampering: if discovery does not fire, every later "refused"
		   result would be vacuous — a read cannot be refused by a layer that is not running. */
		if (cmd == "probe" || cmd == "not_v2")
		{
			Volume vol;
			OpenVolume (vol, path, pw);
			const bool isV2 = vol.IsV2();
			printf ("v2=%d dataOffset=%llu usableSize=%llu sectorSize=%llu hostSize=%llu\n",
			        isV2 ? 1 : 0,
			        (unsigned long long) DataOffsetOf (vol),
			        (unsigned long long) vol.GetSize(),
			        (unsigned long long) vol.GetSectorSize(),
			        (unsigned long long) vol.GetHostSize());
			vol.Close();
			return (cmd == "probe") ? (isV2 ? 0 : 1) : (isV2 ? 1 : 0);
		}

		/* ---- write / read: authenticated I/O must round-trip before any negative test means anything */
		if (cmd == "write" || cmd == "read")
		{
			if (argc < 6) { fprintf (stderr, "%s needs <sector> <fillbyte>\n", cmd.c_str()); return 2; }
			const uint64 sector = strtoull (argv[4], NULL, 0);
			const uint8  fill   = (uint8) strtoul (argv[5], NULL, 0);

			Volume vol;
			OpenVolume (vol, path, pw);
			const size_t ss = vol.GetSectorSize();
			SecureBuffer buf (ss);

			if (cmd == "write")
			{
				memset (buf.Ptr(), fill, ss);
				vol.WriteSectors (buf, sector * ss);
				vol.Close();
				return 0;
			}

			vol.ReadSectors (buf, sector * ss);
			vol.Close();
			for (size_t i = 0; i < ss; i++)
				if (buf.Ptr()[i] != fill)
				{
					fprintf (stderr, "sector %llu byte %zu = 0x%02x, expected 0x%02x\n",
					         (unsigned long long) sector, i, buf.Ptr()[i], fill);
					return 1;
				}
			return 0;
		}

		/* ---- tamper: edit CIPHERTEXT on disk, outside the volume abstraction ------------------------
		   This is what the adversary can do and the volume layer cannot prevent: raw write access to the
		   container. We open once only to learn the true data offset and sector size (rather than
		   hardcoding a layout constant that a future layout change would silently invalidate), close,
		   then flip a single bit with plain stdio. Nothing here goes through Volume, so no tag is
		   updated — which is exactly the state a tampered volume is in. */
		if (cmd == "tamper")
		{
			if (argc < 5) { fprintf (stderr, "tamper needs <sector>\n"); return 2; }
			const uint64 sector = strtoull (argv[4], NULL, 0);

			uint64 dataOffset, ss;
			{
				Volume vol;
				OpenVolume (vol, path, pw);
				dataOffset = DataOffsetOf (vol);
				ss = vol.GetSectorSize();
				vol.Close();
			}

			const uint64 target = dataOffset + sector * ss + 100;   /* mid-sector, nothing special */
			FILE *f = fopen (path.c_str(), "r+b");
			if (!f) { perror ("fopen"); return 1; }
			if (fseeko (f, (off_t) target, SEEK_SET) != 0) { perror ("fseeko"); fclose (f); return 1; }
			int c = fgetc (f);
			if (c == EOF) { fprintf (stderr, "read past end of container\n"); fclose (f); return 1; }
			if (fseeko (f, (off_t) target, SEEK_SET) != 0) { perror ("fseeko"); fclose (f); return 1; }
			if (fputc (c ^ 0x01, f) == EOF) { perror ("fputc"); fclose (f); return 1; }
			if (fclose (f) != 0) { perror ("fclose"); return 1; }
			printf ("flipped 1 bit at host offset %llu (data sector %llu)\n",
			        (unsigned long long) target, (unsigned long long) sector);
			return 0;
		}

		/* ---- read_refuse: the fail-closed policy, reaching a real caller --------------------------- */
		if (cmd == "read_refuse")
		{
			if (argc < 5) { fprintf (stderr, "read_refuse needs <sector>\n"); return 2; }
			const uint64 sector = strtoull (argv[4], NULL, 0);

			Volume vol;
			OpenVolume (vol, path, pw);
			if (!vol.IsV2())
			{
				/* Guard against a vacuous pass: if the layer is inert the read would succeed and a naive
				   "did it throw?" test would report the wrong reason for the wrong outcome. */
				fprintf (stderr, "volume did not open as v2 — a refusal here would prove nothing\n");
				vol.Close();
				return 1;
			}

			const size_t ss = vol.GetSectorSize();
			SecureBuffer buf (ss);
			try
			{
				vol.ReadSectors (buf, sector * ss);
			}
			catch (V2TagMismatch &)
			{
				printf ("read refused: V2TagMismatch\n");
				vol.Close();
				return 0;
			}
			fprintf (stderr, "read of a TAMPERED sector SUCCEEDED — tamper detection is not armed\n");
			vol.Close();
			return 1;
		}

		/* ---- read_override: the mandatory recovery path, and its accounting ------------------------ */
		if (cmd == "read_override")
		{
			if (argc < 5) { fprintf (stderr, "read_override needs <sector>\n"); return 2; }
			const uint64 sector = strtoull (argv[4], NULL, 0);

			Volume vol;
			OpenVolume (vol, path, pw);
			if (!vol.IsV2()) { fprintf (stderr, "not v2\n"); vol.Close(); return 1; }

			if (vol.GetV2IgnoredMismatchCount() != 0)
			{
				fprintf (stderr, "override state leaked across opens — it must be per-instance\n");
				vol.Close();
				return 1;
			}

			vol.SetV2IgnoreTags (true);
			const size_t ss = vol.GetSectorSize();
			SecureBuffer buf (ss);
			vol.ReadSectors (buf, sector * ss);     /* must NOT throw now */

			const uint64 ignored = vol.GetV2IgnoredMismatchCount();
			printf ("override read ok; ignored=%llu firstSector=%llu\n",
			        (unsigned long long) ignored,
			        (unsigned long long) vol.GetV2FirstIgnoredSector());
			vol.Close();

			/* An override that reads past a bad tag without recording it is fail-warn with extra steps. */
			if (ignored == 0)
			{
				fprintf (stderr, "override allowed the read but counted nothing\n");
				return 1;
			}
			return 0;
		}
#endif
		fprintf (stderr, "unknown command: %s\n", cmd.c_str());
		return 2;
	}
	catch (Exception &e)
	{
		fprintf (stderr, "exception: %s\n", StringConverter::GetTypeName (typeid (e)).c_str());
		return 4;
	}
	catch (exception &e)
	{
		fprintf (stderr, "std exception: %s\n", e.what());
		return 4;
	}
}
