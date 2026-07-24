/*
 open_roundtrip.cpp — library-level (in-process) header open round-trip against the REAL product objects.

 WHY THIS EXISTS
 The self-contained verification suite proves the fork's algorithms in isolation; acceptance.sh drives the
 built CLI to the kernel-mount boundary. Neither one links the real C++ mount path and calls it directly,
 so Volume::Open — the function that reads a volume header, derives the header key (iterating KDFs and
 encryption algorithms), and recovers the master key — was only ever exercised "to the kernel boundary".
 This harness links the actual Core.a/Volume.a/Platform.a and calls Volume::Open in process, with NO
 kernel dm-crypt needed: a correct password decrypts the header and yields a non-trivial master key; a
 wrong password (or, under an HKF build, a missing/wrong factor) throws PasswordIncorrect.

 It is deliberately a thin executor: the driver (acceptance.sh) creates volumes with the proven CLI and
 invokes this once per assertion, telling it what outcome to expect. Test logic stays in the shell, the
 same division of labour acceptance.sh already uses for the CLI checks.

 USAGE
   open_roundtrip must_open   <volume> <password> [sim_secret_hex] [sim_mac]
   open_roundtrip must_reject <volume> <password> [sim_secret_hex] [sim_mac]

 must_open   : exit 0 iff Volume::Open succeeds AND the recovered master key is non-trivial (not all-zero).
 must_reject : exit 0 iff Volume::Open throws PasswordIncorrect (the correct rejection for a wrong
               password / missing / wrong factor). Any other outcome is a test failure.

 With sim_secret_hex present (HKF builds only) the process-wide active factor config is set to the
 SIMULATOR backend before Open, exactly as the CLI does — so the factor is mixed into the password the
 same way a real mount would. Omitting it opens with the password alone.
*/

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include "Platform/Platform.h"
#include "Volume/Volume.h"
#include "Volume/VolumePassword.h"

#if defined(VC_ENABLE_HKF)
#include "Main/HardwareKeyFactorCli.h"   // BuildHKFConfig (wx-free); pulls in Common/HardwareKeyFactor.h
#endif

using namespace VeraCrypt;
using namespace std;

static shared_ptr<VolumePassword> MakePassword (const string &s)
{
	return shared_ptr<VolumePassword> (new VolumePassword ((const uint8 *) s.data (), s.size ()));
}

#if defined(VC_ENABLE_HKF)
// Kept alive for the whole process so g_hkfActiveConfig never dangles during Open.
static HKFConfig g_simConfig;

static bool SetSimulatorFactor (const string &simSecretHex, int simMac, string &err)
{
	if (!BuildHKFConfig ("simulator", 0, "", "", "", simSecretHex, simMac, g_simConfig, err))
		return false;
	HKFSetActiveConfig (&g_simConfig);
	return true;
}
#endif

// Returns: 0 opened, 1 PasswordIncorrect, 2 any other error.
static int DoOpen (const string &path, const string &password, bool reportMaster)
{
	// Optionally pin the KDF to the volume's actual hash (env VC_OPEN_KDF, e.g. "HMAC-SHA-512"). With
	// no pin, Volume::Open iterates every KDF — correct, but a *failed* open (wrong password/factor)
	// then re-runs each one including Argon2, which is deliberately slow. The driver knows the hash it
	// created with, so pinning keeps the negative (must_reject) probes fast without changing behaviour
	// for a matching password. Unset => try all, exactly as a real mount with an unknown KDF does.
	shared_ptr<Pkcs5Kdf> kdf;
	if (const char *kdfName = getenv ("VC_OPEN_KDF"))
	{
		if (kdfName[0])
		{
			const string n (kdfName);
			kdf = Pkcs5Kdf::GetAlgorithm (wstring (n.begin (), n.end ()));
		}
	}

	make_shared_auto (Volume, volume);
	try
	{
		volume->Open (
			VolumePath (wstring (path.begin (), path.end ())),
			false,                                  // preserveTimestamps
			MakePassword (password),
			0,                                      // pim (0 = default)
			kdf,                                    // null => iterate every KDF internally
			shared_ptr<KeyfileList> (),             // no keyfiles
			false,                                  // emvSupportEnabled
			VolumeProtection::ReadOnly);            // never write the header — non-destructive probe
	}
	catch (PasswordIncorrect &)
	{
		return 1;
	}
	catch (Exception &e)
	{
		cerr << "  unexpected VeraCrypt exception during Open\n";
		return 2;
	}
	catch (...)
	{
		cerr << "  unexpected non-VeraCrypt exception during Open\n";
		return 2;
	}

	if (reportMaster)
	{
		ConstBufferPtr mk = volume->GetHeader ()->GetMasterKeys ();
		if (mk.Size () == 0)
		{
			cerr << "  master key is empty\n";
			return 2;
		}
		bool allZero = true;
		for (size_t i = 0; i < mk.Size (); ++i)
			if (mk.Get ()[i] != 0) { allZero = false; break; }
		if (allZero)
		{
			cerr << "  master key is all-zero (trivial)\n";
			return 2;
		}
		fprintf (stderr, "  opened; master key size=%zu, first byte=0x%02x (non-trivial)\n",
		         mk.Size (), (unsigned) mk.Get ()[0]);
	}
	return 0;
}

int main (int argc, char **argv)
{
	if (argc < 4)
	{
		cerr << "usage: " << argv[0] << " must_open|must_reject <volume> <password> [sim_secret_hex] [sim_mac]\n";
		return 64;
	}
	const string mode = argv[1];
	const string path = argv[2];
	const string password = argv[3];

	if (argc >= 5)
	{
#if defined(VC_ENABLE_HKF)
		const string simSecretHex = argv[4];
		const int simMac = (argc >= 6) ? atoi (argv[5]) : 1;
		string err;
		if (!SetSimulatorFactor (simSecretHex, simMac, err))
		{
			cerr << "  failed to build simulator factor config: " << err << "\n";
			return 2;
		}
#else
		cerr << "  a factor was supplied but this harness was built without VC_ENABLE_HKF\n";
		return 2;
#endif
	}

	const int rc = DoOpen (path, password, /*reportMaster=*/ mode == "must_open");

#if defined(VC_ENABLE_HKF)
	HKFSetActiveConfig (NULL);   // detach before exit; do not leave a dangling active config
#endif

	if (mode == "must_open")
	{
		if (rc == 0) { cout << "PASS must_open\n"; return 0; }
		cout << "FAIL must_open (rc=" << rc << ")\n";
		return 1;
	}
	if (mode == "must_reject")
	{
		if (rc == 1) { cout << "PASS must_reject (PasswordIncorrect)\n"; return 0; }
		cout << "FAIL must_reject (expected PasswordIncorrect, rc=" << rc << ")\n";
		return 1;
	}
	cerr << "unknown mode: " << mode << "\n";
	return 64;
}
