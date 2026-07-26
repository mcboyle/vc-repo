/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Core_MountOptions
#define TC_HEADER_Core_MountOptions

#include "Platform/Serializable.h"
#include "Volume/Keyfile.h"
#include "Volume/Volume.h"
#include "Volume/VolumeSlot.h"
#include "Volume/VolumePassword.h"

namespace VeraCrypt
{
	struct MountOptions : public Serializable
	{
		MountOptions ()
			:
			CachePassword (false),
#ifdef TC_LINUX
			MountNtfsWithKernelDriver (false),
#endif
			NoFilesystem (false),
			NoHardwareCrypto (false),
			NoKernelCrypto (false),
			Pim (-1),
			PartitionInSystemEncryptionScope (false),
			PreserveTimestamps (true),
			Protection (VolumeProtection::None),
			ProtectionPim (-1),
			Removable (false),
			SharedAccessAllowed (false),
			SlotNumber (0),
#if defined(VC_ENABLE_V2FORMAT)
			V2IgnoreTags (false),
			V2Require (false),
#endif
			UseBackupHeaders (false)
		{
		}

		MountOptions (const MountOptions &other) { CopyFrom (other); }
		virtual ~MountOptions () { }

		MountOptions &operator= (const MountOptions &other) { CopyFrom (other); return *this; }

		TC_SERIALIZABLE (MountOptions);

		bool CachePassword;
		wstring FilesystemOptions;
		wstring FilesystemType;
#ifdef TC_LINUX
		bool MountNtfsWithKernelDriver;
#endif
		shared_ptr <KeyfileList> Keyfiles;
		shared_ptr <DirectoryPath> MountPoint;
		bool NoFilesystem;
		bool NoHardwareCrypto;
		bool NoKernelCrypto;
		shared_ptr <VolumePassword> Password;
		int Pim;
		shared_ptr <Pkcs5Kdf> Kdf;
		bool PartitionInSystemEncryptionScope;
		shared_ptr <VolumePath> Path;
		bool PreserveTimestamps;
		VolumeProtection::Enum Protection;
		shared_ptr <VolumePassword> ProtectionPassword;
		int ProtectionPim;
		shared_ptr <Pkcs5Kdf> ProtectionKdf;
		shared_ptr <KeyfileList> ProtectionKeyfiles;
		bool Removable;
		bool SharedAccessAllowed;
		VolumeSlotNumber SlotNumber;
		bool UseBackupHeaders;
		bool EMVSupportEnabled;
#if defined(VC_ENABLE_V2FORMAT)
		/* The v2 fail-closed override (docs/V2-FORMAT-SPEC.md §"Tag-mismatch policy"). Carried through
		   to the mounted Volume so the FUSE service — which is where reads actually happen — honours it.
		   Deliberately per-mount: it is never written to the volume, so a fresh mount without the flag
		   fails closed again. */
		bool V2IgnoreTags;
		// --v2-require: assert this volume IS v2-format. Discovery stays non-fatal by default (an
		// unreadable tail must not become a lockout), so without this flag a stripped table is
		// indistinguishable from a v1 volume and opens unauthenticated. This is the opt-in that
		// turns that into a refusal. Per-invocation only; never written to the volume.
		bool V2Require;
#endif

	protected:
		void CopyFrom (const MountOptions &other);
	};
}

#endif // TC_HEADER_Core_MountOptions
