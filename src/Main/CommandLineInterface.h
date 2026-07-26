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

#ifndef TC_HEADER_Main_CommandInterface
#define TC_HEADER_Main_CommandInterface

#include "System.h"
#include "Main.h"
#include "Volume/VolumeInfo.h"
#include "Core/MountOptions.h"
#include "Core/VolumeCreator.h"
#include "UserPreferences.h"
#include "UserInterfaceType.h"
#include "Volume/Pkcs5Kdf.h"
#if defined(VC_ENABLE_HKF)
#include "HardwareKeyFactorCli.h"
#endif

namespace VeraCrypt
{
	struct CommandId
	{
		enum Enum
		{
			None,
			AutoMountDevices,
			AutoMountDevicesFavorites,
			AutoMountFavorites,
			BackupHeaders,
			ChangePassword,
			CreateKeyfile,
			CreateVolume,
			DeleteSecurityTokenKeyfiles,
			DismountVolumes,
			DuressDismount,
#if defined(VC_ENABLE_DURESS)
			DuressRegister,
#endif
			DisplayVersion,
			DisplayVolumeProperties,
			ExportTokenKeyfile,
			Help,
			ImportTokenKeyfiles,
			ListTokenKeyfiles,
            ListSecurityTokenKeyfiles,
            ListEMVTokenKeyfiles,
			ListVolumes,
			MountVolume,
			RestoreHeaders,
			SavePreferences,
#if defined(VC_ENABLE_KEYSLOTS)
			KeyslotAdd,
			KeyslotOpen,
			KeyslotRotate,
			KeyslotKill,
			KeyslotList,
#endif
			Test
		};
	};

	struct CommandLineInterface
	{
	public:
		CommandLineInterface (int argc, wchar_t** argv, UserInterfaceType::Enum interfaceType);
		virtual ~CommandLineInterface ();


		CommandId::Enum ArgCommand;
		bool ArgDisplayPassword;
		shared_ptr <EncryptionAlgorithm> ArgEncryptionAlgorithm;
#ifdef TC_LINUX
		bool ArgEmergencyUnmount;
#endif
		shared_ptr <FilePath> ArgFilePath;
		VolumeCreationOptions::FilesystemType::Enum ArgFilesystem;
		bool ArgForce;
		shared_ptr <Pkcs5Kdf> ArgHash;
		shared_ptr <KeyfileList> ArgKeyfiles;
		MountOptions ArgMountOptions;
		shared_ptr <DirectoryPath> ArgMountPoint;
		shared_ptr <Pkcs5Kdf> ArgNewHash;
		shared_ptr <KeyfileList> ArgNewKeyfiles;
		shared_ptr <VolumePassword> ArgNewPassword;
		int ArgNewPim;
		bool ArgNoHiddenVolumeProtection;
		shared_ptr <VolumePassword> ArgPassword;
		int ArgPim;
#if defined(VC_ENABLE_HKF)
		HKFConfig ArgHKFConfig;
#endif
#if defined(VC_ENABLE_KEYSLOTS)
		shared_ptr <VolumePassword> ArgKeyslotPassword;   // the NEW slot's passphrase (add/rotate/open/kill target)
		int ArgKeyslotIndex;                              // --keyslot-kill N
		bool ArgKeyslotDuress;                            // mark the added slot as a duress slot
		int ArgKeyslotBackend;                            // KeyslotBackend: 1=header(default) 2=deniable 3=sidecar
		shared_ptr <FilePath> ArgKeyslotSidecar;          // --keyslot-sidecar path (KSB_SIDECAR)
#endif
		bool ArgQuick;
#if defined(VC_ENABLE_V2FORMAT)
		bool ArgV2Format;                                 // --v2-format: create a v2-format volume (T1-1)
		// T1-1 hidden-volume guard. A v2 outer's MAC table occupies the tail of its data area, which is
		// exactly where a hidden volume goes, so the two destroy each other. Detecting v2 needs the
		// OUTER volume's key (a v2 tail is indistinguishable from v1 free space without it — that is
		// D-10 working), hence a separate password here.
		shared_ptr <VolumePassword> ArgOuterPassword;     // --outer-password: outer volume's password
		int ArgOuterPim;                                  // --outer-pim
		bool ArgSkipV2HostCheck;                          // --skip-v2-host-check: UNSAFE bypass
#endif
#if defined(VC_ENABLE_SPARSE_GUARD)
		// --allow-sparse-host: UNSAFE override for the sparse-container guard. A sparse outer volume
		// discloses a hidden volume's offset and size through the host filesystem's extent map, with no
		// password and from a single image.
		bool ArgAllowSparseHost;
#endif
		FilesystemPath ArgRandomSourcePath;
		uint64 ArgSize;
		shared_ptr <VolumePath> ArgVolumePath;
		VolumeInfoList ArgVolumes;
		VolumeType::Enum ArgVolumeType;
        shared_ptr<SecureBuffer> ArgTokenPin;
        bool ArgAllowScreencapture;
        bool ArgDisableFileSizeCheck;
        bool ArgUseLegacyPassword;
        bool ArgUseDummySudoPassword;

#if defined(TC_UNIX)
		bool ArgAllowInsecureMount;
#endif

		bool StartBackgroundTask;
		UserPreferences Preferences;

	protected:
		void CheckCommandSingle () const;
		shared_ptr <KeyfileList> ToKeyfileList (const wxString &arg) const;
		VolumeInfoList GetMountedVolumes (const wxString &filter) const;

	private:
		CommandLineInterface (const CommandLineInterface &);
		CommandLineInterface &operator= (const CommandLineInterface &);
	};

	shared_ptr<VolumePassword> ToUTF8Password (const wchar_t* str, size_t charCount, size_t maxUtf8Len);
	shared_ptr<SecureBuffer> ToUTF8Buffer (const wchar_t* str, size_t charCount, size_t maxUtf8Len);

	extern unique_ptr <CommandLineInterface> CmdLine;
}

#endif // TC_HEADER_Main_CommandInterface
