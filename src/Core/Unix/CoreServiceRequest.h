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

#ifndef TC_HEADER_Core_Unix_CoreServiceRequest
#define TC_HEADER_Core_Unix_CoreServiceRequest

#include "Platform/Serializable.h"
#include "Core/Core.h"

namespace VeraCrypt
{
	struct CoreServiceRequest : public Serializable
	{
		CoreServiceRequest () : ElevateUserPrivileges (false), FastElevation (false), UseDummySudoPassword (false), AllowInsecureMount (false)
#if defined(VC_ENABLE_ARGON2_PARAMS)
			, Argon2OverrideActive (false), Argon2MemCostKiB (0), Argon2Iterations (0), Argon2Parallelism (1)
#endif
			{ }
		TC_SERIALIZABLE (CoreServiceRequest);

		virtual bool RequiresElevation () const { return false; }

		string AdminPassword;
		FilePath ApplicationExecutablePath;
		bool ElevateUserPrivileges;
		bool FastElevation;
		string UserEnvPATH;
		bool UseDummySudoPassword;
		bool AllowInsecureMount;
#if defined(VC_ENABLE_ARGON2_PARAMS)
		// The explicit Argon2id parameter override (CLI --argon2-memory/-iterations/-parallelism) is a
		// process-global set in the front-end after the privileged CoreService child was already forked,
		// so it does not otherwise reach the child that performs mount-time key derivation. Carry it on
		// every request and re-apply it in the child (CoreService::ProcessRequests) so a volume created
		// with explicit Argon2 params can actually be mounted. Not stored in the header, exactly like PIM.
		bool   Argon2OverrideActive;
		uint32 Argon2MemCostKiB;
		uint32 Argon2Iterations;
		uint32 Argon2Parallelism;
#endif
	};

	struct CheckFilesystemRequest : CoreServiceRequest
	{
		CheckFilesystemRequest () { }
		CheckFilesystemRequest (shared_ptr <VolumeInfo> volumeInfo, bool repair)
			: MountedVolumeInfo (volumeInfo), Repair (repair) { }
		TC_SERIALIZABLE (CheckFilesystemRequest);

		virtual bool RequiresElevation () const;

		shared_ptr <VolumeInfo> MountedVolumeInfo;
		bool Repair;
	};

	struct DismountFilesystemRequest : CoreServiceRequest
	{
		DismountFilesystemRequest () { }
		DismountFilesystemRequest (const DirectoryPath &mountPoint, bool force)
			: Force (force), MountPoint (mountPoint) { }
		TC_SERIALIZABLE (DismountFilesystemRequest);

		virtual bool RequiresElevation () const;

		bool Force;
		DirectoryPath MountPoint;
	};

	struct DismountVolumeRequest : CoreServiceRequest
	{
		DismountVolumeRequest () { }
		DismountVolumeRequest (shared_ptr <VolumeInfo> volumeInfo, bool ignoreOpenFiles, bool syncVolumeInfo)
			: IgnoreOpenFiles (ignoreOpenFiles), MountedVolumeInfo (volumeInfo), SyncVolumeInfo (syncVolumeInfo) { }
		TC_SERIALIZABLE (DismountVolumeRequest);

		virtual bool RequiresElevation () const;

		bool IgnoreOpenFiles;
		shared_ptr <VolumeInfo> MountedVolumeInfo;
		bool SyncVolumeInfo;
	};

#ifdef TC_LINUX
	struct EmergencyDismountVolumeRequest : CoreServiceRequest
	{
		EmergencyDismountVolumeRequest () { }
		EmergencyDismountVolumeRequest (shared_ptr <VolumeInfo> volumeInfo)
			: MountedVolumeInfo (volumeInfo) { }
		TC_SERIALIZABLE (EmergencyDismountVolumeRequest);

		virtual bool RequiresElevation () const;

		shared_ptr <VolumeInfo> MountedVolumeInfo;
	};
#endif

	struct GetDeviceSectorSizeRequest : CoreServiceRequest
	{
		GetDeviceSectorSizeRequest () { }
		GetDeviceSectorSizeRequest (const DevicePath &path) : Path (path) { }
		TC_SERIALIZABLE (GetDeviceSectorSizeRequest);

		virtual bool RequiresElevation () const;

		DevicePath Path;
	};

	struct GetDeviceSizeRequest : CoreServiceRequest
	{
		GetDeviceSizeRequest () { }
		GetDeviceSizeRequest (const DevicePath &path) : Path (path) { }
		TC_SERIALIZABLE (GetDeviceSizeRequest);

		virtual bool RequiresElevation () const;

		DevicePath Path;
	};

	struct GetHostDevicesRequest : CoreServiceRequest
	{
		GetHostDevicesRequest () { }
		GetHostDevicesRequest (bool pathListOnly) : PathListOnly (pathListOnly) { }
		TC_SERIALIZABLE (GetHostDevicesRequest);

		virtual bool RequiresElevation () const;

		bool PathListOnly;
	};

	struct ExitRequest : CoreServiceRequest
	{
		TC_SERIALIZABLE (ExitRequest);
	};

#ifdef TC_MACOSX
	struct ExecuteMacOSXAPFSFormatterRequest : CoreServiceRequest
	{
		ExecuteMacOSXAPFSFormatterRequest () { }
		ExecuteMacOSXAPFSFormatterRequest (const DevicePath &devicePath, uint64 userId, uint64 groupId)
			: Device (devicePath), OwnerGroupId (groupId), OwnerUserId (userId) { }
		TC_SERIALIZABLE (ExecuteMacOSXAPFSFormatterRequest);

		virtual bool RequiresElevation () const;

		DevicePath Device;
		uint64 OwnerGroupId;
		uint64 OwnerUserId;
	};
#endif

	struct MountVolumeRequest : CoreServiceRequest
	{
		MountVolumeRequest () { }
		MountVolumeRequest (MountOptions *options) : Options (options) { }
		TC_SERIALIZABLE (MountVolumeRequest);

		virtual bool RequiresElevation () const;

		MountOptions *Options;

	protected:
		shared_ptr <MountOptions> DeserializedOptions;
	};


	struct SetFileOwnerRequest : CoreServiceRequest
	{
		SetFileOwnerRequest () { }
		SetFileOwnerRequest (const FilesystemPath &path, const UserId &owner) : Owner (owner), Path (path) { }
		TC_SERIALIZABLE (SetFileOwnerRequest);

		virtual bool RequiresElevation () const;

		UserId Owner;
		FilesystemPath Path;
	};
}

#endif // TC_HEADER_Core_Unix_CoreServiceRequest
