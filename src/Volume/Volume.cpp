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

#ifndef TC_WINDOWS
#include <errno.h>
#endif
#include "EncryptionModeXTS.h"
#include "Volume.h"
#include "VolumeHeader.h"
#include "VolumeLayout.h"
#if defined(VC_ENABLE_HKF)
extern "C" {
#include "Common/HardwareKeyFactor.h"
}
#endif
#if defined(VC_ENABLE_KEYSLOTS)
extern "C" {
#include "Common/KeyslotStore.h"   // KeyslotArea, KeyslotStoreCfg, KeyslotOpen (mount-time slot search)
#include "Common/Keyslot.h"        // KeyslotKdfSha512, KEYSLOT_FLAG_DURESS
}
#include "KeyslotParallelExecutor.h"  // VolumeKeyslotParallelFor (C++ header: <thread>; declares its own C linkage)
#include "Pkcs5Kdf.h"
#endif
#include "Common/Crypto.h"

namespace VeraCrypt
{
#if defined(VC_ENABLE_KEYSLOTS)
	// Read-only KeyslotArea over the volume's File, used only by the mount-time slot search below. The
	// header-slack window [512, 64K) is the on-disk keyslot table location (docs/KEYSLOTS-SPEC.md §3);
	// these constants are the volume format's, mirrored from Common/Volumes.h to avoid dragging the full
	// platform stack. The store's open path never writes, so write is a stub and randBytes is unused.
	namespace {
		struct VolKeyslotCtx { const File *file; uint64 base, len; };
		int volKeyslotRead (void *ctx, uint64 off, unsigned char *buf, size_t n)
		{
			VolKeyslotCtx *c = (VolKeyslotCtx *) ctx;
			if (off > c->len || n > c->len - off) return -1;
			try { c->file->ReadAt (BufferPtr (buf, n), c->base + off); } catch (...) { return -1; }
			return 0;
		}
		int volKeyslotWriteStub (void *, uint64, const unsigned char *, size_t) { return -1; }
		uint64 volKeyslotSize (void *ctx) { return ((VolKeyslotCtx *) ctx)->len; }
	}
	// The parallel-for executor (VolumeKeyslotParallelFor) lives in KeyslotParallelExecutor.h so the
	// actual product executor is directly testable (verification/keyslot_parallel_timing_test).
#endif

	Volume::Volume ()
		: HiddenVolumeProtectionTriggered (false),
		SystemEncryption (false),
		VolumeDataOffset (0),
		VolumeDataSize (0),
		EncryptedDataSize (0),
		TopWriteOffset (0),
		TotalDataRead (0),
		TotalDataWritten (0),
		Pim (0),
		EncryptionNotCompleted (false)
	{
	}

	Volume::~Volume ()
	{
	}

	void Volume::CheckProtectedRange (uint64 writeHostOffset, uint64 writeLength)
	{
		uint64 writeHostEndOffset = writeHostOffset + writeLength - 1;

		if ((writeHostOffset < ProtectedRangeStart) ? (writeHostEndOffset >= ProtectedRangeStart) : (writeHostOffset <= ProtectedRangeEnd - 1))
		{
			HiddenVolumeProtectionTriggered = true;
			throw VolumeProtected (SRC_POS);
		}
	}

	void Volume::Close ()
	{
		if (VolumeFile.get() == nullptr)
			throw NotInitialized (SRC_POS);

		VolumeFile.reset();
	}

	shared_ptr <EncryptionAlgorithm> Volume::GetEncryptionAlgorithm () const
	{
		if_debug (ValidateState ());
		return EA;
	}

	shared_ptr <EncryptionMode> Volume::GetEncryptionMode () const
	{
		if_debug (ValidateState ());
		return EA->GetMode();
	}

	void Volume::Open (const VolumePath &volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, int pim, shared_ptr <Pkcs5Kdf> kdf, shared_ptr <KeyfileList> keyfiles, bool emvSupportEnabled, VolumeProtection::Enum protection, shared_ptr <VolumePassword> protectionPassword, int protectionPim, shared_ptr <Pkcs5Kdf> protectionKdf, shared_ptr <KeyfileList> protectionKeyfiles, bool sharedAccessAllowed, VolumeType::Enum volumeType, bool useBackupHeaders, bool partitionInSystemEncryptionScope)
	{
		make_shared_auto (File, file);

		File::FileOpenFlags flags = (preserveTimestamps ? File::PreserveTimestamps : File::FlagsNone);

		try
		{
			if (protection == VolumeProtection::ReadOnly)
				file->Open (volumePath, File::OpenRead, File::ShareRead, flags);
			else
				file->Open (volumePath, File::OpenReadWrite, File::ShareNone, flags);
		}
		catch (SystemException &e)
		{
			if (e.GetErrorCode() ==
#ifdef TC_WINDOWS
				ERROR_SHARING_VIOLATION)
#else
				EAGAIN)
#endif
			{
				if (!sharedAccessAllowed)
					throw VolumeHostInUse (SRC_POS);

				file->Open (volumePath, protection == VolumeProtection::ReadOnly ? File::OpenRead : File::OpenReadWrite, File::ShareReadWriteIgnoreLock, flags);
			}
			else
				throw;
		}

		return Open (file, password, pim, kdf, keyfiles, emvSupportEnabled, protection, protectionPassword, protectionPim, protectionKdf,protectionKeyfiles, volumeType, useBackupHeaders, partitionInSystemEncryptionScope);
	}

	void Volume::Open (shared_ptr <File> volumeFile, shared_ptr <VolumePassword> password, int pim, shared_ptr <Pkcs5Kdf> kdf, shared_ptr <KeyfileList> keyfiles, bool emvSupportEnabled, VolumeProtection::Enum protection, shared_ptr <VolumePassword> protectionPassword, int protectionPim, shared_ptr <Pkcs5Kdf> protectionKdf,shared_ptr <KeyfileList> protectionKeyfiles, VolumeType::Enum volumeType, bool useBackupHeaders, bool partitionInSystemEncryptionScope)
	{
		if (!volumeFile)
			throw ParameterIncorrect (SRC_POS);

		Protection = protection;
		VolumeFile = volumeFile;
		SystemEncryption = partitionInSystemEncryptionScope;

		try
		{
			VolumeHostSize = VolumeFile->Length();
			shared_ptr <VolumePassword> passwordKey = Keyfile::ApplyListToPassword (keyfiles, password, emvSupportEnabled);

			bool skipLayoutV1Normal = false;

			// Test volume layouts
			foreach (shared_ptr <VolumeLayout> layout, VolumeLayout::GetAvailableLayouts (volumeType))
			{
				if (skipLayoutV1Normal && typeid (*layout) == typeid (VolumeLayoutV1Normal))
				{
					// Skip VolumeLayoutV1Normal as it shares header location with VolumeLayoutV2Normal
					continue;
				}

				if (useBackupHeaders && !layout->HasBackupHeader())
					continue;

				SecureBuffer headerBuffer (layout->GetHeaderSize());

				if (layout->HasDriveHeader())
				{
					if (!partitionInSystemEncryptionScope)
						continue;

					if (!GetPath().IsDevice())
						throw PartitionDeviceRequired (SRC_POS);

					File driveDevice;
					driveDevice.Open (DevicePath (wstring (GetPath())).ToHostDriveOfPartition());

					int headerOffset = layout->GetHeaderOffset();

					if (headerOffset >= 0)
						driveDevice.SeekAt (headerOffset);
					else
						driveDevice.SeekEnd (headerOffset);

					if (driveDevice.Read (headerBuffer) != layout->GetHeaderSize())
						continue;
				}
				else
				{
					if (partitionInSystemEncryptionScope)
						continue;

					int headerOffset = useBackupHeaders ? layout->GetBackupHeaderOffset() : layout->GetHeaderOffset();

					if (headerOffset >= 0)
						VolumeFile->SeekAt (headerOffset);
					else
						VolumeFile->SeekEnd (headerOffset);

					if (VolumeFile->Read (headerBuffer) != layout->GetHeaderSize())
						continue;
				}

				EncryptionAlgorithmList layoutEncryptionAlgorithms = layout->GetSupportedEncryptionAlgorithms();
				EncryptionModeList layoutEncryptionModes = layout->GetSupportedEncryptionModes();

				if (typeid (*layout) == typeid (VolumeLayoutV2Normal))
				{
					skipLayoutV1Normal = true;

					// Test all algorithms and modes of VolumeLayoutV1Normal as it shares header location with VolumeLayoutV2Normal
					layoutEncryptionAlgorithms = EncryptionAlgorithm::GetAvailableAlgorithms();
					layoutEncryptionModes = EncryptionMode::GetAvailableModes();
				}

				shared_ptr <VolumeHeader> header = layout->GetHeader();

#if defined(VC_ENABLE_HKF)
				// Factor gating: under HKF_APPLY_HIDDEN_ONLY the hardware factor is mixed only for the
				// hidden layout, so the outer (decoy) header derives from the password alone.
				bool hkfApply = HKFShouldApply (g_hkfActiveConfig, layout->GetType() == VolumeType::Hidden) != 0;
#else
				bool hkfApply = true;
#endif
				if (header->Decrypt (headerBuffer, *passwordKey, pim, kdf, layout->GetSupportedKeyDerivationFunctions(), layoutEncryptionAlgorithms, layoutEncryptionModes, hkfApply))
				{
					// Header decrypted

					if (typeid (*layout) == typeid (VolumeLayoutV2Normal) && header->GetRequiredMinProgramVersion() < 0x10b)
					{
						// VolumeLayoutV1Normal has been opened as VolumeLayoutV2Normal
						layout.reset (new VolumeLayoutV1Normal);
						header->SetSize (layout->GetHeaderSize());
						layout->SetHeader (header);
					}

					Pim = pim;
					Type = layout->GetType();
					SectorSize = header->GetSectorSize();

					VolumeDataOffset = layout->GetDataOffset (VolumeHostSize);
					VolumeDataSize = layout->GetDataSize (VolumeHostSize);
					EncryptedDataSize = header->GetEncryptedAreaLength();

					Header = header;
					Layout = layout;
					EA = header->GetEncryptionAlgorithm();
					EncryptionMode &mode = *EA->GetMode();

					if (layout->HasDriveHeader())
					{
						if (header->GetEncryptedAreaLength() != header->GetVolumeDataSize())
						{
							EncryptionNotCompleted = true;
							// we avoid writing data to the partition since it is only partially encrypted
							Protection = VolumeProtection::ReadOnly;
						}

						uint64 partitionStartOffset = VolumeFile->GetPartitionDeviceStartOffset();

						if (partitionStartOffset < header->GetEncryptedAreaStart()
							|| partitionStartOffset >= header->GetEncryptedAreaStart() + header->GetEncryptedAreaLength())
							throw PasswordIncorrect (SRC_POS);

						EncryptedDataSize -= partitionStartOffset - header->GetEncryptedAreaStart();

						mode.SetSectorOffset (partitionStartOffset / ENCRYPTION_DATA_UNIT_SIZE);
					}

#if defined(VC_ENABLE_V2FORMAT)
					// v2 mode discovery (T1-1). Nothing on disk marks a volume as v2: read data sector 0
					// plus its MAC-table slot and ask which mode's key reproduces the tag. V2_MODE_NONE —
					// a v1 volume, or one whose table is absent/unreadable — leaves V2Mac inert, so v1
					// volumes keep their existing behaviour exactly.
					//
					// Discovery is deliberately NON-FATAL: a read error here degrades to "treat as v1",
					// never to "refuse the mount". Failing a mount because the tail of the disk is
					// unreadable would turn an availability problem into a lockout, and a v1 volume
					// legitimately has no table to read.
					// WHERE THE TABLE IS, and why VolumeDataSize is already the right boundary.
					// VolumeLayoutV2Normal::GetDataSize() returns the value STORED IN THE HEADER, and on
					// a v2 volume VolumeCreator stored the split's USABLE prefix there — not the raw
					// data-area size. So VolumeDataSize is the usable data, and the table begins
					// immediately after it. Do NOT re-derive the split here: that would shrink an
					// already-shrunk figure and point the probe into the middle of user data.
					try
					{
						const uint64 dataSectors = VolumeDataSize / SectorSize;
						if (dataSectors > 0)
						{
							SecureBuffer sector0 (SectorSize);
							SecureBuffer tag0 (V2_MAC_TAG_LEN);
							VolumeFile->ReadAt (sector0, VolumeDataOffset);
							VolumeFile->ReadAt (tag0, VolumeDataOffset + VolumeDataSize + V2FormatSlotOffset (0));

							// KEY LENGTH MUST MATCH THE CREATE SIDE EXACTLY. GetMasterKeys() hands back
							// the whole master-key FIELD of the header — a fixed 256 bytes sized for the
							// largest cascade — while VolumeCreator derives the MAC key from the actual
							// key it generated, EA->GetKeySize() * 2 (64 bytes for AES-XTS). Feeding the
							// full field here changes the HKDF input and therefore every tag, so
							// discovery matched nothing and the volume opened as v1 with authentication
							// silently absent. Truncate to the real key length, the same figure the
							// creator used.
							const ConstBufferPtr mk = header->GetMasterKeys();
							const size_t mkLen = EA->GetKeySize() * 2;
							if (mkLen > 0 && mkLen <= mk.Size())
							{
								V2Mode v2mode = (V2Mode) V2Format::DiscoverMode (mk.Get(), (int) mkLen,
									sector0.Ptr(), SectorSize, tag0.Ptr());

								if (v2mode != V2_MODE_NONE)
									V2Mac.Configure (v2mode, mk.Get(), (int) mkLen, SectorSize,
									                 VolumeDataOffset + VolumeDataSize, dataSectors);
							}
						}
					}
					catch (...) { /* not v2, or the tail is unreadable — stay inert */ }
#endif

					// Volume protection
					if (Protection == VolumeProtection::HiddenVolumeReadOnly)
					{
						if (Type == VolumeType::Hidden)
							throw PasswordIncorrect (SRC_POS);
						else
						{
							try
							{
								Volume protectedVolume;

								protectedVolume.Open (VolumeFile,
									protectionPassword, protectionPim, protectionKdf, protectionKeyfiles,
									emvSupportEnabled,
									VolumeProtection::ReadOnly,
									shared_ptr <VolumePassword> (), 0, shared_ptr <Pkcs5Kdf> (),shared_ptr <KeyfileList> (),
									VolumeType::Hidden,
									useBackupHeaders);

								if (protectedVolume.GetType() != VolumeType::Hidden)
									ParameterIncorrect (SRC_POS);

								ProtectedRangeStart = protectedVolume.VolumeDataOffset;
								ProtectedRangeEnd = protectedVolume.VolumeDataOffset + protectedVolume.VolumeDataSize;
							}
							catch (PasswordException&)
							{
								if (protectionKeyfiles && !protectionKeyfiles->empty())
									throw ProtectionPasswordKeyfilesIncorrect (SRC_POS);
								throw ProtectionPasswordIncorrect (SRC_POS);
							}
						}
					}
					return;
				}
			}

#if defined(VC_ENABLE_KEYSLOTS)
			// Mount-time keyslot auto-search: no native header (slot 0) accepted the password, so try the
			// additional wrappings in the primary header slack. A matching slot recovers the effective
			// header plaintext (the keyslot payload) and the volume is rebuilt from it WITHOUT re-deriving
			// the header key; a slot flagged KEYSLOT_FLAG_DURESS instead throws KeyslotDuress, which the
			// UI turns into the safe duress action (dismount all + scrub, mount nothing). Header-slack
			// backend, normal (primary) layout only. See docs/KEYSLOTS-SPEC.md §9.
			if (volumeType != VolumeType::Hidden && !partitionInSystemEncryptionScope && !useBackupHeaders)
			{
				VolKeyslotCtx kc; kc.file = VolumeFile.get(); kc.base = 512; kc.len = (64 * 1024) - 512;
				KeyslotArea area; area.read = volKeyslotRead; area.write = volKeyslotWriteStub; area.size = volKeyslotSize; area.ctx = &kc;
				KeyslotStoreCfg cfg; memset (&cfg, 0, sizeof cfg);
				cfg.backend = KSB_HEADER; cfg.kdf = &KeyslotKdfSha512; cfg.cost = 500000;
				cfg.vmkLen = 1 + (int) VolumeHeader::GetKeyslotPayloadSize (); cfg.maxSlots = 63;
				cfg.randBytes = 0; cfg.afStripes = 0;

				SecureBuffer vmk (cfg.vmkLen);
				int slotFlags = 0;
				if (KeyslotOpenParallel (&cfg, &area, passwordKey->DataPtr(), (int) passwordKey->Size(), vmk.Ptr(), &slotFlags, VolumeKeyslotParallelFor))
				{
					if (slotFlags & KEYSLOT_FLAG_DURESS)
						throw KeyslotDuress (SRC_POS);      // UI runs the safe duress action

					int eaIndex = vmk[0];
					shared_ptr <EncryptionAlgorithm> ea;
					{
						int i = 0;
						foreach (shared_ptr <EncryptionAlgorithm> a, EncryptionAlgorithm::GetAvailableAlgorithms())
						{ if (i == eaIndex) { ea = a->GetNew(); break; } ++i; }
					}
					if (ea)
					{
						shared_ptr <EncryptionMode> mode (new EncryptionModeXTS ());
						shared_ptr <VolumeLayout> klayout (new VolumeLayoutV2Normal ());
						shared_ptr <VolumeHeader> header = klayout->GetHeader();
						shared_ptr <Pkcs5Kdf> anyKdf = Pkcs5Kdf::GetAvailableAlgorithms().front();
						ConstBufferPtr plain (vmk.Ptr() + 1, cfg.vmkLen - 1);
						if (header->RebuildFromKeyslot (plain, ea, mode, anyKdf))
						{
							Pim = pim;
							Type = klayout->GetType();
							SectorSize = header->GetSectorSize();
							VolumeDataOffset = klayout->GetDataOffset (VolumeHostSize);
							VolumeDataSize   = klayout->GetDataSize (VolumeHostSize);
							EncryptedDataSize = header->GetEncryptedAreaLength();
							Header = header;
							Layout = klayout;
							EA = header->GetEncryptionAlgorithm();
							return;
						}
					}
				}
			}
#endif

			if (partitionInSystemEncryptionScope)
				throw PasswordOrKeyboardLayoutIncorrect (SRC_POS);

			if (!partitionInSystemEncryptionScope && GetPath().IsDevice())
			{
				// Check if the device contains VeraCrypt Boot Loader
				try
				{
					File driveDevice;
					driveDevice.Open (DevicePath (wstring (GetPath())).ToHostDriveOfPartition());

					Buffer mbr (VolumeFile->GetDeviceSectorSize());
					driveDevice.ReadAt (mbr, 0);

					// Search for the string "VeraCrypt"
					const char* bootSignature = TC_APP_NAME;
					size_t nameLen = strlen (bootSignature);
					for (size_t i = 0; i < mbr.Size() - nameLen; ++i)
					{
						if (memcmp (mbr.Ptr() + i, bootSignature, nameLen) == 0)
							throw PasswordOrMountOptionsIncorrect (SRC_POS);
					}
				}
				catch (PasswordOrMountOptionsIncorrect&) { throw; }
				catch (...) { }
			}

			if (keyfiles && !keyfiles->empty())
				throw PasswordKeyfilesIncorrect (SRC_POS);
			throw PasswordIncorrect (SRC_POS);
		}
		catch (...)
		{
			Close();
			throw;
		}
	}

	void Volume::ReadSectors (const BufferPtr &buffer, uint64 byteOffset)
	{
		if_debug (ValidateState ());

		uint64 length = buffer.Size();
		uint64 hostOffset = VolumeDataOffset + byteOffset;
		size_t bufferOffset = 0;

		if (length % SectorSize != 0 || byteOffset % SectorSize != 0)
			throw ParameterIncorrect (SRC_POS);

		if (VolumeFile->ReadAt (buffer, hostOffset) != length)
			throw MissingVolumeData (SRC_POS);

		// first sector can be unencrypted in some cases (e.g. windows repair)
		// detect this case by looking for NTFS header
		if (SystemEncryption && (hostOffset == 0) && ((BE64 (*(uint64 *) buffer.Get ())) == 0xEB52904E54465320ULL))
		{
			bufferOffset = (size_t) SectorSize;
			hostOffset += SectorSize;
			length -= SectorSize;
		}

#if defined(VC_ENABLE_V2FORMAT)
		// v2 per-sector authentication. MUST run HERE — before any decryption — because the tag is over
		// CIPHERTEXT, and `buffer` still holds ciphertext at this point. Verifying after the decrypt calls
		// below would authenticate the wrong bytes while still passing every round-trip test.
		// FAILS CLOSED: a mismatch throws V2TagMismatch and the caller receives no plaintext (the buffer
		// is left holding ciphertext, never a decrypted-but-unauthenticated sector).
		// No-op on a v1 volume, so existing volumes take an unchanged path.
		if (length && V2Mac.IsActive())
			V2Mac.VerifyRange (*VolumeFile, buffer.Get() + bufferOffset,
			                   (byteOffset + bufferOffset) / SectorSize, length / SectorSize);
#endif

		if (length)
		{
			if (EncryptionNotCompleted)
			{
				// if encryption is not complete, we decrypt only the encrypted sectors
				if (hostOffset < EncryptedDataSize)
				{
					uint64 encryptedLength = VC_MIN (length, (EncryptedDataSize - hostOffset));

					EA->DecryptSectors (buffer.GetRange (bufferOffset, encryptedLength), hostOffset / SectorSize, encryptedLength / SectorSize, SectorSize);
				}
			}
			else
				EA->DecryptSectors (buffer.GetRange (bufferOffset, length), hostOffset / SectorSize, length / SectorSize, SectorSize);
		}

		TotalDataRead += length;
	}

	void Volume::ReEncryptHeader (bool backupHeader, const ConstBufferPtr &newSalt, const ConstBufferPtr &newHeaderKey, shared_ptr <Pkcs5Kdf> newPkcs5Kdf)
	{
		if_debug (ValidateState ());

		if (Protection == VolumeProtection::ReadOnly)
			throw VolumeReadOnly (SRC_POS);

		SecureBuffer newHeaderBuffer (Layout->GetHeaderSize());

		Header->EncryptNew (newHeaderBuffer, newSalt, newHeaderKey, newPkcs5Kdf);

		int headerOffset = backupHeader ? Layout->GetBackupHeaderOffset() : Layout->GetHeaderOffset();

		if (headerOffset >= 0)
			VolumeFile->SeekAt (headerOffset);
		else
			VolumeFile->SeekEnd (headerOffset);

		VolumeFile->Write (newHeaderBuffer);
	}

	void Volume::ValidateState () const
	{
		if (VolumeFile.get() == nullptr)
			throw NotInitialized (SRC_POS);
	}

	void Volume::WriteSectors (const ConstBufferPtr &buffer, uint64 byteOffset)
	{
		if_debug (ValidateState ());

		uint64 length = buffer.Size();
		uint64 hostOffset = VolumeDataOffset + byteOffset;

		if (length % SectorSize != 0
			|| byteOffset % SectorSize != 0
			|| byteOffset + length > VolumeDataSize)
			throw ParameterIncorrect (SRC_POS);

		if (Protection == VolumeProtection::ReadOnly)
			throw VolumeReadOnly (SRC_POS);

		if (HiddenVolumeProtectionTriggered)
			throw VolumeProtected (SRC_POS);

		if (Protection == VolumeProtection::HiddenVolumeReadOnly)
			CheckProtectedRange (hostOffset, length);

		SecureBuffer encBuf (buffer.Size());
		encBuf.CopyFrom (buffer);

		EA->EncryptSectors (encBuf, hostOffset / SectorSize, length / SectorSize, SectorSize);
		VolumeFile->WriteAt (encBuf, hostOffset);

#if defined(VC_ENABLE_V2FORMAT)
		// v2 per-sector authentication: tag the CIPHERTEXT we just wrote.
		// ORDER IS DELIBERATE — data first, tags second. Data and tag live in two disk regions and there
		// is no journal, so an interrupted write always leaves one of them stale and those sectors fail
		// closed (power loss, crash, USB pulled mid-write; no adversary required). Both orders lose the
		// same sectors, but this one fails safer: a torn write leaves NEW data under an OLD tag, so an
		// operator using the documented override reads what was actually written. Tags-first would leave
		// a valid-looking tag over stale data — harder to reason about, easier to mistake for intact.
		// See src/Volume/V2SectorMacIo.h and docs/V2-FORMAT-SPEC.md §"Tag-mismatch policy".
		if (V2Mac.IsActive())
			V2Mac.UpdateRange (*VolumeFile, encBuf.Ptr(), byteOffset / SectorSize, length / SectorSize);
#endif

		TotalDataWritten += length;

		uint64 writeEndOffset = byteOffset + buffer.Size();
		if (writeEndOffset > TopWriteOffset)
			TopWriteOffset = writeEndOffset;
	}
}
