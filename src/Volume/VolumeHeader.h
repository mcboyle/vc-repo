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

#ifndef TC_HEADER_Volume_VolumeHeader
#define TC_HEADER_Volume_VolumeHeader

#include "Common/Tcdefs.h"
#include "Common/Volumes.h"
#include "Platform/Platform.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/EncryptionMode.h"
#include "Volume/Keyfile.h"
#include "Volume/VolumePassword.h"
#include "Volume/Pkcs5Kdf.h"
#include "Version.h"


// For specifications of the volume header see Common/Volumes.c

namespace VeraCrypt
{
	typedef uint64 VolumeTime;

	struct VolumeType
	{
		enum Enum
		{
			Unknown,
			Normal,
			Hidden
		};
	};

	struct VolumeHeaderCreationOptions
	{
		ConstBufferPtr DataKey;
		shared_ptr <EncryptionAlgorithm> EA;
		shared_ptr <Pkcs5Kdf> Kdf;
		ConstBufferPtr HeaderKey;
		ConstBufferPtr Salt;
		uint32 SectorSize;
		uint64 VolumeDataSize;
		uint64 VolumeDataStart;
		VolumeType::Enum Type;
	};

	class VolumeHeader
	{
	public:
		VolumeHeader (uint32 HeaderSize);
		virtual ~VolumeHeader ();

		void Create (const BufferPtr &headerBuffer, VolumeHeaderCreationOptions &options);
		bool Decrypt (const ConstBufferPtr &encryptedData, const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, const Pkcs5KdfList &keyDerivationFunctions, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes, bool applyHardwareFactor = true);
		void EncryptNew (const BufferPtr &newHeaderBuffer, const ConstBufferPtr &newSalt, const ConstBufferPtr &newHeaderKey, shared_ptr <Pkcs5Kdf> newPkcs5Kdf);
		uint64 GetEncryptedAreaStart () const { return EncryptedAreaStart; }
		uint64 GetEncryptedAreaLength () const { return EncryptedAreaLength; }
		shared_ptr <EncryptionAlgorithm> GetEncryptionAlgorithm () const { return EA; }
		uint32 GetFlags () const { return Flags; }
		VolumeTime GetHeaderCreationTime () const { return HeaderCreationTime; }
		uint64 GetHiddenVolumeDataSize () const { return HiddenVolumeDataSize; }
		static size_t GetHeaderKeyDerivationSize (shared_ptr <Pkcs5Kdf> kdf);
		static size_t GetLargestSerializedKeySize ();
		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf () const { return Pkcs5; }
		uint16 GetRequiredMinProgramVersion () const { return RequiredMinProgramVersion; }
		size_t GetSectorSize () const { return SectorSize; }
		static uint32 GetSaltSize () { return SaltSize; }
		uint64 GetVolumeDataSize () const { return VolumeDataSize; }
		VolumeTime GetVolumeCreationTime () const { return VolumeCreationTime; }
		void SetSize (uint32 headerSize);
		bool IsMasterKeyVulnerable () const { return XtsKeyVulnerable; }
#if defined(VC_ENABLE_KEYSLOTS)
		/* The volume master-key material (VMK): the concatenated primary + secondary (XTS) master keys
		   as laid out in the header key area (DataKeyAreaMaxSize bytes), populated by a successful
		   Decrypt. Retained for reference; a keyslot actually wraps the full effective plaintext below. */
		ConstBufferPtr GetMasterKeys () const { return ConstBufferPtr (DataAreaKey.Ptr(), DataAreaKey.Size()); }
		static size_t GetMasterKeyDataSize () { return DataKeyAreaMaxSize; }

		/* The EFFECTIVE decrypted-header plaintext: the leading KeyslotPayloadSize bytes of the header
		   that Deserialize actually reads (magic, geometry, and the master-key area) — everything needed
		   to reconstruct a mountable volume WITHOUT re-deriving the header key. This is what a keyslot
		   wraps (docs/KEYSLOTS-SPEC.md §1/§9): a passphrase that recovers these exact bytes reproduces
		   the whole native open, so a plain --mount can recover the VMK from a slot and mount. Populated
		   by a successful Decrypt; empty otherwise. */
		ConstBufferPtr GetHeaderPlaintext () const { return ConstBufferPtr (EffectivePlaintext.Ptr(), EffectivePlaintext.Size()); }
		/* 448 bytes: everything Deserialize reads (through the end of the master-key area). A function, not
		   a static const, so it can reference the offset/size constants declared later in the class. */
		static size_t GetKeyslotPayloadSize () { return DataAreaKeyOffset + DataKeyAreaMaxSize; }

		/* Rebuild this header from KeyslotPayloadSize plaintext bytes recovered from a keyslot, with 'ea'
		   / 'mode' naming the volume's cipher (from the slot's stored EA index). Zero-pads to the full
		   header size (no Deserialize CRC/field lies beyond KeyslotPayloadSize) and runs the same
		   validation + master-key setup as the tail of Decrypt. Returns true on success. */
		bool RebuildFromKeyslot (const ConstBufferPtr &plaintext, shared_ptr <EncryptionAlgorithm> ea, shared_ptr <EncryptionMode> mode, shared_ptr <Pkcs5Kdf> kdf);
#endif

	protected:
#if defined(VC_ENABLE_HKF_MIX_V2)
		/* The KDF sweep + header-key trial for one already-effective password (post hardware-factor mix).
		   Decrypt() computes the factor response once and calls this under each mix version (v2 then v1)
		   so a volume enrolled under either mix opens with a single token round-trip. */
		bool DecryptWithEffectivePassword (const ConstBufferPtr &encryptedData, const VolumePassword &effectivePassword, int pim, shared_ptr <Pkcs5Kdf> kdf, const Pkcs5KdfList &keyDerivationFunctions, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes);
#endif
		bool DecryptWithHeaderKey (const ConstBufferPtr &encryptedData, shared_ptr <Pkcs5Kdf> pkcs5, const ConstBufferPtr &headerKey, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes);
		bool Deserialize (const ConstBufferPtr &header, shared_ptr <EncryptionAlgorithm> &ea, shared_ptr <EncryptionMode> &mode);
		template <typename T> T DeserializeEntry (const ConstBufferPtr &header, size_t &offset) const;
		template <typename T> T DeserializeEntryAt (const ConstBufferPtr &header, const size_t &offset) const;
		void Init ();
		void Serialize (const BufferPtr &header) const;
		template <typename T> void SerializeEntry (const T &entry, const BufferPtr &header, size_t &offset) const;

		uint32 HeaderSize;

		static const uint16 CurrentHeaderVersion = VOLUME_HEADER_VERSION;
		static const uint16 CurrentRequiredMinProgramVersion = TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION;
		static const uint16 MinAllowedHeaderVersion = 1;

		static const int SaltOffset = 0;
		static const uint32 SaltSize = 64;

		static const int EncryptedHeaderDataOffset = SaltOffset + SaltSize;
		uint32 EncryptedHeaderDataSize;

		static const uint32 LegacyEncryptionModeKeyAreaSize = 32;
		static const int DataKeyAreaMaxSize = 256;
		static const uint32 DataAreaKeyOffset = DataKeyAreaMaxSize - EncryptedHeaderDataOffset;

		shared_ptr <EncryptionAlgorithm> EA;
		shared_ptr <Pkcs5Kdf> Pkcs5;

		uint16 HeaderVersion;
		uint16 RequiredMinProgramVersion;
		uint32 VolumeKeyAreaCrc32;

		VolumeTime VolumeCreationTime;
		VolumeTime HeaderCreationTime;

		VolumeType::Enum mVolumeType;
		uint64 HiddenVolumeDataSize;
		uint64 VolumeDataSize;
		uint64 EncryptedAreaStart;
		uint64 EncryptedAreaLength;
		uint32 Flags;
		uint32 SectorSize;

		SecureBuffer DataAreaKey;
		bool XtsKeyVulnerable;
#if defined(VC_ENABLE_KEYSLOTS)
		SecureBuffer EffectivePlaintext;   /* leading KeyslotPayloadSize bytes stashed on a successful Decrypt */
#endif

	private:
		VolumeHeader (const VolumeHeader &);
		VolumeHeader &operator= (const VolumeHeader &);
	};
}

#endif // TC_HEADER_Volume_VolumeHeader
