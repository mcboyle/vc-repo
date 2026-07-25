/*
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "EncryptionModeHctr2.h"

#if defined(VC_ENABLE_HCTR2_MODE)

#include "EncryptionThreadPool.h"

namespace VeraCrypt
{
	void EncryptionModeHctr2::SetKey (const ConstBufferPtr &key)
	{
		if (key.Size() != Hctr2KeySize)
			throw ParameterIncorrect (SRC_POS);

		/* Allocate() re-allocates and wipes; calling Free() first would throw NotInitialized on a
		   never-keyed instance. (Learned on EncryptionModeAdiantum, where its module test caught it on
		   the very first run — same shape here, so the same note.) */
		Key.Allocate (key.Size());
		Key.CopyFrom (key);

		Hctr2Init (&Schedule, Key.Ptr());
		KeySet = true;
	}

	/*
	 * The tweak is the data-unit number as 8 little-endian bytes — the SAME convention XTS uses for its
	 * data unit, and the same one EncryptionModeAdiantum uses, so a sector's identity is bound into the
	 * ciphertext exactly as before and the two wide-block modes agree on what "unit N" means. What
	 * changes versus XTS is granularity: XTS tweaks per 16-byte block within the unit; HCTR2 takes one
	 * call per unit and diffuses across the whole thing.
	 */
	static void TweakFromUnitNo (uint64 unitNo, unsigned char tweak[8])
	{
		for (int i = 0; i < 8; i++)
			tweak[i] = (unsigned char) (unitNo >> (i * 8));
	}

	void EncryptionModeHctr2::ProcessUnits (uint8 *data, uint64 length, uint64 startDataUnitNo, bool encrypt) const
	{
		if (!KeySet)
			throw NotInitialized (SRC_POS);

		/* Wide-block means the unit is indivisible: a partial unit cannot be encrypted, because the
		   construction is defined over the whole length. Refuse rather than silently processing a
		   truncated unit — a short tail would decrypt to garbage that looks like a wrong key. */
		if (length == 0 || (length % EncryptionDataUnitSize) != 0)
			throw ParameterIncorrect (SRC_POS);

		const uint64 units = length / EncryptionDataUnitSize;
		for (uint64 u = 0; u < units; u++)
		{
			unsigned char tweak[8];
			uint8 *p = data + u * EncryptionDataUnitSize;
			TweakFromUnitNo (startDataUnitNo + u, tweak);

			/* in == out is supported by the primitive (documented in Hctr2.h), so this is in place. */
			const int ok = encrypt
				? Hctr2Encrypt (&Schedule, tweak, sizeof tweak, p, EncryptionDataUnitSize, p)
				: Hctr2Decrypt (&Schedule, tweak, sizeof tweak, p, EncryptionDataUnitSize, p);
			if (!ok)
				throw ParameterIncorrect (SRC_POS);   /* length/tweak bounds violated */
		}
	}

	void EncryptionModeHctr2::ProcessSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize, bool encrypt) const
	{
		if (!KeySet)
			throw NotInitialized (SRC_POS);

		/*
		 * HCTR2 is defined over the whole sector, so the sector size IS the block size — unlike XTS,
		 * where a 4096-byte sector is just 256 independent 16-byte blocks. A sector larger than the
		 * primitive supports cannot be split without changing the security property, so it is refused.
		 */
		if (sectorSize < HCTR2_MIN_LEN || sectorSize > HCTR2_MAX_SECTOR)
			throw ParameterIncorrect (SRC_POS);

		for (uint64 s = 0; s < sectorCount; s++)
		{
			unsigned char tweak[8];
			uint8 *p = data + s * sectorSize;
			TweakFromUnitNo (sectorIndex + s + SectorOffset, tweak);

			const int ok = encrypt
				? Hctr2Encrypt (&Schedule, tweak, sizeof tweak, p, sectorSize, p)
				: Hctr2Decrypt (&Schedule, tweak, sizeof tweak, p, sectorSize, p);
			if (!ok)
				throw ParameterIncorrect (SRC_POS);
		}
	}

	void EncryptionModeHctr2::Encrypt (uint8 *data, uint64 length) const
	{
		ProcessUnits (data, length, SectorOffset, true);
	}

	void EncryptionModeHctr2::Decrypt (uint8 *data, uint64 length) const
	{
		ProcessUnits (data, length, SectorOffset, false);
	}

	void EncryptionModeHctr2::EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		ProcessSectors (data, sectorIndex, sectorCount, sectorSize, true);
	}

	void EncryptionModeHctr2::DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		ProcessSectors (data, sectorIndex, sectorCount, sectorSize, false);
	}
}

#endif // VC_ENABLE_HCTR2_MODE
