/*
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "EncryptionModeAdiantum.h"

#if defined(VC_ENABLE_ADIANTUM_MODE)

#include "EncryptionThreadPool.h"

namespace VeraCrypt
{
	void EncryptionModeAdiantum::SetKey (const ConstBufferPtr &key)
	{
		if (key.Size() != AdiantumKeySize)
			throw ParameterIncorrect (SRC_POS);

		/* Allocate() re-allocates and wipes; calling Free() first would throw NotInitialized on a
		   never-keyed instance. (It did — the module test caught it on the very first run.) */
		Key.Allocate (key.Size());
		Key.CopyFrom (key);

		AdiantumInit (&Schedule, Key.Ptr());
		KeySet = true;
	}

	/*
	 * The tweak is the data-unit number as 8 little-endian bytes — the SAME convention XTS uses for its
	 * data unit, so a sector's identity is bound into the ciphertext exactly as before. What changes is
	 * the granularity: XTS tweaks per 16-byte block within the unit; Adiantum takes one call per unit
	 * and diffuses across the whole thing.
	 */
	static void TweakFromUnitNo (uint64 unitNo, unsigned char tweak[8])
	{
		for (int i = 0; i < 8; i++)
			tweak[i] = (unsigned char) (unitNo >> (i * 8));
	}

	void EncryptionModeAdiantum::ProcessUnits (uint8 *data, uint64 length, uint64 startDataUnitNo, bool encrypt) const
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

			/* in == out is supported by the primitive (documented in Adiantum.h), so this is in place. */
			const int ok = encrypt
				? AdiantumEncrypt (&Schedule, tweak, sizeof tweak, p, EncryptionDataUnitSize, p)
				: AdiantumDecrypt (&Schedule, tweak, sizeof tweak, p, EncryptionDataUnitSize, p);
			if (!ok)
				throw ParameterIncorrect (SRC_POS);   /* length/tweak bounds violated */
		}
	}

	void EncryptionModeAdiantum::ProcessSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize, bool encrypt) const
	{
		if (!KeySet)
			throw NotInitialized (SRC_POS);

		/*
		 * Adiantum is defined over the whole sector, so the sector size IS the block size — unlike XTS,
		 * where a 4096-byte sector is just 256 independent 16-byte blocks. A sector larger than the
		 * primitive supports cannot be split without changing the security property, so it is refused.
		 */
		if (sectorSize < 16 || sectorSize > ADIANTUM_MAX_SECTOR)
			throw ParameterIncorrect (SRC_POS);

		for (uint64 s = 0; s < sectorCount; s++)
		{
			unsigned char tweak[8];
			uint8 *p = data + s * sectorSize;
			TweakFromUnitNo (sectorIndex + s + SectorOffset, tweak);

			const int ok = encrypt
				? AdiantumEncrypt (&Schedule, tweak, sizeof tweak, p, sectorSize, p)
				: AdiantumDecrypt (&Schedule, tweak, sizeof tweak, p, sectorSize, p);
			if (!ok)
				throw ParameterIncorrect (SRC_POS);
		}
	}

	void EncryptionModeAdiantum::Encrypt (uint8 *data, uint64 length) const
	{
		ProcessUnits (data, length, SectorOffset, true);
	}

	void EncryptionModeAdiantum::Decrypt (uint8 *data, uint64 length) const
	{
		ProcessUnits (data, length, SectorOffset, false);
	}

	void EncryptionModeAdiantum::EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		ProcessSectors (data, sectorIndex, sectorCount, sectorSize, true);
	}

	void EncryptionModeAdiantum::DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		ProcessSectors (data, sectorIndex, sectorCount, sectorSize, false);
	}
}

#endif // VC_ENABLE_ADIANTUM_MODE
