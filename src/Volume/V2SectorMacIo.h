/*
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

/*
 * V2SectorMacIo — the per-sector MAC I/O layer for the v2 on-disk format (T1-1).
 *
 * This is the tier that makes ciphertext tampering DETECTABLE. The wide-block modes
 * (EncryptionModeHctr2 / EncryptionModeAdiantum) amplify an edit — one changed bit randomises the whole
 * sector — but amplification is not detection, and neither mode is authenticated. The v2 MAC table is
 * what turns "the sector is now garbage" into "the sector was modified, refuse it".
 *
 * ============================================================================================
 * THE TAG IS OVER CIPHERTEXT, NOT PLAINTEXT. This dictates the call ordering and is easy to get
 * backwards:
 *     READ :  read ct -> VerifyRange(ct) -> THEN decrypt
 *     WRITE:  encrypt -> UpdateRange(ct) -> THEN write
 * Verifying after decryption would authenticate the wrong bytes and, worse, would still "work" in
 * round-trip tests while authenticating nothing an attacker touches.
 * ============================================================================================
 *
 * POLICY: FAIL CLOSED (owner decision 2026-07-25; docs/V2-FORMAT-SPEC.md §"Tag-mismatch policy").
 * A mismatch throws. The caller does not receive the plaintext. Fail-warn was considered and rejected:
 * a warning that can be ignored reduces per-sector authentication to advice, and the adversary this
 * format answers is one who edits ciphertext.
 *
 * ---------------------------------------------------------------------------------------------------
 * THE WRITE-ATOMICITY PROBLEM, AND WHY IT MAKES THE OVERRIDE MANDATORY RATHER THAN NICE-TO-HAVE
 *
 * A sector's data and its tag live in two different places on the disk (the data area, and the MAC
 * table at its tail). There is no way to update both atomically without a journal, which this format
 * does not have. So an interrupted write ALWAYS leaves one of two inconsistent states:
 *
 *     data written, tag not  ->  new data + old tag   -> MISMATCH
 *     tag written, data not  ->  old data + new tag   -> MISMATCH
 *
 * Either way the affected sectors fail closed. This is not a hypothetical: power loss, a crash, or a
 * removed USB stick mid-write reaches it with NO adversary involved. It is the concrete mechanism
 * behind the availability cost recorded in the spec, and it is precisely why the operator override
 * below is a REQUIREMENT and not a convenience — without it, one interrupted write can strand a volume.
 *
 * We write DATA FIRST, THEN TAGS, deliberately. Both orders lose the same sectors, but this order fails
 * in the safer direction: a torn write leaves the NEW data on disk under an OLD tag, so an operator who
 * overrides can read what was actually written. The reverse order would leave a valid-looking tag over
 * stale data — a state that is harder to reason about and easier to mistake for intact.
 *
 * ---------------------------------------------------------------------------------------------------
 * THE OVERRIDE (docs/V2-FORMAT-SPEC.md; required shape, implemented here)
 *   1. DELIBERATE   — SetIgnoreTags(true) is never called by default; it exists for an operator who has
 *                     been told what it means. There is no config file entry and no silent fallback.
 *   2. LOGGED       — every ignored mismatch increments IgnoredMismatchCount and records the first
 *                     offending sector, so the caller can surface "you read N unauthenticated sectors".
 *                     An override that leaves no trace is fail-warn with extra steps.
 *   3. SCOPED       — it is per-Volume-instance state, set after open and lost on close. It is NEVER
 *                     written to the volume. A persistent "ignore my tags" property would let an
 *                     adversary who can write the header disable detection outright.
 *   4. CHEAP        — the MAC table is a separate region, so reading past a bad tag costs nothing
 *                     structurally.
 *
 * Gated behind VC_ENABLE_V2FORMAT. When the flag is off, or when the volume is not v2 (Mode == NONE),
 * every entry point below is an explicit no-op — v1 volumes must take byte-identical paths to before.
 */

#ifndef TC_HEADER_Volume_V2SectorMacIo
#define TC_HEADER_Volume_V2SectorMacIo

#include "Platform/Platform.h"
#include "Volume/V2FormatBinding.h"

#if defined(VC_ENABLE_V2FORMAT)

namespace VeraCrypt
{
	struct V2TagMismatch : public Exception
	{
		V2TagMismatch (const string &fileLocation) : Exception (fileLocation) { }
		virtual Exception *CloneNew () const { return new V2TagMismatch (*this); }
	};

	/*
	 * Holds the v2 per-sector-MAC state for one open volume and performs the table I/O.
	 * Deliberately NOT owning the file: the caller passes the already-open host file, because the
	 * table lives inside the same volume file and the caller already holds it.
	 */
	class V2SectorMacIo
	{
	public:
		V2SectorMacIo ()
			: Mode (V2_MODE_NONE), SectorSize (0), TableBaseOffset (0), DataSectors (0),
			  IgnoreTags (false), IgnoredMismatchCount (0), FirstIgnoredSector (0) { }

		/* Arm for a v2 volume. `mode` comes from V2FormatDiscoverMode; `tableBaseOffset` is the HOST
		   offset of the MAC table (data-area start + usable bytes, per V2FormatSplitDataArea). */
		void Configure (V2Mode mode, const uint8 *masterKey, int masterKeyLen,
		                size_t sectorSize, uint64 tableBaseOffset, uint64 dataSectors)
		{
			Mode = mode;
			SectorSize = sectorSize;
			TableBaseOffset = tableBaseOffset;
			DataSectors = dataSectors;
			if (mode != V2_MODE_NONE)
				V2FormatDeriveModeKey (masterKey, masterKeyLen, mode, MacKey);
		}

		bool IsActive () const { return Mode != V2_MODE_NONE; }

		/* --- the override; see the header comment for why each property matters --- */
		void SetIgnoreTags (bool ignore) { IgnoreTags = ignore; }
		bool GetIgnoreTags () const { return IgnoreTags; }
		uint64 GetIgnoredMismatchCount () const { return IgnoredMismatchCount; }
		uint64 GetFirstIgnoredSector () const { return FirstIgnoredSector; }

		/*
		 * Verify `count` sectors of CIPHERTEXT starting at data-sector `firstSector`.
		 * MUST be called BEFORE decryption. Throws V2TagMismatch on the first bad sector unless the
		 * override is set, in which case it counts and continues.
		 */
		void VerifyRange (const File &file, const uint8 *ct, uint64 firstSector, uint64 count) const
		{
			if (!IsActive() || count == 0)
				return;

			SecureBuffer tags ((size_t) (count * V2_MAC_TAG_LEN));
			ReadTags (file, firstSector, count, tags);

			for (uint64 i = 0; i < count; i++)
			{
				const uint8 *sectorCt  = ct + i * SectorSize;
				const uint8 *storedTag = tags.Ptr() + i * V2_MAC_TAG_LEN;

				/* V2FormatSectorVerify does a constant-time compare (v2_ct_eq, blessed at step [84]). */
				if (!V2FormatSectorVerify (MacKey, firstSector + i, sectorCt, SectorSize, storedTag))
				{
					if (!IgnoreTags)
						throw V2TagMismatch (SRC_POS);

					if (IgnoredMismatchCount == 0)
						FirstIgnoredSector = firstSector + i;
					IgnoredMismatchCount++;
				}
			}
		}

		/*
		 * Recompute and store tags for `count` sectors of CIPHERTEXT.
		 * MUST be called AFTER encryption, and the caller MUST write the data before calling this —
		 * see the write-atomicity note in the header comment.
		 */
		void UpdateRange (const File &file, const uint8 *ct, uint64 firstSector, uint64 count) const
		{
			if (!IsActive() || count == 0)
				return;

			SecureBuffer tags ((size_t) (count * V2_MAC_TAG_LEN));
			for (uint64 i = 0; i < count; i++)
				V2FormatSectorTag (MacKey, firstSector + i, ct + i * SectorSize, SectorSize,
				                   tags.Ptr() + i * V2_MAC_TAG_LEN);

			WriteTags (file, firstSector, count, tags);
		}

	protected:
		/* Slots are contiguous and fixed-width, so a sector RANGE is a single contiguous table range —
		   one read/write, not one per sector. That matters: the naive per-sector version would turn every
		   multi-sector I/O into N extra seeks on the hot path. */
		void ReadTags (const File &file, uint64 firstSector, uint64 count, const BufferPtr &out) const
		{
			BoundsCheck (firstSector, count);
			file.ReadAt (out, TableBaseOffset + V2FormatSlotOffset (firstSector));
		}

		void WriteTags (const File &file, uint64 firstSector, uint64 count, const ConstBufferPtr &in) const
		{
			BoundsCheck (firstSector, count);
			file.WriteAt (in, TableBaseOffset + V2FormatSlotOffset (firstSector));
		}

		/* A sector index past the end of the table would read or write OUTSIDE the reserved region —
		   into the backup header group, or past the end of the volume. Refuse rather than trust the
		   caller's arithmetic. */
		void BoundsCheck (uint64 firstSector, uint64 count) const
		{
			if (count == 0 || firstSector + count < firstSector /* overflow */
			    || firstSector + count > DataSectors)
				throw ParameterIncorrect (SRC_POS);
		}

		V2Mode Mode;
		uint8  MacKey[V2_KEY_LEN];
		size_t SectorSize;
		uint64 TableBaseOffset;
		uint64 DataSectors;

		bool           IgnoreTags;
		mutable uint64 IgnoredMismatchCount;
		mutable uint64 FirstIgnoredSector;
	};
}

#endif // VC_ENABLE_V2FORMAT
#endif // TC_HEADER_Volume_V2SectorMacIo
