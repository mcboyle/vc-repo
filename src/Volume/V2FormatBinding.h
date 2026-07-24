/*
 * V2FormatBinding.h — C++ glue for the v2 on-disk format core (Common/V2Format.c), for the Volume/Core
 * mount & create paths (T1-1). Header-only, same pattern as HardwareKeyFactorMix.h: `extern "C"` include
 * of the C module + thin inline helpers in namespace VeraCrypt.
 *
 * Deliberately dependency-light — it operates on plain byte buffers (const uint8_t* / size_t), NOT on
 * VolumePassword/ConstBufferPtr — so the C++ seam compiles and is link-proven standalone against the real
 * V2Format.o + Sha2.o (verification/v2format_cpp.cpp), exactly as hkf_cli_test.cpp link-proves the HKF C
 * module. The product call sites pass `buffer.Ptr()` / `(int) buffer.Size()` from their VeraCrypt buffers.
 *
 * Gated VC_ENABLE_V2FORMAT; when the flag is off the helpers degrade to safe no-ops (DiscoverMode returns
 * V2_MODE_NONE -> the caller mounts as v1), so a stock build is unaffected.
 *
 * WHERE THIS WIRES IN (the remaining owner-gated real-build integration):
 *   - Mount (Core/Volume open, after the header unlocks and the master key is available): read data
 *     sector 0 + its MAC-table slot, call DiscoverMode(masterKey, sector0Ct, tag) -> the wide-block mode;
 *     then select that mode's cipher for the session. Falls through to v1 on V2_MODE_NONE.
 *   - Create (Core/VolumeCreator, when the data-area size is known): call SplitDataArea(totalDataBytes,
 *     sectorSize) to reserve the tail MAC table and shrink the usable data area.
 * BLOCKED ON: the wide-block cipher mode classes (HCTR2/Adiantum as an EncryptionMode) + a per-sector
 * MAC I/O layer — T2-3 (constant-time AES) / T2-4. This header is the seam they plug into.
 */

#ifndef TC_HEADER_Volume_V2FormatBinding
#define TC_HEADER_Volume_V2FormatBinding

#include <stdint.h>
#include <stddef.h>

#if defined(VC_ENABLE_V2FORMAT)
extern "C" {
#include "Common/V2Format.h"
}
#endif

namespace VeraCrypt
{
	namespace V2Format
	{
		/* result of reserving the tail MAC table out of a data area */
		struct DataAreaSplit
		{
			uint64_t usableBytes;   /* usable data prefix (what the filesystem sees) */
			uint64_t tableOffset;   /* MAC-table byte offset from the start of the data area */
			bool     ok;            /* false if the volume is too small to hold a table -> reject for v2 */
		};

		/* Mount-time mode discovery. Returns the wide-block mode, or V2_MODE_NONE when neither mode's key
		   verifies sector 0's tag (a legacy v1 volume, or a wrong master key -> caller mounts as v1). */
		inline int DiscoverMode (const uint8_t *masterKey, int masterKeyLen,
		                         const uint8_t *sector0Ct, size_t ctLen,
		                         const uint8_t *storedTag16)
		{
#if defined(VC_ENABLE_V2FORMAT)
			return (int) V2FormatDiscoverMode (masterKey, masterKeyLen, sector0Ct, ctLen, storedTag16);
#else
			(void) masterKey; (void) masterKeyLen; (void) sector0Ct; (void) ctLen; (void) storedTag16;
			return -1;   /* V2_MODE_NONE -> mount as v1 when the feature is compiled out */
#endif
		}

		/* True iff `mode` is a real v2 wide-block mode (i.e. not V2_MODE_NONE). */
		inline bool ModeIsV2 (int mode) { return mode >= 0; }

		/* Create-time: split a data area of `totalDataBytes` into a usable prefix + a tail MAC table. */
		inline DataAreaSplit SplitDataArea (uint64_t totalDataBytes, uint32_t sectorSize)
		{
			DataAreaSplit s;
			s.usableBytes = totalDataBytes; s.tableOffset = totalDataBytes; s.ok = false;
#if defined(VC_ENABLE_V2FORMAT)
			{
				uint64_t usable = 0, off = 0;
				if (V2FormatSplitDataArea (totalDataBytes, sectorSize, &usable, &off) == 0)
				{
					s.usableBytes = usable; s.tableOffset = off; s.ok = true;
				}
			}
#else
			(void) sectorSize;
#endif
			return s;
		}
	}
}

#endif /* TC_HEADER_Volume_V2FormatBinding */
