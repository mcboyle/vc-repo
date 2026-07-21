/*
 * KeyslotVolumeBinding — C++ mount/CLI glue between the C KeyslotStore module and the Linux/macOS
 * application's volume I/O (docs/KEYSLOTS-SPEC.md §9). KeyslotAreaFile.{c,h} binds the same windows
 * over portable stdio for the verification harness; this binds them over the app's File class so the
 * mount path (Volume::Open) and the --keyslot-* CLI can add/open/rotate/revoke slots on a real volume.
 *
 * The one shipping backend wired here is KSB_HEADER: the primary header's reserved slack
 * [TC_VOLUME_HEADER_EFFECTIVE_SIZE, TC_VOLUME_HEADER_SIZE) = [512, 64K) of the container. The real
 * 512-byte header (slot 0) is never touched and the window ends before the hidden-header region at
 * TC_HIDDEN_VOLUME_HEADER_OFFSET. Gated with the keyslots feature; a build without it is stock.
 */

#ifndef TC_HEADER_Volume_KeyslotVolumeBinding
#define TC_HEADER_Volume_KeyslotVolumeBinding

#include "Platform/Platform.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include "Platform/File.h"
#include "Core/RandomNumberGenerator.h"
#include "Common/Volumes.h"

extern "C" {
#include "Common/KeyslotStore.h"   // pulls Keyslot.h, which declares KeyslotKdfSha512
}

namespace VeraCrypt
{
	// Iterations for the per-slot PBKDF2-HMAC-SHA512 wrap KDF. Fixed (public) parameter, like the
	// keyfile-pool constants: the open path sizes its work from it, never from record bytes.
	static const unsigned int KeyslotKdfCost = 500000;

	// Window of a File bound as a C KeyslotArea. read/write are window-relative and bounds-checked.
	struct KeyslotFileArea
	{
		File  *file;
		uint64 base;
		uint64 len;

		static int  ReadCb  (void *ctx, uint64 off, unsigned char *buf, size_t n)
		{
			KeyslotFileArea *a = (KeyslotFileArea *) ctx;
			if (off > a->len || n > a->len - off) return -1;
			try { a->file->ReadAt (BufferPtr (buf, n), a->base + off); } catch (...) { return -1; }
			return 0;
		}
		static int  WriteCb (void *ctx, uint64 off, const unsigned char *buf, size_t n)
		{
			KeyslotFileArea *a = (KeyslotFileArea *) ctx;
			if (off > a->len || n > a->len - off) return -1;
			try { a->file->WriteAt (ConstBufferPtr (buf, n), a->base + off); } catch (...) { return -1; }
			return 0;
		}
		static uint64 SizeCb (void *ctx) { return ((KeyslotFileArea *) ctx)->len; }
	};

	// Fill 'area' + 'ctx' for the KSB_HEADER slack window over 'file'.
	inline void KeyslotBindHeaderSlack (KeyslotArea &area, KeyslotFileArea &ctx, File *file)
	{
		ctx.file = file;
		ctx.base = TC_VOLUME_HEADER_EFFECTIVE_SIZE;
		ctx.len  = TC_VOLUME_HEADER_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE;   // [512, 64K)
		area.read  = &KeyslotFileArea::ReadCb;
		area.write = &KeyslotFileArea::WriteCb;
		area.size  = &KeyslotFileArea::SizeCb;
		area.ctx   = &ctx;
	}

	// RandomNumberGenerator adapter for per-slot salts (KeyslotStoreCfg.randBytes).
	inline void KeyslotRandBytes (unsigned char *buf, size_t n)
	{
		BufferPtr b (buf, n);
		// allowAnyLength = true: the store fills whole 1 KiB slot records at once, which exceeds the
		// RNG pool size (320 B); GetData otherwise rejects a request larger than one pool.
		RandomNumberGenerator::GetData (b, true);
	}

	// Store config for the KSB_HEADER backend wrapping a 'vmkLen'-byte VMK. maxSlots 63 fits the
	// 63KiB slack at the 1KiB table stride; afStripes 0 keeps byte-identical legacy records.
	inline KeyslotStoreCfg KeyslotHeaderCfg (int vmkLen)
	{
		KeyslotStoreCfg cfg;
		cfg.backend   = KSB_HEADER;
		cfg.kdf       = &KeyslotKdfSha512;
		cfg.cost      = KeyslotKdfCost;
		cfg.vmkLen    = vmkLen;
		cfg.maxSlots  = 63;
		cfg.randBytes = &KeyslotRandBytes;
		cfg.afStripes = 0;
		return cfg;
	}
}

#endif // VC_ENABLE_KEYSLOTS

#endif // TC_HEADER_Volume_KeyslotVolumeBinding
