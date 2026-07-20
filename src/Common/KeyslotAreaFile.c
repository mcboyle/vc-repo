/*
 * KeyslotAreaFile — see KeyslotAreaFile.h. Window geometry comes from the real volume-layout
 * constants in Volumes.h, so the header binding is exactly the slack the format leaves random:
 * bytes [TC_VOLUME_HEADER_EFFECTIVE_SIZE, TC_VOLUME_HEADER_SIZE) of the primary header region.
 */

#include "KeyslotAreaFile.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include <string.h>

/* Geometry mirrored from Common/Volumes.h:51-52 (whose prototypes drag the full platform type stack
   this lean module must not depend on). These are on-disk format constants: they cannot change
   without breaking every existing volume, and the #ifndef keeps a real build that includes
   Volumes.h first authoritative. */
#ifndef TC_VOLUME_HEADER_SIZE
#define TC_VOLUME_HEADER_SIZE           (64 * 1024L)
#endif
#ifndef TC_VOLUME_HEADER_EFFECTIVE_SIZE
#define TC_VOLUME_HEADER_EFFECTIVE_SIZE 512
#endif

/* ---- bounds-checked stdio callbacks (offsets are window-relative) ---- */

static int ksaf_seek (KeyslotAreaFile *c, uint64 off)
{
#if defined(_MSC_VER)
	return _fseeki64 (c->f, (__int64) (c->base + off), SEEK_SET);
#else
	return fseeko (c->f, (off_t) (c->base + off), SEEK_SET);
#endif
}

static int ksaf_read (void *ctx, uint64 off, unsigned char *buf, size_t len)
{
	KeyslotAreaFile *c = (KeyslotAreaFile *) ctx;
	if (c->f == NULL || off + len > c->len || off + len < off)
		return -1;
	if (ksaf_seek (c, off) != 0)
		return -1;
	return fread (buf, 1, len, c->f) == len ? 0 : -1;
}

static int ksaf_write (void *ctx, uint64 off, const unsigned char *buf, size_t len)
{
	KeyslotAreaFile *c = (KeyslotAreaFile *) ctx;
	if (c->f == NULL || off + len > c->len || off + len < off)
		return -1;
	if (ksaf_seek (c, off) != 0)
		return -1;
	if (fwrite (buf, 1, len, c->f) != len)
		return -1;
	return fflush (c->f) == 0 ? 0 : -1;
}

static uint64 ksaf_size (void *ctx)
{
	return ((KeyslotAreaFile *) ctx)->len;
}

/* ---- open/close ---- */

int KeyslotAreaFileOpen (KeyslotAreaFile *ctx, const char *path, int writable)
{
	ctx->f = fopen (path, writable ? "r+b" : "rb");
	ctx->base = 0;
	ctx->len = 0;
	return ctx->f ? 0 : -1;
}

void KeyslotAreaFileClose (KeyslotAreaFile *ctx)
{
	if (ctx->f)
	{
		fclose (ctx->f);
		ctx->f = NULL;
	}
	ctx->base = 0;
	ctx->len = 0;
}

/* ---- backend bindings ---- */

void KeyslotAreaBindWindow (KeyslotArea *area, KeyslotAreaFile *ctx, uint64 base, uint64 len)
{
	ctx->base = base;
	ctx->len  = len;
	area->read  = ksaf_read;
	area->write = ksaf_write;
	area->size  = ksaf_size;
	area->ctx   = ctx;
}

int KeyslotAreaBindSidecar (KeyslotArea *area, KeyslotAreaFile *ctx)
{
	uint64 sz;
	if (ctx->f == NULL)
		return -1;
#if defined(_MSC_VER)
	if (_fseeki64 (ctx->f, 0, SEEK_END) != 0) return -1;
	sz = (uint64) _ftelli64 (ctx->f);
#else
	if (fseeko (ctx->f, 0, SEEK_END) != 0) return -1;
	sz = (uint64) ftello (ctx->f);
#endif
	KeyslotAreaBindWindow (area, ctx, 0, sz);
	return 0;
}

void KeyslotAreaBindHeaderSlack (KeyslotArea *area, KeyslotAreaFile *ctx)
{
	/* the format leaves this slack random; the real 512-byte header below it is never touched,
	   and the window ends before the hidden-volume header at TC_HIDDEN_VOLUME_HEADER_OFFSET */
	KeyslotAreaBindWindow (area, ctx, TC_VOLUME_HEADER_EFFECTIVE_SIZE,
	                       TC_VOLUME_HEADER_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE);
}

int KeyslotAreaBindDeniable (KeyslotArea *area, KeyslotAreaFile *ctx,
                             uint64 freeStart, uint64 freeEnd, uint64 hiddenReservedStart)
{
	uint64 end = freeEnd;
	if (hiddenReservedStart != 0 && hiddenReservedStart < end)
		end = hiddenReservedStart;                 /* never place bare records in hidden space */
	if (freeStart >= end || end - freeStart < KEYSLOT_TABLE_STRIDE)
		return -1;
	KeyslotAreaBindWindow (area, ctx, freeStart, end - freeStart);
	return 0;
}

#endif /* VC_ENABLE_KEYSLOTS */
