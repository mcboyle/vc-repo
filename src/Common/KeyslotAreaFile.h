/*
 * KeyslotAreaFile — file-backed KeyslotArea bindings for the three keyslot backends
 * (docs/KEYSLOTS-SPEC.md §9). This is the volume-I/O seam KeyslotStore.c needs, implemented over
 * portable stdio for container files and sidecars:
 *
 *   KSB_SIDECAR  — the whole sidecar file is the area.
 *   KSB_HEADER   — the primary header's reserved slack, bytes
 *                  [TC_VOLUME_HEADER_EFFECTIVE_SIZE, TC_VOLUME_HEADER_SIZE) of the container:
 *                  the real 512-byte header is never touched, and the window ends before the
 *                  hidden-volume header region at TC_HIDDEN_VOLUME_HEADER_OFFSET.
 *   KSB_DENIABLE — a caller-supplied free-space extent inside the data region, clamped so it can
 *                  never reach into a hidden volume's reserved space.
 *
 * All access is bounds-checked against the bound window; offsets the store passes are window-relative.
 * The C++ mount path binds the same windows over its File/Stream classes (real-build glue); this
 * module is the reference binding and what the CLI tools and the verification harness drive.
 * Gated with the keyslots feature; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_KeyslotAreaFile
#define TC_HEADER_Common_KeyslotAreaFile

#include "Tcdefs.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include <stdio.h>
#include "KeyslotStore.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct KeyslotAreaFile
{
	FILE  *f;
	uint64 base;   /* window start, bytes into the file */
	uint64 len;    /* window length in bytes */
} KeyslotAreaFile;

/* Open 'path' (writable != 0 for read/write). Returns 0 on success, -1 on error. */
int  KeyslotAreaFileOpen  (KeyslotAreaFile *ctx, const char *path, int writable);
void KeyslotAreaFileClose (KeyslotAreaFile *ctx);

/* Bind an arbitrary [base, base+len) window of the file as the KeyslotArea. */
void KeyslotAreaBindWindow (KeyslotArea *area, KeyslotAreaFile *ctx, uint64 base, uint64 len);

/* KSB_SIDECAR: the whole file. Returns 0 on success, -1 if the size cannot be read. */
int  KeyslotAreaBindSidecar (KeyslotArea *area, KeyslotAreaFile *ctx);

/* KSB_HEADER: the primary header's reserved slack [512, 64K) of the container file. */
void KeyslotAreaBindHeaderSlack (KeyslotArea *area, KeyslotAreaFile *ctx);

/* KSB_DENIABLE: the free-space extent [freeStart, freeEnd) of the data region, additionally clamped
   below 'hiddenReservedStart' (pass the hidden volume's reserved start, or 0 for none) so bare
   records can never be placed inside a hidden volume's space. Returns 0 on success, -1 if the
   resulting window is empty or ill-formed. */
int  KeyslotAreaBindDeniable (KeyslotArea *area, KeyslotAreaFile *ctx,
                              uint64 freeStart, uint64 freeEnd, uint64 hiddenReservedStart);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_KeyslotAreaFile */
