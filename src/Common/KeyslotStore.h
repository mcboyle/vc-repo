/*
 * KeyslotStore — placement of keyslot records, behind one seam with three backends.
 *
 * Keyslot.{c,h} defines the per-slot wrap/unwrap crypto; this module decides WHERE a record lives and
 * how a candidate slot is found. All backends operate on an abstract KeyslotArea (read/write/size over
 * any medium — a header region, a file, an in-memory buffer), so the placement logic is testable
 * without real volume I/O. Backends (docs/KEYSLOTS-SPEC.md §3):
 *   - KSB_HEADER   : a fixed table of labeled records in the volume header's reserved slack.
 *   - KSB_SIDECAR  : the same labeled-record table, in a separate file/area (volume untouched).
 *   - KSB_DENIABLE : "bare" records (no plaintext markers) at a passphrase-derived offset, so the
 *                    presence and number of extra keys is deniable.
 *
 * The wrapped payload is flags[1] || vmk, so the slot flags (incl. the duress bit) are encrypted with
 * the key material — no plaintext markers, which the deniable backend requires. Gated behind
 * -DVC_ENABLE_KEYSLOTS; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_KeyslotStore
#define TC_HEADER_Common_KeyslotStore

#include "Tcdefs.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include "Keyslot.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum
{
	KSB_HEADER   = 1,
	KSB_DENIABLE = 2,
	KSB_SIDECAR  = 3
} KeyslotBackend;

/* Abstract medium the records live in. read/write return 0 on success, non-zero on error/out-of-range.
   All three callbacks and ctx are supplied by the caller (volume header, file, or test buffer). */
typedef struct KeyslotArea
{
	int    (*read)  (void *ctx, uint64 off, unsigned char *buf, size_t len);
	int    (*write) (void *ctx, uint64 off, const unsigned char *buf, size_t len);
	uint64 (*size)  (void *ctx);
	void    *ctx;
} KeyslotArea;

typedef struct KeyslotStoreCfg
{
	KeyslotBackend backend;
	KeyslotKdfFn   kdf;                                 /* product: derive_key_sha512 binding */
	unsigned int   cost;                                /* KDF cost (PBKDF2 iterations) */
	int            vmkLen;                              /* wrapped master-key length (all slots equal) */
	int            maxSlots;                            /* table size for KSB_HEADER / KSB_SIDECAR */
	void         (*randBytes) (unsigned char *, size_t);/* CSPRNG for per-slot salts */
	int            afStripes;                           /* anti-forensic stripes s (docs/AF-SPLIT-SPEC.md):
	                                                       0 or 1 = off (byte-identical legacy records);
	                                                       s >= 2 AF-splits the payload before wrapping.
	                                                       Public parameter like 'cost': the open path
	                                                       sizes its fixed per-slot work from it, never
	                                                       from record bytes. Bounded by the stride. */
#if defined(VC_ENABLE_KEYSLOT_POLICY)
	int            policy;                               /* 0 = v1 legacy payload (flags[1]||vmk), opens
	                                                       byte-identically; 1 = v2 policy payload
	                                                       (flags[1]||expiryUnix[8]||vmk). Table-level like
	                                                       'cost'/'afStripes'; per-slot policy still varies
	                                                       (each v2 slot carries its own flags + expiry).
	                                                       docs/KEYSLOT-POLICY-DESIGN.md. */
#endif
} KeyslotStoreCfg;

/* Fixed on-medium stride of one labeled table slot (KSB_HEADER / KSB_SIDECAR). */
#define KEYSLOT_TABLE_STRIDE 1024

/* Add a slot wrapping 'vmk' (cfg->vmkLen bytes) under 'pass'. 'flags' may set KEYSLOT_FLAG_DURESS.
   Returns the slot index placed (>=0) or -1 (table full / area too small / write error). */
int KeyslotAdd (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                const unsigned char *pass, int passLen, int flags,
                const unsigned char *vmk);

/* Try to open any slot with 'pass'. On success returns 1, fills vmkOut (cfg->vmkLen bytes) and, if
   non-NULL, *flagsOut. Returns 0 if no slot matches. */
int KeyslotOpen (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                 const unsigned char *pass, int passLen,
                 unsigned char *vmkOut, int *flagsOut);

/* Open exactly labeled-table slot 'index' with 'pass' (admin-side; used by rotation to locate the
   slot to retire). Reveals per-index success, unlike the constant-time KeyslotOpen mount path.
   Returns 1 and fills vmkOut (+ *flagsOut if non-NULL) on a match, 0 otherwise. Labeled backends only. */
int KeyslotOpenAt (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index,
                   const unsigned char *pass, int passLen,
                   unsigned char *vmkOut, int *flagsOut);

/* Revoke slot 'index' (KSB_HEADER / KSB_SIDECAR): overwrite it with fresh random. Returns 0 on
   success. The VMK is unchanged, so revocation is instant and needs no body re-encryption. */
int KeyslotRevoke (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index);

/* Count occupied labeled table slots (KSB_HEADER / KSB_SIDECAR). Deniable slots are, by design, not
   enumerable without their passphrase, so this returns 0 for KSB_DENIABLE. */
int KeyslotCount (const KeyslotStoreCfg *cfg, KeyslotArea *area);

#if defined(VC_ENABLE_KEYSLOT_SHRED)
/* ---- verifiable keyslot shredding (ROI item 41) ----------------------------------------------------
 * KeyslotRevoke already overwrites the whole slot with fresh random. KeyslotShred adds a verifiable
 * receipt: it hashes the slot BEFORE, overwrites the entire stride (ciphertext + AF stripes + salt +
 * tag + pad) with CSPRNG random, reads back what ACTUALLY landed on the medium, and returns an
 * attestation = SHA-256("VCKSSHRED1" || index || H(before) || H(after)). An auditor can check the two
 * hashes differ and that `after` is the value now on disk — i.e. the old wrapped key (and every AF
 * stripe of it) is gone, with a record of it. Honest limit: this is a LOGICAL overwrite; on SSDs /
 * copy-on-write media the physical block may persist (docs/THREAT-MODEL.md) — the attestation records
 * the logical erase, it does not defeat wear-levelling. */
int KeyslotShred (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index,
                  unsigned char attestation[32]);
#endif

#if defined(VC_ENABLE_KEYSLOT_POLICY)
/* ---- per-slot policy (ROI item 15; docs/KEYSLOT-POLICY-DESIGN.md) -----------------------------------
 * Requires cfg->policy == 1 (v2 records). read-only + expiry live in the ENCRYPTED payload
 * (authenticated, hidden); max-attempts is a CLEARTEXT pad counter — necessarily cleartext so lockout
 * can be enforced without the key, and therefore rollback-defeatable (restoring an old table copy
 * resets it). Not offered on the deniable backend (no cleartext metadata by design). */

#define KEYSLOT_LOCKED (-2)   /* KeyslotOpenAtPolicy: slot is locked out (attempts >= maxAttempts) */

/* Add a v2 policy slot. 'flags' may set KEYSLOT_FLAG_DURESS / KEYSLOT_FLAG_READONLY. 'expiryUnix' is a
   Unix time after which the slot stops opening (0 = never). 'maxAttempts' locks the slot after that many
   failed admin opens (0 = unlimited). Returns the slot index (>=0) or -1. Labeled backends only. */
int KeyslotAddPolicy (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                      const unsigned char *pass, int passLen, int flags,
                      const unsigned char *vmk, uint64 expiryUnix, int maxAttempts);

/* Constant-time mount open with expiry enforcement. Identical to KeyslotOpen, but a matched slot whose
   expiry != 0 and expiry < nowUnix is rejected SILENTLY (returns 0, as if the passphrase were wrong —
   no expiry oracle). On success returns 1, fills vmkOut, *flagsOut (incl. the read-only bit), and
   *expiryOut if non-NULL. Pass nowUnix = 0 to disable the expiry check. */
int KeyslotOpenPolicy (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                       const unsigned char *pass, int passLen, uint64 nowUnix,
                       unsigned char *vmkOut, int *flagsOut, uint64 *expiryOut);

/* Admin indexed open with lockout (rotate/list path; reveals per-index success). Reads the cleartext
   attempt counter first: if maxAttempts>0 and attempts>=maxAttempts, returns KEYSLOT_LOCKED without
   trying. Otherwise unwraps; on failure increments the counter (write-back) and returns 0; on success
   resets it to 0, enforces expiry silently (returns 0 if expired), and returns 1. Labeled backends
   only. Reports *attemptsOut / *maxAttemptsOut (cleartext) if non-NULL. */
int KeyslotOpenAtPolicy (const KeyslotStoreCfg *cfg, KeyslotArea *area, int index,
                         const unsigned char *pass, int passLen, uint64 nowUnix,
                         unsigned char *vmkOut, int *flagsOut,
                         int *attemptsOut, int *maxAttemptsOut);
#endif /* VC_ENABLE_KEYSLOT_POLICY */

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_KeyslotStore */
