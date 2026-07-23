/*
 * AtomicHeader — atomic, power-loss-resilient header writes (ROI-TOP-50 item 50).
 *
 * VeraCrypt keeps a primary header and a backup header. A crash BETWEEN writing the two during a
 * password/keyfile change (or a keyslot add/rotate/revoke) can leave both stale-or-torn and brick the
 * volume. This treats the two copies as an A/B pair with a monotonic generation counter and a commit
 * tag, so a torn write of one copy is always recoverable from the other:
 *
 *   committed copy = header[headerLen] || gen[8 big-endian] || commitTag[32]
 *   commitTag      = HMAC-SHA256(K, header || gen)          (K = a volume-derived key, 32 bytes)
 *
 *   write:  compute newGen = max(valid gens)+1; write the INACTIVE (older/invalid) copy fully; fsync;
 *           it is now the newest by gen. A half-written copy fails its commitTag (not "committed").
 *   mount:  pick the VALID copy with the greatest gen; if the newest is torn, fall back to the older
 *           valid one; if NEITHER is valid, fail closed (refuse to mount stale/garbage).
 *
 * The 8-byte gen never wraps in practice. Rollback to an older COMPLETE copy is out of scope (needs a
 * monotonic counter in tamper-resistant storage). True power-loss recovery needs real hardware; what is
 * proven in-sandbox is the torn-write recovery logic (see verification/atomic_header_test.c).
 *
 * Gated behind VC_ENABLE_ATOMIC_HEADER; default build stays byte-for-byte stock.
 */
#ifndef TC_HEADER_Common_AtomicHeader
#define TC_HEADER_Common_AtomicHeader

#include "Tcdefs.h"

#if defined(VC_ENABLE_ATOMIC_HEADER)

#if defined(__cplusplus)
extern "C" {
#endif

#define ATOMIC_HEADER_GEN_SIZE  8
#define ATOMIC_HEADER_TAG_SIZE  32
#define ATOMIC_HEADER_OVERHEAD  (ATOMIC_HEADER_GEN_SIZE + ATOMIC_HEADER_TAG_SIZE)   /* 40 */

/* Build a committed copy at 'out' (needs headerLen + ATOMIC_HEADER_OVERHEAD bytes):
   header || gen[8 BE] || HMAC-SHA256(K, header || gen). K is 32 bytes. */
void AtomicHeaderBuild (const unsigned char K[32], const unsigned char *header, int headerLen,
                        uint64 gen, unsigned char *out);

/* 1 if 'copy' carries a valid commit tag (fully written / committed), 0 if torn or corrupt. */
int AtomicHeaderValid (const unsigned char K[32], const unsigned char *copy, int headerLen);

/* Read the gen field of a copy (only meaningful when AtomicHeaderValid()==1). */
uint64 AtomicHeaderGen (const unsigned char *copy, int headerLen);

/* Select the VALID copy with the greatest gen, copying its header into outHeader (headerLen bytes) and
   its gen into *outGen (if non-NULL). Returns 0 (A chosen) or 1 (B chosen), or -1 if NEITHER copy is
   valid — fail closed, refuse to mount. */
int AtomicHeaderSelect (const unsigned char K[32],
                        const unsigned char *copyA, const unsigned char *copyB, int headerLen,
                        unsigned char *outHeader, uint64 *outGen);

/* Next generation to write = max(valid gens) + 1 (1 when neither copy is valid). */
uint64 AtomicHeaderNextGen (const unsigned char K[32],
                            const unsigned char *copyA, const unsigned char *copyB, int headerLen);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_ATOMIC_HEADER */

#endif /* TC_HEADER_Common_AtomicHeader */
