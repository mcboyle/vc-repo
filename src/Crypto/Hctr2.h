/*
 * HCTR2 wide-block ("length-preserving tweakable SPRP") encryption mode — shippable form of the proven
 * verification PoC (verification/hctr2_poc.c, suite step [26]: all official HCTR2 KATs). Gated
 * VC_ENABLE_HCTR2; default builds are byte-for-byte stock.
 *
 * WHAT IT IS. Like Adiantum, HCTR2 encrypts a whole sector as ONE block: every output byte depends on
 * every input byte, so flipping one ciphertext bit scrambles the entire sector on decrypt. That closes
 * the 16-byte-granular malleability XTS leaves open (docs/HCTR2-SPEC.md, docs/ADIANTUM-SPEC.md, D-4).
 * It is malleability-hardening, NOT authentication — a MAC still detects tampering; a wide-block mode
 * only amplifies the damage tampering does, so an attacker cannot make a surgical 16-byte edit.
 *
 * WHY BOTH HCTR2 AND ADIANTUM EXIST — read this before choosing one (D-4).
 * They deliver the same wide-block property by different means, and the choice is a HARDWARE question:
 *
 *   - HCTR2 runs its block cipher over the WHOLE sector (XCTR keystream, one AES call per 16 bytes),
 *     plus two POLYVAL passes. On hardware with AES-NI that is fast. WITHOUT AES-NI it is slow, and a
 *     table-driven AES would also reintroduce the cache-timing leak measured in docs/CT-HARDENING-R17.md.
 *   - Adiantum calls AES-256 ONCE PER SECTOR and does the bulk work in XChaCha12, which is fast in
 *     software. That is why it is the non-AES-NI answer.
 *
 * So: HCTR2 where AES-NI is present, Adiantum where it is not. D-4 also records that this MUST be a
 * per-volume property stored in the header, never a per-machine runtime choice — otherwise a volume
 * created on an AES-NI machine will not open on one without it, and the intended users move media
 * between borrowed and unreliable machines. Both modes must therefore exist on every platform.
 *
 * THIS BUILD USES THE CONSTANT-TIME AES (src/Crypto/AesCt), NOT the table-driven in-tree Gladman AES.
 * That is a deliberate correctness-and-safety default, and it has a real cost worth stating plainly:
 * AesCt is table-free and branch-free (docs/CT-AES-SPEC.md, ctgrind-CLEAN at step [88]), but it is
 * SOFTWARE AES invoked once per 16-byte block across the whole sector — so HCTR2-over-AesCt is
 * substantially slower than Adiantum on the same non-AES-NI machine. It is correct everywhere and
 * appropriate where AES-NI exists; a production build targeting AES-NI hardware should dispatch the
 * block cipher to the hardware instruction, which is constant-time by construction. Do not "optimise"
 * this by swapping in the table-driven AES: that trades a measured cache-timing leak for speed on
 * exactly the hardware that cannot afford it.
 *
 * VC_ENABLE_HCTR2 implies VC_ENABLE_CTAES (make HCTR2=1 sets both).
 */

#ifndef TC_HEADER_Crypto_Hctr2
#define TC_HEADER_Crypto_Hctr2

#if defined(VC_ENABLE_HCTR2)

#include <stddef.h>
#include "Crypto/AesCt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HCTR2_MAX_SECTOR  4096      /* largest sector this build supports */
#define HCTR2_MAX_TWEAK   64        /* largest tweak (sector index / associated data) */
#define HCTR2_MIN_LEN     16        /* the construction is defined for len >= one block */

typedef struct Hctr2Key_t
{
	AesCtKey256   blk;              /* constant-time AES-256: one expanded key, both directions */
	unsigned char hbar[16];         /* POLYVAL key   h = E_K(0^128)                              */
	unsigned char L[16];            /* mask          L = E_K(0^127 || 1)                         */
} Hctr2Key;

/* Expand a 256-bit key into the HCTR2 subkeys. */
void Hctr2Init (Hctr2Key *hk, const unsigned char key[32]);

/* Wide-block encrypt/decrypt one sector. len must be in [HCTR2_MIN_LEN, HCTR2_MAX_SECTOR];
   tlen <= HCTR2_MAX_TWEAK. `in` and `out` are len bytes and MAY ALIAS (in == out is supported).
   Returns 1 on success, 0 if the length/tweak bounds are violated (output untouched). */
int Hctr2Encrypt (const Hctr2Key *hk, const unsigned char *tweak, size_t tlen,
                  const unsigned char *pt, size_t len, unsigned char *ct);
int Hctr2Decrypt (const Hctr2Key *hk, const unsigned char *tweak, size_t tlen,
                  const unsigned char *ct, size_t len, unsigned char *pt);

#ifdef __cplusplus
}
#endif

#endif /* VC_ENABLE_HCTR2 */
#endif /* TC_HEADER_Crypto_Hctr2 */
