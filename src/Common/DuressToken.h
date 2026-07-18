/*
 * DuressToken — recognise a duress passphrase in user space, with no plaintext stored and no
 * on-disk header change.
 *
 * The safe duress action (dismount everything + scrub RAM keys, mount nothing — see
 * Core/UserInterface DuressDismount) can be triggered by a dedicated *duress passphrase*. VeraCrypt
 * has a single password per volume and no keyslot table, so a duress passphrase cannot live in the
 * volume header without a format change. Instead it is recognised locally: a random per-registration
 * salt and the tag HMAC-SHA256(salt, passphrase) are what get stored/compared; the passphrase itself
 * is never kept, and the stored tag reveals nothing usable to derive it. The comparison is
 * constant-time.
 *
 * This is deliberately independent of the volume's own key derivation — matching the duress
 * passphrase does not read or touch any volume, it only decides to run the safe-dismount action. All
 * of this is compiled only when -DVC_ENABLE_DURESS is set; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_DuressToken
#define TC_HEADER_Common_DuressToken

#include "Tcdefs.h"

#if defined(VC_ENABLE_DURESS)

#if defined(__cplusplus)
extern "C" {
#endif

#define DURESS_TAG_SIZE   32    /* HMAC-SHA256 output */
#define DURESS_SALT_SIZE  16    /* random per-registration salt */
#define DURESS_MAX_PASS   256   /* upper bound on passphrase bytes accepted */

/*
 * Derive the duress tag: tagOut = HMAC-SHA256(key = salt, data = passphrase), using VeraCrypt's own
 * in-tree hmac_sha256 (Common/Pkcs5.c). passLen is clamped to DURESS_MAX_PASS. tagOut must have room
 * for DURESS_TAG_SIZE bytes.
 */
void DuressTokenDerive (const unsigned char *salt, int saltLen,
                        const unsigned char *pass, int passLen,
                        unsigned char tagOut[DURESS_TAG_SIZE]);

/* Constant-time equality over 'len' bytes. Returns 1 if all bytes match, 0 otherwise; the running
   time depends only on 'len', not on where (or whether) the buffers first differ. */
int DuressTokenMatch (const unsigned char *a, const unsigned char *b, int len);

/*
 * Convenience: derive the tag for 'pass' under 'salt' and constant-time-compare it to 'expectedTag'.
 * Returns 1 on match (this passphrase is the duress passphrase), 0 otherwise. The scratch tag is
 * wiped before returning.
 */
int DuressTokenCheck (const unsigned char *salt, int saltLen,
                      const unsigned char *pass, int passLen,
                      const unsigned char expectedTag[DURESS_TAG_SIZE]);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_DURESS */

#endif /* TC_HEADER_Common_DuressToken */
