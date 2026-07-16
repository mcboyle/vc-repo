/*
 * HardwareKeyFactor — optional hardware second factor for VeraCrypt key derivation.
 *
 * A hardware token computes a secret response from a challenge (the volume's 64-byte PBKDF2 salt);
 * that response is mixed into the password buffer *before* PBKDF2, using the exact same pool
 * construction VeraCrypt already uses for keyfiles (Common/Keyfiles.c). The volume header is NOT
 * changed — the token behaves like a dynamically-computed keyfile, so a volume simply cannot be
 * opened without both the password and the physical token.
 *
 * Two hardware backends plus a software simulator (for testing without hardware) sit behind one seam:
 *   - HKF_BACKEND_YK_HMAC_SHA1      : YubiKey OTP-slot HMAC-SHA1 challenge-response (libykpers)
 *   - HKF_BACKEND_FIDO2_HMAC_SECRET : FIDO2 hmac-secret assertion (libfido2)
 *   - HKF_BACKEND_SIMULATOR         : software virtual token (HMAC computed in-process; TESTING ONLY)
 *
 * Backends are compiled only when their macro is defined, so a build with no token support carries
 * no extra dependency:
 *   -DVC_ENABLE_YUBIKEY_HMAC   (links libykpers-1)
 *   -DVC_ENABLE_FIDO2          (links libfido2)
 *   -DVC_ENABLE_HKF_SIMULATOR  (no external dependency; do not ship in release builds)
 *
 * EXPERIMENTAL. This is a private fork of the key-derivation path; volumes created with a hardware
 * factor are not interoperable with stock VeraCrypt and are unrecoverable if the token (and any
 * backup token / password-only fallback) is lost. Not for real data without review.
 */

#ifndef TC_HEADER_Common_HardwareKeyFactor
#define TC_HEADER_Common_HardwareKeyFactor

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum
{
	HKF_BACKEND_NONE              = 0,
	HKF_BACKEND_YK_HMAC_SHA1      = 1,
	HKF_BACKEND_FIDO2_HMAC_SECRET = 2,
	HKF_BACKEND_SIMULATOR         = 3,
	HKF_BACKEND_RAW_SECRET        = 4   /* mix a caller-supplied secret (e.g. a Shamir reconstruction) */
} HKFBackend;

#define HKF_POOL_SIZE      128   /* must match KEYFILE_POOL_SIZE */
#define HKF_MAX_RESPONSE   64
#define HKF_MAX_CRED_ID    256

/* Result codes (negative = failure). */
#define HKF_OK              0
#define HKF_ERR_CONFIG    (-1)
#define HKF_ERR_NO_DEVICE (-2)
#define HKF_ERR_DEVICE    (-3)
#define HKF_ERR_UNSUPPORTED (-4)

/* Apply policy: which header the factor gates.
 *   HKF_APPLY_ALL          - factor gates whichever header is being derived (a normal volume, or
 *                            both headers of a hidden-volume container). This is the default and the
 *                            behaviour of a plain factor-protected volume.
 *   HKF_APPLY_HIDDEN_ONLY  - factor gates ONLY the hidden header; the outer (decoy) header derives
 *                            from the password alone. Used for a factor-gated decoy layout so the
 *                            outer volume can be surrendered with the password while the real volume
 *                            additionally requires the token. */
#define HKF_APPLY_ALL          0
#define HKF_APPLY_HIDDEN_ONLY  1

typedef struct HKFConfig_struct
{
	int backend;              /* HKFBackend */

	/* YubiKey HMAC-SHA1 */
	int  ykSlot;              /* 1 or 2 (maps to SLOT_CHAL_HMAC1 / SLOT_CHAL_HMAC2) */
	int  ykMayBlock;          /* non-zero: allow the device to block for a touch */

	/* FIDO2 hmac-secret */
	char          fidoRpId[128];              /* relying-party id, e.g. "veracrypt-volume" */
	unsigned char fidoCredId[HKF_MAX_CRED_ID];/* credential id created at enrollment time */
	int           fidoCredIdLen;
	char          fidoPin[128];               /* device PIN, or "" if none */

	/* Simulator (testing only) */
	unsigned char simSecret[64];
	int           simSecretLen;
	int           simMac;     /* 1 = HMAC-SHA1 (emulate YubiKey), 2 = HMAC-SHA256 (emulate FIDO2) */

	/* RAW_SECRET: a secret supplied by the caller (e.g. reconstructed from Shamir shares) that is
	   mixed into the password directly, like a keyfile. */
	unsigned char rawSecret[64];
	int           rawSecretLen;

	/* Application policy: which header(s) the factor gates. */
	int           applyPolicy; /* HKF_APPLY_ALL (default) or HKF_APPLY_HIDDEN_ONLY */
} HKFConfig;

/*
 * Compute the token response for a challenge (pass the volume's PBKDF2 salt, PKCS5_SALT_SIZE bytes).
 * On success writes the raw response (20 bytes for HMAC-SHA1, 32 for hmac-secret) to response_out
 * (which must hold >= HKF_MAX_RESPONSE bytes) and its length to *response_len_out.
 * Returns HKF_OK (0) on success or a negative HKF_ERR_* code.
 */
int HKFComputeResponse (const HKFConfig *cfg,
                        const unsigned char *challenge, int challenge_len,
                        unsigned char *response_out, int *response_len_out);

/*
 * Mix a token response into a password buffer, byte-for-byte identically to how VeraCrypt mixes a
 * keyfile (rolling CRC-32 into a HKF_POOL_SIZE pool via modular addition, then pool added into the
 * password and the length extended to the pool size). 'password' must have room for HKF_POOL_SIZE
 * bytes; *password_len is updated in place.
 */
void HKFMixResponseIntoPassword (unsigned char *password, int *password_len,
                                 const unsigned char *response, int response_len);

/*
 * Optional process-wide active configuration, set by the mount/format caller (the UI or CLI layer)
 * just before a volume operation; NULL means the hardware factor is disabled and derivation is
 * unchanged. This keeps the derivation call-sites to a single guarded line; a production build would
 * instead thread HKFConfig through the mount options / CRYPTO_INFO rather than a global.
 */
extern const HKFConfig *g_hkfActiveConfig;
void HKFSetActiveConfig (const HKFConfig *cfg);

/*
 * Convenience for the derivation call-sites: if a factor is configured, compute the response over
 * 'salt' (the volume's PBKDF2 salt) and mix it into (userKey, *keyLength) in place, exactly as a
 * keyfile would be applied. Returns HKF_OK if there is nothing to do or on success, or a negative
 * HKF_ERR_* if a configured token is missing or fails (the caller should abort the operation).
 */
int HKFApplyIfConfigured (unsigned char *userKey, int *keyLength,
                          const unsigned char *salt, int salt_len);

/*
 * Decide whether the hardware factor should be mixed for the header currently being derived, given
 * the active config and whether that header belongs to a hidden layout. Returns 1 to mix, 0 to skip
 * (also 0 when no factor is configured). Pure function; used by the mount/create call-sites to gate
 * the factor by outer-vs-hidden under HKF_APPLY_HIDDEN_ONLY.
 */
int HKFShouldApply (const HKFConfig *cfg, int layoutIsHidden);

#if defined(__cplusplus)
}
#endif

#endif /* TC_HEADER_Common_HardwareKeyFactor */
