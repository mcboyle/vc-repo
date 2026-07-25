/*
 * NetShare — network-bound share source (McCallum–Relyea), shippable module.
 *
 * Recovers a 32-byte share that REQUIRES a network server's participation, where the server never
 * learns the share, the client, or the volume. A stolen off-network machine cannot recover it. The
 * recovered bytes feed the existing RAW_SECRET / Shamir path (docs/NETWORK-SHARE-SPEC.md) — there is
 * no new derivation seam and no on-disk header change.
 *
 *   server long-term:  s (secret),  S = s*G                (S is published)
 *   provision:         c (ephemeral), C = c*G,  K = c*S
 *                      then c and K are DISCARDED — only the public {S, C} remain on disk
 *   recover:           e (ephemeral), X = C + e*G          -> send X to the server
 *                      server:        Y = s*X               (the server sees only the blinded X)
 *                      client:        K = Y - e*S = c*S     -> share = SHA-256(compress(K))
 *
 * WHY THIS MODULE EXISTS AT ALL (and what was missing before it)
 * The MR exchange has been proven repeatedly — over a small prime field [10], the full Ed25519 group
 * [39], an AF_UNIX socketpair [49] and real two-host TCP [101]. But every one of those POCs put the
 * RAW extended-coordinate `pt` struct on the wire and said so: "a production build would send
 * compressed 32-byte points ... a serialization detail". That detail is not free — a compressed point
 * must be DECOMPRESSED on receipt, which needs a modular square root, and no decompression existed
 * anywhere in this tree. So the audit line "the remaining gap is only the product --ns-* CLI wiring
 * (a code task)" understated it: a wire format was missing, and a wire format needs new crypto.
 * NetSharePointDecompress (RFC 8032 section 5.1.3) is that crypto, anchored to the official RFC 8032
 * section 7.1 vectors — see verification/netshare_module_test.c.
 *
 * TRANSPORT IS INJECTED, NOT BUILT IN. This module contains no sockets: the caller supplies a
 * NetShareTransportFn, exactly as KeyslotStore takes a KeyslotArea and the keyslot scan takes a
 * parallel-for. That keeps the crypto testable with no network, keeps platform socket code out of
 * Common/, and lets the same core drive TCP, TLS, or a Tang-style HTTP endpoint.
 *
 * Gated behind -DVC_ENABLE_NETSHARE; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_NetShare
#define TC_HEADER_Common_NetShare

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETSHARE_POINT_LEN   32   /* a compressed Ed25519 point (RFC 8032 section 5.1.2) */
#define NETSHARE_SHARE_LEN   32   /* SHA-256(compress(K)) */
#define NETSHARE_SCALAR_LEN  32

/* Versioned public credential written at enrolment. Contains NO secret: c and K are destroyed after
   enrolment, so a stolen credential is useless without the server.
 *
 * The trailing checksum is NOT decoration. Ed25519 points are dense in their encoding: flipping a bit
 * in a stored point usually yields ANOTHER VALID POINT, so a corrupt credential would parse cleanly and
 * recovery would silently return a different share — surfacing to the user as "wrong password" with no
 * hint that the credential is at fault. That is the data-loss-shaped failure this module is built to
 * avoid, so corruption is detected here and reported as NETSHARE_ERR_CRED. (The first version of this
 * module lacked the checksum and its own doc comment claimed the property anyway; the module test
 * caught it — see verification/netshare_module_test.c section [4].)
 *
 * It is a corruption check, not authentication: an attacker who can rewrite the credential can also
 * rewrite the checksum. They still learn nothing — the credential is public — and cannot recover the
 * share without the server. Integrity against a tampering adversary belongs to whatever protects the
 * volume header, not to this blob. */
#define NETSHARE_CRED_VERSION 1
#define NETSHARE_CRED_CKSUM_LEN 4
/* magic[3] || ver[1] || S[32] || C[32] || cksum[4] */
#define NETSHARE_CRED_LEN     (4 + NETSHARE_POINT_LEN * 2 + NETSHARE_CRED_CKSUM_LEN)

/* Return codes. Negative = failure; the caller must not treat any of them as "wrong password". */
#define NETSHARE_OK               0
#define NETSHARE_ERR_PARAM      (-1)
#define NETSHARE_ERR_POINT      (-2)   /* a point was not a canonical, on-curve encoding */
#define NETSHARE_ERR_TRANSPORT  (-3)   /* the server could not be reached / gave a short reply */
#define NETSHARE_ERR_CRED       (-4)   /* the credential blob is malformed or an unknown version */

/*
 * Transport seam. Send exactly 'reqLen' bytes and return the server's reply.
 * MUST return NETSHARE_OK only when 'respLen' bytes were genuinely received; anything else (no route,
 * refused, short read, timeout) must return non-zero so the caller can distinguish "off-network" from
 * "wrong key". Conflating the two is the failure this module is designed to avoid.
 */
typedef int (*NetShareTransportFn) (void *ctx,
                                    const unsigned char *req, size_t reqLen,
                                    unsigned char *resp, size_t respCap, size_t *respLen);

/* CSPRNG seam (the product passes its RNG; tests pass a deterministic one). */
typedef void (*NetShareRandFn) (void *ctx, unsigned char *buf, size_t len);

/* ---- point serialisation (exposed so the verification harness can anchor them) ---------------- */

/* Decompress a 32-byte RFC 8032 point encoding. Rejects non-canonical y (y >= p), points not on the
   curve, and the invalid (x==0, sign==1) encoding. Returns NETSHARE_OK or NETSHARE_ERR_POINT. */
int NetSharePointValidate (const unsigned char enc[NETSHARE_POINT_LEN]);

/* Round-trip helper: decompress then re-compress. Used by the harness against the official RFC 8032
   section 7.1 public keys — a decompression bug that still re-compresses to the same bytes is not
   possible, since the x-coordinate is recomputed from y. */
int NetSharePointRoundTrip (const unsigned char enc[NETSHARE_POINT_LEN],
                            unsigned char out[NETSHARE_POINT_LEN]);

/* ---- credential blob -------------------------------------------------------------------------- */

int NetShareCredSerialise (const unsigned char S[NETSHARE_POINT_LEN],
                           const unsigned char C[NETSHARE_POINT_LEN],
                           unsigned char out[NETSHARE_CRED_LEN]);

int NetShareCredParse (const unsigned char *blob, size_t blobLen,
                       unsigned char S[NETSHARE_POINT_LEN],
                       unsigned char C[NETSHARE_POINT_LEN]);

/* ---- the two operations ------------------------------------------------------------------------ */

/*
 * Enrol against a server whose public S is already known (fetched out of band, or from a prior
 * NetShareRecover peer). Picks a fresh c, computes C = c*G and K = c*S, writes the credential and the
 * share, then wipes c and K. The share is what the caller feeds to RAW_SECRET; the credential is what
 * goes on disk.
 */
int NetShareEnroll (const unsigned char S[NETSHARE_POINT_LEN],
                    NetShareRandFn rand, void *randCtx,
                    unsigned char credOut[NETSHARE_CRED_LEN],
                    unsigned char shareOut[NETSHARE_SHARE_LEN]);

/*
 * Recover the share from a credential by one round trip to the server. Picks a fresh blinding e each
 * call, so two recoveries of the same credential put DIFFERENT values on the wire and the server
 * cannot correlate them.
 *
 * Returns NETSHARE_ERR_TRANSPORT when the server was unreachable — distinct from a wrong answer, so
 * the caller can report "off network" rather than "wrong password".
 */
int NetShareRecover (const unsigned char *cred, size_t credLen,
                     NetShareTransportFn transport, void *transportCtx,
                     NetShareRandFn rand, void *randCtx,
                     unsigned char shareOut[NETSHARE_SHARE_LEN]);

/*
 * The server side of one round: Y = s*X. Exposed so a test (and a reference server) share the exact
 * code path the protocol depends on. 'sSeed' is clamped per RFC 8032 section 5.1.5.
 */
int NetShareServerRespond (const unsigned char sSeed[NETSHARE_SCALAR_LEN],
                           const unsigned char X[NETSHARE_POINT_LEN],
                           unsigned char Y[NETSHARE_POINT_LEN]);

/* S = s*G for a server secret seed — how a server publishes its public key. */
int NetShareServerPublic (const unsigned char sSeed[NETSHARE_SCALAR_LEN],
                          unsigned char S[NETSHARE_POINT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* TC_HEADER_Common_NetShare */
