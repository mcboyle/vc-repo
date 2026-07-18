/*
 * keyslot_poc.c — proof-of-concept for the multiple-keyslots per-slot key-wrapping crypto.
 *
 * This anchors docs/KEYSLOTS-SPEC.md: it is the one genuinely cryptographic part of the keyslots
 * design (where the storage backends only differ in *where* a slot record is written). A keyslot
 * stores the volume's master-key material wrapped under a key derived from that slot's passphrase:
 *
 *     dk        = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, 72 bytes)
 *     encKey    = dk[0..32),  iv = dk[32..40),  macKey = dk[40..72)
 *     ct        = ChaCha20(encKey, iv) XOR masterKeyMaterial          (confidentiality)
 *     tag       = HMAC-SHA256(macKey, header || ct)                   (authenticity + slot match)
 *     record    = header || ct || tag
 *
 * Opening a slot recomputes dk from the passphrase, verifies the MAC (constant-time) to confirm the
 * passphrase belongs to this slot, then decrypts ct back to the master key. A wrong passphrase fails
 * the MAC and yields nothing. The master key is identical across all slots, so add/rotate/revoke
 * never re-encrypts the volume body.
 *
 * Layer 2 of the two-way convention: links the REAL in-tree Crypto/Sha2.c (SHA-256) and
 * Crypto/chacha256.c (ChaCha20); PBKDF2/HMAC are the standard constructions over that SHA-256.
 * Layer 1 is keyslot_reference.py (independent, over hashlib). build_and_verify.sh diffs the REF
 * lines byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"
#include "Crypto/chacha256.h"

#define SHA256_BLK 64
#define SHA256_DIG 32

/* ---- HMAC-SHA256 over the real Sha2.c ---- */
static void hmac_sha256_poc (const unsigned char *key, int keyLen,
                             const unsigned char *msg, int msgLen,
                             unsigned char out[SHA256_DIG])
{
	sha256_ctx ctx;
	unsigned char k0[SHA256_BLK], pad[SHA256_BLK], inner[SHA256_DIG];
	int i;
	if (keyLen > SHA256_BLK) {
		sha256_begin (&ctx); sha256_hash (key, (unsigned int) keyLen, &ctx); sha256_end (k0, &ctx);
		memset (k0 + SHA256_DIG, 0, SHA256_BLK - SHA256_DIG);
	} else {
		if (keyLen > 0) memcpy (k0, key, keyLen);
		memset (k0 + keyLen, 0, SHA256_BLK - keyLen);
	}
	for (i = 0; i < SHA256_BLK; i++) pad[i] = k0[i] ^ 0x36;
	sha256_begin (&ctx); sha256_hash (pad, SHA256_BLK, &ctx);
	if (msgLen > 0) sha256_hash (msg, (unsigned int) msgLen, &ctx);
	sha256_end (inner, &ctx);
	for (i = 0; i < SHA256_BLK; i++) pad[i] = k0[i] ^ 0x5c;
	sha256_begin (&ctx); sha256_hash (pad, SHA256_BLK, &ctx); sha256_hash (inner, SHA256_DIG, &ctx);
	sha256_end (out, &ctx);
}

/* ---- PBKDF2-HMAC-SHA256 (single-block outputs concatenated; RFC 8018) ---- */
static void pbkdf2_hmac_sha256 (const unsigned char *pw, int pwLen,
                                const unsigned char *salt, int saltLen,
                                uint32_t iterations, unsigned char *out, int outLen)
{
	int blocks = (outLen + SHA256_DIG - 1) / SHA256_DIG;
	int blk, i;
	unsigned char T[SHA256_DIG], U[SHA256_DIG];
	unsigned char saltBlk[128 + 4];
	for (blk = 1; blk <= blocks; blk++) {
		uint32_t j;
		int k;
		memcpy (saltBlk, salt, saltLen);
		saltBlk[saltLen + 0] = (unsigned char) (blk >> 24);
		saltBlk[saltLen + 1] = (unsigned char) (blk >> 16);
		saltBlk[saltLen + 2] = (unsigned char) (blk >> 8);
		saltBlk[saltLen + 3] = (unsigned char) (blk);
		hmac_sha256_poc (pw, pwLen, saltBlk, saltLen + 4, U);
		memcpy (T, U, SHA256_DIG);
		for (j = 1; j < iterations; j++) {
			hmac_sha256_poc (pw, pwLen, U, SHA256_DIG, U);
			for (k = 0; k < SHA256_DIG; k++) T[k] ^= U[k];
		}
		{
			int off = (blk - 1) * SHA256_DIG;
			int n = (outLen - off < SHA256_DIG) ? (outLen - off) : SHA256_DIG;
			for (i = 0; i < n; i++) out[off + i] = T[i];
		}
	}
}

/* ---- slot record ---- */
#define MK_LEN     64    /* master-key material wrapped by the slot (XTS: 32-byte data + 32-byte tweak) */
#define HDR_LEN    8     /* record header: magic[4] ver kdf flags reserved */
#define REC_LEN    (HDR_LEN + MK_LEN + SHA256_DIG)

static int keyslot_wrap (const unsigned char *pw, int pwLen,
                         const unsigned char *salt, int saltLen, uint32_t iters,
                         const unsigned char masterKey[MK_LEN], unsigned char rec[REC_LEN])
{
	unsigned char dk[72];
	ChaCha256Ctx cc;
	unsigned char *ct  = rec + HDR_LEN;
	unsigned char *tag = rec + HDR_LEN + MK_LEN;
	rec[0]='V'; rec[1]='C'; rec[2]='K'; rec[3]='S'; rec[4]=1; rec[5]=1; rec[6]=0; rec[7]=0;
	pbkdf2_hmac_sha256 (pw, pwLen, salt, saltLen, iters, dk, sizeof (dk));
	ChaCha256Init (&cc, dk, dk + 32, 20);           /* encKey=dk[0..32), iv=dk[32..40), ChaCha20 */
	ChaCha256Encrypt (&cc, masterKey, MK_LEN, ct);
	hmac_sha256_poc (dk + 40, 32, rec, HDR_LEN + MK_LEN, tag);   /* macKey=dk[40..72) over header||ct */
	{ volatile unsigned char *p = dk; size_t n = sizeof (dk); while (n--) *p++ = 0; }
	return 0;
}

static int ct_equal (const unsigned char *a, const unsigned char *b, int n)
{ unsigned char d = 0; int i; for (i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0; }

/* returns 1 and fills masterOut on success (passphrase belongs to this slot), 0 on MAC failure */
static int keyslot_unwrap (const unsigned char *pw, int pwLen,
                           const unsigned char *salt, int saltLen, uint32_t iters,
                           const unsigned char rec[REC_LEN], unsigned char masterOut[MK_LEN])
{
	unsigned char dk[72], tag[SHA256_DIG];
	ChaCha256Ctx cc;
	const unsigned char *ct  = rec + HDR_LEN;
	const unsigned char *rtag = rec + HDR_LEN + MK_LEN;
	int ok;
	pbkdf2_hmac_sha256 (pw, pwLen, salt, saltLen, iters, dk, sizeof (dk));
	hmac_sha256_poc (dk + 40, 32, rec, HDR_LEN + MK_LEN, tag);
	ok = ct_equal (tag, rtag, SHA256_DIG);
	if (ok) {
		ChaCha256Init (&cc, dk, dk + 32, 20);
		ChaCha256Encrypt (&cc, ct, MK_LEN, masterOut);   /* stream cipher: decrypt == encrypt */
	}
	{ volatile unsigned char *p = dk; size_t n = sizeof (dk); while (n--) *p++ = 0; }
	return ok;
}

static void print_hex (const char *label, const unsigned char *p, int n)
{ int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

/* ---- FIXED vector, shared with keyslot_reference.py ---- */
#define ITERS 4096
static const char *PW      = "slot-1 passphrase";
static const char *PW_WRONG = "slot-1 passphras3";

int main (void)
{
	unsigned char salt[16], mk[MK_LEN], rec[REC_LEN], back[MK_LEN];
	int i, roundtrip, rejected, wrongMk;

	for (i = 0; i < 16; i++)     salt[i] = (unsigned char) ((i * 11 + 5) & 0xff);
	for (i = 0; i < MK_LEN; i++) mk[i]   = (unsigned char) (0x40 + i);

	keyslot_wrap ((const unsigned char *) PW, (int) strlen (PW), salt, 16, ITERS, mk, rec);
	print_hex ("REF slot_record = ", rec, REC_LEN);

	roundtrip = keyslot_unwrap ((const unsigned char *) PW, (int) strlen (PW), salt, 16, ITERS, rec, back)
	            && memcmp (back, mk, MK_LEN) == 0;
	memset (back, 0, sizeof (back));
	wrongMk = keyslot_unwrap ((const unsigned char *) PW_WRONG, (int) strlen (PW_WRONG), salt, 16, ITERS, rec, back);
	rejected = !wrongMk;

	printf ("REF roundtrip recovers master key = %s\n", roundtrip ? "YES" : "NO");
	printf ("REF wrong passphrase rejected = %s\n", rejected ? "YES" : "NO");
	return 0;
}
