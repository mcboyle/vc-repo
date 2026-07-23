/*
 * netshare_poc.c — proof-of-concept for the network-bound share source (Tang/Clevis-style).
 *
 * Anchors docs/NETWORK-SHARE-SPEC.md. It proves the McCallum-Relyea (MR) exchange: a client can
 * recover a provisioning secret K only with the server's help, the server never sees K or the
 * client's long-term value, and a stolen OFFLINE machine (no server) cannot recover K.
 *
 *   server long-term:  s (secret),  S = g^s               (public)
 *   provision:         c (ephemeral), C = g^c (stored),   K = S^c = g^(s c)   (then c,K discarded)
 *   recover:           e (ephemeral), X = C * g^e = g^(c+e)   -> send X to server
 *                      server:        Y = X^s = g^(s(c+e))    (sees only the blinded X, not C or K)
 *                      client:        K = Y * (S^e)^-1 = g^(s(c+e)) * g^(-s e) = g^(s c)
 *   share bytes:       SHA-256(K) — fed to the split-key factor as a Shamir share / RAW_SECRET.
 *
 * The recovery identity holds in ANY group, so the security argument is independent of parameter
 * size; this PoC uses the prime field mod (2^61 - 1) so modular multiply fits __int128 and the code
 * stays small and obviously-correct. The SHIPPING binding uses a real curve (P-256/Ed25519) or a
 * 2048-bit+ MODP group — see the spec. SHA-256 here is the REAL in-tree Crypto/Sha2.c (layer 2);
 * netshare_reference.py is the independent reference (Python bigint + hashlib).
 *
 * Verified properties (printed):
 *   REF lines (byte-for-byte vs python): S, C, K_provision, X, Y, K_recovered, share
 *   [A] recovered K == provisioned K
 *   [B] blinded X != C, and a different ephemeral e still recovers the same K (server obliviousness)
 *   [C] a wrong server key s' does NOT recover K (offline / server-presence binding)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

/* prime field: largest prime below 2^61 (NOT Mersenne, so g=3 has large order); operands < 2^61 so
   products fit in __int128. A real deployment uses a curve (P-256/Ed25519) or a 2048-bit+ MODP group;
   the MR identity is size-independent, so this small field proves the protocol, not the parameters. */
static const uint64_t P = 2305843009213693921ULL;   /* prime, 61-bit */
static const uint64_t G = 3;

static uint64_t mulmod (uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a * b) % P); }

static uint64_t powmod (uint64_t base, uint64_t exp)
{
	uint64_t r = 1; base %= P;
	while (exp) { if (exp & 1) r = mulmod (r, base); base = mulmod (base, base); exp >>= 1; }
	return r;
}

/* modular inverse via Fermat: a^(p-2) mod p (p prime) */
static uint64_t invmod (uint64_t a) { return powmod (a, P - 2); }

static void put_u64_le (unsigned char out[8], uint64_t v)
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char)(v >> (8 * i)); }

/* share = SHA-256(K serialized little-endian), via the real in-tree Sha2.c */
static void share_of (uint64_t K, unsigned char out[32])
{ unsigned char kb[8]; put_u64_le (kb, K); sha256 (out, kb, 8); }

static void print_hex (const char *label, const unsigned char *p, int n)
{ int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }
static void print_u64 (const char *label, uint64_t v) { printf ("%s%020llu\n", label, (unsigned long long) v); }

/* FIXED vector, shared with netshare_reference.py */
static const uint64_t S_SECRET = 1234567890123456789ULL;   /* server long-term secret s */
static const uint64_t C_EPH    = 1111111111111111111ULL;   /* provisioning ephemeral c  */
static const uint64_t E_EPH    =  999999999999999999ULL;   /* recovery ephemeral e      */
static const uint64_t E_EPH2   =  424242424242424242ULL;   /* a different recovery e     */
static const uint64_t S_WRONG  = 5555555555555555555ULL;   /* an attacker's wrong server key */

/* one MR recovery round; returns recovered K */
static uint64_t mr_recover (uint64_t S_pub, uint64_t C_pub, uint64_t s_server, uint64_t e)
{
	uint64_t X = mulmod (C_pub, powmod (G, e));   /* client blinds:  X = C * g^e   */
	uint64_t Y = powmod (X, s_server);            /* server:         Y = X^s       */
	uint64_t Se = powmod (S_pub, e);              /* client unblinds: K = Y*(S^e)^-1 */
	return mulmod (Y, invmod (Se));
}

int main (void)
{
	uint64_t S = powmod (G, S_SECRET);            /* server public */
	uint64_t C = powmod (G, C_EPH);               /* stored at provisioning */
	uint64_t Kprov = powmod (S, C_EPH);           /* K = S^c */
	unsigned char shareProv[32], shareRec[32];

	uint64_t X = mulmod (C, powmod (G, E_EPH));
	uint64_t Y = powmod (X, S_SECRET);
	uint64_t Krec = mr_recover (S, C, S_SECRET, E_EPH);

	print_u64 ("REF S = ", S);
	print_u64 ("REF C = ", C);
	print_u64 ("REF Kprov = ", Kprov);
	print_u64 ("REF X = ", X);
	print_u64 ("REF Y = ", Y);
	print_u64 ("REF Krec = ", Krec);
	share_of (Kprov, shareProv);
	print_hex ("REF share = ", shareProv, 32);

	/* [A] recovered secret equals provisioned secret */
	printf ("[A] recovered K == provisioned K = %s\n", Krec == Kprov ? "YES" : "NO");
	share_of (Krec, shareRec);
	printf ("[A] share matches = %s\n", memcmp (shareProv, shareRec, 32) == 0 ? "YES" : "NO");

	/* [B] blinding: X hides C, and a different ephemeral still recovers the same K */
	{
		uint64_t Krec2 = mr_recover (S, C, S_SECRET, E_EPH2);
		printf ("[B] blinded X != C = %s\n", X != C ? "YES" : "NO");
		printf ("[B] different ephemeral recovers same K = %s\n", Krec2 == Kprov ? "YES" : "NO");
	}

	/* [C] offline / server-presence binding: a wrong server key cannot recover K */
	{
		uint64_t Kwrong = mr_recover (S, C, S_WRONG, E_EPH);
		printf ("[C] wrong server key fails to recover K = %s\n", Kwrong != Kprov ? "YES" : "NO");
	}

	return 0;
}
