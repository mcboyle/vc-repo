/*
 * monotcounter_poc.c — rollback/replay protection via a monotonic counter
 * (docs/ROLLBACK-COUNTER-SPEC.md, IDEAS-BACKLOG.md A).
 *
 * Merkle roots (docs/MERKLE-SPEC.md) and per-sector MACs (docs/PERSECTOR-AUTH-SPEC.md)
 * detect MODIFICATION but not REPLAY of a whole older-but-internally-consistent
 * snapshot. A counter held in tamper-resistant hardware (TPM NV / token / secure
 * element) that ONLY EVER INCREMENTS closes that gap: bind its value into the
 * top-level commit authenticator so an old snapshot carries an old counter and
 * fails against the advanced hardware counter.
 *
 *   otk_c = ChaCha20(commit_key, le64(counter))[0..32]   # counter monotonic ->
 *   tag   = Poly1305(otk_c, state_root)                  #   otk never repeats
 *   mount: read counter C from hardware; recompute tag over the stored state_root
 *   with C; accept iff it matches AND the on-disk counter == C.
 *
 * The counter being monotonic makes it a perfect one-time-MAC nonce (never
 * reused). Drives the REAL in-tree Crypto/chacha256.c + the step-18 Poly1305;
 * monotcounter_reference.py is independent. build_and_verify.sh diffs REF lines.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/chacha256.h"
#include "poly1305.h"

#define NVER 4

static void le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

static void commit_tag (const unsigned char ck[32], uint64_t counter,
                        const unsigned char state_root[32], unsigned char tag[16])
{
	ChaCha256Ctx c; unsigned char nonce[8], zero[32], otk[32];
	le64 (counter, nonce); memset (zero, 0, sizeof zero);
	ChaCha256Init (&c, ck, nonce, 20);
	ChaCha256Encrypt (&c, zero, 32, otk);
	poly1305 (tag, state_root, 32, otk);
	memset (otk, 0, sizeof otk);
}

static int ct_eq16 (const unsigned char *a, const unsigned char *b)
{ unsigned char d = 0; int i; for (i = 0; i < 16; i++) d |= (unsigned char)(a[i] ^ b[i]); return d == 0; }

/* verify: binding AND plain counter-equality must both hold */
static int verify (const unsigned char ck[32], uint64_t hw_counter, uint64_t disk_counter,
                   const unsigned char state_root[32], const unsigned char tag[16])
{
	unsigned char t[16];
	if (disk_counter != hw_counter) return 0;
	commit_tag (ck, hw_counter, state_root, t);
	return ct_eq16 (t, tag);
}

/* modeled TPM-NV / secure-element monotonic counter: increment-only */
typedef struct { uint64_t value; } NvCounter;
static uint64_t nv_increment (NvCounter *nv) { return ++nv->value; }
static int nv_try_set (NvCounter *nv, uint64_t v) { if (v <= nv->value) return 0; nv->value = v; return 1; }

static void state_root (int version, unsigned char out[32])
{ int i; for (i = 0; i < 32; i++) out[i] = (unsigned char) ((version * 97 + i * 13 + 5) & 0xff); }

static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

int main (void)
{
	unsigned char ck[32], sr[NVER][32], tags[NVER][16];
	uint64_t counters[NVER];
	NvCounter nv = { 0 };
	int v;

	for (v = 0; v < 32; v++) ck[v] = (unsigned char) (0x20 + v);

	/* commit v0..v3, each binding the current counter, then advancing it */
	for (v = 0; v < NVER; v++) {
		counters[v] = nv.value;
		state_root (v, sr[v]);
		commit_tag (ck, counters[v], sr[v], tags[v]);
		printf ("REF commit_tag_%d ", v); hex (tags[v], 16); printf ("\n");
		nv_increment (&nv);
	}

	/* fresh accept: each version verifies at its own counter */
	{
		int ok = 1;
		for (v = 0; v < NVER; v++) if (!verify (ck, counters[v], counters[v], sr[v], tags[v])) ok = 0;
		printf ("REF fresh_accept %s\n", ok ? "YES" : "NO");
	}

	/* rollback: v1 snapshot (counter 1) restored, but hardware advanced to 3 */
	printf ("REF rollback_detected %s\n", !verify (ck, 3, counters[1], sr[1], tags[1]) ? "YES" : "NO");

	/* forged on-disk marker to 3: tag1 was bound to counter 1, recompute under 3 fails */
	printf ("REF forged_marker_detected %s\n", !verify (ck, 3, 3, sr[1], tags[1]) ? "YES" : "NO");

	/* tamper the live state_root but keep its tag */
	{
		unsigned char t[32]; memcpy (t, sr[3], 32); t[0] ^= 0x01;
		printf ("REF tamper_state_detected %s\n", !verify (ck, counters[3], counters[3], t, tags[3]) ? "YES" : "NO");
	}

	/* monotonicity: refuse equal / lower; accept a forward jump */
	{
		int mono = (nv_try_set (&nv, nv.value) == 0)
		        && (nv_try_set (&nv, nv.value - 1) == 0)
		        && (nv_try_set (&nv, nv.value + 5) == 1);
		printf ("REF monotonic_enforced %s\n", mono ? "YES" : "NO");
	}

	/* wrong commit key */
	{
		unsigned char wk[32]; memcpy (wk, ck, 32); wk[0] ^= 0x01;
		printf ("REF wrongkey_detected %s\n", !verify (wk, counters[3], counters[3], sr[3], tags[3]) ? "YES" : "NO");
	}

	return 0;
}
