/*
 * atomic_header_test.c — atomic, power-loss-resilient header writes (ROI item 50) over the real
 * AtomicHeader module.
 *
 * The core claim: an update writes the inactive A/B copy fully then it becomes newest by generation;
 * a torn write of that copy is always recoverable from the other. This SIMULATES a torn write over an
 * in-memory medium: for every split point k, the in-flight copy is (new[0:k] || old[k:]), and the
 * recovery logic (AtomicHeaderSelect) must ALWAYS return a valid committed header — never garbage,
 * never fail-closed while a good copy exists — and specifically the newest valid one.
 *
 * Two ways: the commit-tag layout is cross-checked byte-for-byte vs atomic_header_reference.py, and
 * the recovery invariant is exercised across all torn offsets. Negative controls: corrupting the
 * chosen (newest) copy forces fallback to the other; corrupting BOTH copies fails closed (-1); true
 * power-loss recovery needs real hardware and is out of scope (documented).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/AtomicHeader.h"

#define HLEN 512
#define CSZ  (HLEN + ATOMIC_HEADER_OVERHEAD)   /* 552 */

static int all_pass = 1;
static void check (const char *n, int ok) { printf("  %-58s %s\n", n, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }
static void mkheader (unsigned char *h, unsigned char seed) { int i; for (i=0;i<HLEN;i++) h[i]=(unsigned char)(seed + i*31u); }
static void hexline (const char *tag, const unsigned char *b, int n){ int i; printf("%s ",tag); for(i=0;i<n;i++) printf("%02x",b[i]); printf("\n"); }

int main (void)
{
	unsigned char K[32];
	unsigned char H1[HLEN], H2[HLEN], H3[HLEN];
	unsigned char slotAold[CSZ], slotB[CSZ], newA[CSZ], tornA[CSZ], got[HLEN];
	uint64 g; int i, k, chosen;

	for (i=0;i<32;i++) K[i]=(unsigned char)(0x11*i+7);
	mkheader(H1, 0x10); mkheader(H2, 0x55); mkheader(H3, 0xC3);

	/* prior committed state: A=gen1/H1, B=gen2/H2 (B newest) */
	AtomicHeaderBuild(K, H1, HLEN, 1, slotAold);
	AtomicHeaderBuild(K, H2, HLEN, 2, slotB);

	printf("[baseline select + next-gen]\n");
	check("both copies valid", AtomicHeaderValid(K,slotAold,HLEN) && AtomicHeaderValid(K,slotB,HLEN));
	chosen = AtomicHeaderSelect(K, slotAold, slotB, HLEN, got, &g);
	check("select picks newest (B, gen 2, H2)", chosen==1 && g==2 && !memcmp(got,H2,HLEN));
	check("next gen = 3", AtomicHeaderNextGen(K,slotAold,slotB,HLEN)==3);

	/* commit-tag KAT inputs for python (copy B: header H2, gen 2) */
	hexline("K", K, 32); hexline("HEADER", H2, HLEN); printf("GEN 2\n");
	hexline("CTAG", slotB + HLEN + ATOMIC_HEADER_GEN_SIZE, ATOMIC_HEADER_TAG_SIZE);

	printf("[torn-write simulation: update to gen 3 / H3 into copy A, crash at every offset]\n");
	AtomicHeaderBuild(K, H3, HLEN, 3, newA);
	{
		int recovered_new=0, recovered_prev=0, bad=0;
		for (k=0; k<=CSZ; k++) {
			/* torn copy = first k bytes of the new write, remaining bytes are the old copy */
			memcpy(tornA, newA, (size_t)k);
			if (k < CSZ) memcpy(tornA+k, slotAold+k, (size_t)(CSZ-k));
			chosen = AtomicHeaderSelect(K, tornA, slotB, HLEN, got, &g);
			if (chosen < 0) { bad++; continue; }               /* must never fail while B is intact */
			if (AtomicHeaderValid(K,tornA,HLEN) && AtomicHeaderGen(tornA,HLEN)==3) {
				/* A fully/coherently written as gen3 -> newest -> H3 */
				if (!(g==3 && !memcmp(got,H3,HLEN))) bad++; else recovered_new++;
			} else {
				/* A torn (or old gen1) -> fall back to newest valid = B gen2 H2 */
				if (!(g==2 && !memcmp(got,H2,HLEN))) bad++; else recovered_prev++;
			}
		}
		printf("    offsets=%d  recovered_new(H3)=%d  recovered_prev(H2)=%d  bad=%d\n",
		       CSZ+1, recovered_new, recovered_prev, bad);
		check("every torn offset recovers a valid committed header (never garbage/fail)", bad==0);
		check("the fully-written offset (k=CSZ) recovers the new gen-3 header", recovered_new>=1);
		check("torn offsets fall back to the previous committed header", recovered_prev>=1);
	}

	printf("[negative controls]\n");
	/* state: A=gen3/H3 valid, B=gen2/H2 valid -> select picks A(H3) */
	memcpy(tornA, newA, CSZ);
	chosen = AtomicHeaderSelect(K, tornA, slotB, HLEN, got, &g);
	check("with both valid, newest (A, gen3, H3) is chosen", chosen==0 && g==3 && !memcmp(got,H3,HLEN));
	/* corrupt the CHOSEN copy's commit tag -> must fall back to B */
	tornA[HLEN + ATOMIC_HEADER_GEN_SIZE + 4] ^= 0x01;
	chosen = AtomicHeaderSelect(K, tornA, slotB, HLEN, got, &g);
	check("corrupt chosen copy -> fall back to older valid (B, gen2, H2)", chosen==1 && g==2 && !memcmp(got,H2,HLEN));
	/* corrupt BOTH copies -> fail closed */
	{
		unsigned char badB[CSZ]; memcpy(badB, slotB, CSZ); badB[HLEN + ATOMIC_HEADER_GEN_SIZE + 1] ^= 0x01;
		check("corrupt BOTH copies -> fail closed (-1), refuse to mount", AtomicHeaderSelect(K, tornA, badB, HLEN, got, &g)==-1);
	}

	printf("\n%s\n", all_pass ? "PASS: A/B+gen+commit-tag; torn writes always recover a committed header; both-bad fails closed"
	                          : "FAIL: atomic header");
	return all_pass ? 0 : 1;
}
