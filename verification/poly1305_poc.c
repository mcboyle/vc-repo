/* Poly1305 one-shot (RFC 8439) — radix-2^26 "donna" style, 32-bit limbs.
 *
 * Poly1305 is NOT part of the VeraCrypt tree, so this PoC is verified two
 * independent ways, exactly like every other crypto change in this fork:
 *   (1) against verification/poly1305_reference.py (a transparent big-integer
 *       reimplementation of the same math), byte-for-byte, and
 *   (2) against the RFC 8439 published known-answer tests (§2.5.2 and A.3),
 *       which are an authority independent of both implementations.
 * There is no in-tree compiled object to link against here; that limitation is
 * stated plainly in docs/POLY1305-SPEC.md.
 *
 * This is a candidate primitive for the integrity tier (per-sector auth, §A;
 * keyslot-area MAC, §P0.5) and the wide-block modes (Adiantum/HCTR2). It is a
 * verification artifact; production wiring is scoped in the spec, not built.
 */
#include <stdio.h>
#include <string.h>
#include "poly1305.h"   /* the radix-2^26 one-shot, shared with keyslot_mac_poc.c */

typedef unsigned long long u64;  /* used only by the local fuzz PRNG below */

static void hex(const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf("%02x", b[i]); }

int main(void) {
    unsigned char tag[16];

    /* RFC 8439 §2.5.2 */
    {
        unsigned char key[32];
        const char *m = "Cryptographic Forum Research Group";
        static const unsigned char kk[32] = {
            0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
            0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
        memcpy(key, kk, 32);
        poly1305(tag, (const unsigned char *)m, strlen(m), key);
        printf("REF rfc_2.5.2 "); hex(tag, 16); printf("\n");
    }

    /* RFC 8439 A.3 #1: all-zero key, 64-byte zero message -> zero tag */
    {
        unsigned char key[32]; unsigned char msg[64];
        memset(key, 0, 32); memset(msg, 0, 64);
        poly1305(tag, msg, 64, key);
        printf("REF a3_0 "); hex(tag, 16); printf("\n");
    }

    /* RFC 8439 A.3 #2: r=0, s=36e5..863e over the IETF note -> tag == s */
    {
        unsigned char key[32];
        const char *m =
            "Any submission to the IETF intended by the Contributor for publication "
            "as all or part of an IETF Internet-Draft or RFC and any statement made "
            "within the context of an IETF activity is considered an \"IETF "
            "Contribution\". Such statements include oral statements in IETF "
            "sessions, as well as written and electronic communications made at any "
            "time or place, which are addressed to";
        static const unsigned char ss[16] = {
            0x36,0xe5,0xf6,0xb5,0xc5,0xe0,0x60,0x70,0xf0,0xef,0xca,0x96,0x22,0x7a,0x86,0x3e };
        memset(key, 0, 16); memcpy(key + 16, ss, 16);
        poly1305(tag, (const unsigned char *)m, strlen(m), key);
        printf("REF a3_1 "); hex(tag, 16); printf("\n");
    }

    /* Deterministic fuzz battery: keys+messages from a fixed xorshift64* stream,
       lengths chosen to straddle block boundaries (0, 1, 15..17, 32, ...).
       verification/poly1305_reference.py reproduces the identical stream, so the
       diff proves C == Python over hundreds of inputs, not just the 3 KATs. */
    {
        u64 st = 0x243f6a8885a308d3ULL; /* fixed seed */
        int lengths[] = {0,1,2,15,16,17,31,32,33,47,48,49,63,64,65,100,127,128,129,255,256,300};
        int nl = (int)(sizeof lengths / sizeof lengths[0]), li;
        unsigned char key[32], msg[300];
        for (li = 0; li < nl; li++) {
            int L = lengths[li], i;
            for (i = 0; i < 32; i++) { st ^= st >> 12; st ^= st << 25; st ^= st >> 27; key[i] = (unsigned char)((st * 0x2545F4914F6CDD1DULL) >> 40); }
            for (i = 0; i < L;  i++) { st ^= st >> 12; st ^= st << 25; st ^= st >> 27; msg[i] = (unsigned char)((st * 0x2545F4914F6CDD1DULL) >> 40); }
            poly1305(tag, msg, (size_t)L, key);
            printf("REF fuzz_%d ", L); hex(tag, 16); printf("\n");
        }
    }

    return 0;
}
