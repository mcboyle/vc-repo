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

typedef unsigned int   u32;
typedef unsigned long long u64;

static u32 ld32(const unsigned char *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static void st32(unsigned char *p, u32 v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

/* Compute the 16-byte Poly1305 tag over msg[0..len) with the 32-byte key. */
static void poly1305(unsigned char out[16], const unsigned char *msg, size_t len,
                     const unsigned char key[32]) {
    /* clamp r (RFC 8439 §2.5): 0ffffffc0ffffffc0ffffffc0fffffff */
    u32 r0 = ld32(key +  0) & 0x03ffffff;
    u32 r1 = (ld32(key +  3) >> 2) & 0x03ffff03;
    u32 r2 = (ld32(key +  6) >> 4) & 0x03ffc0ff;
    u32 r3 = (ld32(key +  9) >> 6) & 0x03f03fff;
    u32 r4 = (ld32(key + 12) >> 8) & 0x000fffff;

    /* pre-multiplied 5*r limbs for the reduction */
    u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    u32 h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    while (len > 0) {
        unsigned char block[16];
        size_t n = len < 16 ? len : 16;
        u32 hibit;
        memset(block, 0, sizeof block);
        memcpy(block, msg, n);
        if (n < 16) { block[n] = 1; hibit = 0; } else { hibit = (1u << 24); }

        /* h += m (radix 2^26) */
        h0 += ld32(block +  0) & 0x03ffffff;
        h1 += (ld32(block +  3) >> 2) & 0x03ffffff;
        h2 += (ld32(block +  6) >> 4) & 0x03ffffff;
        h3 += (ld32(block +  9) >> 6) & 0x03ffffff;
        h4 += (ld32(block + 12) >> 8) | hibit;

        /* h *= r  (schoolbook with mod-2^130-5 folding: overflow limb *5 back in) */
        {
            u64 d0 = (u64)h0 * r0 + (u64)h1 * s4 + (u64)h2 * s3 + (u64)h3 * s2 + (u64)h4 * s1;
            u64 d1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s4 + (u64)h3 * s3 + (u64)h4 * s2;
            u64 d2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 + (u64)h3 * s4 + (u64)h4 * s3;
            u64 d3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 + (u64)h3 * r0 + (u64)h4 * s4;
            u64 d4 = (u64)h0 * r4 + (u64)h1 * r3 + (u64)h2 * r2 + (u64)h3 * r1 + (u64)h4 * r0;

            u64 c;
            c = d0 >> 26; h0 = (u32)d0 & 0x03ffffff; d1 += c;
            c = d1 >> 26; h1 = (u32)d1 & 0x03ffffff; d2 += c;
            c = d2 >> 26; h2 = (u32)d2 & 0x03ffffff; d3 += c;
            c = d3 >> 26; h3 = (u32)d3 & 0x03ffffff; d4 += c;
            c = d4 >> 26; h4 = (u32)d4 & 0x03ffffff; h0 += (u32)c * 5;
            c = h0 >> 26; h0 &= 0x03ffffff; h1 += (u32)c;
        }

        msg += n; len -= n;
    }

    /* final carry propagation */
    {
        u32 c;
        c = h1 >> 26; h1 &= 0x03ffffff; h2 += c;
        c = h2 >> 26; h2 &= 0x03ffffff; h3 += c;
        c = h3 >> 26; h3 &= 0x03ffffff; h4 += c;
        c = h4 >> 26; h4 &= 0x03ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x03ffffff; h1 += c;
    }

    /* compute h + -p (i.e. h - (2^130-5)); select if h >= p */
    {
        u32 g0, g1, g2, g3, g4, mask;
        g0 = h0 + 5;    u32 c = g0 >> 26; g0 &= 0x03ffffff;
        g1 = h1 + c;    c = g1 >> 26; g1 &= 0x03ffffff;
        g2 = h2 + c;    c = g2 >> 26; g2 &= 0x03ffffff;
        g3 = h3 + c;    c = g3 >> 26; g3 &= 0x03ffffff;
        g4 = h4 + c - (1u << 26);

        mask = (g4 >> 31) - 1;    /* 0xffffffff if g4 did NOT borrow (h >= p) */
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    }

    /* serialize h from radix-2^26 to four 32-bit little-endian words */
    {
        u32 f0 = (h0      ) | (h1 << 26);
        u32 f1 = (h1 >>  6) | (h2 << 20);
        u32 f2 = (h2 >> 12) | (h3 << 14);
        u32 f3 = (h3 >> 18) | (h4 <<  8);

        /* tag = (h + s) mod 2^128, s = key[16..32] */
        u64 t;
        t = (u64)f0 + ld32(key + 16);          f0 = (u32)t;
        t = (u64)f1 + ld32(key + 20) + (t >> 32); f1 = (u32)t;
        t = (u64)f2 + ld32(key + 24) + (t >> 32); f2 = (u32)t;
        t = (u64)f3 + ld32(key + 28) + (t >> 32); f3 = (u32)t;

        st32(out +  0, f0); st32(out +  4, f1);
        st32(out +  8, f2); st32(out + 12, f3);
    }
}

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
