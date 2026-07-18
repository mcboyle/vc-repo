/* poly1305.h — Poly1305 one-shot (RFC 8439), radix-2^26 "donna" 32-bit limbs.
 * Shared by verification/poly1305_poc.c (step [18], proven vs the RFC KATs and an
 * independent python bigint) and verification/keyslot_mac_poc.c (step [20], the
 * keyslot-area MAC consumer). Header-only, all-static; include after <string.h>. */
#ifndef VERIFY_POLY1305_H
#define VERIFY_POLY1305_H
#include <string.h>

typedef unsigned int       poly_u32;
typedef unsigned long long poly_u64;

static poly_u32 poly_ld32(const unsigned char *p) {
    return (poly_u32)p[0] | ((poly_u32)p[1] << 8) | ((poly_u32)p[2] << 16) | ((poly_u32)p[3] << 24);
}
static void poly_st32(unsigned char *p, poly_u32 v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

/* Compute the 16-byte Poly1305 tag over msg[0..len) with the 32-byte one-time key. */
static void poly1305(unsigned char out[16], const unsigned char *msg, size_t len,
                     const unsigned char key[32]) {
    /* clamp r (RFC 8439 §2.5): 0ffffffc0ffffffc0ffffffc0fffffff */
    poly_u32 r0 = poly_ld32(key +  0) & 0x03ffffff;
    poly_u32 r1 = (poly_ld32(key +  3) >> 2) & 0x03ffff03;
    poly_u32 r2 = (poly_ld32(key +  6) >> 4) & 0x03ffc0ff;
    poly_u32 r3 = (poly_ld32(key +  9) >> 6) & 0x03f03fff;
    poly_u32 r4 = (poly_ld32(key + 12) >> 8) & 0x000fffff;

    poly_u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    poly_u32 h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    while (len > 0) {
        unsigned char block[16];
        size_t n = len < 16 ? len : 16;
        poly_u32 hibit;
        memset(block, 0, sizeof block);
        memcpy(block, msg, n);
        if (n < 16) { block[n] = 1; hibit = 0; } else { hibit = (1u << 24); }

        h0 += poly_ld32(block +  0) & 0x03ffffff;
        h1 += (poly_ld32(block +  3) >> 2) & 0x03ffffff;
        h2 += (poly_ld32(block +  6) >> 4) & 0x03ffffff;
        h3 += (poly_ld32(block +  9) >> 6) & 0x03ffffff;
        h4 += (poly_ld32(block + 12) >> 8) | hibit;

        {
            poly_u64 d0 = (poly_u64)h0 * r0 + (poly_u64)h1 * s4 + (poly_u64)h2 * s3 + (poly_u64)h3 * s2 + (poly_u64)h4 * s1;
            poly_u64 d1 = (poly_u64)h0 * r1 + (poly_u64)h1 * r0 + (poly_u64)h2 * s4 + (poly_u64)h3 * s3 + (poly_u64)h4 * s2;
            poly_u64 d2 = (poly_u64)h0 * r2 + (poly_u64)h1 * r1 + (poly_u64)h2 * r0 + (poly_u64)h3 * s4 + (poly_u64)h4 * s3;
            poly_u64 d3 = (poly_u64)h0 * r3 + (poly_u64)h1 * r2 + (poly_u64)h2 * r1 + (poly_u64)h3 * r0 + (poly_u64)h4 * s4;
            poly_u64 d4 = (poly_u64)h0 * r4 + (poly_u64)h1 * r3 + (poly_u64)h2 * r2 + (poly_u64)h3 * r1 + (poly_u64)h4 * r0;

            poly_u64 c;
            c = d0 >> 26; h0 = (poly_u32)d0 & 0x03ffffff; d1 += c;
            c = d1 >> 26; h1 = (poly_u32)d1 & 0x03ffffff; d2 += c;
            c = d2 >> 26; h2 = (poly_u32)d2 & 0x03ffffff; d3 += c;
            c = d3 >> 26; h3 = (poly_u32)d3 & 0x03ffffff; d4 += c;
            c = d4 >> 26; h4 = (poly_u32)d4 & 0x03ffffff; h0 += (poly_u32)c * 5;
            c = h0 >> 26; h0 &= 0x03ffffff; h1 += (poly_u32)c;
        }
        msg += n; len -= n;
    }

    {
        poly_u32 c;
        c = h1 >> 26; h1 &= 0x03ffffff; h2 += c;
        c = h2 >> 26; h2 &= 0x03ffffff; h3 += c;
        c = h3 >> 26; h3 &= 0x03ffffff; h4 += c;
        c = h4 >> 26; h4 &= 0x03ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x03ffffff; h1 += c;
    }

    {
        poly_u32 g0, g1, g2, g3, g4, mask;
        g0 = h0 + 5;    poly_u32 c = g0 >> 26; g0 &= 0x03ffffff;
        g1 = h1 + c;    c = g1 >> 26; g1 &= 0x03ffffff;
        g2 = h2 + c;    c = g2 >> 26; g2 &= 0x03ffffff;
        g3 = h3 + c;    c = g3 >> 26; g3 &= 0x03ffffff;
        g4 = h4 + c - (1u << 26);

        mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    }

    {
        poly_u32 f0 = (h0      ) | (h1 << 26);
        poly_u32 f1 = (h1 >>  6) | (h2 << 20);
        poly_u32 f2 = (h2 >> 12) | (h3 << 14);
        poly_u32 f3 = (h3 >> 18) | (h4 <<  8);

        poly_u64 t;
        t = (poly_u64)f0 + poly_ld32(key + 16);          f0 = (poly_u32)t;
        t = (poly_u64)f1 + poly_ld32(key + 20) + (t >> 32); f1 = (poly_u32)t;
        t = (poly_u64)f2 + poly_ld32(key + 24) + (t >> 32); f2 = (poly_u32)t;
        t = (poly_u64)f3 + poly_ld32(key + 28) + (t >> 32); f3 = (poly_u32)t;

        poly_st32(out +  0, f0); poly_st32(out +  4, f1);
        poly_st32(out +  8, f2); poly_st32(out + 12, f3);
    }
}
#endif /* VERIFY_POLY1305_H */
