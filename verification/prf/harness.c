/* Standalone validation harness for the BLAKE2b PRF added to VeraCrypt.
   Compiles the ACTUAL functions extracted from Common/Pkcs5.c against the
   REAL in-tree blake2b primitive (blake2b.o), and checks them against
   independently-derived (Python hashlib/hmac/pbkdf2) test vectors. */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* --- Minimal shim standing in for VeraCrypt's Tcdefs/Crypto.h/Endian.h --- */
typedef uint32_t uint32;

#define PKCS5_SALT_SIZE      64
#define BLAKE2B_BLOCKSIZE    128
#define BLAKE2B_DIGESTSIZE   64

static uint32_t bswap_32(uint32_t x) {
    return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8) |
           ((x & 0x00FF0000u) >> 8)  | ((x & 0xFF000000u) >> 24);
}
static void burn(void *p, size_t n) { volatile unsigned char *q = (volatile unsigned char*)p; while (n--) *q++ = 0; }

/* blake2b.c (Argon2) calls this Argon2 helper; provide a secure-zero stub for the harness. */
void clear_internal_memory(void *v, size_t n);
void clear_internal_memory(void *v, size_t n) { if (v) memset(v, 0, n); }

/* Exact ABI of the in-tree blake2b (from Crypto/Argon2/src/blake2/blake2b.h) */
#define BLAKE2B_BLOCKBYTES 128
typedef struct __blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    uint8_t  last_node;
} blake2b_state;
int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

/* Pull in the shipped functions verbatim */
#include "pkcs5_blake2b_extract.c"

static int check(const char *label, const unsigned char *got, const char *hex) {
    /* hex -> bytes */
    size_t n = strlen(hex) / 2, i; unsigned char exp[256];
    for (i = 0; i < n; i++) { unsigned v; sscanf(hex + 2*i, "%2x", &v); exp[i] = (unsigned char)v; }
    if (memcmp(got, exp, n) != 0) {
        printf("  [FAIL] %s\n    got: ", label);
        for (i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n    exp: %s\n", hex);
        return 1;
    }
    printf("  [ OK ] %s\n", label);
    return 0;
}

int main(void) {
    int fails = 0;
    unsigned char out[256];

    printf("BLAKE2b primitive + HMAC/PBKDF2 glue validation\n");

    /* 1) Raw BLAKE2b-512("abc") — official RFC 7693 vector */
    { blake2b_state s; blake2b_init(&s, 64); blake2b_update(&s, "abc", 3); blake2b_final(&s, out, 64);
      fails += check("BLAKE2b-512(\"abc\")",
        out, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
             "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"); }

    /* 2) HMAC-BLAKE2b(key="key", "abc") — cross-checked with python hmac */
    { unsigned char d[64]; memcpy(d, "abc", 3);
      hmac_blake2b((unsigned char*)"key", 3, d, 3);
      fails += check("HMAC-BLAKE2b(key,\"abc\")",
        d, "05cc4815438d5cfe68fff446b8df57828cc96189de4b4e928e3f06d815d64e5b"
           "c15124a02ffd39859b3e2476da03bc0235ca86df623af2a5631779809e9fd04a"); }

    /* 3) PBKDF2-HMAC-BLAKE2b, VeraCrypt test inputs: pwd="password", salt=12 34 56 78, iters=5 */
    { unsigned char salt[4] = {0x12,0x34,0x56,0x78};
      derive_key_blake2b((unsigned char*)"password", 8, salt, 4, 5, out, 4, (volatile long*)0);
      fails += check("PBKDF2-BLAKE2b dklen=4", out, "9778a47f");

      derive_key_blake2b((unsigned char*)"password", 8, salt, 4, 5, out, 64, (volatile long*)0);
      fails += check("PBKDF2-BLAKE2b dklen=64 (1 block)", out,
        "9778a47faa44cf2d2d0580687855ffc22c78ba94122e70c03e86dc3bfdea3123"
        "715a2aa24f871ac1d458d464df9aed1c2d52f29dca3a869aeaba02db21b92dbd");

      derive_key_blake2b((unsigned char*)"password", 8, salt, 4, 5, out, 96, (volatile long*)0);
      fails += check("PBKDF2-BLAKE2b dklen=96 (2 blocks)", out,
        "9778a47faa44cf2d2d0580687855ffc22c78ba94122e70c03e86dc3bfdea3123"
        "715a2aa24f871ac1d458d464df9aed1c2d52f29dca3a869aeaba02db21b92dbd"
        "ca60dd69a56f97c7efa70a75643b1fe162b0670f0c550320e423cb76e413c705"); }

    /* 4) Long-password path (> 128-byte block => pre-hashed), cross-checked below */
    { unsigned char longpwd[200]; unsigned char salt[4] = {0x12,0x34,0x56,0x78}; int i;
      for (i = 0; i < 200; i++) longpwd[i] = (unsigned char)i;
      derive_key_blake2b(longpwd, 200, salt, 4, 3, out, 64, (volatile long*)0);
      fails += check("PBKDF2-BLAKE2b long-pwd (>block) dklen=64", out, LONGPWD_EXPECT); }

    printf(fails ? "\nRESULT: %d FAILURE(S)\n" : "\nRESULT: ALL VECTORS PASS\n", fails);
    return fails ? 1 : 0;
}
