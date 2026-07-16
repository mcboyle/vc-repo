# Adding SHA3-512 (FIPS 202) as an HMAC/PBKDF2 PRF to VeraCrypt 1.26.29

This adds **SHA3-512** (Keccak, FIPS 202) as a user-selectable key-derivation PRF (PBKDF2 with
HMAC-SHA3-512), alongside SHA-512, SHA-256, BLAKE2s-256, Whirlpool, Streebog, Argon2, and BLAKE2b.

Unlike the earlier BLAKE2b work — which reused a primitive VeraCrypt already shipped for Argon2 —
SHA-3 is **not** present anywhere in the tree, so this change also **imports a Keccak implementation**
and **wires it into the build system** on every platform. That, plus a new C++ hash wrapper, is the
extra surface a genuinely new primitive requires.

## The imported primitive (`Crypto/Sha3.c` / `Crypto/Sha3.h`)

A compact, endian-portable **FIPS 202** implementation written from scratch (public domain / CC0):

- Keccak-f[1600], 24 rounds, standard round-constant / rotation / pi tables.
- SHA3-512 parameters: rate r = 72 bytes (576 bits), capacity 1024 bits, digest 64 bytes.
- **Correct SHA-3 domain-separated padding** (`0x06 … 0x80`) — *not* legacy Keccak (`0x01`), which is
  the single most common way a "Keccak" implementation silently produces the wrong digest.
- Absorb/squeeze use explicit little-endian **lane arithmetic** (shift/mask), never a raw
  reinterpretation of the 64-bit state as bytes, so the code is correct on big- and little-endian hosts.

It was validated against the official NIST vectors **before** being wired to anything (see Verification).

Why from-scratch rather than dropping in `tiny_sha3`/XKCP: it removes any endianness ambiguity, keeps
the licensing unambiguous, and — because SHA3-512 has comprehensive published KATs — correctness is
provable by test. The implementation is small and deliberately readable for review.

## What a PRF touches (same dispatch sites as before)

The GUI PRF/hash dropdowns iterate `FIRST_PRF_ID..LAST_PRF_ID`, so no menu-list code changed. Every
site that switches on the hash ID got a case:

| File | Change |
|---|---|
| `Crypto/Sha3.c`, `Crypto/Sha3.h` | **new** — the Keccak/SHA3-512 primitive |
| `Common/Crypto.h` | `SHA3_512` enum value (independent of Argon2); `#include "Sha3.h"` |
| `Common/Crypto.c` | `Hashes[]` table row (display name `"SHA3-512"`) |
| `Common/Pkcs5.c` | **HMAC-SHA3-512 + PBKDF2**; `get_kdf_name` + `get_pkcs5_iteration_count` cases |
| `Common/Pkcs5.h` | prototypes for `hmac_sha3_512` / `derive_key_sha3_512` |
| `Common/Volumes.c` | PRF case in the **mount** switch and the **format** switch |
| `Common/EncryptionThreadPool.c` | PRF case in the parallel key-derivation switch |
| `Common/Random.c` | cases in the RNG entropy-pool's **three** switches (size, hash, cleanup) |
| `Common/Tests.c` | known-answer self-tests |
| `Volume/Hash.{h,cpp}` | **new** `Sha3_512` C++ hash wrapper + registration (SHA-3 had none) |
| `Volume/Pkcs5Kdf.{h,cpp}` | `Pkcs5HmacSha3_512` KDF class + registration |
| `Volume/Volume.make` | add `../Crypto/Sha3.o` (Linux/macOS build) |
| `Crypto/Crypto.vcxproj`, `Crypto/Crypto.vcxproj.filters` | add `Sha3.c` / `Sha3.h` (Windows build) |

### Design decisions
- **Independent of Argon2.** `SHA3_512` is placed *after* the `#ifndef VC_DCS_DISABLE_ARGON2` block, so
  it exists in every non-boot configuration (BLAKE2b, by contrast, is gated with Argon2 because it
  borrows Argon2's primitive). No existing PRF's numeric value shifts; `SHA3_512` becomes `LAST_PRF_ID`.
- **Gating** mirrors the other in-tree hashes (blake2s / whirlpool / streebog): the enum value is
  unconditional; the `Hashes[]` row and every dispatch case are under `#ifndef WOLFCRYPT_BACKEND`; the
  primitive is compiled in the default (non-wolfCrypt) build. It is a non-boot PRF
  (SystemEncryption = FALSE, excluded from pre-boot/MBR/GPT authentication).
- **Names:** PRF picker shows **"SHA3-512-PBKDF2"** (`get_kdf_name`); benchmark / RNG lists show
  **"SHA3-512"** (`HashGetName`). C++ KDF name is **"HMAC-SHA3-512"**.
- **Iteration count** (non-boot): `pim == 0 → 500000`, else `15000 + pim*1000` (same as SHA-512).
- **HMAC block size = 72 bytes** (SHA3-512's rate). As with BLAKE2b, this exceeds the small
  `PKCS5_SALT_SIZE + 4` scratch buffer, so a dedicated 72-byte pad buffer is used for the ipad/opad
  block — reusing the smaller buffer would overflow the stack.

### One bug fixed in the earlier BLAKE2b work
While wiring SHA-3's RNG cases I found that the random-pool **cleanup** switch in `Common/Random.c` had
no `BLAKE2B` case, even though BLAKE2b is selectable as the pool hash. Selecting BLAKE2b for random-pool
enrichment would therefore have hit `TC_THROW_FATAL_EXCEPTION` during context cleanup. This changeset
adds the missing `BLAKE2B` cleanup case as well as the `SHA3_512` one. If you already applied the
BLAKE2b patch, this fix rides along in the SHA-3 delta (it is the only BLAKE2b-touching line in it).

## Verification

Two independent references, both compiling the **actual shipped code**:

**1. Primitive vs NIST FIPS 202** (`verification/sha3_primitive_test.c`, builds the real `Crypto/Sha3.c`):
```
[ OK ] SHA3-512("")                 (NIST)
[ OK ] SHA3-512("abc")              (NIST)
[ OK ] SHA3-512(0x00..0xC7, 200 B)  (multi-block absorption)
[ OK ] SHA3-512(len=71 / 72 / 73)   (rate-1 / rate / rate+1 — padding boundaries)
PRIMITIVE: ALL FIPS-202 VECTORS PASS
```

**2. HMAC/PBKDF2 vs Python `hashlib`/`hmac`** (`verification/hmac_pbkdf2_test.c`, includes the
`hmac_sha3_512` / `derive_key_sha3_512` extracted verbatim from `Common/Pkcs5.c`):
```
[ OK ] HMAC-SHA3-512(key,"abc")
[ OK ] PBKDF2-SHA3-512 dklen=4                 (partial block)
[ OK ] PBKDF2-SHA3-512 dklen=64 (1 block)
[ OK ] PBKDF2-SHA3-512 dklen=96 (2 blocks)     (multi-block loop)
[ OK ] PBKDF2-SHA3-512 long-pwd (>72 B)        (key pre-hash branch)
RESULT: ALL SHA3 HMAC/PBKDF2 VECTORS PASS
```
The same dklen=4 and dklen=96 vectors are baked into `Common/Tests.c`, so VeraCrypt's built-in
**Test Vectors** self-check now covers SHA3-512.

To reproduce (from the VeraCrypt `src/` directory, with the patch applied):
```bash
# 1) primitive
gcc -O2 -Iverification -ICrypto verification/sha3_primitive_test.c Crypto/Sha3.c -o t && ./t
    # (verification/Tcdefs-stub.h stands in for Common/Tcdefs.h so the test builds standalone;
    #  Sha3.c itself compiles unmodified against the real header in a full build.)
# 2) HMAC/PBKDF2 (extract the shipped glue, then build)
awk '/HMAC-SHA3-512 and PBKDF2/{f=1} f{print} /endif .. TC_WINDOWS_BOOT .SHA3-512./{if(f)exit}' \
    Common/Pkcs5.c > verification/pkcs5_sha3_extract.c
gcc -O2 -Iverification -ICrypto verification/hmac_pbkdf2_test.c Crypto/Sha3.c -o t2 && ./t2
```

**3. Real C++ classes, compiled and linked end-to-end** (`verification/cpp_integration_test.cpp` +
`build_cpp_integration_test.sh`). Tests 1 and 2 exercise the C functions; this one builds the *actual*
`VeraCrypt::Sha3_512` and `VeraCrypt::Pkcs5HmacSha3_512` classes — the ones a Linux/macOS binary uses —
by compiling ~20 real object files (all hash primitives, the real `Common/Pkcs5.c`, the C++
`Hash.cpp`/`Pkcs5Kdf.cpp`, `VolumePassword`, the Platform serialization layer, CPU detection) and
linking them into a running program:
```
[ OK ] C++ Sha3_512("abc") via ProcessData/GetDigest
[ OK ] Sha3_512 GetBlockSize=72 GetDigestSize=64 GetName=SHA3-512
[ OK ] C++ Pkcs5HmacSha3_512 PBKDF2 dklen=64
[ OK ] Pkcs5HmacSha3_512 GetName=HMAC-SHA3-512 GetIterationCount(pim=0)=500000
RESULT: ALL C++ CLASS-LEVEL VECTORS PASS
```
This drives the full real path — `VolumePassword` → `Pkcs5HmacSha3_512::DeriveKey` →
`derive_key_sha3_512` (real `Pkcs5.o`) → `sha3_512_*` (real `Sha3.o`) — through the real
`Buffer`/`BufferPtr` abstraction, and confirms every object links ABI-clean. The only link-time stubs
(`cpp_test_linkstubs.c`) stand in for sibling-algorithm SIMD/asm/Argon2 entrypoints the SHA3 test never
calls; the entire SHA3 path is real. Run it with `sh verification/build_cpp_integration_test.sh` from
the patched `src/` directory.

Every modified source file was additionally compiled: `Crypto/Sha3.c`, `Common/Pkcs5.c`,
`Volume/Hash.cpp`, and `Volume/Pkcs5Kdf.cpp` all compile **cleanly** to real objects against the real
headers; the Windows-only files (`Crypto.c`, `Volumes.c`, `Random.c`, `EncryptionThreadPool.c`,
`Tests.c`) produce diagnostics **identical** to the pristine 1.26.29 tree (no new errors), and every
`#if/#endif` was verified balanced and correctly nested.

## Building

- **Linux:** `cd src && make` (needs wxWidgets + PKCS#11 as usual; `make NOGUI=1` for the console tool).
  `Sha3.o` is added to the default (`ENABLE_WOLFCRYPT=0`) object list.
- **Windows:** open the VeraCrypt solution and build; `Sha3.c`/`Sha3.h` are in `Crypto.vcxproj`.
- **macOS:** the standard `build.sh`.

## Applying the patches

Two patches are included — use whichever matches your starting tree:
```bash
# If you already applied the BLAKE2b patch (SHA-3 delta only):
cd VeraCrypt/src && patch -p1 < sha3-only-on-blake2b.patch

# If starting from a clean 1.26.29 tree (adds BOTH BLAKE2b and SHA3-512):
cd VeraCrypt/src && patch -p1 < sha3-prf.patch
```
Both were dry-run verified to apply cleanly. The `src/` folder in this package is the full modified
tree (both PRFs) if you prefer to drop files in directly.

## ⚠️ Compatibility and security caveats

- **Not interoperable with stock VeraCrypt.** A volume whose header key you derive with SHA3-512 opens
  only in a build that includes this PRF; stock VeraCrypt will report a wrong password. Existing-algorithm
  volumes are unaffected. Keep the build (and source) if you make SHA3-512 volumes.
- SHA3-512 is a conservative, standardized choice (FIPS 202). Adding a PRF never weakens the existing
  ones, but the security floor of any build is the weakest PRF it will accept — only add primitives you
  trust, and always validate against published vectors (done here).
- Educational work on the open-source VeraCrypt (Apache 2.0 + TrueCrypt License 3.0, which permit
  modification). It has not been through VeraCrypt's own audit/QA — review before trusting real data.
  The imported primitive in particular is a fresh implementation; although it matches the NIST vectors
  byte-for-byte, a production fork might prefer a long-deployed implementation (e.g. XKCP) or wiring to
  the wolfCrypt backend's SHA-3.
