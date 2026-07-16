# Adding BLAKE2b-512 as an HMAC/PBKDF2 PRF to VeraCrypt 1.26.29

This adds **BLAKE2b-512** as a user-selectable key-derivation PRF (PBKDF2 with HMAC-BLAKE2b),
alongside the existing SHA-512, SHA-256, BLAKE2s-256, Whirlpool, Streebog, and Argon2 options.

## Why BLAKE2b (and why this is a clean example)

VeraCrypt already ships a vetted BLAKE2b implementation in-tree — it's the hash underneath Argon2
(`Crypto/Argon2/src/blake2/blake2b.c`), and `Crypto.h` already `#include`s its header. It was simply
never exposed as a standalone PRF. So this change adds a *real, reviewed* hash to the key-derivation
menu **without importing any new cryptographic primitive** — the additions land exactly on the PRF
extension points. (A second `blake2b.c` was deliberately *not* added: it would collide at link time
with the copy Argon2 already provides, which `Random.c` also uses.)

## What a PRF touches (every dispatch site)

The GUI PRF/hash dropdowns iterate `FIRST_PRF_ID..LAST_PRF_ID` automatically, so no menu-list code
needed changing. Everything else that switches on the hash ID had to get a case, or mount/format/RNG
would silently break:

| File | Change |
|---|---|
| `Common/Crypto.h` | `BLAKE2B` added to the Hash enum; `BLAKE2B_BLOCKSIZE 128` define |
| `Common/Crypto.c` | `Hashes[]` table row (display name `"BLAKE2b"`) |
| `Common/Pkcs5.c` | **HMAC-BLAKE2b + PBKDF2-HMAC-BLAKE2b** implementation; `get_kdf_name` + `get_pkcs5_iteration_count` cases |
| `Common/Pkcs5.h` | prototypes for `hmac_blake2b` / `derive_key_blake2b` |
| `Common/Volumes.c` | PRF case in the **mount** switch and the **format/create-header** switch |
| `Common/EncryptionThreadPool.c` | PRF case in the parallel key-derivation switch (the normal multithreaded mount path) |
| `Common/Random.c` | cases in the RNG entropy-pool's two switches (so BLAKE2b works as the RNG hash) |
| `Common/Tests.c` | known-answer self-tests (see below) |
| `Volume/Pkcs5Kdf.{h,cpp}` | `Pkcs5HmacBlake2b` KDF class + registration (Linux/macOS GUI + CLI). The C++ `Blake2b` *hash* wrapper already existed for Argon2, so `Hash.{h,cpp}` were untouched |

### Design decisions
- **Enum placement:** `BLAKE2B` is added *after* `ARGON2`, so no existing PRF's numeric value shifts
  (a saved RNG-hash preference keeps pointing at the same algorithm). It becomes the new `LAST_PRF_ID`.
- **Compile-time gating:** all new code is under `#ifndef VC_DCS_DISABLE_ARGON2`, matching the
  availability of the BLAKE2b primitive it reuses. That macro is only set for the space-constrained
  DCS/UEFI bootloader — a non-boot PRF wouldn't belong there anyway. BLAKE2b is marked
  System-Encryption = FALSE and is excluded from pre-boot (MBR/GPT) authentication.
- **Naming:** the PRF picker shows **"BLAKE2b-PBKDF2"** (`get_kdf_name`); the benchmark/RNG lists show
  **"BLAKE2b"** (`HashGetName`) — deliberately *distinct* from the `"BLAKE2b-512"` label Argon2 already
  uses internally, so no duplicate rows appear.
- **Iteration count:** `pim == 0 → 500000`, else `15000 + pim*1000` (same as SHA-512/Whirlpool).
- **One real bug avoided:** the BLAKE2s HMAC reuses a 68-byte scratch buffer for the ipad/opad block
  because BLAKE2s's block is 64 bytes. BLAKE2b's block is **128 bytes**, so this port uses a dedicated
  128-byte pad buffer — reusing the smaller buffer would have overflowed the stack.

## Verification

The cryptographic core was validated **before** wiring, against an independent reference
(Python `hashlib.blake2b` + a from-scratch HMAC/PBKDF2), by compiling the *actual* shipped functions
(extracted verbatim from `Common/Pkcs5.c`) against the *real* in-tree `blake2b.c`:

```
[ OK ] BLAKE2b-512("abc")                    (official RFC 7693 vector)
[ OK ] HMAC-BLAKE2b(key,"abc")
[ OK ] PBKDF2-BLAKE2b dklen=4                (partial block)
[ OK ] PBKDF2-BLAKE2b dklen=64 (1 block)
[ OK ] PBKDF2-BLAKE2b dklen=96 (2 blocks)    (exercises the multi-block loop)
[ OK ] PBKDF2-BLAKE2b long-pwd (>128B)       (exercises the key pre-hash branch)
RESULT: ALL VECTORS PASS
```

Reproduce it:
```bash
# from the VeraCrypt src/ directory
gcc -O2 -c Crypto/Argon2/src/blake2/blake2b.c -o blake2b.o \
    -I. -ICrypto/Argon2/include -ICrypto/Argon2/src/blake2
# extract the shipped glue so the test uses the real code, then build the harness:
awk '/HMAC-BLAKE2b-512 and PBKDF2/{f=1} f{print} /endif .. .defined.TC_WINDOWS_BOOT/{if(f)exit}' \
    Common/Pkcs5.c > pkcs5_blake2b_extract.c
gcc -O2 -o run verification/harness.c blake2b.o \
    -DLONGPWD_EXPECT='"7a905d4cce7aefce4e0228a009030c467c56f3e1b9c1c74bec8f4d9f32a37d41c86ce42c3468dd7fe140dbc0b3d8fd93685e4ee3f0a261d6a43d49355908a3f1"'
./run
```

The same two PBKDF2 vectors are baked into `Common/Tests.c`, so VeraCrypt's built-in
**Test Vectors** self-check (Tools → Test Vectors, or the CLI `--test`) now covers BLAKE2b too.

Every modified source file was also syntax-checked; each produces diagnostics **identical** to the
pristine 1.26.29 tree (i.e. the edits introduce no new errors), and `Pkcs5.c` — which holds the bulk of
the new code — compiles cleanly.

## Building

No build-system files changed (no new source file was added), so the normal build works as-is:
- **Linux:** `cd src && make` (needs wxWidgets + PKCS#11 headers as usual; `make NOGUI=1` for the console tool).
- **Windows:** open the VeraCrypt solution and build.
- **macOS:** the standard `build.sh`.

You can apply the changes to a fresh tree instead of using these files:
```bash
cd VeraCrypt/src && patch -p1 < blake2b-prf.patch
```

## ⚠️ Compatibility and security caveats

- **Not interoperable with stock VeraCrypt.** Any volume whose header key you derive with BLAKE2b can
  only be mounted by a build that includes this PRF. Stock VeraCrypt will try its known PRFs, fail to
  find a match, and report a wrong password. This is a private fork of the on-disk format — keep the
  build (and this source) if you make BLAKE2b volumes. It does **not** affect volumes made with the
  existing algorithms.
- BLAKE2b-512 is a well-regarded, conservative choice (BLAKE2 is in RFC 7693; BLAKE2b targets 64-bit
  CPUs). Adding a PRF doesn't weaken existing ones, but the security floor of *any* build is the
  weakest algorithm it will accept — only add primitives you trust, and always validate against
  published vectors (done here).
- This is example/educational work on the open-source VeraCrypt (Apache 2.0 + TrueCrypt License 3.0,
  which permit modification). Review it yourself before trusting real data to it; it has not been
  through VeraCrypt's own audit/QA.

## Possible follow-ups
- **SHA3-512 (Keccak)** as a PRF — this one *would* require importing a Keccak implementation (not in
  the tree), plus the same set of dispatch-site edits shown above.
- A matching test-vector entry and a short doc note in the VeraCrypt user guide.
