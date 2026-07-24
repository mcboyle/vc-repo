# Constant-time AES-256 (T2-3)

**Status: PROVEN as a PoC (suite step `[87]`); promotion into `src/` as a selectable cipher is the
follow-up.** Required by the wide-block roadmap: on non-AES-NI hardware the **Adiantum** branch still
invokes AES-256 on **one 16-byte block per sector** (D-4). That call must be **constant-time** — a
table-based AES leaks the key through cache timing (measured LEAKY at ct step A1 / `docs/CT-HARDENING-R17.md`)
— but it does **not** need to be fast (one block per sector, A-2). This spec records the construction and
its proof.

## Construction — reuse the proven GF(2⁸) arithmetic, no new primitive

The only place AES indexes memory with secret-derived data is the **S-box** (a 256-byte table). Replace
just that with arithmetic, using the project's **already-proven** constant-time GF(2⁸) core (Shamir.c's
branchless, table-free `gf_mul`/`gf_inv` — dudect-screened and ctgrind-clean at step `[41]`):

```
S(x) = affine( x⁻¹ in GF(2⁸) )
     = A(gf_inv(x)),   A(b) = b ⊕ rotl8(b,1) ⊕ rotl8(b,2) ⊕ rotl8(b,3) ⊕ rotl8(b,4) ⊕ 0x63
```

`gf_inv(x) = x²⁵⁴` is the AES-field inverse (Shamir uses the same field, reduction `0x1b`). Every other
AES step is already table-free / branch-free:

| step | constant-time because |
|---|---|
| SubBytes / key-schedule SubWord | `S(x) = A(gf_inv(x))` — arithmetic, no table, no branch |
| ShiftRows | a **fixed** byte permutation (independent of data) |
| MixColumns | masked branch-free `xtime`: `(a<<1) ⊕ (0x1b & (0−(a>>7)))` — same masking idiom as `gf_mul` |
| AddRoundKey | XOR |

So there is **no secret-dependent memory index or branch anywhere** in the cipher or its key schedule.

## Verification (`verification/ctaes_poc.c`, step `[87]`)

Proven the two ways the other cipher PoCs use — an **official KAT** plus the **real in-tree object** —
with the constant-time property demonstrated directly:

1. **Official FIPS-197 Appendix C.3 AES-256 vector** reproduced byte-exact: key `000102…1f`, input
   `00112233…ff` → **`8ea2b7ca516745bfeafc49904b496089`**.
2. **Byte-for-byte agreement with the real in-tree Gladman AES** (`Aescrypt`/`Aeskey`/`Aestab`) over
   **4096 random keys/blocks** (0 mismatches), plus the S-box shown bijective over all 256 inputs with
   correct anchors (`S(0x00)=0x63`, `S(0x53)=0xed`, `S(0xff)=0x16`).
3. **ctgrind CLEAN** — built `-DCT_USE_VALGRIND`, the key + plaintext are poisoned
   (`VALGRIND_MAKE_MEM_UNDEFINED`) and the whole cipher runs under memcheck with **0 secret-dependent
   branches/indexes** (contrast: table AES flags under the same test). This is the constant-time proof,
   not just an argument; it runs in the suite when valgrind is present and is a CI/real-build leg
   otherwise.

## Honest notes

- **Speed.** `gf_inv` as `x²⁵⁴` (square-and-multiply) per S-box byte is slow — deliberately. This is the
  once-per-sector Adiantum AES call, so "exists and is constant-time" is the bar; a faster bitsliced
  variant (Boyar–Peralta S-box / BearSSL-style) can replace the S-box later behind the same interface
  without changing the format.
- **Promotion.** This PoC is standalone; wiring it as a selectable AES implementation in `src/` (so the
  Adiantum `EncryptionMode` picks it on non-AES-NI hardware) is the follow-up, and unblocks **T2-4**
  (HCTR2/Adiantum promotion), which in turn unblocks the T1-1 v2 mount/create call sites
  (`docs/V2-FORMAT-SPEC.md`).
- **Scope.** Confidentiality-side hardening of the block cipher; no format or deniability impact.

## Cross-references

`docs/CT-HARDENING-R17.md` (the table-AES-is-leaky measurement this answers) · `docs/ADIANTUM-SPEC.md`
(the once-per-sector AES call) · `src/Common/Shamir.c` (the proven `gf_mul`/`gf_inv`) · `ROADMAP.md`
BACKLOG "Constant-time AES".
