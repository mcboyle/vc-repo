# HKF v2 mixing (Rank-1) — HKDF derivation with a version-try loop

*Status: core primitive + version-try loop built and verified in-sandbox (suite step `[80]`); the
mount/create integration across both derivation code paths is the remaining real-build wiring.*

This is the addendum's **Rank-1** remediation: replace the CRC-32 keyfile-pool mixing seam
(`HKFMixResponseIntoPassword`, "v1") with an HKDF-SHA256 derivation ("v2"). Gated behind
`VC_ENABLE_HKF_MIX_V2`; default builds stay byte-for-byte stock.

## Why

The v1 seam folds four CRC state bytes per input byte into a 128-byte pool with modular addition. For
≤32-byte inputs that is provably injective (the security-analysis report), but a raw 33–64-byte Shamir
`RAW_SECRET` wraps the pool and injectivity is unproven (`docs/CRC-SEAM-ADDENDUM.md §3`). §6 conditioning
and Rec 1 salt-binding both keep inputs ≤32 bytes, but they patch the *precondition*; Rank-1 removes the
concern *structurally* by using a PRF combine that preserves entropy for any input length.

## Construction

```
password[0..128) = HKDF-SHA256(salt = <empty>,
                               IKM  = original-password || response,
                               info = "VeraCrypt/HKF/mix/v2",
                               L    = 128)
*password_len = 128
```

- **HKDF-Extract** `PRK = HMAC-SHA256(0^32, password || response)` then **HKDF-Expand** to 128 bytes.
- HKDF is a PRF over its input, so the map `(password, response) -> mixed` preserves min-entropy with no
  wrap-around and no CRC folding — injective by construction for any `response_len ≤ HKF_MAX_RESPONSE`.
- The versioned **`info` label** provides domain separation; this subsumes the separately-tracked
  "cSHAKE domain-separated KDF labels" item (addendum §7).

## Backward compatibility — a version-try loop, not a format break

The mix changes the *value* fed to PBKDF2/Argon2 but leaves the on-disk header untouched (no new field,
no magic). So a volume enrolled under v1 still opens: the mount path tries **v2 first, then falls back
to v1** (`HKFMixResponseIntoPasswordVer`). New volumes are created under **v2**. There is no format
version byte to read — the correct version is discovered by which mix reproduces a mountable key, exactly
as the report anticipated.

Cost: one extra header-key derivation attempt at mount for a v1 volume (the v2 attempt fails first). A
v1 volume can be transparently upgraded to v2 on the next password change (re-mix under v2, rewrite the
header under the same key material).

## Verification (`verification/hkf_mixv2_test.c` + `hkf_mixv2_reference.py`, suite step `[80]`)

Two independent ways:
1. the v2 mixed password diffed **byte-for-byte** against an independent python HKDF-SHA256
   (regression anchor `78b0e7e5…`);
2. the **version-try loop** behaviour over the real `HKFMixResponseIntoPasswordVer`.

Negative controls: a wrong response opens **neither** version (no false match); v1 and v2 differ for the
same input (so the try-loop is genuinely necessary); a 1-bit change in the response avalanches ~half of
the v2 output (511/1024 bits — PRF diffusion, unlike the localized CRC mix). gcc-13 + clang-18; in the
flag matrix.

## Remaining real-build wiring

The two derivation code paths (`Common/Volumes.c` C path; `Volume/VolumeHeader.cpp::Decrypt` +
`Core/VolumeCreator.cpp` C++ path, via `Volume/HardwareKeyFactorMix.h`) call the mix at a single site
each. Rank-1 finishes by: create → `HKFMixResponseIntoPasswordVer(HKF_MIX_V2, …)`; mount → the v2→v1
try loop around the existing header-decrypt attempt. That is behavioural on a real volume and validated
by the acceptance harness (`docs/REAL-BUILD-VALIDATION.md`), not sandbox-testable here.
