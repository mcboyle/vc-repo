# HKF v2 mixing (Rank-1) — HKDF derivation with a version-try loop

*Status: core primitive + version-try loop verified in-sandbox (suite step `[80]`); the mount/create
call sites are now WIRED on both derivation paths and the wiring seam is verified in-sandbox (suite step
`[81]`); **Rank-1 salt binding (T2-1 / D-1) built + verified in-sandbox (suite step `[93]`)**, see
"Salt binding" below. What remains is the behavioural header round-trip on a real build (mount/create
pipeline link) and, for the C path, the Windows driver toolchain — both real-build-only, see
`docs/REAL-BUILD-VALIDATION.md`.*

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

## Salt binding (T2-1 / D-1) — gated `VC_ENABLE_HKF_MIX_V2_SALTBIND`

The base v2 derivation extracts with a fixed empty salt (`0^32`). **Salt binding** folds the **volume
salt** into HKDF-Extract instead:

```
password[0..128) = HKDF-SHA256(salt = <the volume's PBKDF2 salt>,
                               IKM  = original-password || response,
                               info = "VeraCrypt/HKF/mix/v2",
                               L    = 128)
```

- **What it buys.** The mixed password — hence the header key — is now bound to *this* volume's salt. A
  factor response, or a reconstructed/threshold `RAW_SECRET`, enrolled against volume A no longer opens
  volume B at the same password: the salts differ, so the derived keys differ. It also inherits the
  volume salt's domain separation into the Extract step (HKDF's intended use of the salt input).
- **Backward-compatibility shape.** This is a **derivation-value change, not a header-format change** —
  same shape as the Rank-1 migration itself. The mount version-try loop is unaffected; an existing v2
  volume re-derives once the salt is bound (migration is tracked as **T1-3**). With the flag **off** the
  derivation is byte-identical to plain v2 (the step-`[80]` `MIXV2EXP` anchor is unchanged), so enabling
  it only adds the salt-bound entry point. A `NULL`/empty salt falls back to the `0^32` derivation rather
  than silently weakening.
- **API.** `HKFMixResponseIntoPasswordV2Salt(password, len, response, rlen, salt, saltLen)` and the
  salt-aware dispatch `HKFMixResponseIntoPasswordVerSalt(...)`. Under the flag, `HKFApplyIfConfiguredVer`
  (C create path), the C-path mount (`Volumes.c`), and the C++ mount/create overload
  (`HKFMixPasswordWithResponse` ← `VolumeHeader::Decrypt` / `HKFMixPasswordVer`) all thread the header
  salt through, so create and mount bind the same salt. `make HKF_MIX_V2_SALTBIND=1` enables it (implies
  `VC_ENABLE_HKF_MIX_V2`).
- **Verified** (suite step `[93]`, `hkf_saltbind_test.c` + `hkf_mixv2_reference.py`): the salt-bound
  mixed password equals an independent python HKDF whose Extract salt is the volume salt
  (`MIXV2SALTEXP`), the unbound path stays byte-identical to the step-`[80]` anchor, and the properties
  hold — different salts give different keys, salt-bound ≠ unbound, `NULL` salt falls back. The real-build
  mount/create round-trip (that a salt-bound-created volume opens under the salt-bound mount and *not*
  under a different volume's salt) is real-build-only, like the rest of the v2 wiring.

### Build-configuration compatibility — the v1↔v2 asymmetry (T2-1 fix)

The mix version a build performs is fixed at compile time and **is not recorded in the header**, so
compatibility is not only a property of *volumes* — it is also a property of *builds*, and the two
directions are **asymmetric**:

- **v2 builds are forward-compatible with v1 volumes.** A build that compiles the v2 mix in runs the
  mount-time version-try loop (v2 first, then v1), so it opens *both* v1 and v2 volumes.
- **v1-only builds are NOT backward-compatible with v2 volumes.** A build without the v2 mix has no
  try-loop; given a v2 volume it v1-mixes the password, the header decrypt fails, and it reports
  **"Incorrect password."** for the *correct* password. For the D-13 audience that false negative — under
  duress, indistinguishable from a genuinely wrong password — is close to the worst diagnostic the tool
  can emit.

This failure was **reachable** before the fix: a plain `make HKF=1` produced a v1-only build, while
`make … HKF_MIX_V2_SALTBIND=1` produced a v2 volume, and the former could not open the latter. The fix
(in `src/Makefile`) makes **every** HKF-enabled build (`HKF` / `HKF_SIMULATOR` / `YUBIKEY` / `FIDO2`)
default to the v2 salt-bound mix. Because a v2 build is a strict superset for *mounting* (it still opens
legacy v1 volumes through the try-loop), unifying on v2 removes the only distributable v1-only
configuration without losing the ability to read older volumes. A plain `make` with no HKF knob stays
byte-for-byte stock and is unaffected. A companion compile-time `#error` in `HardwareKeyFactor.h` rejects
the narrower, no-longer-reachable combination of the v2 mix *without* salt binding — defence-in-depth for
a hand-rolled `-DVC_ENABLE_HKF_MIX_V2`, since an unsalted-v2 build would fail to open a salt-bound volume
the same way. The verification suite keeps the unsalted derivation reachable via
`-DVC_ALLOW_UNSALTED_HKF_MIX_V2` (step `[80]`'s `MIXV2EXP` anchor must stay byte-identical).

**Why config-level prevention rather than a runtime diagnostic.** The alternative — have the mount path
detect the mismatch and report *"this volume uses a derivation this build does not support"* instead of
"wrong password" — is rejected on two grounds. First, unlike the `HKF_SALT_BIND` RAW_SECRET parameter
(supplied at mount like PIM, so its mismatch has a remedy: re-supply `--hkf-bind-salt`; see
`docs/SALT-BINDING-SPEC.md`), the mix version is baked into the binary — a user cannot re-supply the
*build* they were handed, so there is nothing a clearer message lets them do. Second, such a message is a
**disclosure oracle**: it tells anyone holding the volume (a coercer included) that it requires a factor
they have not been given, which is exactly the kind of leak a deniability-focused tool must not emit.
Keeping the derivation silent and removing the bad configuration at build time is therefore both safer and
strictly more useful than a diagnostic. The change is preventive: no v2 volumes exist outside testing
yet, so it lands before the exposure window opens.

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

## Wiring — done, and the compute-once seam

Both derivation code paths are now wired (gated `VC_ENABLE_HKF_MIX_V2`; default and `VC_ENABLE_HKF`-only
builds are unchanged):

- **C path** (`Common/Volumes.c`, Windows driver / shared): `CreateVolumeHeaderInMemory` mixes under
  `HKF_MIX_V2` via `HKFApplyIfConfiguredVer`. `ReadVolumeHeaderWithAbort` became a thin wrapper that
  computes the factor response **once** (`HKFComputeActiveResponse`, reading the header salt directly),
  then calls the unchanged 600-line derivation body (renamed `ReadVolumeHeaderWithAbortImpl`, now taking
  a precomputed response + version) under `HKF_MIX_V2`; on `ERR_PASSWORD_WRONG` it resets the shared
  abort flag and retries under `HKF_MIX_V1`. A single backend query serves both attempts.
- **C++ path** (`Volume/VolumeHeader.cpp` + `Core/VolumeCreator.cpp`, via `Volume/HardwareKeyFactorMix.h`,
  the path Linux actually runs): both `VolumeCreator.cpp` create sites use `HKFMixPasswordVer(..,
  HKF_MIX_V2)`. `VolumeHeader::Decrypt` computes the response once (`HKFComputeActiveResponse`) and calls
  the extracted `DecryptWithEffectivePassword` helper under v2 then v1, mixing the same response via
  `HKFMixPasswordWithResponse` — no second token round-trip.

**Compute-once, mix-twice:** the token/backend is queried exactly once per mount even though the mix runs
under two versions. This is required for hardware backends (a YubiKey/FIDO2 round-trip per version would
double the touch prompts) and is the reason the seam exposes `HKFComputeActiveResponse` separately from
the mix.

## Verified in-sandbox (suite step `[81]`, `hkf_mixv2_wiring_test.c`)

Over the real compiled `HardwareKeyFactor.o`, driving the process-wide active config
(`HKFSetActiveConfig`, as the CLI does): create-under-v2 via `HKFApplyIfConfiguredVer`; the mount
wrapper opens a v2-enrolled volume on the first attempt and a v1-enrolled (legacy) volume via the v1
fallback, **querying the backend exactly once** across both; `HKFComputeActiveResponse` equals a direct
`HKFComputeResponse(active cfg)`; and the **C create path derives byte-identical keys to the C++
overload's operations** (cross-path identity). Negative controls: a wrong active factor opens **neither**
version; v1 ≠ v2 (the version argument is genuinely consumed). The v2-enrolled key is additionally
cross-checked byte-for-byte against the independent python HKDF (`hkf_mixv2_reference.py`).

## Remaining real-build wiring

The behavioural **header round-trip** (create a volume, then mount it through the real KDF/cipher
pipeline) links the whole mount/create stack and is validated by the acceptance harness
(`docs/REAL-BUILD-VALIDATION.md`), not sandbox-testable here. The C-path edits additionally build only
under the **Windows driver toolchain** — `Common/Volumes.c` is Windows-only (not in any Linux `.make`,
uses `<io.h>`/`WORD`/`TC_EVENT`); the Linux mount/create runs entirely through the C++ path.
