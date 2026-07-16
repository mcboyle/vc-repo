# VeraCrypt hardware second factor (YubiKey HMAC-SHA1 + FIDO2 hmac-secret) — EXPERIMENTAL

Adds an **optional hardware token** as a second factor in VeraCrypt's key derivation. To open (or
create) a volume you then need **both the password and the physical token** — a leaked or guessed
passphrase alone is no longer enough.

This is the first change in this fork that hardens the factor that is actually the weak link
(password entropy) rather than the cipher, which was never the weak link.

> **Status: experimental. Not for real data without review.** It modifies the key-derivation path.
> Volumes created with a hardware factor are **not** interoperable with stock VeraCrypt, and are
> **unrecoverable if the token is lost** and you kept no backup (read *Lockout / backup* before you
> enroll anything). Existing volumes and volumes created without a factor are unaffected.

---

## How it works

The token computes a secret **response** from a **challenge**, and the response is mixed into the
password *before* PBKDF2:

1. **Challenge = the volume header's existing 64-byte PBKDF2 salt** — already present in every header
   and read before derivation, so nothing new is stored.
2. Token response:
   - **YubiKey HMAC-SHA1 CR:** `HMAC-SHA1(slot_secret, salt)` -> 20 bytes (secret never leaves the key).
   - **FIDO2 hmac-secret:** `HMAC-SHA256(credential_secret, SHA-256(salt))` -> 32 bytes (the CTAP2
     `hmac-secret` extension takes a 32-byte salt, so the 64-byte salt is hashed to 32).
3. The response is mixed into the password using **VeraCrypt's exact keyfile pool method** (rolling
   CRC-32 into a 128-byte pool, then `password[i] += pool[i]`). The token behaves like a *dynamically
   computed keyfile*.
4. PBKDF2 runs on the mixed password as usual. **No header format change** — the header never records
   that a token is required; you simply cannot derive the right key without it.

### Both derivation paths are hooked

VeraCrypt derives keys in two places, and this drop hooks both so the factor works everywhere and the
keys are **byte-identical across platforms**:

- **C path** — `Common/Volumes.c` (Windows driver / bootloader / shared code). Hooks at mount
  (after the salt is read) and at volume creation (after the salt is generated).
- **C++ path** — `Volume/VolumeHeader.cpp::Decrypt` (mount) and `Core/VolumeCreator.cpp` (create),
  which the **Linux/macOS application** actually uses. A small helper `Volume/HardwareKeyFactorMix.h`
  produces an effective `VolumePassword` with the response mixed in. Both the primary **and** backup
  header derivations are hooked, so a backup header can't be opened with password only.

When no factor is configured, both paths are behaviourally unchanged.

---

## Files and patches

```
src/Common/HardwareKeyFactor.h        module interface (config, backends, compute + mix + hook)
src/Common/HardwareKeyFactor.c        module: mixing seam + YubiKey + FIDO2 + simulator backends
src/Volume/HardwareKeyFactorMix.h     C++ glue: VolumePassword mixing for the Linux/macOS path
src/Main/HardwareKeyFactorCli.h       CLI helper: option strings -> validated HKFConfig (wx-free)

volumes-hkf-hooks.patch               C path  : Common/Volumes.c   (mount + create hooks)
volumeheader-hkf-hook.patch           C++ path: Volume/VolumeHeader.cpp::Decrypt (mount)
volumecreator-hkf-hook.patch          C++ path: Core/VolumeCreator.cpp (primary + backup create)
cli-hkf-options.patch                 CLI     : Main/CommandLineInterface.{h,cpp} (options + wiring)

verification/                         self-contained proof (see Verification)
```

The module is C and self-contained; the two headers are header-only. No dependency is added unless a
backend is enabled.

---

## Build

Backends are opt-in via macros; a build with none is behaviourally identical to stock.

| Macro | Enables | Link |
|---|---|---|
| `VC_ENABLE_YUBIKEY_HMAC` | YubiKey HMAC-SHA1 CR backend | `-lykpers-1` |
| `VC_ENABLE_FIDO2` | FIDO2 hmac-secret backend | `-lfido2` |
| `VC_ENABLE_HKF_SIMULATOR` | software virtual token (**testing only — never ship**) | — |
| `VC_ENABLE_HKF` | the derivation hooks + CLI options (define whenever any backend is on) | — |

1. Apply the patches. They were generated with an `a/src ...` prefix, so from inside `src/` use
   `-p2`, or from the repo root use `-p1`:
   ```sh
   cd src
   patch -p2 < ../volumes-hkf-hooks.patch
   patch -p2 < ../volumeheader-hkf-hook.patch
   patch -p2 < ../volumecreator-hkf-hook.patch
   patch -p2 < ../cli-hkf-options.patch
   ```
2. Add the sources/headers and flags. For the Linux/macOS Makefile build, add
   `Common/HardwareKeyFactor.c` to the object list that already contains `Keyfiles.o`
   (`Common/Common.make`), and set:
   ```make
   LIBS     += -lykpers-1 -lfido2
   CFLAGS   += -DVC_ENABLE_HKF -DVC_ENABLE_YUBIKEY_HMAC -DVC_ENABLE_FIDO2
   CXXFLAGS += -DVC_ENABLE_HKF -DVC_ENABLE_YUBIKEY_HMAC -DVC_ENABLE_FIDO2
   ```
   Dev packages: `libykpers-1-dev`, `libfido2-dev`. On Windows, add `Common\HardwareKeyFactor.c` to
   `Common\Common.vcxproj` (+ `.filters`), link `ykpers-1` / `fido2`, and set the same defines.

Not for pre-boot volumes (no USB stack there, and `MAX_PASSWORD` is 64); intended for the normal app.

---

## Command-line usage

The CLI patch adds these options (see `Main/HardwareKeyFactorCli.h`):

```
--hkf-backend <none|yubikey|fido2|simulator>
--hkf-yk-slot <1|2>                 (yubikey; default 2)
--hkf-fido-rp <relying-party-id>    (fido2)
--hkf-fido-credid <hex>             (fido2; credential id from enrollment)
--hkf-fido-pin <pin>                (fido2; optional)
--hkf-sim-secret <hex> --hkf-sim-mac <1|2>   (simulator; testing only)
```

Examples:
```sh
# mount with a YubiKey (slot 2) as the second factor
veracrypt --text --hkf-backend yubikey --hkf-yk-slot 2  /path/to/volume  /mnt/point

# create a volume that will require a FIDO2 authenticator
veracrypt --text --create --hkf-backend fido2 \
          --hkf-fido-rp veracrypt-volume --hkf-fido-credid 1122aabb...  /path/to/volume
```

The GUI is not wired in this drop — that is the remaining productionization (a dialog section
populating the same `HKFConfig`; the C++ derivation path it would drive is already in place).

---

## Hardware setup

### YubiKey — HMAC-SHA1 challenge-response
```sh
# slot 2, require a touch; record the generated secret for backup (see Lockout / backup)
ykman otp chalresp --touch --generate 2
# legacy tool equivalent: ykpersonalize -2 -ochal-resp -ochal-hmac -ohmac-lt64 -oserial-api-visible
```
Use `--hkf-backend yubikey --hkf-yk-slot 2`. Test enrollment before trusting data to it.

### FIDO2 — hmac-secret
Create a credential with the `hmac-secret` extension for a relying-party id you choose (e.g.
`veracrypt-volume`), set a device PIN, and record the returned **credential id**. Pass it via
`--hkf-backend fido2 --hkf-fido-rp ... --hkf-fido-credid ...`.

---

## Lockout / backup — READ THIS

A hardware factor means **losing the token loses the volume** — a far larger practical risk than any
cipher weakness. Plan for it *before* enrolling:

- **YubiKey HMAC-SHA1:** you generated the 20-byte secret, so you can program **one or more backup
  keys with the *same* secret** — they produce identical responses and open the same volumes. (Use
  `ykpersonalize` with an explicit key value rather than `--generate`.)
- **FIDO2 hmac-secret:** the per-credential secret is generated *inside* the authenticator and never
  exported, so **you cannot clone it** — two authenticators give different responses. Back up by
  enrolling multiple authenticators (needs multi-credential support beyond this drop) **or** keep a
  password-only recovery path.
- **Always keep a recovery path:** a securely stored plaintext copy, or a second password-only
  volume/backup. Never make a hardware-factor volume your only copy.

---

## Verification

Run the self-contained proof (needs only the module + a C/C++ compiler + Python 3):

```sh
cd verification && ./build_and_verify.sh
```

Proven there:

- **HMAC-SHA1** matches RFC 2202 case 1; **FIDO2-profile** response
  (`HMAC-SHA256(cred, SHA-256(salt))`) matches an independent reference.
- The **password mixing** is byte-identical to a from-scratch reimplementation of VeraCrypt's keyfile
  pool method.
- **CLI parsing** builds the right `HKFConfig` for yubikey/fido2/simulator, rejects bad input, and a
  config parsed from CLI strings drives the real crypto to the expected response.

Also verified during development (harnesses in `verification/`):

- **C path, full chain** *token -> mix -> real `derive_key_sha3_512`* equals an independent Python
  PBKDF2 (`628882be...`); a wrong token secret changes **64/64** header-key bytes (access gated).
  `htest.c`.
- **C++ path, full chain** — the real `HKFMixPassword` + real `Pkcs5HmacSha3_512::DeriveKey` produce
  the **same** mixed password (`f965c9e3...`) and the **same** header key (`628882be...`) as the C
  path and the reference. Cross-platform key consistency confirmed. `hkf_cpp.cpp`.
- **Real backends compile+link against the real libraries** (`ykpers-1`, `fido2`) and run, returning
  `HKF_ERR_NO_DEVICE` gracefully with no token attached. `hw_probe.c`.
- Hook call-sites type-check against the real `KEY_INFO` field types. `hook_typecheck.c`.

**Honest limit:** there is no physical token in the build environment, so the *hardware round-trip*
(a real key computing a real response over USB) is the one thing you must test yourself with the
setup above; and the wxWidgets CLI glue in `cli-hkf-options.patch` compiles in your full build (the
wx-free parsing logic it calls is verified here). The cryptography, the mixing, both derivation
seams, and the option parsing are all proven. For the YubiKey HMAC-SHA1 profile the simulator
computes the *same* HMAC the key does (you program the secret), so a simulator config with your slot
secret is a faithful stand-in and a backup/recovery check.

The stub `verification/Tcdefs.h` exists only so the module builds outside the tree — do not ship it.
