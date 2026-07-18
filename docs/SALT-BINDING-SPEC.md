# Salt-binding for RAW_SECRET — design & status

**Status: implemented and verified.** An option that makes the `RAW_SECRET` factor return
`HMAC-SHA256(secret, volume_salt)` instead of the raw secret, **binding a reconstructed/threshold
secret to the specific volume's PBKDF2 salt**. Gated behind `-DVC_ENABLE_HKF_SALT_BIND`
(`make HKF_SALT_BIND=1`); a build without it is byte-for-byte stock and `RAW_SECRET` behaves exactly
as before.

## Why

The `RAW_SECRET` backend mixes a caller-supplied secret (typically a Shamir reconstruction) into the
password like a static keyfile — it ignores the volume salt, so the *same* reconstructed secret
produces the *same* factor on every volume. Salt-binding turns it into a challenge-response factor,
exactly like the YubiKey/FIDO2 backends (whose response is `f(secret, challenge=salt)`):

- **Per-volume factor.** The same set of Shamir shares reconstructs one secret, but salt-binding makes
  that secret yield a **different factor on each volume** (different salt → different response). One
  leaked reconstruction is not directly reusable against a different volume.
- **Domain separation.** Two volumes protected by the same threshold group are cryptographically
  independent at the factor level.
- **Consistency with the hardware backends.** RAW_SECRET now composes into the same
  `response = f(secret, salt)` shape the rest of the factor seam already uses.

## Mechanism

`Common/HardwareKeyFactor.c`, gated: the `HKFConfig.rawSecretBindSalt` flag (0 = stock behaviour). In
`HKFComputeResponse`'s `RAW_SECRET` case, when the flag is set:

```
response = HMAC-SHA256(key = rawSecret, msg = challenge)      # challenge is the volume's PBKDF2 salt
```

computed with VeraCrypt's real in-tree `sha256()` (standard ipad/opad HMAC). The 32-byte response is
then mixed into the password by the existing keyfile-pool method — no header-format change; the factor
still behaves like a dynamically-computed keyfile.

CLI: `--hkf-bind-salt` sets the flag for the current create/mount. As with the token backends, the
same option must be supplied at mount as at create (the choice is not stored). Because the reconstructed
secret plus the volume salt fully determine the response, no extra state is needed.

## Verification (proven two ways, per the project convention)

`verification/saltbind_test.c` + `saltbind_reference.py`, wired into `build_and_verify.sh` step `[12]`:

- The harness drives the **real** `HKFComputeResponse` with a `RAW_SECRET` config and
  `rawSecretBindSalt = 1`; the 32-byte response is diffed **byte-for-byte** against an independent
  Python `HMAC-SHA256(secret, salt)` (anchor `4619ed18…`). The C side computes it over the **real
  in-tree `Sha2.c`**.
- With the flag off, the response is the raw secret unchanged (backward compatibility).
- Changing the salt by one bit changes the response (the binding genuinely depends on the salt).

The existing HKF verification (steps `[1]`–`[3]`) still passes with the new config field, and a build
without `-DVC_ENABLE_HKF_SALT_BIND` is unchanged.

## Honest notes

- **Not deniable / not a header change.** This is confidentiality/access-control hardening of the
  factor, nothing about the on-disk format changes.
- **Same-secret-different-volume only.** Salt-binding stops a reconstructed secret from being *directly*
  reused on another volume; it does not protect the shares themselves — share distribution remains the
  real risk surface for the split-key factor (`docs/THREAT-MODEL.md`, `docs/SPLIT-KEY-SPEC.md`).
- **Record the choice.** Like PIM and the token options, whether salt-binding was used is not stored;
  a volume enrolled with `--hkf-bind-salt` only opens when it is supplied again.
