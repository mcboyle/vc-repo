# Addendum — Implementation verification against the fork source

*Appended to: "Security Analysis of the CRC-32 Keyfile-Pool Mixing Seam in a Hardened VeraCrypt
1.26.29 Fork." Produced by checking the report's stated assumptions against the current
`src/Common/HardwareKeyFactor.{c,h}`, `src/Common/Shamir.h`, and
`src/Main/CommandLineInterface.cpp`.*

The report's Caveats section states:

> I did not review the actual fork source beyond the description provided; all claims about
> `HKFMixResponseIntoPassword` behavior rest on the stated byte-for-byte facts. If those facts are
> inaccurate (especially "no wrap-around for ≤32-byte inputs" and "pool starts zeroed"), the
> injectivity conclusion could change.

This addendum discharges that caveat. **Two of the three assumptions hold as stated. The third holds
for the two hardware backends but not for a third supported path, which is reachable in the current
default configuration.**

---

## 1. Confirmed against source

| Assumption | Status | Evidence |
|---|---|---|
| Pool starts zeroed | **Confirmed** | `memset (pool, 0, sizeof (pool));` before the accumulation loop, so `+=` is effectively `=` on first write |
| Four CRC state bytes per input byte, `writePos` advancing by 4, wrapping at 128 | **Confirmed** | The loop writes `crc>>24`, `crc>>16`, `crc>>8`, `crc` at `pool[writePos++]` with `if (writePos >= HKF_POOL_SIZE) writePos = 0;` |
| Pool is 128 bytes | **Confirmed** | `#define HKF_POOL_SIZE 128` |
| Final step adds pool into password and extends length to 128 | **Confirmed** | matches the report's description exactly |

The report's characterisation of the construction is accurate.

## 2. The wrap-around boundary, measured

At four pool bytes per input byte into a 128-byte pool, wrap begins at **33 input bytes**. Replicating
the write schedule exactly:

```
input 20 bytes -> each pool position written 0 or 1 times   (no wrap)
input 32 bytes -> each pool position written exactly 1 time (no wrap; pool exactly filled)
input 44 bytes -> positions written up to 2 times           (WRAPPED)
input 56 bytes -> positions written up to 2 times           (WRAPPED)
```

So the report's ≤32-byte precondition is exactly right, and both hardware backends satisfy it:

- **YubiKey HMAC-SHA1** → 20 bytes → positions 0–79, no wrap ✓
- **FIDO2 hmac-secret (HMAC-SHA256)** → 32 bytes → positions 0–127 exactly once, no wrap ✓
- **Simulator** → 20 bytes (`simMac=1`) or 32 bytes (`simMac=2`), no wrap ✓

## 3. The gap: RAW_SECRET permits 64 bytes today

The report anticipates this as a *future* risk:

> if a future input backend produces inputs >32 bytes, wrap-around and repeated additive accumulation
> resume and the injectivity proof no longer holds — Rank 1/2 becomes mandatory, not optional.

**That backend is already present.** In the current source:

- `#define HKF_MAX_RESPONSE 64`
- `#define SHAMIR_MAX_SECRET 64`, `unsigned char rawSecret[64];`
- the `HKF_BACKEND_RAW_SECRET` dispatch rejects only `rawSecretLen <= 0 || rawSecretLen > HKF_MAX_RESPONSE`

A Shamir-reconstructed secret of 33–64 bytes is therefore an accepted configuration, and it wraps the
pool. **This is the path the threshold/split-key factor uses.**

**Precision about what this does and does not establish.** The report *proves* injectivity for ≤32
bytes. For >32 bytes the proof does not apply — the serialization no longer places each byte's state
in disjoint pool positions, so two trajectory segments fold together under mod-256 addition. This
addendum does **not** demonstrate a collision, and none should be inferred: the map from 512 input
bits to 1024 pool bits remains expanding, so counting does not rule out injectivity. The correct
statement is that entropy preservation on this path is **unproven**, which is precisely the condition
the analysis was commissioned to eliminate.

## 4. Salt-binding is opt-in, not default

The report's Recommendation 1 assumes salt-binding is available and should become the default.
Confirmed available, confirmed **not** currently default:

- compiled only under `VC_ENABLE_HKF_SALT_BIND`
- enabled per-invocation by the CLI flag `--hkf-bind-salt`, which sets `rawSecretBindSalt = 1`
- when enabled, `response = HMAC-SHA256(secret, volume_salt)` and `*response_len_out = 32`

## 5. Consequence: Recommendation 1 closes two gaps, not one

Because the salt-bound response is **always exactly 32 bytes**, enabling salt-binding by default lands
every RAW_SECRET invocation precisely at the upper bound of the proven-injective regime. It therefore
closes:

1. **cross-volume factor reuse** — the weakness the report identifies, and
2. **the >32-byte wrap-around exposure** — which the report classified as hypothetical, and which is
   in fact reachable today.

Recommendation 1 should be read as strictly more valuable than the report states, and remains
config-only with no cryptographic redesign.

## 6. Additional suggested change: unconditional length conditioning

Independent of the salt-binding default and of any Rank-1/Rank-2 migration, the injectivity
precondition can be made unconditional inside `HKFComputeResponse`:

```c
/* Keep every backend inside the proven-injective regime: 4 pool bytes per input byte
   over a 128-byte pool means wrap begins at 33 bytes. Condition anything longer. */
if (*response_len_out > 32) {
    unsigned char h[32];
    sha256 (h, response_out, (uint_32t) *response_len_out);
    memcpy (response_out, h, 32);
    *response_len_out = 32;
    burn (h, sizeof h);
}
```

This is ~6 lines, adds no dependency (the in-tree `sha256()` is already linked on this path), and
makes the report's Section-(B) conclusion hold for *any* present or future backend regardless of flag
state. It is defence in depth, not a substitute for Recommendation 1.

**Verification note:** this change alters derived keys for any existing volume whose factor exceeded
32 bytes, so it needs the same v2→v1 mount-time try loop as the Rank-1 migration, or a documented
re-enrollment. For ≤32-byte factors — every hardware backend, and every salt-bound RAW_SECRET — it is
a no-op and existing volumes are unaffected.

## 7. Migration scope — correction to prior project guidance

The report clarifies that Rank-1/Rank-2 remediation changes the *value* fed to the KDF but leaves the
on-disk header untouched, so backward compatibility is a mount-time version-try loop rather than a
format break. Project planning had parked several `[FORMAT]`-tagged items pending this analysis on the
assumption a format migration might be forced. That assumption was too conservative. Revised
disposition:

| Item | Disposition |
|---|---|
| 91 — slot AND-composition | **Unblock.** Keyslot policy; unrelated to the password seam. |
| 98 — KMAC256 keyslot-area auth | **Unblock.** Authenticates the keyslot area, not the derivation input. |
| 97 — cSHAKE domain-separated KDF labels | **Fold into v2.** HKDF-Expand's `info` parameter (Rank 1) or KMAC's customization string (Rank 2) subsumes this entirely; building it separately would be duplicated work. |
| 96 — two-stage derivation (cheap factor pre-check) | **Design against v2**, not against the current seam. |

## 8. Net assessment

The report's central conclusion stands: for the fork's short, near-uniform inputs the CRC seam
preserves min-entropy exactly, and replacement is sound hygiene rather than an urgent fix. Nothing in
this addendum contradicts that.

What changes is the *ordering and urgency of the remediation*, because the precondition the conclusion
depends on is not currently enforced by the code — it happens to hold for two backends and can be
violated by a third under the default configuration. Recommendation 1 should ship first and closes
both gaps; the §6 conditioning makes the precondition structural rather than incidental; and the
Rank-1 HKDF migration remains the clean long-term answer, now known to cost a mount-time try loop
rather than a format break.

---

## Implementation status in this fork

Tracking which of the addendum's recommendations are implemented in-tree. Updated as work lands.

| Recommendation | Status | Where |
|---|---|---|
| §6 — unconditional length conditioning (`>32 bytes → sha256()→32`) | **IMPLEMENTED** behind `VC_ENABLE_HKF_LEN_CONDITION` | `HKFComputeResponse` wrapper in `src/Common/HardwareKeyFactor.c`; verified at `verification/build_and_verify.sh` step `[78]` (`hkf_lencond_test.c` + `hkf_lencond_reference.py`) |
| §5 / Rec 1 — salt-binding **on by default** | available today via `VC_ENABLE_HKF_SALT_BIND` + `--hkf-bind-salt` (opt-in); making it the default is a policy/CLI change, not yet flipped | `src/Common/HardwareKeyFactor.c` (`rawSecretBindSalt`), `docs/SALT-BINDING-SPEC.md` |
| Rank-1 HKDF migration (v2 derivation) + mount-time version-try loop | not started (long-term) | — |

### §6 implementation notes

`HKFComputeResponse` now dispatches to the backend (`hkf_dispatch_response`) and, when built with
`-DVC_ENABLE_HKF_LEN_CONDITION`, folds any response longer than 32 bytes through the in-tree
`sha256()` down to exactly 32 bytes before it reaches the pool mix. Consequences:

- **No-op for every ≤32-byte response** — YubiKey (20), FIDO2 hmac-secret (32), simulator (20/32), and
  salt-bound RAW_SECRET (32) are byte-for-byte identical with or without the flag, so all existing
  hardware/salt-bound volumes are unaffected.
- **Closes the reachable gap** — a raw Shamir-reconstructed RAW_SECRET of 33–64 bytes (the
  threshold/split-key path) is conditioned to 32 bytes, landing it inside the proven-injective regime
  instead of wrapping the pool.
- **Compatibility** — for a volume enrolled with a >32-byte raw factor, enabling the flag changes the
  derived key, so that volume must be re-enrolled (or opened with a version-try loop). This is the
  same backward-compatibility shape as the Rank-1 migration (a derivation-value change, **not** an
  on-disk format change).

Default builds (and HKF builds without the flag) remain byte-for-byte stock.
