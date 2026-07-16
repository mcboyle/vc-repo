# Threshold / split-key factor (Shamir M-of-N) — design & status

**Status: implemented and verified.** This adds an *M-of-N* factor to the VeraCrypt key-derivation
path: the secret that (together with the password) unlocks a volume is reconstructed from **any
`threshold` of `N` shares** via Shamir Secret Sharing, then mixed into the password before PBKDF2 —
the same seam as the hardware factor, so there is **no header-format change**.

This is the safe answer to the whole duress thread. Unlike a destructive wipe it destroys nothing and
leaves no "I triggered something" artifact; it just makes the key require several parties/factors.

## Why this is the strongest coercion primitive

- **Split trust.** With, say, 2-of-3 shares held by different people/devices/locations, **no single
  person can open the volume alone** — so coercing one person in isolation yields nothing to extract.
- **Safe dead-man.** Withhold a share (a trustee stops cooperating, a network share stops being
  served, a location becomes unreachable) and the volume becomes **inaccessible, not destroyed** — no
  crypto-erase, no forensic "destruction" tell, and it's recoverable if the share returns.
- **Redundancy.** Lose up to `N − threshold` shares and you can still open the volume; no single
  point of failure, unlike one password or one token.
- **Composability.** A share is just bytes, so a share can be a keyfile, a passphrase-derived value,
  a **YubiKey/FIDO2 response** (the factor already built), or a **network-fetched** value
  (Tang-style). Mix and match per deployment.

## Mechanism

Standalone Shamir over GF(2⁸) (AES field, `Common/Shamir.{c,h}`):
- `shamir_split(secret, len, threshold, n, random_bytes, shares)` — enrollment. Each secret byte is
  an independent degree-`(threshold−1)` polynomial; shares are evaluated at distinct x = 1..N. The
  caller supplies `(threshold−1)·len` CSPRNG bytes (explicit, so it's testable and forces real
  randomness in production).
- `shamir_combine(shares, count, secret, len)` — mount. Lagrange interpolation at x = 0.

A share is `{ x : 1 byte, y : one byte per secret byte }` — serialize as `x:hex(y)` or a small blob.

Integration via a new `HKF_BACKEND_RAW_SECRET`: the reconstructed secret is placed in
`HKFConfig.rawSecret` and mixed into the password by the existing
`HKFApplyIfConfigured`/`HKFMixResponseIntoPassword` seam (identical to keyfile mixing). Flow:

- **Enroll:** generate a random secret `S`; `shamir_split(S)` → distribute the N shares; create the
  volume with the factor = `RAW_SECRET(S)` so the header requires `S`.
- **Mount:** collect any `threshold` shares; `shamir_combine` → `S`; load as `RAW_SECRET`; derive.
  The volume itself stores no shares — it just requires `S`, reconstructed in memory at mount.

Because it rides the same seam, it **composes with the decoy layout**: set
`applyPolicy = HKF_APPLY_HIDDEN_ONLY` to gate only the hidden volume behind the threshold, and/or make
one of the shares a YubiKey response.

## Verified (`verification/shamir_test.c`, `shamir_chain.c`)

- **GF(2⁸) known-answer tests:** `0x57·0x83 = 0xC1`, `0x53·0xCA = 0x01`, `inv(0x53) = 0xCA`.
- **Threshold property:** any `threshold` shares reconstruct the secret and **all** valid subsets give
  the *same* secret; fewer than `threshold` do **not** reconstruct it. Cross-checked byte-for-byte
  against an independent Python implementation (shares and reconstruction both match).
- **Full chain** *shares → reconstruct → mix → real `derive_key_sha3_512`*: any valid 3-of-5 subset
  yields the identical header key (`a8b0cbb7…`, equal to an independent Python PBKDF2); a
  below-threshold set flips **64/64** header-key bytes — access is gated at the derivation level.

Run: `cd verification && ./build_and_verify.sh` (self-contained: GF + split/combine + threshold +
Python cross-check). `shamir_chain.c` needs the compiled VeraCrypt objects and is included for
reference.

## Operational notes (state these to users)

- **Randomness:** `shamir_split` mixes in caller-supplied bytes — use a real CSPRNG at enrollment.
- **Share distribution is the risk surface**, not the math: where/how shares are stored and who holds
  them defines the actual security. A 2-of-3 with all three shares in one drawer is a 1-of-1.
- **Reconstruction is in RAM** — pair with key-scrubbing (unmount/idle/lock) so the reconstructed
  secret and derived keys don't linger; this is the cross-platform memory-scrub work item.
- **Recovery:** keep enough shares (and their locations) to reach `threshold`; losing more than
  `N − threshold` is unrecoverable — same discipline as any key material.
