# Network-bound share source (Tang/Clevis-style) — design spec

**Status: DESIGN — specced; the McCallum–Relyea exchange proven, network client + wire format not yet
built.** A share for the split-key factor whose recovery **requires a network server's participation**,
where the **server never sees the key** and a **stolen, off-network machine stays locked**. It composes
as a Shamir share source, so it drops into the threshold/split-key factor already built
(`docs/SPLIT-KEY-SPEC.md`) with no new seam in the derivation path.

## Why this shape

- **Automatic unlock while on a trusted network; locked when removed.** Like Tang/Clevis: a machine on
  the LAN can recover the share unattended; taken off the network (stolen laptop, seized server) it
  cannot.
- **The server learns nothing.** It performs one oblivious computation on a *blinded* value and never
  sees the recovered key, which client asked, or the volume. So compromising the server does not
  compromise past or future volumes — it only lets an attacker deny service or, if they also hold the
  disk, participate in recovery.
- **No new derivation seam.** The recovered secret is hashed to bytes and handed to the existing
  `RAW_SECRET` / Shamir path, or used as a keyslot passphrase. Nothing changes in PBKDF2/Argon2.

## The protocol: McCallum–Relyea (PROVEN — `verification/netshare_poc.c`)

MR is a blinded key-agreement over any group with a commutative operation (an elliptic curve, or a
prime-field DH group). The recovery identity is **independent of parameter size**, which is why the
PoC proves it over a small prime field and the shipping build uses real parameters (below).

```
server long-term:  s (secret),  S = g^s                       (S is published)
provision:         c (ephemeral), C = g^c (stored on client), K = S^c = g^(s·c)
                   then c and K are discarded — only C (public) remains on disk
recover:           e (ephemeral), X = C · g^e = g^(c+e)       -> send X to the server
                   server:        Y = X^s = g^(s(c+e))         (server sees only the blinded X)
                   client:        K = Y · (S^e)^-1 = g^(s(c+e)) · g^(-s·e) = g^(s·c)
share bytes:       SHA-256(K)  -> a Shamir share / RAW_SECRET for the split-key factor
```

Proven two ways (real in-tree `Sha2.c` vs. an independent Python bigint reference, byte-for-byte;
build_and_verify.sh step `[10]`, anchor share `cc288fab…`):
- **[A] Correctness** — the recovered `K` equals the provisioned `K`, so the share is stable.
- **[B] Server-obliviousness / blinding** — the value the server receives (`X`) is not `C`, and a
  *different* recovery ephemeral `e` still recovers the *same* `K`. The server's input is a fresh
  blinded point each time; it cannot link recoveries or learn `C`/`K`.
- **[C] Offline / server-presence binding** — a wrong server key (an attacker who lacks `s`) does not
  recover `K`. Without the server's `X^s` step, `C` alone yields nothing.

## Shipping parameters — now proven on the full Ed25519 group (step `[39]`)

The original PoC field was `p = 2305843009213693921` (61-bit) purely so modular multiply fits
`__int128`. The production-parameter MR exchange is now proven on the **full Ed25519 group** (step
`[39]`, `verification/netshare_ed25519_poc.c`), the spec-preferred full-group curve — chosen over a
bare X25519 ladder precisely because MR needs point **addition** `X = C + e·G`, not just scalar
multiply. The group is implemented from scratch (project convention: no new dependency) in extended
twisted-Edwards coordinates on the proven 256-bit bignum core, with a single field inversion per
scalar multiply. It is validated two ways:

1. **Official KAT** — the three RFC 8032 §7.1 Ed25519 public keys (basepoint scalar-mult of the
   SHA-512-clamped secret) are reproduced exactly, anchoring the group arithmetic to the standard.
2. **Two-way** — the full MR flow (`S = s·G`, `C = c·G`, `K = c·S`; recover `X = C + e·G`,
   `Y = s·X`, `K = Y − e·S`) and the derived share = SHA-256(compress(K)) are diffed byte-for-byte
   against `netshare_ed25519_reference.py` (independent Python bigint, affine group). Share anchor
   `ab8b717f…`; the recover-matches-provision, wrong-server-differs and server-sees-only-blinded-X
   properties all hold.

A deployment may still instead use NIST P-256 (as Tang/jose do) or a 2048-bit+ MODP group (RFC 3526)
for a DH instantiation; the exchange algebra is identical. What is **not** yet built is below.

## Integration (how the share is used)

1. **Provision** (`--netshare-enroll SERVER`): fetch `S` from the server, pick `c`, store `C` (a public
   blob) beside the volume config, compute `K = S^c`, hash to a share, and register that share with the
   split-key factor (or wrap a keyslot under it). Discard `c`, `K`.
2. **Unlock:** run MR recovery against the server to reconstruct `K` → the share → the reconstructed
   secret is mixed into the password (existing `RAW_SECRET`/Shamir seam), or opens a keyslot.
3. **Threshold composition:** because it is just one Shamir share, combine it — e.g. `2-of-3` among a
   network share, a YubiKey response, and a passphrase — so no single source (including the server)
   can unlock alone. This is the recommended deployment.

## Honest limitations (state these to users)

- **Availability / DoS.** Binding unlock to a server means **no server, no unlock**. Use it as one
  Shamir share among several (with a recoverable threshold) so a downed server is not a lockout;
  keep an offline recovery share.
- **Network observability.** An attacker on-path sees that a recovery happened and to which server
  (metadata), even though the blinded `X` and the key stay secret. Use TLS and treat the server
  address as sensitive.
- **Server compromise.** A stolen server key `s` does **not** by itself decrypt any volume (the
  attacker still needs `C` from the disk and the other threshold shares), but it removes this share's
  contribution and lets the holder participate in recovery. **Rotate `s`** to revoke — re-provision `C`
  against the new `S` (no volume re-encryption; this is just re-deriving the share).
- **Not deniable.** The stored `C` and the config reveal that a network-bound share exists. This is
  confidentiality/access-control, not hidden-volume deniability.
- **Trust-on-first-provision.** Provisioning trusts the server's advertised `S`; verify `S` out-of-band
  (pin it) or an active attacker at enroll time can substitute their own.

## What remains to build

The MR algebra, the production-parameter (Ed25519) group, **and the end-to-end exchange over a real
transport** are now proven (steps `[10]`, `[39]`, `[49]`).

**Transport round-trip — proven (step `[49]`, `verification/netshare_transport_poc.c`).** The exchange
now runs through an **actual kernel `AF_UNIX` socket** to a **separate server process** (a forked
child), with a persisted `C`-blob `{ S, C }`:

- **enroll** computes the share `K = c·S` offline and stores the blob;
- **unlock** picks a fresh ephemeral `e`, sends the blinded `X = C + e·G` over the socket, receives
  `Y = s·X`, and recovers `K = Y − e·S = s·C`, reproducing the enrolled share;
- the recovered share **equals the enrolled share byte-for-byte**, cross-checked against an
  independent python (`netshare_transport_reference.py`) over the real in-tree `Sha2.c`;
- the server **sees only the blinded `X`** (never `C`, never `K`), and a fresh `e` makes `X` differ on
  every unlock — the server cannot correlate;
- **off-network** (no server answering) the share is **unrecoverable**; a **wrong server** (different
  `s`) yields a different share. So the machine unlocks only *with* the network party, as designed.

Remaining, real-build only (needs a live external server, not sandbox-testable): swap the socket for
**HTTP(S) to a real Tang server** (or a custom endpoint) and wire the recovered share into the
split-key factor / a keyslot via the CLI. Serialization is a detail the PoC simplifies — it moves
points in extended-coordinate wire form and stores `C` the same way, where a production build sends
**compressed** points (32 B); and a production build swaps the from-scratch group for a constant-time,
side-channel-hardened implementation (or delegates to `jose`/`clevis`) — the from-scratch group here is
proven correct against RFC 8032 but is **not** constant-time and is for validation, not shipping.
