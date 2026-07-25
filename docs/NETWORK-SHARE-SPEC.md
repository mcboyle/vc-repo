# Network-bound share source (Tang/Clevis-style) — design spec

**Status: MODULE BUILT — the McCallum–Relyea exchange is proven at production parameters and cross-host
over real TCP, and `src/Common/NetShare.{c,h}` is the shippable module (compressed wire format, RFC 8032
§5.1.3 decompression, step `[102]`). Remaining: the `--ns-*` CLI and a constant-time group.**
A share for the split-key factor whose recovery **requires a network server's participation**,
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

**Two-host TCP — proven (step `[101]`, `verification/netshare_tcp_poc.c`).** The same MR crypto driven
over `AF_INET`, run for real across two lab machines (server on 10.0.70.81, client on .82): the same
anchor share `edf4bd73…` recovered over the wire, fresh blinding per unlock, off-network and
wrong-server both failing.

## Shippable module — `src/Common/NetShare.{c,h}` (step `[102]`)

**"Serialization is a detail" was the wrong framing, and it hid the last piece of real crypto.** Every
PoC above moves the raw extended-coordinate `pt` struct on the wire. A shipping build sends **compressed
32-byte points**, and a compressed point must be **decompressed** on receipt — recovering `x` from `y`
via a modular square root (RFC 8032 §5.1.3). Nothing in this tree had ever done that. So the gap after
`[101]` was not "just the CLI": it was a missing wire format, and the wire format needed new, unanchored
crypto. See `docs/CANT-CLAIMS-AUDIT.md` for the correction in full.

`NetShare.{c,h}` closes it, gated `-DVC_ENABLE_NETSHARE`:

- **compressed-point wire format** with `pt_decompress` per RFC 8032 §5.1.3, rejecting non-canonical
  `y ≥ p`, off-curve `y`, and the invalid `x = 0`-with-sign-bit encoding. `sqrt(-1)` is *computed*
  (`2^((p−1)/4) mod p`) rather than hardcoded — a mistyped 256-bit constant would be a silent
  wrong-branch bug on a path that only some inputs take.
- **transport is injected** (`NetShareTransportFn`), so `Common/` contains no sockets and the crypto is
  testable with no network — the same seam pattern as `KeyslotArea` and the keyslot parallel-for.
- **versioned credential blob** `NSC‖ver‖S‖C‖cksum`, carrying no secret: `c` and `K` are wiped at
  enrolment, so a stolen disk holds only public values.
- **off-network is `NETSHARE_ERR_TRANSPORT`, never a bad share** — the caller can say "server
  unreachable" instead of "wrong password".

Anchored **OFFICIAL** (`verification/netshare_module_test.c`, 31/31): all five RFC 8032 §7.1 Ed25519
public keys — compressed points from an implementation we did not write — decompress and re-compress
byte-identically. That is not a tautology: compression recomputes `x` from the decompressed
coordinates, so an `x` recovered on the wrong branch re-encodes with the wrong sign bit and fails.

**Why the credential carries a checksum.** The first version validated both stored points and claimed
in its own comment that corruption "is reported as a credential problem and never as a failed unlock."
The module test disproved it: point encodings are dense, so a flipped bit usually yields *another valid
point* — parse returned OK and recovery silently produced a different share, i.e. "wrong password" for a
corrupt credential. The test sweeps eight bit positions and separately asserts at least one still parses
as a valid point, so the checksum is demonstrably load-bearing. It detects corruption, not tampering:
an attacker who can rewrite the blob can rewrite the checksum, and gains nothing by it — the credential
is public and useless without the server.

## What remains

- the **`--ns-*` enrol/unlock CLI options** and a TCP/HTTPS implementation of `NetShareTransportFn`
  (now genuinely just wiring — the module and its proof are in place);
- HTTP(S) to a real **Tang** endpoint rather than the bare framing used here;
- a **constant-time** group implementation before shipping. The from-scratch group is proven correct
  against RFC 8032 but is **not** side-channel hardened. This matters less than for a password KDF —
  the scalars here are ephemeral blinding factors and a per-credential `c` that is destroyed at
  enrolment — but it is not a claim to skip. It is stated here as an open item, not as done.
