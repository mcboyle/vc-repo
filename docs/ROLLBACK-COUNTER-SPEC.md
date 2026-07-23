# Rollback / replay protection — monotonic counter bound into the commit

**Status: binding construction + replay properties proven; the counter source is `[HW]`/real-build.**
Addresses `IDEAS-BACKLOG.md` §A ("Rollback / replay protection via a monotonic counter") — the missing
piece that **both** the Merkle tree (`docs/MERKLE-SPEC.md`) and per-sector authentication
(`docs/PERSECTOR-AUTH-SPEC.md`) explicitly defer to.

## The gap it closes

A Merkle root or a set of per-sector MACs proves the volume has not been *modified* since it was
authenticated. Neither catches **replay**: an attacker who images the whole volume — data, tags, Merkle
root, MAC — then lets the user work, then restores that older image, presents a snapshot that is
*internally consistent*. Every integrity check passes, yet the user has been silently rolled back to an
earlier state (undoing a revocation, restoring a deleted file, resurrecting a compromised key). This is
the snapshot-*replay* variant of the multi-snapshot problem.

Defeating replay needs one bit of state the attacker **cannot rewind**. A monotonic counter in
tamper-resistant hardware — TPM NV counter, a hardware-token counter, or a secure element — provides
exactly that: it only ever increments, and its current value is readable but not settable backward.

## Construction (bind the counter into the top-level authenticator)

```
commit_key = KDF(VMK, "rollback-commit")            # 32 bytes, never on disk
On each commit (any authenticated write that advances volume state):
    counter    = hardware_counter.increment()       # monotonic, never reused
    otk        = ChaCha20(commit_key, le64(counter), counter=0)[0..32]
    tag        = Poly1305(otk, state_root)           # state_root = e.g. the Merkle root
    store (counter, state_root, tag) on disk
On mount:
    C = hardware_counter.read()                      # trusted, cannot be rewound
    accept iff  disk.counter == C  AND  Poly1305(ChaCha20(commit_key, le64(C))[0..32], state_root) == tag
```

- **The counter is the nonce.** Because a monotonic counter never repeats, using `le64(counter)` as the
  ChaCha nonce means the derived one-time Poly1305 key is *never reused* — Poly1305's one-time-key rule
  is satisfied for free, no separate random nonce needed.
- **Two independent checks.** The plain equality `disk.counter == C` catches a wholesale old snapshot
  directly; the cryptographic binding catches an attacker who forges the on-disk counter marker to the
  current value (the tag was computed under the *old* counter, so it still fails). Either alone suffices;
  both together are belt-and-suspenders.
- `ChaCha20` is the in-tree `Crypto/chacha256.c`; `Poly1305` is the step-`[18]` implementation.

## What the PoC proves (`verification/monotcounter_poc.c` + `monotcounter_reference.py`, step `[22]`)

Proven the two ways the fork requires — the C PoC drives the **real in-tree ChaCha20 + Poly1305**; an
independent Python reference reproduces every value byte-for-byte over 10 vectors (4 commit tags, anchor
`commit_tag_0 = e8bbc4f0…`). A modeled increment-only `NvCounter` stands in for the TPM NV counter:

- **Fresh accept** — each version verifies at the counter it was committed under.
- **Rollback detected** — restoring the v1 snapshot (counter 1) is rejected once the hardware counter
  has advanced to 3 (user committed v2, v3).
- **Forged-marker detected** — forging the on-disk counter marker to 3 still fails, because v1's tag was
  bound to counter 1.
- **Tamper detected** — modifying the live `state_root` while keeping its tag is rejected at its counter.
- **Monotonic enforced** — the modeled counter refuses to set an equal or lower value and accepts only a
  forward jump (the hardware property the whole scheme rests on).
- **Wrong key detected** — a `commit_key` off by one bit fails verification.

## Operational policy — the central design decision (was open)

The crypto is complete and verified; the *operational policy* — what to do on a counter mismatch, which
anchors to trust, how to recover, and how this interacts with deniability — is the design decision the
spec previously left open ("a recovery path must be specified"). Fixed here.

### 1. Fail-WARN, not fail-stop (default)

Rollback *prevention* on disk alone is provably impossible: an in-band, disk-only counter is rewound by
the same snapshot that rewinds the data (van Dijk et al., *Offline Untrusted Storage with Immutable
Attestation*, STC '07). Detection requires **external non-rewindable state**, and even then the
increment-then-store step has an unavoidable window — Ariadne (Kaptchuk et al., USENIX Security 2016)
shows a correct scheme needs "at least a single bit flip per update," and at the instant of a crash
between *increment counter* and *store state* a **benign power loss is indistinguishable from a rollback
attack**. Therefore the honest default for a **portable** tool is fail-warn:

| Observation | Verdict | Action |
|---|---|---|
| anchor counter **==** stored state counter | OK | mount normally |
| anchor **newer by exactly 1** | **WARN** — probable interrupted commit / crash | surface a clear warning, let the user proceed after acknowledging (a benign crash lands here) |
| anchor **newer by > 1** | **ALARM** — probable rollback / replay | refuse by default; require explicit override with a stern warning |

**Do not "harden" this to fail-stop by default.** A fail-stop default lets an ordinary power loss brick a
journalist's volume — turning a freshness feature into an availability weapon against exactly the user it
is meant to protect. Fail-stop may be offered as an opt-in for a threat model that prefers unavailability
to any replay risk, but it is not the default, and this reasoning is recorded so it is not silently
reversed later.

### 2. Anchor taxonomy (ranked; some sources are explicitly NOT dependable)

The external non-rewindable state is the entire trust anchor. Ranked by dependability:

1. **TPM 2.0 NV monotonic counter** (`TPM2_NV_Increment` on an NV index with `TPMA_NV_COUNTER`) — the
   strongest widely-available anchor where present.
2. **Hardware token / phone / paper checkpoint** — a YubiKey or phone app that stores the last counter,
   or a written-down checkpoint value, for **portability** across machines without a usable TPM. Weaker
   (user-mediated, loseable) but real external state.
3. **Explicitly NOT dependable — do not use as the anchor:**
   - **FIDO2 signature counters** — optional in the spec and per-credential; many authenticators keep
     them at 0 or do not increment reliably. Not a general monotonic counter.
   - **Intel SGX monotonic counters** — the `sgx_create_monotonic_counter` API was **deprecated/removed**
     (limited write endurance, rollback issues); do not build on it.

### 3. Recovery path (was flagged, now specified)

For the dead-TPM / lost-token case, the shipping default is **escrowed higher-counter re-seal**: at
enrollment the user records a recovery secret (paper/offline) that authorizes a one-time re-seal of the
state to a counter value **strictly greater than any previously used** on a new anchor. Because the new
value is higher than every prior value, the re-seal cannot itself be used to roll the volume back. The
alternative, for users who reject any escrow, is an **explicit opt-out**: freshness protection off, with
the volume reverting to modification-detection-only (Merkle / per-sector auth) and the loss of rollback
detection stated plainly. Pick escrowed-re-seal as the default; expose the opt-out.

### 4. Deniability caveat for hidden volumes

An **off-device freshness anchor for a *hidden* volume is itself a tell**: a TPM NV index, token slot, or
paper checkpoint that exists *only* because a hidden volume needs freshness betrays that the hidden volume
exists. For a hidden volume, either anchor freshness **locally / on paper in a form whose existence is
independently deniable**, or use **padded, indistinguishable anchor records** (an anchor that looks the
same whether or not a hidden volume is present). Never provision a hidden-volume-specific external anchor
that a decoy would not also have. Cross-reference `docs/THREAT-MODEL.md` and `docs/KEY-DISCLOSURE-LEGAL.md`.

## Integration & honest notes

- **The counter source is `[HW]` and is the entire trust anchor.** The crypto here is complete; what it
  needs is a real monotonic counter: TPM 2.0 NV index with a monotonic attribute (`TPM2_NV_Increment`),
  a hardware token that exposes a counter, or a secure element (see the ranked taxonomy above). A purely
  on-disk "counter" buys nothing — the attacker rewinds it with the snapshot. Selecting and provisioning
  that source is the real-build work; this PoC deliberately models it.
- **One counter increment per commit, not per write.** Incrementing on every sector write would exhaust
  a TPM NV counter and murder performance. The counter advances once per *commit* (a batch of writes
  flushed with a new top-level `state_root`); pick the commit granularity in the integration.
- **Availability / bricking risk.** If the hardware counter is lost (dead TPM, lost token) the volume
  cannot be mounted — the same "one lost factor away from losing everything" tradeoff the enrollment
  docs already flag. The recovery path is now specified above (escrowed higher-counter re-seal, default;
  or explicit freshness-off opt-out) — and the fail-warn policy above keeps a benign crash from being
  treated as an attack. The risk must still be stated to the user at enrollment.
- **Composes with, does not replace, Merkle / per-sector auth.** Those detect modification; this adds
  freshness. Bind this PoC's `state_root` to the Merkle root so one counter protects the whole volume's
  integrity state at once.
- **TOCTOU at mount.** The counter must be read and the binding checked *before* the volume is exposed,
  and re-sealed atomically on unmount; the ordering discipline belongs in the integration.
- **Scope.** Replay/freshness of the user's own volume state is integrity/access-control infrastructure —
  well inside the project's boundary.
