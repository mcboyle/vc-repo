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

## Integration & honest notes

- **The counter source is `[HW]` and is the entire trust anchor.** The crypto here is complete; what it
  needs is a real monotonic counter: TPM 2.0 NV index with a monotonic attribute (`TPM2_NV_Increment`),
  a hardware token that exposes a counter, or a secure element. A purely on-disk "counter" buys nothing —
  the attacker rewinds it with the snapshot. Selecting and provisioning that source is the real-build
  work; this PoC deliberately models it.
- **One counter increment per commit, not per write.** Incrementing on every sector write would exhaust
  a TPM NV counter and murder performance. The counter advances once per *commit* (a batch of writes
  flushed with a new top-level `state_root`); pick the commit granularity in the integration.
- **Availability / bricking risk.** If the hardware counter is lost (dead TPM, lost token) the volume
  cannot be mounted — the same "one lost factor away from losing everything" tradeoff the enrollment
  docs already flag. A recovery path (an escrowed higher-counter re-seal, or an opt-out) must be
  specified, and the risk stated to the user.
- **Composes with, does not replace, Merkle / per-sector auth.** Those detect modification; this adds
  freshness. Bind this PoC's `state_root` to the Merkle root so one counter protects the whole volume's
  integrity state at once.
- **TOCTOU at mount.** The counter must be read and the binding checked *before* the volume is exposed,
  and re-sealed atomically on unmount; the ordering discipline belongs in the integration.
- **Scope.** Replay/freshness of the user's own volume state is integrity/access-control infrastructure —
  well inside the project's boundary.
