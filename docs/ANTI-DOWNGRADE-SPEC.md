# Header-version + anti-downgrade parameter binding

**Status: binding construction + downgrade-detection proven; wiring into the real header MAC is
real-build.** Addresses `IDEAS-BACKLOG.md` §A ("Header version + anti-downgrade binding") — the small
capstone that closes §A's integrity tier, and the cheapest of the integrity items.

## The gap it closes

A volume header records the parameters the software must use to open it: the KDF (Argon2id memory,
iterations, parallelism), the PRF, the cipher and mode, and a format version. If those bytes are not
authenticated, an attacker who can write to the header can **downgrade** them — set Argon2 memory to
8 KiB, select a weaker PRF, roll the version back to one with a known weakness — hoping the victim's
software silently re-derives under the weakened parameters. That either makes the victim's own
derivation cheap to brute-force offline, or steers them onto a broken code path. This is the classic
downgrade/rollback-of-parameters attack (the reason TLS, LUKS2, and Signal all authenticate their
negotiated parameters).

The fix is to **bind every negotiated parameter into an authenticator** so any edit is detected and the
volume **fails closed** rather than deriving under attacker-chosen weak parameters.

## Construction

```
canonical(params) = fixed-width big-endian, no field-boundary ambiguity:
    version:u16 | prf_id:u16 | cipher_id:u16 | mode_id:u16 |
    argon_mem_kib:u32 | argon_iters:u32 | argon_parallelism:u8        (17 bytes)

binding_key = KDF(password, salt)          # the header key; params under test, not the KDF itself
param_tag   = HMAC-SHA256(binding_key, canonical(params))
verify:     recompute param_tag; constant-time compare; refuse the volume on mismatch
```

- **Fixed-width canonical encoding** is essential: variable-length or delimiter-based encodings let an
  attacker shift bytes across field boundaries to make two distinct parameter sets serialize
  identically. Every field here is a fixed-width big-endian integer, so the serialization is injective —
  distinct parameters ⇒ distinct bytes ⇒ distinct tag.
- **Keyed from the password.** Because `binding_key` derives from the password, an attacker who edits the
  header cannot recompute a matching tag without the password — so the check is an authenticator, not a
  mere checksum.
- `HMAC-SHA256` drives the in-tree `Crypto/Sha2.c`.

## What the PoC proves (`verification/downgrade_poc.c` + `downgrade_reference.py`, step `[23]`)

Proven the two ways the fork requires — the C PoC drives the **real in-tree SHA-256**; an independent
Python reference (`hashlib` HMAC + `struct` serialization) reproduces every value byte-for-byte over 13
vectors (anchor `param_tag = 0692cc06…`, `canon_base = 0002000300010002001000000000000304`, for the
RFC-9106-class baseline `mem=1 GiB, iters=3, parallelism=4`):

- **Accept baseline** — the correct parameter set verifies.
- **Every downgrade rejected** — weakening Argon2 memory (1 GiB→8 KiB), iterations, or parallelism;
  selecting a weaker PRF, cipher, or mode; rolling the version back — each changes the tag and is
  rejected. `all_downgrades_detected = YES`.
- **Wrong password rejected** — a different password yields a different `binding_key` and tag.
- **Canonical encoding unambiguous** — swapping the memory and iterations *values* produces distinct
  canonical bytes (the fixed-width layout cannot alias two distinct sets).

## Integration & honest notes

- **Where the tag lives.** The `param_tag` is a small header field. It rides with the keyslot-area MAC
  work (`docs/KEYSLOT-MAC-SPEC.md`) — in fact the parameters can simply be included in the region that
  MAC already covers, making this largely a *canonical-serialization + coverage* task rather than a new
  authenticator. Deciding that overlap is the integration step.
- **Two ways to bind, pick one and document it.** (a) *Detect*: a separate `param_tag` as above, checked
  before use. (b) *Fail-closed by construction*: feed `canonical(params)` into the header-key derivation
  as associated data, so downgraded parameters produce a different key and the VMK unwrap fails on its
  own. (b) needs no extra stored field and cannot be stripped, but couples the KDF change to this work;
  (a) is simpler to add to the existing MAC. The PoC demonstrates (a); the spec recommends folding the
  parameters into the keyslot-area MAC's covered region as the concrete plan.
- **Version field enables safe upgrades.** Binding the version lets future formats change parameters
  without a downgrade being silent: an old version that is genuinely weaker is rejected unless the user
  explicitly re-enrolls at the new parameters.
- **Not secret, just authenticated.** The parameters remain readable (the software needs them to derive);
  binding only prevents *undetected modification*, which is the whole requirement.
- **Scope.** Authenticating the volume's own parameter choices is integrity/access-control
  infrastructure — well inside the project's boundary.
