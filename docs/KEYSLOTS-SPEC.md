# Multiple keyslots — design spec & status

**Status: core built and verified; CLI + on-volume mount integration is the remaining (real-build)
step.** The keyslot record crypto (`src/Common/Keyslot.{c,h}`), the three-backend store
(`src/Common/KeyslotStore.{c,h}`), and the shipping KDF binding (`src/Common/KeyslotKdf.c`) are built,
gated behind `-DVC_ENABLE_KEYSLOTS` (`make KEYSLOTS=1`), and verified — the wrapping two ways
(build_and_verify.sh `[8]`) and the full add/open/rotate/revoke lifecycle across the labeled and
deniable backends end-to-end against the real modules (`[9]`). What remains is the CLI surface and the
mount-time slot search wired to real volume I/O (§9), which cannot be exercised in a sandbox.

This is the one item in the project that deliberately introduces a **fork-only on-disk format** (every
other feature mixes into the password pool and leaves the header untouched). It is the enabling
primitive for per-person keys, key **rotation**, **revocation**, and a real duress **keyslot** — none
of which are possible with VeraCrypt's single password/keyfile set.

Two decisions frame this spec (chosen up front):
- **Fork-only.** A keyslotted volume need not open in stock VeraCrypt 1.26.29. (Same stance already
  taken for hardware-factored volumes.)
- **All three storage backends**, user-selectable behind one seam — mirroring how
  `HardwareKeyFactor` exposes YubiKey/FIDO2/simulator/raw behind one interface.

---

## 1. The model: one master key, many wrappings

VeraCrypt encrypts the volume body under master keys stored (encrypted) in a 512-byte header; that
header is itself encrypted under `HeaderKey = PBKDF2/Argon2(password, salt)`. There is exactly **one**
such wrapping — one password opens the volume.

Keyslots generalise this the way LUKS does, **without re-encrypting the volume body**:

- The **volume master-key material (VMK)** — the plaintext of VeraCrypt's 512-byte header, i.e. the
  concatenated primary + secondary (XTS) master keys — never changes.
- **Slot 0** is the native VeraCrypt header (the primary password's wrapping), left exactly as-is.
- **Slots 1..N** are *additional independent wrappings of the same VMK*, each under its own
  passphrase/factor, stored in one of the three backends below.

To open the volume, any one slot's passphrase unwraps the VMK → mount. To add a key, wrap the VMK
under a new passphrase and write a slot. To revoke, delete a slot. To rotate, add the new slot then
delete the old. The body is never touched. Because slot 0 is the untouched native header, a factored
or hidden volume keeps every property it already had.

## 2. Per-slot wrapping crypto (PROVEN — `verification/keyslot_poc.c`)

Each slot record is a self-contained authenticated wrapping of the VMK. The construction, and its
byte-for-byte proof against an independent Python reference over the **real** in-tree `Sha2.c` and
`chacha256.c`, are in `verification/keyslot_poc.c` + `keyslot_reference.py` (build_and_verify.sh step
`[8]`):

```
dk     = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, 72 bytes)   # KDF (real: derive_key_sha512 in-tree)
encKey = dk[0..32)   iv = dk[32..40)   macKey = dk[40..72)
ct     = ChaCha20(encKey, iv) XOR VMK          # confidentiality
tag    = HMAC-SHA256(macKey, header || ct)     # authenticity AND "does this passphrase own this slot?"
record = header || ct || tag
```

- **Opening** recomputes `dk`, recomputes the MAC, and **constant-time-compares** it to the stored
  tag: a match means this passphrase belongs to this slot; a mismatch yields nothing (wrong
  passphrase, or not this slot). Only on a match is `ct` decrypted to the VMK.
- **Encrypt-then-MAC**, independent per-slot salt, and the MAC-as-slot-selector mean slots are
  mutually independent: compromising or deleting one reveals nothing about the others.

Record layout (fixed, little-endian; `MK_LEN` = VMK length):

| field | size | notes |
|---|---|---|
| magic | 4 | `"VCKS"` (0x56434b53) |
| version | 1 | 1 |
| kdf_id | 1 | 1 = PBKDF2-HMAC-SHA512 (ship), 2 = Argon2id |
| flags | 1 | bit0 = **duress slot** (see §5) |
| reserved | 1 | 0 |
| *(kdf params: iterations / Argon2 m,t,p)* | var | per kdf_id |
| salt | 32 | per-slot CSPRNG |
| ct | MK_LEN | ChaCha20-wrapped VMK |
| tag | 32 | HMAC-SHA256 |

> **AF-split records (v2, step `[36]`):** with `KeyslotStoreCfg.afStripes = s ≥ 2` the payload is
> AF-split (`src/Common/AfSplit.{c,h}`, `docs/AF-SPLIT-SPEC.md`) before wrapping, so `ct` grows to
> `s·plen`. Labeled records then carry `version = 2` and `s` in the tag-authenticated reserved
> field (informational, like the stored cost — the operative value is the public config, keeping the
> constant-time search's per-slot work fixed); bare/deniable records stay field-free. `s` is bounded
> by the 1024-byte stride (`46 + s·plen + 32 ≤ 1024`); 0/1 leaves the record byte-identical legacy.

> **Ship note:** the PoC uses PBKDF2-HMAC-**SHA256** + ChaCha20 because those compose from primitives
> already proven this session and link cleanly in the harness. The shipping module should use the
> in-tree **`derive_key_sha512`** (PBKDF2-HMAC-SHA512, the same KDF VeraCrypt already trusts, with a
> PIM-scaled iteration count) for `kdf_id=1`; the record/MAC structure is unchanged. Anchor for the
> PoC construction: slot record begins `56434b53…` (see the regression value in the harness output).

## 3. Storage backends (one seam, three locations)

The slot **record** above is identical across backends; they differ only in **where** it is written
and **how** a candidate slot is located. A `KeyslotStore` interface (mirroring `HKFBackend`) abstracts
`enumerate / read / write / erase`, with three implementations:

### 3a. In-header keyslot table — `KSB_HEADER`
VeraCrypt reserves a **64 KiB region** for the primary header (`TC_VOLUME_HEADER_SIZE`) but only the
first **512 bytes** (`TC_VOLUME_HEADER_EFFECTIVE_SIZE`) are the real header; the remaining ~63.5 KiB is
random-filled slack. Slots 1..N live there as a fixed table (e.g. 32 slots × record size, still «1 KiB
each). No new regions, no shift of the data area (`TC_VOLUME_DATA_OFFSET` unchanged).
- **Pros:** simple, self-contained in the volume, backup/restore "just works", clean rotation/revoke.
- **Cons / deniability:** a populated table in that slack is a **visible "this volume has N keys"
  structure** — it undermines hidden-volume deniability and marks the volume as non-stock. Acceptable
  when deniability is not the goal (you want split trust / rotation / revocation), not when it is.

### 3b. Deniable free-space slots — `KSB_DENIABLE`
Slot records are written into the volume's **free space** (which VeraCrypt already fills with random
data), at an offset **derived secretly from the slot passphrase** — so without the passphrase you can
neither find the record nor prove it exists (a record is indistinguishable from the random fill).
- *Discovery:* `offset = KDF_offset(passphrase) mod usable_free_space`, sector-aligned; read there,
  attempt unwrap, accept on MAC match. A small deterministic probe sequence handles collisions.
- **Pros:** the **number and presence of extra keys is deniable** — the only backend that keeps the
  project's deniability ethos.
- **Cons / honesty:** inherits every hidden-volume limitation — **multi-snapshot** (writing a slot
  changes free space; repeat imaging can reveal it), **SSD** TRIM/wear-leveling remnants, and the risk
  of **colliding with a real hidden volume's area** (the enroller must respect the hidden-volume
  reserved region). Capacity is bounded and a slot can be overwritten by later file writes unless the
  region is treated as reserved. This is the hardest backend and carries the loudest caveats.

### 3c. Sidecar keyslot file — `KSB_SIDECAR`
Slot records live in a separate file/device (e.g. `volume.vcslots`); **the volume header is untouched**
(this backend alone keeps the "no on-disk change to the volume" invariant).
- **Pros:** zero on-disk cost to the volume; trivially backed up/rotated; the volume looks exactly
  stock.
- **Cons:** the sidecar's **existence is a tell**, and it is a **loss/availability risk** (lose it and
  those slots are gone — though slot 0 / the primary password still opens the volume). Best when the
  sidecar can live somewhere its presence is unremarkable (a token, a server, a keyring).

## 4. Operations

- **Enroll (`--keyslot-add`):** open the volume via any existing slot to recover the VMK, `keyslot_wrap`
  it under the new passphrase/factor, write the record via the chosen backend. A slot may itself be
  gated by a HardwareKeyFactor (the slot passphrase is mixed with a token response first) — keyslots
  and the existing factor seam compose.
- **Open (mount):** for each slot the backend yields, `keyslot_unwrap`; first MAC match → VMK → mount.
  Slot 0 (native header) is always tried, so the primary password always works.
- **Rotate:** add new slot, verify it opens, then erase the old (overwrite its bytes with fresh random).
- **Revoke (`--keyslot-kill N`):** overwrite slot N with random. The VMK is unchanged, so revocation is
  instant and needs no body re-encryption — **but** an attacker who copied the disk earlier still holds
  the old wrapping (state this: revocation protects future access, not a past image).

## 5. Duress keyslot (supersedes the local salt+tag)

A slot with `flags.bit0 = duress` does not unwrap to the VMK; on a MAC match it **triggers
`UserInterface::DuressDismount()`** (dismount all + scrub RAM, mount nothing — see
`docs/DURESS-DISMOUNT-SPEC.md`). This is a strictly stronger home for the duress passphrase than the
current local `--duress-salt/--duress-hash`: the duress secret rides *inside the volume's keyslot
area* instead of a separate config, so there is no external "a duress scheme exists" tell — its
deniability is exactly that of the chosen backend (fully deniable under `KSB_DENIABLE`).

## 6. Deniability & threat model (honest, per backend)

| backend | extra-key presence | stock-mountable | multi-snapshot / SSD | best when |
|---|---|---|---|---|
| header table | **visible** | no | n/a (in header) | you want rotation/revocation/split-trust, deniability not required |
| deniable free-space | **deniable** | no | **weak** (same as hidden volumes) | deniability is the goal; accept the hidden-volume caveats |
| sidecar | volume clean; sidecar is a tell | yes (volume) | n/a | the sidecar can live somewhere unremarkable |

Cross-cutting honesty (consistent with `docs/THREAT-MODEL.md`): **revocation does not reach a disk
image taken earlier**; **imaged-first** defeats any on-disk change; and a **duress keyslot** is only as
deniable as its backend. None of this fabricates evidence — it is access-control storage, and the
DESCOPED evidence-fabrication boundary stays where it is (`ROADMAP.md`).

**Indistinguishable (factor-gated) slots need no format work — but ship them as access-control
convenience, never as a standalone deniability claim.** VeraCrypt's on-disk format already has **no magic
bytes** and presents as a 64-byte random salt followed by ciphertext, and this fork's existing
**factor-mixing** (`docs/HARDWARE-2FA.md`, mixed into the password before PBKDF2) already yields
factor-gated access with **no on-disk change** — a slot that opens only with the extra factor is
indistinguishable from a plain volume without it. That is worth shipping as **multi-factor access
control** (split trust, hardware second factor, threshold). It is **not** a standalone deniability
mechanism: an adversary who knows the tool ships factor-gating knows a hidden factor *may* exist and can
re-coerce (see `docs/THREAT-MODEL.md`, the Canetti-sense and decoy-can-aggravate notes), and the
multi-snapshot / media limits apply unchanged. Do not market indistinguishable slots as deniability.

## 7. Migration & compatibility

Fork-only. A `--keyslot-enable` step reads the volume with the primary password, recovers the VMK, and
initialises the chosen backend (writing an empty table / preparing the sidecar). No body
re-encryption, ever. Slot 0 remains the native header, so the volume still opens with the primary
password on this fork exactly as before; only slots 1..N require the fork.

## 8. Modules & what is proven

Built (gated `-DVC_ENABLE_KEYSLOTS`):
- `src/Common/Keyslot.{c,h}` — the record wrap/unwrap: `KeyslotWrapWithDK/UnwrapWithDK` (pure, the
  crypto proven in `[8]`) and passphrase-based `KeyslotWrap/Unwrap` over a pluggable `KeyslotKdfFn`.
- `src/Common/KeyslotStore.{c,h}` — the `KeyslotArea` medium abstraction and all three backends
  (`KSB_HEADER` / `KSB_SIDECAR` labeled table; `KSB_DENIABLE` bare records at a passphrase-derived
  slot), with `KeyslotAdd/Open/Revoke/Count`. The wrapped payload is `flags[1] || vmk`, so the duress
  bit and every other flag are encrypted, never marked in the clear.
- `src/Common/KeyslotKdf.c` — the shipping `KeyslotKdfSha512` binding to the in-tree
  `derive_key_sha512` (PBKDF2-HMAC-SHA512), kept in its own TU so only it pulls `Pkcs5`.

**Constant-time search** (P0 hardening): `KeyslotOpen` scans a fixed number of slots and runs the KDF,
MAC, and decrypt on *every* slot via `KeyslotUnwrapCT` (always-decrypt), using the config's cost and
length rather than the possibly-random stored bytes, and selects the match in constant time with no
early return. This leaks neither which slot matched nor how many are populated. The cost is one KDF per
table slot per open (the standard LUKS trade-off); size the table accordingly.

Proven:
- **Wrapping crypto, two ways** — real compiled `Sha2.c`/`chacha256.c` vs. an independent Python
  reference, byte-for-byte; round-trip + wrong-passphrase rejection (`verification/keyslot_poc.c`,
  step `[8]`, anchor `56434b53…`).
- **Store lifecycle, end-to-end against the real modules** — add / open / rotate / revoke on the
  labeled backend, the encrypted duress flag round-tripping, and the deniable backend's
  passphrase-derived placement + non-enumerability (`verification/keyslot_store_test.c`, step `[9]`).

## 9. Integration seam — bindings built (step `[37]`); mount/CLI glue remains (real-build)

The volume-I/O seam is now shipping code: **`src/Common/KeyslotAreaFile.{c,h}`** (gated
`VC_ENABLE_KEYSLOTS`) binds all three backends over portable stdio for container files and sidecars,
with every access bounds-checked against the bound window:

- `KeyslotAreaBindHeaderSlack` — the primary header's reserved slack
  `[TC_VOLUME_HEADER_EFFECTIVE_SIZE, TC_VOLUME_HEADER_SIZE)` = `[512, 64K)` (63 slots). Proven in
  step `[37]` on a synthetic container: the real 512-byte header, the hidden-header region and the
  data region stay **byte-untouched**, and slots survive a close + cold reopen through real file I/O.
- `KeyslotAreaBindSidecar` — the whole sidecar file.
- `KeyslotAreaBindDeniable` — a caller-supplied free-space extent, **clamped below the
  hidden-volume reserved start** so bare records can never land in hidden space. Step `[37]` also
  proves the snapshot behaviour honestly: a before/after diff is confined to exactly one stride slot
  inside the bound window, the rewritten slot carries no plaintext markers and passes monobit /
  chi-square screens against the random fill — and the diff **does** reveal that a slot changed:
  the multi-snapshot location leak is asserted in the test as the documented limitation
  (`docs/THREAT-MODEL.md`), not hidden.
- AF-split records (`[36]`) compose through the file bindings (tested).

**Built and proven on a real volume** (step `[6-realbuild]`, `docs/REAL-BUILD-VALIDATION.md`):

- **C++ mount-path binding** — `Volume/KeyslotVolumeBinding.h` binds the header-slack window over the
  app's `File` class (`kdf` → `KeyslotKdfSha512`, `randBytes` → `RandomNumberGenerator`), and
  `VolumeHeader::GetMasterKeys()` / `GetMasterKeyDataSize()` surface the VMK on a successful open.
- **CLI** — `--keyslot-add` / `--keyslot-open` / `--keyslot-rotate` / `--keyslot-kill N` /
  `--keyslot-list` (`Main/CommandLineInterface.cpp`, `Main/UserInterface.cpp::KeyslotCommand`). Each
  recovers the VMK with `--password` via the native header **or** an existing keyslot, then runs the
  matching store op on the header-slack backend. `KeyslotOpenAt` (`Common/KeyslotStore.c`) is the
  admin-side per-index open rotation uses to locate the slot to retire (distinct from the
  constant-time `KeyslotOpen` used for opening). Proven: enroll→open (exact master-key match)→wrong-pass
  reject→add/kill→rotate→duress-flag round-trip, with slot 0 and the body byte-untouched throughout.

All three backends are selectable from the CLI via `--keyslot-backend header|sidecar|deniable`
(`Volume/KeyslotVolumeBinding.h` binds each window over the app `File`; the CLI opens a sidecar with
`--keyslot-sidecar <path>`, created + random-filled to 64 KiB on first use). Proven on a real volume
(acceptance harness):

- **sidecar** — slots live in a separate file; the **volume container is byte-identical** after
  add/open, and the slot recovers the exact master key.
- **deniable** — a bare record at a passphrase-derived offset in the container's data region; the
  **header region `[0, 64K)` is byte-identical**, the slot opens with its passphrase and recovers the
  master key, and a wrong passphrase opens nothing. The slot is not enumerable (`--keyslot-list`
  reports this by design).

**Mount-time auto-search — built and proven** (`Volume/Volume.cpp`). A plain `--mount` whose password
does not open any native header now falls through to the header-slack keyslots (`Volume::Open` builds a
read-only `KeyslotArea` over the volume `File` and calls `KeyslotOpen`):

- a **normal** matching slot recovers the effective header plaintext (the keyslot payload — now the
  full 448-byte `Deserialize` input, not just the master keys), rebuilds the header via
  `VolumeHeader::RebuildFromKeyslot` (zero-padding the reserved tail no field/CRC covers), and mounts
  from it **without re-deriving the header key**;
- a slot flagged `KEYSLOT_FLAG_DURESS` throws `KeyslotDuress` (registered in the volume exception set,
  so it crosses the CoreService boundary), which the CLI catches to run the safe duress action
  (dismount all + scrub, **mount nothing**).

Proven on a real volume (acceptance harness): a plain `--mount` with a normal slot passphrase recovers
the VMK, rebuilds the header, and reaches the kernel `dmsetup` step (would mount on a real kernel); a
plain `--mount` with a duress slot passphrase fires the duress action and never touches the volume; a
wrong passphrase is rejected. Only the final dm-crypt table load is unexercised in a sandbox (the
universal Tier-2 boundary).

Remaining, real-build only (needs the kernel / real media):
- **Backup-header mirroring** — the backup-header group at volume end mirrors the primary group; a slot
  table in the primary slack is not mirrored automatically, so restoring a backup header will not
  restore slots unless the restore path learns to mirror the table.
- **Deniable-backend multi-snapshot robustness** must be validated on real media (same caveat class as
  hidden volumes, `docs/THREAT-MODEL.md`): a before/after image diff reveals that *a* slot-sized region
  changed, though not its contents (step `[37]` asserts this bound honestly).

## 10. Design backlog (documented here; NOT implemented) — record versioning & naming

Two `[FORMAT]`-adjacent design items a future session should carry (design only; do not implement without
a format review):

- **Record format-version + checksum + anti-relocation field.** Keyslot records currently carry no
  explicit format-version byte, no self-checksum, and no anti-relocation binding — integrity rests on
  the wrap MAC and KDF-parameter validation at read time. A robust on-disk format should add, mirroring
  **LUKS2's `csum` / `csum_alg`** (per-metadata-object checksum with a named algorithm): (1) a
  **format-version** byte so the reader can reject/upgrade unknown layouts instead of misparsing; (2) a
  **checksum** over the record so silent corruption is caught before the MAC path; and (3) an
  **anti-relocation** field binding the record to its slot index / area offset so a valid record cannot
  be copied to another slot (the same index-binding idea as the per-sector auth tag,
  `docs/PERSECTOR-AUTH-SPEC.md`). These change the on-disk record, so they are a format decision, not a
  drop-in.
- **Backup-header table mirroring** — already flagged in §9 as real-build-remaining; tracked here too so
  the restore-path work (mirror the primary slack table into the backup-header group) is not lost.

**Naming precision (do not "fix" by renaming).** `KSB_SIDECAR` is a **keyslot sidecar**, not a "detached
header": it keeps **slot 0 in-volume** (the native VeraCrypt header stays on the data device), and only
the *extra* slot table lives in the sidecar file. The LUKS2 contrast worth documenting is that a **true
detached header** leaves the data device with **no signature at all** — a stronger deniability posture,
and a different feature. Do not relabel `KSB_SIDECAR` as a detached header; if a real detached-header
mode is ever wanted, it is a separate backend.
