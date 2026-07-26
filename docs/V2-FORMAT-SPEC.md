# v2 on-disk format — design spec (T1-1)

**Status: DESIGN ONLY. Owner-gated, NOT built.** This spec records the intended v2 format so it can be
reviewed before any code exists. It fixes the three owner decisions captured in
`handoff/TASK-TRACKER.md` (§T1-1 design inputs) into a concrete layout and mount algorithm, and states a
**deniability-impact line for every v2 feature** as the D-10 hard rule requires. Nothing here is
implemented; the crypto primitives it composes (HCTR2, Adiantum, keyed-BLAKE3 per-sector auth, HKF mix
v2) are each already proven in isolation — see the cross-references.

## The hard rule (D-10)

> **No v2 feature may reduce deniability below v1. A feature that does is descoped, not shipped.**

Deniability here means the property `docs/THREAT-MODEL.md` protects: the **existence of a hidden volume**
inside a decoy's free space is not detectable. It does **not** mean "the outer/decoy volume is secret" —
the decoy is openly a VeraCrypt volume whose password the user surrenders under coercion. So the test for
every v2 feature is narrow and specific: *does this feature give an examiner any new way to tell a
decoy-with-hidden-volume from a decoy-only volume?* If yes, it is out.

## Decisions this spec implements (owner, 2026-07-24)

1. **Wide-block mode selector — store nothing; derive/trial the mode at mount.**
2. **v1/v2 detection — trial-derivation loop** (try v2 interpretations, fall back to v1), mirroring the
   existing HKF mix v2→v1 loop.
3. **Per-sector MACs — a full-volume MAC table** (fixed size over *every* data sector; slots for
   never-written sectors hold keystream, indistinguishable from real tags).

## What v1 looks like today (the baseline we must not regress)

Per `src/Common/Volumes.h`, one VeraCrypt volume occupies a 64 KiB **header area** with a 4× group
(primary-normal, primary-hidden, backup-normal, backup-hidden), data starting at 128 KiB
(`TC_VOLUME_DATA_OFFSET`). Within the first 512 bytes of a header:

```
offset 0    : 64-byte PKCS5 salt          (PLAINTEXT, random)
offset 64   : encrypted region (XTS under the header key) — MAGIC "VERA", version, required-version,
              key-area CRC, timestamps, sizes, flags, sector size, header CRC, master keydata (256..511)
offset 512.. : header-area slack [512, 64K) — random (keyslots already bind here, docs/KEYSLOTS-SPEC.md)
```

The data area is XTS-encrypted, **unauthenticated**, and its free space is indistinguishable from
random — which is exactly what makes a hidden volume deniable. **Every one of these properties must
survive v2.**

## v2 at a glance — what changes and what does not

| Element | v1 | v2 | On-disk visibility |
|---|---|---|---|
| 64-byte salt | plaintext random | plaintext random | **unchanged** |
| Header encrypted region | XTS, header key | **XTS, header key (unchanged)** | **byte-identical processing** |
| MAGIC / version fields | present, encrypted | present, encrypted, **untouched** | no new cleartext marker |
| Data-area cipher | XTS | **HCTR2 (AES-NI) or Adiantum (no-AES-NI)**, chosen at creation | random either way |
| Per-sector integrity | none | **full-volume keyed-BLAKE3 MAC table** | random (real tags ∪ keystream) |
| On-disk version/mode marker | — | **none — derived by trial** | nothing to read |

The one structural rule that makes this safe: **the header is processed identically for v1 and v2.**
A single header decryption (XTS, header key) validates MAGIC for both, so the trial loop never needs a
second KDF pass to "find out the version." Everything that distinguishes v2 lives in the **data area**,
where every byte is already required to look random.

## Mount algorithm — trial-derivation (decisions 1 + 2)

```
derive header key from (password [+ HKF factor], salt)      # KDF runs once per mix-variant
decrypt header region (XTS)                                  # identical for v1 and v2
if MAGIC != "VERA": try next mix-variant / fail

# the data-area interpretation is discovered by trial, cheaply (no further KDF):
for interp in [ v2/HCTR2 , v2/Adiantum , v1/XTS(legacy) ]:
    read sector 0 and its MAC-table slot (v2) — location is a deterministic function of volume size
    if interp is v2:  accept iff keyed-BLAKE3 MAC of sector 0 verifies under K_mac[interp.mode]
    if interp is v1:  accept (legacy, no MAC) — only reached if both v2 interpretations failed
    on accept: this is the volume's mode for the whole session
```

**Why the MAC can discriminate the mode — the key, not the ciphertext.** The per-sector tag is over the
sector **ciphertext** (encrypt-then-MAC, per `docs/PERSECTOR-AUTH-SPEC.md`), and the ciphertext bytes on
disk are identical regardless of which wide-block cipher one would *decrypt* them with — so the tag alone
cannot tell HCTR2 from Adiantum. The discrimination therefore comes from a **per-mode
domain-separated MAC key**:

```
K_mac[mode] = keyed-BLAKE3( master_key, "VeraCrypt/v2/mac/" || mode )      # mode ∈ {hctr2, adiantum}
tag_i       = keyed-BLAKE3( K_mac[mode], le64(i) || ciphertext_i )[0..16]
```

At mount, sector 0's stored tag is recomputed under `K_mac[hctr2]` and `K_mac[adiantum]`; **exactly one
reproduces it**, and that identifies the mode — with the tag still over ciphertext (AE order preserved)
and nothing stored on disk. This also gives **anti-downgrade for free**: because the tag binds the mode
through the key, a v2 sector cannot be silently reinterpreted under the other mode or stripped to v1
without failing verification.

The **per-sector MAC is thus the mode oracle**: recomputing one sector's tag under each candidate mode's
MAC key is a cheap symmetric operation, so decisions (1) and (3) compose — the thing that authenticates
data also tells mount which mode wrote it, with no stored selector and no extra Argon2. Cost in the
common case (no HKF factor): **1 KDF + 3 cheap data trials.** With an HKF factor the mix-variant loop
(v2-mix → v1-mix, and the D-1 salt-bound variant) multiplies the KDF count by 2–3; that is inherent to
the mix-version trial and unchanged by this spec.

**Why store nothing (decision 1) is the most-deniable choice.** Against an adversary without the
password, "selector encrypted in the header" and "no selector at all" are equally indistinguishable from
random — but storing nothing removes the *mild creating-hardware fingerprint* that a recorded
HCTR2/Adiantum field would carry (D-4 flagged this), and there is simply no field that a future bug could
ever expose. It still satisfies D-4 "per-volume, not per-machine": the **creator** fixes the mode by how
it writes the body; **mount** discovers it by trial on any hardware, AES-NI or not. This **supersedes**
the D-4 delta's "recorded in a v2 header field" leaning.

## Per-sector MAC table (decision 3) — and the hidden-volume tension it must survive

This is the crux of the whole format, because **authenticated full-disk encryption and hidden volumes
are in direct tension**: naive per-sector integrity over the *whole* volume would make the outer
(decoy) volume's integrity check **fail on exactly the free-space sectors a hidden volume secretly
uses** — which *reveals the hidden volume*. That failure mode is the single thing v2 must not introduce.

### Three separately-evidenced layers — do not collapse

"Authenticated wide-block encryption" is not one claim; it is **three layers with very different
evidentiary standing**, and this spec must not let them be read as a single settled result:

1. **Wide-block confidentiality** — *well supported.* This is exactly what the shipped Adiantum (step
   `[24]`) and HCTR2 (step `[26]`) work covers: a tweakable SPRP over the whole sector, proven against
   official vectors. NIST's cryptographic-accordion effort builds on HCTR2-derived constructions, which
   is itself a reason to **keep HCTR2**. Nothing below weakens this layer.
2. **Authenticated wrapping** — *not built; design pending.* The per-sector MAC table specified here is a
   *design*, gated and unbuilt (see the DESIGN-ONLY status above). HCTR2/Adiantum themselves are **not**
   authenticated (`docs/HCTR2-SPEC.md` "Still not authenticated"); detection is a separate tier that this
   format composes on top. Treat the authenticated-FDE construction as pending review, not as a property
   the mode already provides.
3. **Key-committing security** — *least settled; assume nothing.* Whether the composed construction
   commits to its key (resists a ciphertext that decrypts under two keys) is **not** established here, and
   2026 literature revisits both the birthday-bound ceiling and key-committing security for
   EtE-HCTR2-style robust-AE constructions. No key-commitment property may be claimed or relied on until
   it is separately designed and proven.

The verdict "keep HCTR2" is unchanged — only the **breadth of the robustness claim narrows**: HCTR2 is a
confidentiality mode, the authenticated wrapping is pending design, and key-commitment is an open question.

### Tag-mismatch policy — FAIL CLOSED (owner decision, 2026-07-25)

**On a per-sector tag mismatch at read time, the volume FAILS CLOSED: the read is refused and no data is
returned.** This was an open question until now; `src/Volume/V2FormatBinding.h` carried it explicitly so
it would be decided deliberately rather than inferred later from whatever the I/O layer happened to do.
It is recorded here **before** that layer is built, which is the point.

**The alternative, and why it lost.** *Fail-warn* — surface the mismatch, return the data anyway — is
the policy `docs/ROLLBACK-COUNTER-SPEC.md` chose for the rollback counter, so the precedent existed.
It was rejected here because a warning that can be ignored reduces per-sector authentication to advice:
the adversary this format exists to answer is one who **edits ciphertext**, and under fail-warn the
edited plaintext still reaches the filesystem. Under D-5's posture (maximum security for a small number
of high-risk users), silently-usable modified data is the worse failure.

**The cost, stated plainly because it is real and it is being accepted, not avoided.**

- **One corrupt sector makes that sector unreadable.** There is no bad-block tolerance and no partial
  recovery of a damaged volume through the normal path.
- **This is an availability risk, not a theoretical one.** Flash with wear-levelling can retire a block;
  an interrupted write can leave a sector and its tag inconsistent; ordinary media develop bad sectors.
  Each of those now surfaces as a hard read failure rather than as degraded data.
- **It interacts with the deniability story.** A hidden volume whose outer volume is written over will
  produce tag mismatches in the overwritten region — expected behaviour, but it means "fails closed" is
  a state a legitimate user can reach without any adversary involved.

**Therefore the I/O layer MUST ship a recovery path — this is a requirement, not a nicety.** Without one,
fail-closed converts a single bad sector into a lost volume, which for a disk encryptor is a worse
outcome than the tampering it defends against. The requirement:

1. A **deliberate operator override** that reads past a failing tag. Not a config default, not a silent
   fallback — an explicit action taken by someone who has been told what it means.
2. The override is **logged**, and the fact that it was used is surfaced to the user. An override that
   leaves no trace re-creates fail-warn with extra steps.
3. It is **per-invocation and scoped**, never a persistent volume property. A volume must not be able to
   carry "ignore my tags" as state, or an adversary who can write the header can disable detection.
4. The reserved MAC table is **separable** from the data area, so the override costs nothing structurally
   — this is cheap to build and there is no excuse for shipping the policy without it.

**What this lets the project claim, and what it does not.** With fail-closed plus the override,
`docs/THREAT-MODEL.md` may claim **tamper-evidence**: modified ciphertext is detected and refused rather
than silently returned. It may **not** claim tamper-*resistance* — nothing here prevents an adversary
with write access from destroying data, and a wide-block mode plus a MAC detects and amplifies tampering
rather than preventing it. Nor does it establish key-commitment (see the three-layer note above).

**THE OVERRIDE IS REACHABLE FROM THE PRODUCT (step `[107]`): `--v2-ignore-tags`.** Until this landed, the
four requirements above were satisfied by a C++ API (`Volume::SetV2IgnoreTags`) that **nothing in
`src/Main/` ever called** — so a user whose volume hit a torn write had a volume that failed closed with
no way to recover it. Fail-closed with an unreachable recovery path is exactly the "worse than the
tampering it defends against" outcome this section warns about. How each requirement is now met:

1. **Deliberate** — an explicit CLI switch, never a default, with no configuration-file equivalent.
2. **Logged and surfaced** — a warning at mount time that authentication is disabled, and `--list -v`
   reports `Per-sector authentication: DISABLED (--v2-ignore-tags)` plus `N sector(s) returned WITHOUT
   valid authentication; first at sector M`. Reads happen in the **forked FUSE service**, so the counters
   are carried back through `VolumeInfo` serialization; that channel is explicitly tested, because a
   count that never arrives leaves the override unlogged, which is fail-warn with extra steps.
3. **Scoped** — it lives in `MountOptions`, exists only for the life of the mount, and is never written
   to the volume. A later mount without the flag fails closed again.
4. **Cheap** — unchanged; the table is a separate region.

**A v2 VOLUME IS REFUSED BY KERNEL CRYPTO (dm-crypt), BY DESIGN.** `CoreLinux::MountVolumeNative` maps
the container onto a loop device and lets the kernel do every read and write against the file;
`Volume::ReadSectors` — where tags are verified — is never called. A v2 volume mounted that way would
open normally and have **no tamper detection at all**, with nothing to say so. `MountVolumeNative` now
throws `NotApplicable` for a v2 volume, which is the existing "cannot use kernel crypto" signal, so the
caller falls back to the FUSE service where the MAC is live. **The cost is accepted, not overlooked:
every v2 mount runs at FUSE speed.** Warning-and-continuing was rejected for the same reason fail-warn
was rejected above — a warning that can be scripted past is not a control.

**STATUS: this policy is now LIVE, and demonstrated rather than merely implemented (step `[106]`).**
`--v2-format` creates a volume whose MAC table is populated at creation time; `Volume::Open` discovers
it; `Volume::ReadSectors` verifies before decrypting and `WriteSectors` re-tags after encrypting. On a
real container, flipping one ciphertext bit on disk makes the affected sector's read throw
`V2TagMismatch` with no plaintext returned, an untouched sector still reads, the documented override
recovers the sector and reports `IgnoredMismatchCount`, and a fresh open fails closed again because the
override is never persisted (`verification/realbuild/v2_tamper_e2e.sh`, 20/20, CI-gated).

Two scope limits, stated so the claim is not read wider than it is:

- **The data is still XTS.** `VolumeCreator` hardcodes `EncryptionModeXTS` and `EncryptionAlgorithm`
  offers only XTS, so no volume is wide-block encrypted yet. The MAC authenticates XTS ciphertext — which
  is genuinely useful, since it detects exactly the edits XTS's 16-byte malleability permits — but the
  `V2Mode` value is at present only a **MAC key domain**, not a statement about how data is encrypted.
  Discovery is effectively binary ("this is a v2 volume").
- **Backup-header mirroring of the table is still absent**, so header recovery still drops integrity
  (see "Keys and backup" below). That remains a real-build acceptance item.

### Layout

A contiguous **MAC table** sized for **every** data sector of the volume, placed at a deterministic
offset (a function of volume size). The shipping module (step `[85]`) places it at the **tail of the data
area** (`V2FormatSplitDataArea`), so the **front** of the volume — header group + data start — stays
byte-identical in structure to v1, and a v2 volume is not distinguishable from v1 by its early layout.
Slot width is **16 bytes** (`V2_MAC_TAG_LEN`, a 128-bit truncated tag); the usable data area shrinks by
the table size, and the table region must still be clamped below a hidden-volume start
(`docs/KEYSLOTS-SPEC.md` reasons about the same clamp). For each data sector `i` the table holds one
fixed-width slot:

- **written sectors** → the real tag `keyed-BLAKE3(K_mac, le64(i) ‖ ciphertext_i)[0..16]`
  (`docs/PERSECTOR-AUTH-SPEC.md`, proven step `[21]`);
- **never-written sectors** → **keystream** from the volume's cipher, byte-indistinguishable from a real
  tag.

Because a real tag and a keystream slot are both pseudorandom, the table as a whole is uniform random —
so its *presence and size* leak nothing about *which* sectors are used.

### Geometry and key contract between create and mount — the three ways this silently broke

The table is found by *agreement*, not by a stored pointer: nothing on disk says "this is a v2 volume".
Create writes tags somewhere and mount probes somewhere, and if those two computations disagree by even
one byte — or if the two sides feed the MAC KDF different key material — `V2FormatDiscoverMode` returns
`NONE`, the layer stays inert, and the volume opens **as v1 with authentication absent**. Nothing throws
and nothing is logged. All three of the following were shipping simultaneously while
`v2_sector_mac_io_test` passed 15/15 and `v2_mode_discovery.sh` passed 9/9; step `[106]` found them by
composing create with mount on one real volume. Treat these as the format's binding contract:

1. **The usable/table split is applied EXACTLY ONCE, at header-creation time.**
   `VolumeCreator::CreateVolume` calls `V2Format::SplitDataArea` and stores the resulting *usable* prefix
   in the header's `VolumeDataSize`. `VolumeLayoutV2Normal::GetDataSize()` returns that stored value — so
   on a v2 volume it is **already the usable size**. Anything downstream that splits it again shrinks an
   already-shrunk figure and puts the table inside user data. Mount must likewise treat
   `VolumeDataSize` as the boundary and the table as beginning immediately after it.

2. **The table region must be reserved against the backup header.** For a non-quick Normal volume the
   backup header is written at the **current sequential file position**, which the format loop leaves at
   the end of the usable data — i.e. exactly where the table starts. The population step must therefore
   advance the write position past `V2FormatMacTableBytes(usableSectors, sectorSize)` before returning,
   or the backup header lands on top of the first 128 KiB of tags and the container comes out short by
   the table size. The arithmetic closes exactly: `usable + table == the full data area`, so a correctly
   built v2 container is the size the user asked for, not larger.

3. **The MAC key is derived from the REAL master key, not the master-key field.**
   `VolumeHeader::GetMasterKeys()` returns the entire fixed **256-byte** key field (sized for the largest
   cascade), while `VolumeCreator` derives from the key it actually generated — `EA->GetKeySize() * 2`,
   i.e. **64 bytes** for AES-XTS. Both sides must use the latter length. This one is especially quiet:
   the offsets agree, real tag bytes are read from the right place, and only the HKDF input differs.

The end-to-end guard for all three is `verification/realbuild/v2_tamper_e2e.sh` (20/20), which is the
only check in the tree that composes the create path with the mount path. Its first assertion — *a
`--v2-format` volume opens AS v2* — is load-bearing: without it, every later "the read was refused" is
vacuous, because a read cannot be refused by a layer that is not running.

### ⚠ THE RESOLUTION BELOW IS SUPERSEDED — IT DOES NOT SURVIVE FAIL-CLOSED (step `[107]`)

**Read this before the section that follows.** The resolution below was written on 2026-07-24, *before*
the tag-mismatch policy was decided. It rests entirely on one premise:

> "On reading a sector whose MAC does not verify, v2 treats it as uninitialised / free … it is **not**
> flagged as tampering."

**The policy that shipped is the opposite of that premise.** FAIL CLOSED (owner, 2026-07-25) means a tag
mismatch **refuses the read and returns no data**. "Mismatch = free space" and "mismatch = refuse" are
contradictory behaviours, and every deniability conclusion below is derived from the first one. The two
decisions were taken a day apart and never reconciled.

**The conflict is also structural, not only behavioural.** The MAC table is placed at the **tail of the
outer's data area**; a hidden volume is placed at the **tail of the outer's data area**. They are the
same bytes. Measured on a real 20 MiB outer with a 5 MiB hidden volume
(`verification/realbuild/v2_hidden_guard.sh` steps [1]/[6], originally 6/6 as v2_hidden_collision.sh):

```
outer MAC table = [20212736, 20840448)
hidden volume   = [15597568, 20840448)   <- the table is ENTIRELY inside the hidden volume
```

Demonstrated end to end on real containers: the outer opens with authentication active; creating the
hidden volume is **accepted with no guard and damages nothing yet** (VeraCrypt deliberately does not wipe
the outer's free space); then the first *write* to the hidden volume overwrites the outer's MAC table,
and the outer thereafter **opens as v1 with authentication silently gone**. The damage is deferred past
the moment of decision, which is the worst possible time for it to appear.

So under the shipped policy there are two distinct costs, and both are real:

1. **Availability/integrity:** using the hidden volume destroys the outer's authentication outright.
2. **Deniability (the D-10 concern):** even with the table moved elsewhere, the outer's table still holds
   slots for the sectors a hidden volume occupies. Under fail-closed, an examiner holding the *decoy*
   password sees reads **refused** over precisely the hidden volume's extent, where v1 would have
   returned unremarkable random bytes. That is a new distinguisher that v1 does not have — which is
   exactly what the D-10 hard rule forbids.

**RESOLVED (owner, 2026-07-26): option 1 — mutually exclusive, ENFORCED.** Of the three candidates
(mutually exclusive / revert to fail-open / ship the tell documented), fail-open was rejected because it
gives up tamper detection — an attacker's edit becomes indistinguishable from free space — and
"documented" was rejected because it knowingly ships a deniability regression to the users most dependent
on decoys. So the combination is now refused at creation time:

- `TextUserInterface::CreateVolume` opens the **outer** volume before creating a hidden volume and
  **refuses if the outer is v2**, naming v2 as the reason.
- Detection needs the outer's key, because a v2 tail is indistinguishable from v1 free space without it
  (D-10 working as intended, not an oversight). Hence `--outer-password` / `--outer-pim`, prompted when
  absent and interactive.
- **Unverifiable is treated as unsafe.** A wrong or missing outer password is refused, not assumed
  benign — a wrong password is indistinguishable from "it is v2 and we could not tell".
- `--skip-v2-host-check` is the documented expert/recovery bypass. It is what keeps the hazard
  demonstrable, and the harness uses it to prove the damage is still real.
- The whole guard is inside `#if defined(VC_ENABLE_V2FORMAT)`, so a stock build is byte-for-byte
  unchanged — consistent with the fork's gating convention.

Proven by `verification/realbuild/v2_hidden_guard.sh` (**12/12**), wired into `acceptance.sh` as a
regression guard. It asserts the *specificity* of the guard as well as its existence: a hidden volume
inside a **v1** outer must still be created and must still open, so a guard that refused everything would
fail. **Note the scope limit:** the guard lives in the CLI creation path, which is where hidden-volume
creation is driven in this fork. A GUI wizard path would need the same check — it does not inherit it.

---

### The resolution of the tension — SUPERSEDED, retained for the argument's structure

**v2 provides integrity for what the volume actually wrote — NOT for its free space.** On reading a
sector whose MAC does not verify, v2 treats it as **uninitialised / free**, exactly as v1 treats random
free space — it is **not** flagged as tampering. Consequences, each a deniability-impact line:

- A **hidden volume** lives in the outer volume's free region. The outer's MAC slots for that region are
  keystream; the hidden volume overwrites those sectors with *its own* ciphertext and *its own* MAC
  table. Mounted with the decoy password, the outer sees those sectors as "MAC-mismatch = free" — the
  **same view v1 gives of random free space.** ⇒ **no new tell. Passes D-10.**
- An examiner with the **decoy password** can see which *decoy* sectors are genuinely written (their MACs
  verify) vs free. That is allocation of the *decoy*, which is **not secret** — the user surrendered that
  password. It does **not** reveal the hidden volume (hidden sectors read as free from the outer's view).
  ⇒ **no reduction vs v1.**
- The honest cost: authenticated FDE in v2 is **"integrity for allocated data," not "integrity for the
  whole disk."** Tampering with free-space sectors (where a hidden volume may be) is undetectable by the
  outer volume — but that is **already true in v1** (free space is unauthenticated random), so v2 does
  not regress; it *adds* integrity over allocated data while preserving free-space ambiguity.

### Keys and backup

- `K_mac[mode]` is a distinct sub-key derived from the volume master key by **mode-domain-separated** KDF
  (`keyed-BLAKE3(master_key, "VeraCrypt/v2/mac/" || mode)`), never the raw master key; see
  `docs/PERSECTOR-AUTH-SPEC.md`. The mode separation is what makes the ciphertext tag double as the
  mount-time mode oracle (above) and provides anti-downgrade binding.
- ~~The MAC table and any v2 data-area state **must be mirrored into the backup header group** (the
  3rd/4th 64 KiB slots) or header recovery silently drops integrity — a real-build acceptance item.~~
  **WITHDRAWN — tested and false (step `[107]`).** Three separate things were checked on real v2
  containers rather than assumed:
  1. **Opening via the backup header already discovers v2.** `Volume::Open(useBackupHeaders = true)`
     returns `IsV2() == true` with the identical usable size, because the backup header is produced by
     re-encrypting *the same* `VolumeHeader` object and therefore carries the same stored
     `VolumeDataSize` — which is the only v2 geometry the mount path needs.
  2. **Header restore preserves it.** Both restore paths (internal backup and external backup file) end
     in `CoreBase::ReEncryptVolumeHeaderWithNewSalt`, which calls `header->EncryptNew(...)` on the
     decrypted header object. Fields are carried over verbatim; nothing is recomputed from volume size.
  3. **The table could not be mirrored into a header slot even if it needed to be.** It is one 16-byte
     slot per data sector — 310 KiB for a 10 MiB volume, ~32 GiB for 1 TiB. A 64 KiB header slot cannot
     hold it, so the item as written was never implementable.

  The genuine tail-region risk is not header recovery at all: it is the hidden-volume collision
  documented above. This entry is struck through rather than deleted because "the register named a
  defect the code does not have" is itself worth remembering — the same failure mode as the withdrawn
  ChaCha20-Poly1305 row in `docs/VERIFICATION-ANCHORS.md`.

## Shipping module (`src/Common/V2Format.{c,h}`, step `[85]`)

The format's shippable core exists and is proven two ways (real in-tree `Sha2.c` vs independent python,
byte-identical over 9 REF lines; suite step `[85]`, gated `-DVC_ENABLE_V2FORMAT` / `make V2FORMAT=1`):
`V2FormatDeriveModeKey`, `V2FormatSectorTag`, `V2FormatSectorVerify` (const-time), `V2FormatDiscoverMode`
(the store-nothing mount trial), and the layout math (`V2FormatMacTableBytes` / `V2FormatSplitDataArea` /
`V2FormatSlotOffset`).

**Shipping PRF: HMAC-SHA256 over the in-tree `Crypto/Sha2.c`.** There is no vetted in-tree BLAKE3, and
adding one would be a large unverified dependency; HMAC-SHA256 is the fork's existing MAC workhorse
(DuressToken, KeyslotKdf), so the shipping module adds **no new crypto dependency**. The step-`[84]`
reference PoC proved the same format **logic** with keyed-BLAKE3 — the format is **PRF-agnostic**, and
keyed-BLAKE3 remains the target if a vetted in-tree BLAKE3 is ever added (the two would be selectable by a
PRF-id under the same trial machinery, exactly as HKF mix v2↔v1 already are). Anchors (HMAC-SHA256):
`K_mac[hctr2] = ef82a0ba…`, `tag0 = fecde672…`.

**C++ binding (`src/Volume/V2FormatBinding.h`, step `[86]`).** The mount/create paths reach the module
through a header-only C++ glue (same pattern as `HardwareKeyFactorMix.h`): `V2Format::DiscoverMode`,
`V2Format::SplitDataArea`, `V2Format::ModeIsV2`, in namespace `VeraCrypt`, over plain byte buffers. It is
**link-proven** standalone — a g++ TU drives the real `V2Format.o` + `Sha2.o` and reproduces the step-`[85]`
`tag0` anchor through the C++ layer (exactly as `hkf_cli_test.cpp` link-proves the HKF C module). When
`VC_ENABLE_V2FORMAT` is off the helpers degrade to safe no-ops (`DiscoverMode` → v1), so a stock build is
unaffected. This header is the seam the mount/create call sites plug into.

**Create-side call site — WIRED (real-build compile only).** The cipher-independent half of the create
path is in place, gated `VC_ENABLE_V2FORMAT`: a `--v2-format` CLI switch → `CommandLineInterface::ArgV2Format`
→ `VolumeCreationOptions::V2Format` → `Core/VolumeCreator.cpp`, where `V2Format::SplitDataArea` reserves the
tail MAC table out of `headerOptions.VolumeDataSize` (the usable data the filesystem sees shrinks by the
table; a volume too small to hold a table is rejected). This threads through exactly like the `--quick`
switch. It is **real-build-only for compilation** — the default build (no flag) is byte-for-byte stock, so
CI's compile matrix does not exercise it; validated by inspection against the `--quick` precedent, like the
HKF C++ wiring.

**Remaining (real-build, owner-gated):** the **mount-side** call site — `DiscoverMode` in the mount trial
(Core/Volume open, after unlock, reading data sector 0 + its tag) — plus **writing/populating** the reserved
MAC table at create, backup-header mirroring, and real-media validation. These are **blocked on the
wide-block cipher mode classes** (HCTR2/Adiantum as an `EncryptionMode` + a per-sector MAC I/O layer, i.e.
T2-3/T2-4): there is no mode to select among, no sector-0 ciphertext to read, and nothing to write the table
bytes until those exist. The create-side reservation above is the furthest the format can wire without them.

## HKF-v2 salt binding (D-1) fits here, not separately

The D-1 salt-binding migration (bind the volume salt into HKDF-Extract so the same factor yields a
per-volume key, closing correction R-2) is a **derivation-level** change: existing pre-binding v2 volumes
derive a different key once salt is bound. It rides the **same mix-variant trial** the mount loop already
performs (salt-bound → unbound → v1), so it needs **no** new on-disk field. It is examined by the R22
migration brief (T3-1) before build. See `docs/HKF-MIX-V2-SPEC.md`.

## Anti-downgrade

Because v2 stores no version marker, an adversary might try to present a v2 volume as v1 to strip
integrity. Two things prevent a silent downgrade:

1. The per-sector tag **binds the mode through `K_mac[mode]`** (above), so a v2 sector cannot be
   reinterpreted under the other mode or as unauthenticated v1 without failing verification — the mode
   separation *is* the anti-downgrade binding, at no extra cost.
2. Forging a valid v1 volume from v2 data would require **re-encrypting under the master key**, which the
   adversary does not have — so a keyless downgrade yields mount failure, not silent integrity-stripping.
   A downgrade by someone who *does* hold the password is not a threat (they already have the plaintext).

This is the same parameter-binding principle proven for the header parameters in the anti-downgrade PoC
(step `[23]`, `docs/ROLLBACK-COUNTER-SPEC.md`), applied here at the per-sector-MAC-key level.

## Deniability-impact summary (the D-10 checklist)

| v2 feature | Deniability impact | Verdict |
|---|---|---|
| Header processed as v1 (XTS) | none — byte-identical to v1 | ✅ |
| No stored version/mode marker | none — nothing to read; trial-derived | ✅ (strictly better than a recorded field) |
| Wide-block data cipher (HCTR2/Adiantum) | none — ciphertext random either way, as XTS was | ✅ |
| Full-volume MAC table (keystream in free slots) | none over free space (mismatch = free, not tamper); reveals only decoy allocation to the decoy-password holder | ✅ passes D-10 |
| Salt binding (D-1) | none on disk — trial-derived mix variant | ✅ |

## What is NOT decided here (for the design proper / owner)

- **MAC slot width and table offset formula — DECIDED and implemented** (step `[85]`): 16-byte slot,
  one per data sector, table at the tail of the data area (`V2FormatSplitDataArea`), sized up to a whole
  sector. Still needs real-media validation that the tail placement is clamped below the hidden-volume
  start on an actual decoy/hidden layout.
- **Sector size interaction** — the layout math takes `sectorSize` (512 vs 4096) and is unit-tested at
  512; the create/mount path must pass the volume's real sector size through.
- **Migration UX** — v1→v2 is a re-encrypt (new format), not an in-place flag flip; scope with R22.
- **Verification plan** — before any code: a Python reference for (a) the trial-mount discriminator and
  (b) the MAC-table-with-keystream-free-slots indistinguishability, then the two-way proof against real
  compiled objects, per `CLAUDE.md` §Verification. Regression anchors to be added to the suite.

## Cross-references

`handoff/TASK-TRACKER.md` §T1-1 (decisions) · `docs/THREAT-MODEL.md` (deniability definition) ·
`docs/HCTR2-SPEC.md`, `docs/ADIANTUM-SPEC.md` (the two wide-block modes) ·
`docs/PERSECTOR-AUTH-SPEC.md` (keyed-BLAKE3 per-sector tag) · `docs/HKF-MIX-V2-SPEC.md` (mix + trial
loop) · `docs/DECOY-VOLUME-SPEC.md` (hidden/decoy layout) · `docs/KEYSLOTS-SPEC.md` (header-slack
binding) · `ROADMAP.md` §DESIGN (D-10 entry).
