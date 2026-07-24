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

### Layout

A contiguous **MAC table** sized for **every** data sector of the volume, placed at a deterministic
offset (a function of volume size) between the header group and the data it protects. For each data
sector `i` the table holds one fixed-width slot:

- **written sectors** → the real tag `keyed-BLAKE3(K_mac, le64(i) ‖ ciphertext_i)[0..16]`
  (`docs/PERSECTOR-AUTH-SPEC.md`, proven step `[21]`);
- **never-written sectors** → **keystream** from the volume's cipher, byte-indistinguishable from a real
  tag.

Because a real tag and a keystream slot are both pseudorandom, the table as a whole is uniform random —
so its *presence and size* leak nothing about *which* sectors are used.

### The resolution of the tension (state this explicitly)

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
- The MAC table and any v2 data-area state **must be mirrored into the backup header group** (the 3rd/4th
  64 KiB slots) or header recovery silently drops integrity — a real-build acceptance item.

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

- **MAC slot width and table offset formula** — fix the exact bytes-per-sector overhead and the
  size→offset function; validate the table never collides with the hidden-volume start
  (`docs/KEYSLOTS-SPEC.md` already reasons about clamping below the hidden start).
- **Sector size interaction** — MAC-table sizing across 512 vs 4096-byte sectors.
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
