# Factor-gated decoy volume — design & status

**Status: Phase 1 implemented and verified. Phases 2–3 are design notes; the Phase 3 "keep-warm"
staging daemon is deliberately out of scope (see §6).**

This builds a coercion-resistant *appear-to-comply* option on top of VeraCrypt's existing hidden
volume: the outer (decoy) volume opens with a password alone, while the inner (real) volume
additionally requires the hardware factor. Under coercion you can surrender the password; the real
volume still cannot be opened without the token.

It reuses VeraCrypt's two-header hidden-volume layout unchanged — the decoy filesystem spans the
whole container and the real data hides in its free space, so there is **no size mismatch to
explain** and no on-disk format change. The only additions are (1) factor-gating the hidden header
and (2) the operational guidance below.

---

## 1. Threat model (be honest about this)

**Provides:** a defensible endpoint under coercion. "There is no second password" is literally true
— the second door needs a physical token, not a memorized secret. With the threshold/split-key
factor it is impossible to open the real volume alone, so coercing one person in isolation yields
nothing.

**Does NOT defend against** (state these to any user):
- **Repeat imaging / multi-snapshot.** Using the hidden volume writes into the decoy's "free" space;
  an adversary who images the disk twice can detect that. Booting/mounting a decoy does not fix the
  underlying deniability weakness. (Fredrickson, Barker & Long, "A Multiple Snapshot Attack on
  Deniable Storage Systems," 2021.)
- **SSDs.** TRIM leaks the free-space map and the FTL's out-of-place writes / wear-leveling can
  retain fragments — including of the hidden-volume creation itself. Classic hidden-volume
  deniability is weak on flash; treat it as such.
- **Discovery of the tooling.** Any artifact that reveals a decoy scheme exists undermines the whole
  thing (see §6).
- **Imaged-first.** If the adversary copied the disk before coercing, the copy is unaffected — but,
  unlike destructive duress, you still have something to hand over.

Destructive "duress wipe" is strictly worse than this for the same goal: a wipe destroys deniability
(a header flipping from valid to random *proves* you triggered destruction) and can escalate the
situation, whereas a decoy gives you something to *give*.

---

## 2. Mechanism (Phase 1 — implemented)

VeraCrypt already tries the entered password against each volume layout (outer header at offset 0,
hidden header at 64 KiB) and mounts whichever decrypts. The change is *which secret is tried against
which header*:

- **Outer / decoy header** → key derived from **password only** (factor not mixed).
- **Hidden / real header** → key derived from **password + hardware factor**, via the existing
  `HKFMixPassword` / `HKFApplyIfConfigured` seam.

A new policy field selects behaviour:

| `HKFConfig.applyPolicy` | Effect |
|---|---|
| `HKF_APPLY_ALL` (default) | factor gates whichever header derives — a normal factor-protected volume, unchanged from the base hardware-factor feature |
| `HKF_APPLY_HIDDEN_ONLY` | factor gates the hidden header **only**; the outer (decoy) header derives from the password alone |

The decision is made where the layout type is known, by the pure function
`HKFShouldApply(cfg, layoutIsHidden)`:

- mount: `Volume/Volume.cpp` passes `HKFShouldApply(g_hkfActiveConfig, layout->GetType() ==
  VolumeType::Hidden)` into `VolumeHeader::Decrypt` as the new `applyHardwareFactor` gate (defaulted
  `true`, so no other caller changes).
- create: `Core/VolumeCreator.cpp` gates each derive site (primary **and** backup header) on
  `HKFShouldApply(cfg, options->Type == VolumeType::Hidden)`, so the hidden volume's headers are
  factor-gated and the decoy's are not.

**Files:** `decoy-hkf-hooks.patch` (Volume.cpp + VolumeHeader.cpp + VolumeCreator.cpp) plus the
updated `Common/HardwareKeyFactor.{c,h}` (`applyPolicy`, `HKFShouldApply`). No header-format change.

### Verified

`verification/hkf_decoy.cpp` builds a two-header container with the real `Pkcs5HmacSha3_512` KDF and
the real `HKFMixPassword`, and confirms:
- `HKFShouldApply`: `HIDDEN_ONLY`→(normal 0, hidden 1); `ALL`→(1,1); no factor→(0,0).
- **Password only, no token** → opens the decoy, **cannot** open the real volume.
- **Password + token** → opens the real volume.
The real-hardware USB round-trip remains the one thing to test on your own device.

---

## 3. Container layout (Phase 1)

Standard VeraCrypt hidden-volume container. Create the hidden (real) volume with headroom, and keep a
decoy fill cap = `container − real − margin` so decoy use never encroaches on the real region.
Mounting the outer with hidden-volume *protection ON* (when you hold both secrets) prevents decoy
writes from corrupting the real data.

---

## 4. Staged decoy content (Phase 2 — design only, not implemented)

For the decoy to be worth surrendering it must look like a real, mildly-sensitive dataset that
*explains why it was encrypted* (e.g. financial/personal documents), with realistic clutter and a
coherent persona — not an empty or too-clean volume. The consistency bar is: filesystem timestamps
spread over time, in-file timestamps (document metadata, EXIF) agreeing with them, and any
application artifacts consistent with the file set. This phase is a content-preparation helper only;
it is not implemented here.

---

## 5. Where a full decoy OS would live (not this seam)

VeraCrypt's **Hidden OS** already implements a bootable decoy OS + hidden OS, but it lives in the
pre-boot bootloader (DCS/EFI), is MBR/legacy-BIOS only (no GPT/UEFI), and is a separate, heavier
integration surface from the header-derivation seam used here. Phase 1's factor-gating applies to the
container/hidden-volume path, not to the boot path.

---

## 6. Out of scope: automated "keep-warm" staging daemon (Phase 3)

The original sketch included a background process that would automatically advance a decoy's apparent
state over time — forging activity timestamps and injecting synthetic usage history so a decoy looks
like a lived-in daily driver under forensic examination.

**This is intentionally not built and not specified here.** Access control and deniable *storage*
(everything in Phases 1–2) protect data you hold; a tool whose function is to *manufacture a false
record of activity that never happened, specifically to defeat forensic examination,* is
evidence-fabrication, and it is most useful against exactly the legitimate investigative processes
that the sympathetic threat model is not about. The honest way to keep a decoy believable is to
actually use it periodically (which VeraCrypt's own guidance recommends), not to synthesize a fake
history.

If believability against a sophisticated adversary is the requirement, the sound direction is the
access-pattern-hiding research (write-only ORAM: HIVE, DataLair) and honest user guidance about the
multi-snapshot and SSD limitations in §1 — not fabricated artifacts.

---

## 7. Suggested phasing

1. **Phase 1 (done):** factor-gated hidden header — mount + create + backup, verified.
2. **Phase 2 (optional helper):** decoy content preparation with the §4 consistency checks.
3. **Phase 3:** not planned (see §6).
