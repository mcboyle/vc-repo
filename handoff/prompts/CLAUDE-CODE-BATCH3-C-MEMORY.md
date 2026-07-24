# Claude Code task — batch 3 / C: memory-hygiene code items (R16)

**Repo:** `vc-repo`, branch off `master`. **Run after prompts A and B** — this is the lowest-priority of
the three and B writes the doc this work is described in (`docs/KEYS-IN-RAM.md`).
**Gate:** `verification/build_and_verify.sh --strict` exits 0, **0 SKIP**, anchors intact, negative
control still fails.

Two items. **C1 is an investigation that may or may not produce code — do the investigation first and
report before building anything.** C2 is a new advisory module.

---

## C1 — Is re-authentication enforced on resume? *(investigate first)*

**Background, stated precisely, because an earlier analysis of this got it wrong.**

R16 recommends *"a suspend-to-RAM hook that scrubs and forces re-authentication on resume."* An earlier
addendum claimed no suspend hook existed at all. **That was wrong** — it came from a malformed grep
(`s3 sleep` instead of `sleep`, so `PrepareForSleep` never matched). The corrected picture:

- `Core/KeyScrubEvents.h:12` documents the trigger as *"Linux: logind `Lock`/**`PrepareForSleep`** via
  sd-bus (`VC_KEYSCRUB_LOGIND`)"* — `PrepareForSleep` being exactly the suspend signal.
- Five events route into one `ScrubNow()` → `VcScrubAll()`: unmount, idle timeout, screen lock,
  `PrepareForSleep`, new-device-connect; plus duress via `HKFScrubActiveConfig`.
- **But** `StartLogindScreenLockMonitor()` is **called and never defined** — one occurrence in the tree,
  the call site. The sd-bus subscription is a documented sketch: *"Left to the packager to wire to their
  event loop; intentionally not linked by default."*

So **the scrub side is designed and routed but not wired**, by deliberate choice. That choice is
defensible and this task does **not** overturn it.

**What is genuinely unknown, and is your job:** whether *re-authentication* is enforced on resume. The
scrub half is specified; the re-auth half nobody has checked. Find out:

- After a scrub fires (from any trigger — the question generalizes beyond suspend), what is the state of
  a mounted volume? Are keys gone but the volume still mounted and serving I/O? Is the mount torn down?
  Is the user prompted on next access?
- Trace the actual path: `VcScrubAll()` → what happens to the registered regions the volume layer
  depends on → what the next I/O or CLI operation does.

**Report the answer before writing any code.** There are three possible outcomes and they imply very
different work:

1. **Re-auth already enforced** → document it in `KEYS-IN-RAM.md`/`MEMORY-SCRUB.md` and stop.
2. **Volume unusable after scrub but with a poor failure mode** (e.g. I/O errors rather than a clean
   prompt) → a UX/robustness item, worth specifying.
3. **Keys scrubbed but volume still usable** → the scrub is not achieving what it claims, which is a
   real defect and the most important thing this session could find.

**A hidden design decision to surface, not silently resolve** (R17/R16 both gloss it): re-auth of
*what*? Password only, or password plus hardware factor? If the factor is a YubiKey that may be unplugged
during suspend, forcing full re-auth can lock a user out of a mounted volume on lid-close. That is a
usability/security trade with a real failure mode for the target users. **Write up the options; do not
pick one unilaterally.**

---

## C2 — IOMMU / DMA-protection advisory

R16 names this as one of only two things in the entire brief worth building. It does not exist:
`grep -rn -i "iommu|thunderbolt|dma"` across `src/Common/` and `docs/` returns nothing relevant.

**The template already exists and should be followed closely.** `VcSwapHibernateStatus()` in
`src/Common/KeyScrub.{c,h}` does exactly this shape for a different exposure:

- Reads platform state best-effort and read-only (`/proc/swaps`, `/sys/power/state`).
- Returns a bitmask of `VC_HIBERNATE_*` bits so the caller can warn loudly while volumes are mounted.
- **Fails toward "unknown, not safe"** — returns 0 meaning *unknown* on a platform without `/proc` +
  `/sys`, never "safe."
- Ships `VcSwapHibernateStatusFrom(swapsPath, powerStatePath)` — a fixture-driven variant taking explicit
  paths so the verification harness can drive it without touching the real `/proc`.

Build the DMA advisory the same way: `VcDmaProtectionStatus()` plus a `...From()` fixture variant,
bitmask return, fail-closed on unknown.

**Decide and document which signal(s) you read** — this is the open design question and R16 does not
resolve it:

- **Linux:** IOMMU enablement (`/sys/class/iommu/`, or `intel_iommu=`/`amd_iommu=` in
  `/proc/cmdline`); Thunderbolt security level (`/sys/bus/thunderbolt/devices/domain*/security`).
- **Windows:** Kernel DMA Protection state — API/registry, compile-only here.
- **macOS:** no reliable userspace read known — likely always-warn, like the flash probe's macOS
  rotational case.

Pick the reads that are actually available and meaningful, say why, and treat everything else as unknown.
Resist the urge to synthesize a single confident verdict from partial signals — the flash probe (C3,
batch 2) is the precedent: only positive confirmation on every axis clears the warning.

**Verification** (this is genuinely sandbox-testable — do not hand-wave it):

- Unit-test the Linux reads against **fixture paths**: IOMMU present/absent, Thunderbolt security levels
  including unrecognized values, missing files, unreadable directories.
- Assert **fail-closed** as a *named* check: every unknown/error input produces a warning, never silence.
  This is the assertion that matters most; make it explicit the way `flash_probe_test.c` does.
- Wire it as a suite step.
- Windows/macOS paths are **compile-checked only** here. State it in exactly that form: *"Linux probe
  unit-tested against fixtures; Windows/macOS probes compile-checked, need a real build."*

**Scope note:** this is an *advisory*. It warns; it does not gate mounting. Do not add a hard block on
unverified DMA protection — that would break users on hardware they cannot change, which is precisely the
portability failure R16 spends the whole brief arguing against.

---

## Working style

- **C1 is an investigation.** Report findings before writing code; do not assume outcome 3 and start
  building.
- **Verify, don't assert.** Show output. The earlier error on this exact topic came from trusting a grep
  that was wrong — construct searches carefully and prefer reading the code over pattern-matching.
- **State the ceiling.** Fixture-tested is not platform-tested; say which is which.
- **`burn()` any secret-bearing intermediate you introduce**; extend the zeroization-liveness controls to
  any new buffer whose lifetime you created.
- **Small commits, one concern each.**
- **Scope boundary unchanged.**

## Out of scope

- Implementing `StartLogindScreenLockMonitor()` — deliberately left to packagers; that decision stands
  unless C1 finds it causes a real defect.
- Register-resident keys, TEE integration, any dependency on CPU memory encryption — R16 declined all of
  these; see `docs/KEYS-IN-RAM.md` (written in prompt B).
- Gating mounts on DMA-protection state (advisory only).
- Anything from prompts A or B.

## Definition of done

1. C1 answered with evidence: what happens to a mounted volume after a scrub, which of the three
   outcomes holds, and the re-auth-of-what options written up without a unilateral choice.
2. If C1 found a real defect (outcome 3), it is reported clearly — fixing it may be a separate session.
3. C2 built on the `VcSwapHibernateStatus` template: bitmask return, `...From()` fixture variant,
   fail-closed, Linux reads unit-tested against fixtures, named fail-closed assertion, suite step added,
   Windows/macOS compile-checked with the gap stated.
4. `--strict` exit 0, 0 SKIP, anchors intact, negative control still fails.
5. Closing summary: what was verified in-sandbox, what needs a real build, measured suite tally.
