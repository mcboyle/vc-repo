# Threat model & honest limitations

What this fork does and does not protect against. Written to be honest rather than reassuring —
overselling deniability gets high-risk people hurt.

## What the factors actually buy

- **Offline brute force of a seized disk → defeated.** With a hardware or threshold factor, the
  header key cannot be derived from the password alone, so imaging the disk and grinding passwords
  offline does not work without the token/shares.
- **Leaked/guessed password alone → insufficient.** The factor is required in addition.
- **Coercion (rubber-hose):**
  - *Factor-gated decoy* — surrender the password; the outer volume opens, the real one still needs
    the token. Gives you something to hand over.
  - *Threshold / split-key* — with M-of-N shares held separately, **no single person can open the
    volume alone**, so coercing one person in isolation yields nothing. Withholding a share makes the
    data **inaccessible, not destroyed** (safe dead-man; recoverable if the share returns).
  - *Safe duress-dismount* (`docs/DURESS-DISMOUNT-SPEC.md`, `-DVC_ENABLE_DURESS`) — an explicit panic
    switch or a **duress passphrase** (recognised in user space via a stored salted HMAC tag, no
    header change) that **dismounts everything and scrubs RAM keys, mounting nothing**. Non-destructive:
    it destroys no data and leaves no "I triggered something" artifact, so — unlike a destructive
    duress-wipe — it forfeits no deniability and is fully recoverable. Its one tell is that the stored
    (salt, tag) reveals a duress scheme exists; keep it where that is itself deniable.

## What it does NOT protect against (state these to users)

- **Multi-snapshot / repeat imaging.** Using a hidden volume writes into the decoy's "free" space; an
  adversary who images the disk two or more times can detect a hidden volume from the block-change
  pattern (Fredrickson, Barker & Long, *A Multiple Snapshot Attack on Deniable Storage Systems*,
  2021). Applies to essentially all hidden-volume systems, this fork included. A decoy does not fix
  it; the real mitigation is write-only ORAM access-pattern hiding (backlog).
- **SSDs.** TRIM leaks the free-space map; the flash translation layer's out-of-place writes and
  wear-leveling can retain fragments — including of the hidden-volume creation itself. Classic
  hidden-volume deniability is **weak on flash**. Prefer factor/threshold protection (confidentiality)
  over relying on deniability on an SSD. Two mitigations now have proven cores (keyslot/format
  integration pending): **anti-forensic key splitting** (`docs/AF-SPLIT-SPEC.md`) makes a *partial*
  keyslot remnant worthless, and **decoy-fragments-by-default** (`docs/DECOY-FRAGMENTS-SPEC.md`) makes a
  hidden-volume artifact's presence uninformative.
- **Imaged-first.** An adversary who copies the disk *before* coercion holds an untouched copy; no
  post-hoc measure on your machine affects it. (This is also why destructive duress-wipe is a trap —
  it hits a copy that no longer matters, and destroys deniability by leaving a "destruction"
  artifact.)
- **Memory extraction while running.** Keys and any reconstructed Shamir secret live in RAM (cold-boot,
  DMA over Thunderbolt/FireWire). The **cross-platform memory-scrub** (`docs/MEMORY-SCRUB.md`,
  `-DVC_ENABLE_KEYSCRUB`) now covers the **user-space** secrets on Linux/macOS: the reconstructed
  Shamir/raw secret and HardwareKeyFactor material are kept ChaCha-encrypted at rest in RAM and erased
  on unmount / idle timeout / screen lock / new-device-connect. **Two caveats remain, stated plainly:**
  (1) the **mounted master key lives in the kernel device-mapper (dm-crypt)**, not this process, so no
  user-space scrub reaches it — a mounted volume's master key is kernel-resident and still exposed; and
  (2) the **screen-lock and new-device triggers are OS glue not exercisable in a sandbox** — validate
  them on a real desktop session. Erasure shrinks the exposure window; a live-DMA attacker can still
  race the instant a secret is revealed for use. Treat a machine with a *mounted* volume as exposed.
- **Evil maid / firmware.** The existing bootloader fingerprint check detects bootloader tampering
  but not a UEFI-level keylogger or firmware implant. Measured boot / Secure Boot signing is backlog.
- **The tooling itself.** For the decoy, discovery of a decoy scheme undermines it; for split-key,
  **where the shares live and who holds them is the real security**, not the math (a 2-of-3 with all
  shares in one drawer is a 1-of-1).

## Verification caveat

The cryptography, mixing, both derivation paths, CLI parsing, decoy gating, and Shamir are all
verified (byte-for-byte vs an independent reference and vs real VeraCrypt objects). The **real
YubiKey/FIDO2 USB round-trip** cannot be exercised in a sandbox — the hardware paths are proven to
compile, link against the real libraries, and fail safe with no device; **validate the actual
challenge-response on a physical token before trusting any data to it.** For the YubiKey HMAC-SHA1
profile the simulator computes the same HMAC the key does (you program the secret), so a simulator
config with your slot secret is a faithful stand-in and a backup/recovery check.
