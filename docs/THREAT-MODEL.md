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

## What it does NOT protect against (state these to users)

- **Multi-snapshot / repeat imaging.** Using a hidden volume writes into the decoy's "free" space; an
  adversary who images the disk two or more times can detect a hidden volume from the block-change
  pattern (Fredrickson, Barker & Long, *A Multiple Snapshot Attack on Deniable Storage Systems*,
  2021). Applies to essentially all hidden-volume systems, this fork included. A decoy does not fix
  it; the real mitigation is write-only ORAM access-pattern hiding (backlog).
- **SSDs.** TRIM leaks the free-space map; the flash translation layer's out-of-place writes and
  wear-leveling can retain fragments — including of the hidden-volume creation itself. Classic
  hidden-volume deniability is **weak on flash**. Prefer factor/threshold protection (confidentiality)
  over relying on deniability on an SSD.
- **Imaged-first.** An adversary who copies the disk *before* coercion holds an untouched copy; no
  post-hoc measure on your machine affects it. (This is also why destructive duress-wipe is a trap —
  it hits a copy that no longer matters, and destroys deniability by leaving a "destruction"
  artifact.)
- **Memory extraction while running.** Keys and any reconstructed Shamir secret live in RAM. On
  Windows, VeraCrypt encrypts/erases them; **on Linux/macOS this is not yet done** (cold-boot, DMA
  over Thunderbolt/FireWire). The cross-platform memory-scrub work item (ROADMAP) closes this — until
  then, treat a running/locked machine as exposed.
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
