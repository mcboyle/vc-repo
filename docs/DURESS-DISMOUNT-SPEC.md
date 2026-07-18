# Safe duress-dismount — design & status

**Status: implemented and verified.** A non-destructive duress action: on command, **dismount every
mounted volume and scrub user-space key material from RAM, mounting nothing**. It can be triggered
explicitly (a panic switch) or by a dedicated **duress passphrase** recognised in user space. Nothing
on disk is altered.

This is the safe answer to coercion. Unlike a destructive "wipe on duress" it destroys nothing,
leaves **no "I triggered something" artifact**, and forfeits no deniability — it simply returns the
machine to a locked state, exactly as a normal unmount would, and is fully recoverable afterwards.
Gated behind `-DVC_ENABLE_DURESS` (`make DURESS=1`); a build without it is byte-for-byte stock.

## Why non-destructive is the right primitive

- **A destructive wipe is a trap.** An adversary who imaged the disk first holds an untouched copy, so
  the wipe hits a copy that no longer matters — while the *act* of destruction is itself incriminating
  and destroys the deniability the rest of this fork is built on (`docs/THREAT-MODEL.md` → imaged-first).
- **Locking down is enough and is deniable.** Dismount + RAM-scrub returns the system to "nothing
  mounted, no keys in memory" — indistinguishable from a machine that was simply never unlocked.
- **It composes with what is already here.** The RAM scrub is exactly the KeyScrub `ScrubNow()` path
  (`docs/MEMORY-SCRUB.md`); duress-dismount is that plus a force-dismount of every volume.

## The action

`UserInterface::DuressDismount()` (Main), reached by `CommandId::DuressDismount`:

1. Force-dismount every mounted volume (`Core->DismountVolume(v, ignoreOpenFiles=true)`), swallowing
   per-volume errors so one stuck mount cannot stop the rest. The kernel dm-crypt master keys are
   released by these dismounts.
2. If built with `-DVC_ENABLE_KEYSCRUB`, call `KeyScrubManager::ScrubNow("duress")` — erase every
   registered user-space secret (reconstructed Shamir secret, HardwareKeyFactor material) and tear
   down the in-RAM key-obfuscation area.
3. Mount nothing.

## Triggers

### Explicit panic switch

```sh
veracrypt --duress-dismount        # dismount everything + scrub, now
```

### Duress passphrase (no header change, no plaintext stored)

VeraCrypt has one password per volume and no keyslot table, so a duress passphrase cannot live in the
volume header without a format change. Instead it is recognised **locally**: you register a random
16-byte salt and the 32-byte tag `HMAC-SHA256(salt, duress_passphrase)` (`src/Common/DuressToken.c`).
At mount time, if the entered password's tag matches, the safe duress action runs **instead of**
mounting:

```sh
# one-time: pick a duress passphrase and compute (salt, tag) offline
python3 -c 'import hmac,hashlib,os; s=os.urandom(16); \
  print("salt", s.hex()); \
  print("hash", hmac.new(s, b"my duress passphrase", hashlib.sha256).hexdigest())'

# then wire the registered (salt, tag) into how you invoke veracrypt (wrapper/config):
veracrypt --duress-salt <hex16> --duress-hash <hex32> --mount /dev/sdX /mnt/x
# → if the password you type is the duress passphrase, everything dismounts + scrubs; nothing mounts.
```

Properties:
- The duress passphrase itself is **never stored** — only the salt and the HMAC tag, which do not
  reveal it.
- The comparison is **constant-time** (`DuressTokenMatch`), so it leaks no timing signal about how
  close a guess was.
- Recognition **reads no volume** and touches **no header** — it only decides whether to run the
  action.

## Honest limitations (state these to users)

- **The registered (salt, tag) is a local tell.** Its presence in a config/wrapper reveals that a
  duress scheme exists. Keep it where its existence is itself deniable, or supply it out-of-band at
  invocation. (A future, stronger home is the multiple-keyslots work — a real duress keyslot — which
  needs the header/keyslot-table format change on the backlog.)
- **This is not anti-forensics.** It locks the machine down; it does not fabricate history or hide
  that VeraCrypt is installed. Fabricating a false record of activity is out of scope for this project
  and stays that way (`ROADMAP.md` → DESCOPED).
- **Imaged-first still applies.** If the disk was copied before duress, no on-machine action affects
  that copy — which is exactly why the response is a safe lockdown, not a destructive wipe.
- **The mounted master key is kernel-held.** The RAM scrub covers user-space secrets; the dismounts
  release the dm-crypt keys, but a kernel/DMA attacker who strikes *before* the dismount completes is
  out of scope (`docs/MEMORY-SCRUB.md`).

## Verification (proven two ways, per the project convention)

Self-contained (`verification/duress_selftest.c` + `duress_reference.py`, wired into
`build_and_verify.sh` step `[7]`):

1. **Independent Python reimplementation** — HMAC-SHA256 built by hand (ipad/opad over `hashlib`).
2. **Real compiled VeraCrypt object** — the harness links the actual in-tree `Crypto/Sha2.c` (SHA-256)
   under `Common/DuressToken.c`.

Diffed **byte-for-byte** on a fixed vector, plus: the check accepts the duress passphrase and rejects
a wrong one, and the constant-time compare is exact (equal matches; a one-byte difference does not).

**Regression anchor:** `HMAC-SHA256(salt, "correct horse battery staple")` with `salt[i]=(i*7+3)&0xff`
(16 bytes) = `3d874ea97ea3fa5bc792bd87554ae502c7ebde535ed06243a9b171247afeb808` (also cross-checked
against Python's stdlib `hmac`).

### What is NOT unit-tested here

The dismount/scrub **orchestration** in `UserInterface::DuressDismount()` drives the mount/unmount
subsystem and the wx application, which cannot be exercised in this sandbox. The verified core is the
duress-passphrase recognition (the crypto) and the fact that the action is wired to `ScrubNow()`;
exercise the end-to-end dismount on a real build with mounted volumes.
