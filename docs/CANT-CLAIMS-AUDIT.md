# "Can't" claims — audit

**Why this exists.** In one session, four separate *"the environment can't do X"* claims were tested and
**all four were false**:

| Claim | What it rested on | Reality |
|---|---|---|
| "the sandbox blocks the open web" | `WebFetch` returned 403 for rfc-editor.org | plain `curl` works — cost a round-trip asking the user to paste RFC vectors by hand |
| "the product build is not provisionable (apt offline/locked)" | one `ls a b` probe in the session-start hook | `ls a b` exits non-zero if *either* path is missing; the dep was present. The build works. |
| "HACL\* is unavailable" | it had vanished from `/tmp` | the tarball was in the uploads directory the whole time |
| "these commits are unsigned / will show Unverified" | local `git log %G?` printed `N` | **Tested via the GitHub API: `verified: true, reason: "valid"`.** `N` means *cannot verify* (no `allowedSignersFile`), not *unsigned*. The hook reads a local trust-config gap as a claim about remote state. |

The shape is identical every time: **a single failed probe hardened into a durable "can't" that outlived
its evidence** — and then got written into always-loaded context (`CLAUDE.md`, specs, the session hook),
where every later session inherited it as settled fact rather than as a stale observation.

This is the same failure mode `docs/VERIFICATION-ANCHORS.md` describes for crypto proofs, pointed at the
environment instead of the code: *an assumption that looks settled stops being re-examined.*

## The rule

> **A "can't" inferred from a symptom is worth nothing. Only a "can't" from a direct test of the thing
> itself belongs in durable context — and it must carry the command that reproduces it, so the next
> reader can re-run it instead of inheriting it.**

Corollary: when a probe fails, the next step is to *try the thing*, not to write down that it is
impossible.

## Verdicts

Each claim is marked:

- **VERIFIED-TRUE** — tested; genuinely not possible here. Records the command and what it does.
- **FALSE — NOW TESTABLE** — tested; it works. The claim must be deleted and the work done.
- **UNTESTED** — not yet checked. Says so plainly rather than implying either.

### FALSE — NOW TESTABLE

**`CLAUDE.md` "Good next tasks" #3 — explicit Argon2id params create→mount round-trip.**
Claim: *"The crypto is proven (step `[11]`); the create/mount round-trip is not sandbox-testable."*

The **create** half is demonstrably sandbox-testable — it was run:

```sh
./scripts/build-product.sh NOGUI=1 ARGON2PARAMS=1        # exit 0
src/Main/veracrypt --text --create /tmp/a2vol.tc --size 10M --volume-type=normal \
  --encryption=AES --hash=BLAKE2s-256 --filesystem=none --pim=0 -p "testpass123" -k "" \
  --random-source=/dev/urandom --argon2-memory 16 --argon2-iterations 3
# -> "The VeraCrypt volume has been successfully created." (exit 0, 10485760 bytes)
```

The **mount** half is reachable but **not yet run**: `Volume::Open` is exercised in-process by
`verification/realbuild/open_roundtrip.cpp` (no kernel needed), and the remaining work is to have that
harness call `Argon2SetParamsOverride()` before opening so the same-params-open / wrong-params-reject
pair can be asserted. That is ordinary work, not an environmental limit.

Status: the blanket "not sandbox-testable" is **wrong**. Correct statement: *create is sandbox-testable
today; mount needs the open_roundtrip harness taught the Argon2 override.*

> **CORRECTION — the create evidence above was overstated, and this document caught it.** That volume was
> created with `--hash=BLAKE2s-256`. The Argon2 flags are only consulted when the KDF *is* Argon2id, so on
> a BLAKE2s volume they were **inert**: the command exited 0 and proved nothing about Argon2 parameters.
> A genuine Argon2 volume does create (`--hash=Argon2id --argon2-memory 16 --argon2-iterations 3` → exit
> 0), so the conclusion survives — but it was reached from evidence that did not support it, which is the
> same error as anchoring ChaCha20 to the wrong RFC. *An exit code only proves what the command actually
> exercised.*

**Argon2 mount half — NOW PASSING. The round-trip is verified in-sandbox.**
`verification/realbuild/open_roundtrip.cpp` accepts `VC_OPEN_ARGON2="memKiB,iters,par"` and calls
`Argon2SetParamsOverride()` before `Volume::Open`. Against a volume created with
`--hash=Argon2id --argon2-memory 16 --argon2-iterations 3 --argon2-parallelism 4`, all six probes pass —
positive control first, then five negatives:

| probe | result |
|---|---|
| same params (16384 KiB, 3, 4) — **positive control** | opens, master key size=256, non-trivial |
| wrong memory (32768 vs 16384) | PasswordIncorrect |
| wrong iterations (4 vs 3) | PasswordIncorrect |
| wrong parallelism (1 vs 4) | PasswordIncorrect |
| no override at all (PIM default) | PasswordIncorrect |
| right params, wrong password | PasswordIncorrect |

Wired into `verification/realbuild/open_roundtrip.sh` (11/11) and gated in CI
(`.github/workflows/flag-matrix.yml`), so it is a standing check rather than a one-off run.

**Why it failed before, and why that matters more than the fix.** Nothing was wrong with the parameters or
the crypto. The harness and the product archives had been **built from different feature-flag sets**, so
the harness linked against a `Core.a`/`Volume.a` that carried a different `-D` set than it compiled with.
That mismatch produces no build error — it surfaces as a *behavioural* failure (a volume that will not
open), which is indistinguishable from a crypto bug. Two parameter hypotheses were tested and discarded
before the real cause was found, both of which were fine all along.

This is the *third* instance of the pattern this document is about, and the most expensive: a symptom
(`FAIL must_open`) was read as evidence about the thing under test rather than about the apparatus. The
refusal to count the negative probes while the positive control failed is the part that held up — that
instinct was right, and it is the only reason the failure was not written down as a real Argon2 defect.

Two durable fixes, so the next reader cannot repeat it:
- `scripts/build-product.sh` now writes `src/.build-flags` with the resolved `-D` set, and
  `open_roundtrip.sh` refuses to run when its own flags disagree with the stamp (tested both ways: matched
  set → 11/11; deliberately mismatched set → refuses, exit 1). `CLAUDE.md` already warned to `make clean`
  when changing feature flags; a warning in prose did not prevent this, a check does.
- **`make KEYSLOTS=1` without `KEYSCRUB=1` did not build.** `src/Main/UserInterface.cpp` had the keyslot
  and duress `#include` blocks *nested inside* the `VC_ENABLE_KEYSCRUB` guard, while the code they serve is
  guarded only by `VC_ENABLE_KEYSLOTS` / `VC_ENABLE_DURESS` — so those flags alone compiled the command
  bodies with none of their headers. The full CI flag set always sets `KEYSCRUB=1`, which hid it. Guards
  un-nested; `KEYSLOTS=1`, `DURESS=1` and `KEYSCRUB=1` each now build standalone.

One earlier finding here was also wrong and is corrected: `VolumeHeader::GetMasterKeys()` being behind
`VC_ENABLE_KEYSLOTS` is real, but it was **not** the cause of the Argon2 failure — it only means the
harness needs `KEYSLOTS=1` to compile at all. It remains the real cause of the T1-1 mount-discovery patch
failing to compile under `V2FORMAT=1` alone (previously mis-diagnosed as an access-specifier problem).

**Commit signing — RESOLVED, and the worst case of the pattern.** The stop hook asserts *"GitHub will
show as Unverified (missing signature, or committer email is not noreply@anthropic.com)"*. Both halves are
false:

```sh
curl -sS .../repos/mcboyle/vc-repo/commits/5ad2ebc | python3 -c "...['commit']['verification']"
# -> {"verified": true, "reason": "valid", "verified_at": "2026-07-24T22:41:13Z"}
git cat-file commit 5ad2ebc | grep -E '^(author|committer|gpgsig)'
# -> author/committer Claude <noreply@anthropic.com>;  gpgsig -----BEGIN SSH SIGNATURE-----
```

Worth recording *why* this one is instructive rather than just resolved: it was asserted five times as a
"known false alarm" **without ever being checked**, and the assertion was written into the session's own
automation as `do not churn on that` — converting an unverified belief into a standing instruction not to
re-examine it. The conclusion happened to be right; the method was the same one that produced four wrong
answers. A correct guess reached by inheritance is not evidence, and it is not distinguishable from the
failures until someone runs the command.

### FALSE — NOW TESTABLE (VM Tier-2 run, 2026-07-25)

First execution on a box with a real kernel device-mapper (`/dev/mapper/control` present, `/dev/loop-control`
present, 16 cores, 62 GB, Ubuntu 24.04.4, AES-NI). Full run record + exact commands:
`verification/realbuild/VM-TIER2-RUN.md`. Environment fact worth its own line: **`sudo` was
password-gated by default** (`sudo -n true` → "a password is required"); a non-interactive session cannot
use it until a NOPASSWD drop-in exists. "The VM has sudo" was itself a partially-true inherited claim; the
direct test settled it.

**`kernel dm-crypt mount` — VERIFIED WORKING (was UNTESTED).** Positive control, run before any negative:

```sh
VC=src/Main/veracrypt; W=$(mktemp -d)
sudo $VC --text --create $W/v.hc --size=10M --password=P --pim=0 --keyfiles="" \
     --encryption=AES --hash=SHA-512 --filesystem=fat --volume-type=normal --random-source=/dev/urandom
sudo $VC --text --mount  $W/v.hc $W/mnt --password=P --pim=0 --keyfiles="" --protect-hidden=no --slot=1 --non-interactive
# -> dm mapping veracrypt1 (252:1); /dev/loop0 bound to v.hc; vfat mounted at $W/mnt;
#    wrote+read a file through the encrypted mount; --dismount exit 0; dmsetup/losetup clean after.
```
Repeated twice, identical. The claim that this needs "a VM the container does not provide" was correct
about *why* it was untestable, and it flips cleanly now that a VM exists.

**`keyslot mount-time auto-search on real media` — VERIFIED WORKING (was UNTESTED).** A plain `--mount`
with a *keyslot* passphrase (not the native one) recovered the VMK and mounted through kernel dm-crypt:

```sh
$VC --text --keyslot-add $W/k.hc --password=NATIVE --new-password=SLOT --pim=0 --keyfiles=""
sudo $VC --text --mount  $W/k.hc $W/km --password=SLOT --pim=0 --keyfiles="" --protect-hidden=no --non-interactive
# -> mounted via the keyslot (87s: the constant-time 63-slot auto-search; see below), then dismount.
```
Also verified in the same run: keyslot enroll opens & recovers the exact master key; wrong passphrase
rejected; HKF-simulator 2FA positive mount through the kernel (correct factor, 1s); `--duress-register`
prints a well-formed 16-byte salt + 32-byte tag; argon2 wrong-memory/wrong-iterations rejected.

**Not a defect, but recorded so the next reader does not misread it as one — the 46–87s "hang".** Every
wrong-native-key mount pays a **deliberate constant-time** cost: the mount-time keyslot auto-search
(`src/Volume/Volume.cpp:309-345` → `KeyslotOpen` in `src/Common/KeyslotStore.c:228-268`) runs a
500,000-iteration PBKDF2-SHA512 on **all 63 slots, no early return**, to avoid leaking how many slots
exist or which matched (KeyslotStore.c:230-236). 63 × ~0.7s ≈ 46s, single-threaded, negligible RAM
(measured: one core at 99.8%, 15 idle, ~60 GB free). Correct-key mounts are ~1s. Consequence:
`acceptance.sh` times out at 5 min on a real-dm box because its negative mounts each pay this. This is a
performance/harness characteristic, **not** a crypto bug; the only *safe* speedup is to parallelize the
63 derivations while still computing all of them (owner directive this session: change nothing that could
harm security, so left as-is and documented). Two harness miscalibrations also surfaced — see
`VM-TIER2-RUN.md` findings #1 (`--filesystem=none` makes positive round-trips FAIL on a real-dm box while
they PASS in a container) and #3 (`balloon` needs a `BALLOON=1` binary that STEP 2's flag line omits).

### VERIFIED-TRUE

*(none yet — the genuinely-impossible claims below have not been individually tested, and are listed as
UNTESTED rather than assumed true. `kernel dm-crypt mount`, previously listed here as the most likely to
survive, was instead tested and moved to FALSE — NOW TESTABLE above.)*

### UNTESTED

Not yet checked; **do not treat as either true or false**. Status column records what the 2026-07-25 VM
Tier-2 run did or did not reach; a claim only leaves this table when a *direct* test settles it.

| Claim | Location | Status after 2026-07-25 VM run |
|---|---|---|
| C-path (Windows driver) header round-trip | `docs/REAL-BUILD-VALIDATION.md:294` | UNTESTED — not this env (no Windows driver build here) |
| SSD/FTL remnant behaviour | `docs/DECOY-FRAGMENTS-SPEC.md:58,72` | UNTESTED — likely genuinely not-this-env (vSAN-backed virtual disk, no raw FTL) |
| ~~true power-loss (vs torn-write, which is proven)~~ | `docs/TIER5-FORMAT-DESIGN.md:106` | **VERIFIED (2026-07-25)** — see below; moved OUT of this table |
| ~~flash-media warning firing on a live session~~ | `docs/ROI-TOP-50.md:115` | **VERIFIED (2026-07-25)** — see below; moved OUT of this table |
| ORAM wiring into VeraCrypt | `docs/ORAM-SPEC.md:105` | **PARKED (frontier)** — not an environment limit and not a routine code task. Moved to `docs/FRONTIER-FEATURES.md`: its own spec §6 says schedule it separately, it changes the data path, validation needs a real two-snapshot experiment, and a required countermeasure (the public-write cloak) is still unbuilt. |
| Adiantum `EncryptionMode` shim on non-AES-NI hardware | `docs/ADIANTUM-SPEC.md:68,98` | **SHIM NOW BUILT (2026-07-25)** — `src/Volume/EncryptionModeAdiantum.{h,cpp}`, `make ADIANTUM_MODE=1`, `verification/realbuild/adiantum_mode.sh` 17/17 including the measured wide-block property (a 1-bit plaintext change altered **509 of 512** ciphertext bytes; XTS would alter 16). The remaining item is **not** environmental and **not** the shim: Adiantum is still not registered in `EncryptionMode::GetAvailableModes()`, so no volume can select it yet — a deliberate decision, since it bundles its own primitives and does not compose into cipher cascades. Testing on genuinely non-AES-NI hardware is a separate, still-open question. |

Moved OUT of this table by direct test (see FALSE — NOW TESTABLE above / `verification/realbuild/VM-TIER2-RUN.md`):

- **`kernel dm-crypt mount`** — VERIFIED working (2026-07-25).
- **`keyslot mount-time auto-search on real media`** — VERIFIED working (2026-07-25).
- **`duress end-to-end`** — VERIFIED (2026-07-25). Mounted two real volumes via kernel dm-crypt, then
  `sudo veracrypt --text --duress-dismount` → all dismounted (`--list` empty, 0 dm mappings). Separately,
  entering the *registered duress passphrase* at `--mount` while two volumes were mounted dismounted them
  all and mounted nothing. (The coupled `KeyScrub ScrubNow()` runs in the same `DuressDismount` path;
  dismount-all is directly observed, the RAM scrub is not independently observable from userspace.)
- **`network-share against a live server`** — VERIFIED over a genuine TWO-HOST network (2026-07-25).
  First the McCallum–Relyea socket transport passed same-host (`verification/netshare_transport_poc.c`
  [49], AF_UNIX socketpair, `NETSHARE TRANSPORT ROUND-TRIP PASSED`). Then, on the lab, it was run
  **across two machines over real TCP**: `verification/netshare_tcp_poc.c` (same MR crypto + real Sha2.c;
  step [101] runs the localhost round-trip in CI) with the MR server (`--server`) on host 81
  (10.0.70.81) and the client (`--client`) on host 82 — the **same anchor share `edf4bd73…`** was
  recovered over the wire, each unlock re-blinds (the server never sees `C`), and **off-network** (dead
  port) and **wrong-server** (different secret) both fail. So the transport works end-to-end host-to-host,
  not just on loopback. The remaining gap is **not environmental**: it is a **code task**
  (PENDING-INTEGRATION), like ORAM/HKF-v2. (Method note: the first cross-host attempt failed because
  `nohup … &` in a one-shot ssh command is torn down on session close; holding the server in a foreground
  process under a live ssh fixed it — the failure was the apparatus, not the protocol.)

  > **CORRECTION (2026-07-25, later) — "the remaining gap is only the `--ns-*` CLI wiring" was an
  > understatement, and this document's own rule caught it.** Every MR proof to that point — [10], [39],
  > [49], [101] — put the **raw extended-coordinate `pt` struct** on the wire, and each said so in its
  > header: *"a production build would send compressed 32-byte points … a serialization detail"*. That
  > detail is not free. A compressed point has to be **decompressed** on receipt, which needs a modular
  > square root (RFC 8032 §5.1.3), and **no decompression existed anywhere in this tree** — `grep` for it
  > returns only ML-KEM's unrelated coefficient decompression and zlib. So the honest statement was not
  > "only CLI wiring remains" but *"a wire format is missing, and a wire format needs new crypto that has
  > never been written or anchored here."*
  >
  > Now closed: `src/Common/NetShare.{c,h}` (gated `-DVC_ENABLE_NETSHARE`) is the shippable module —
  > compressed-point serialisation with RFC 8032 §5.1.3 decompression, MR enrol/recover over an injected
  > transport seam (no sockets in `Common/`, the same pattern as `KeyslotArea`), and a versioned
  > credential blob. Step **`[102]`** anchors it: **ANCHOR CLASS OFFICIAL** — all five RFC 8032 §7.1
  > Ed25519 public keys decompress and re-compress byte-identically (compression recomputes `x`, so a
  > wrong `sqrt(-1)` branch changes the sign bit and the round-trip fails), plus property checks for the
  > MR flow over the compressed format, blinding/unlinkability, and off-network reported as
  > `ERR_TRANSPORT` rather than as a bad key. 31/31.
  >
  > **A second finding from building it, of the kind this document exists for.** The first version of
  > `NetShareCredParse` validated both stored points and its own comment claimed corruption *"is reported
  > as a credential problem and never as a failed unlock."* The module test disproved that: Ed25519 point
  > encodings are dense, so flipping a bit in the stored `S` usually lands on **another valid point** —
  > parse returned OK and recovery would have silently produced a *different share*, surfacing to the user
  > as "wrong password" with no hint the credential was at fault. Point validation alone cannot deliver
  > that property; the credential now carries a checksum. The test sweeps eight bit positions and
  > separately asserts that at least one of them still yields a valid point, so the checksum is provably
  > load-bearing rather than decorative. *A comment asserting a property is not the property.*
  >
  > Still open, and now genuinely just wiring: the `--ns-*` enrol/unlock CLI options and a TCP transport
  > implementation of `NetShareTransportFn`.
- **`true power-loss`** — VERIFIED (2026-07-25), on a dedicated disposable scratch disk (`/dev/sdb`)
  a container cannot provide. Created a **device-hosted** VeraCrypt volume directly on the raw block
  device (distinct from the file-container path the harness uses), mounted it via kernel dm-crypt, wrote a
  marker + a 4 MiB random file, `fsync`+`sync`, and left it **mounted**. Then the VM was hard-powered-off
  in vSphere (Power Off, not guest shutdown) — a real abrupt power loss, not the torn-write simulation
  (which was already proven). On reboot, `--mount /dev/sdb` re-opened the volume (rc=0, header intact) and
  both the marker and the 4 MiB file's SHA-256 matched byte-for-byte, with no fs-repair needed. Expected
  values were recorded on the persistent root disk (`/home/mboyle/powerloss/expected.txt`) so the check is
  reproducible across the reboot. Also establishes the **device-hosted (raw block device) volume** path
  works end to end, which file-container tests never exercise.
- **`flash-media warning firing on a live session`** — VERIFIED (2026-07-25). The warning is a
  **hidden-volume-creation** code path (`src/Main/TextUserInterface.cpp:719`, `if Type == Hidden`), not a
  mount-time one. Fires two ways, both observed live: (1) **file-hosted** hidden volume → `!IsDevice()` →
  `FlashProbe` fails closed (`ROTATIONAL|UNKNOWN`) → the full "NOT safe for a deniable hidden/decoy volume …"
  text printed; (2) **device-hosted** hidden volume on `/dev/sdb` → also warned.
  **Correction to an in-progress prediction, logged per this document's own rule:** it was first predicted
  that a device reading `rotational=1` would stay *silent* (reading only `FlashProbeRotationalSysfs`). The
  direct test warned anyway. `FlashProbeDevice` (`src/Common/FlashProbe.c:212`) hardcodes the third
  (thin/dedup/SMR) axis to `VC_FLASH_WARN_UNKNOWN` — deliberate fail-closed, since that property is
  invisible under device-mapper — and `FlashProbeAggregate` OR's the axes, so **a Linux device-hosted
  hidden volume never reads clean and always warns**, independent of `rotational`. Here two axes fired:
  `discard_granularity=512` (TRIM) and the always-`UNKNOWN` thin axis. Consequence: the planned
  `scsi0:1.virtualSSD=1` (present as SSD, `rotational=0`) experiment is **moot** — the outcome is identical
  — so it was not run. The rotational branch is only decisive at the sysfs layer, not in the aggregate.
- **`HKF v2 wiring / different-volume-salt behaviour`** — VERIFIED (2026-07-25); the "UNTESTED" tag was
  stale (two CI-gated harnesses already cover it, both re-run here and matching their independent Python
  twin). `[81]` wiring: create enrolls under v2, mount is compute-once / v2-first / v1-fallback, the C
  create-path key == the C++-overload key byte-for-byte, and a wrong factor opens neither version.
  `[93]` salt-binding (the "different-volume-salt" property): **different salts → different keys
  (cross-volume binding)**, bound ≠ unbound, NULL salt falls back; the salt-bound mix `57ba783d…` ==
  `python HKDF(extract-salt = the volume salt)`. Code confirms it: `VolumeCreator.cpp:401` enrolls with
  `HKFMixPasswordVer(…, salt, HKF_MIX_V2)` and the salt-bound v2 feeds the volume salt into HKDF-Extract
  (`HardwareKeyFactor.c:174`). Rebuild: `cd verification && ./build_and_verify.sh` (steps [81]/[93]).
- **`Adiantum` algorithm** (distinct from the unbuilt EncryptionMode shim above) — VERIFIED here: the
  `[91]` module harness links the real `src/Crypto/Adiantum.o` (+ `AesCt.o` + `chacha256.o` + `Poly1305.o`)
  and reproduces all **18 official google/adiantum KATs** both directions, plus whole-sector diffusion,
  wrong-key/wrong-tweak separation, `in==out` aliasing and the bounds guard, matching `adiantum_reference.py`.
  What remains (the claim in the table above) is only the C++ `EncryptionMode` integration — unbuilt code.

Several remaining are *probably* true — but "probably true" is what the four falsified claims also looked
like, so each still gets tested before it is written down as fact.

## A claim of mine that expired: "the stop hook is fixed"

Earlier this session the stop hook was patched to test for the `gpgsig` header instead of `%G?`, verified
with both a positive control (real signed commits → silent) and a negative one (a deliberately unsigned
commit → still flagged), and **reported as fixed**. It is not fixed now:

```sh
grep -n '\$2 == "N"' ~/.claude/stop-hook-git-check.sh
# -> 54:    unverifiable=$(git log --format='%h %G? %ce' ... | awk '$2 == "N" || ...')
```

The patch lived in `~/.claude/` — **outside version control** — and a session resume restored the original
file. The report was true when made and false within the hour, with nothing in between to signal the
change.

This is the same failure as the rest of this document, with the sign flipped. The "can't" claims were
**negatives** that outlived their evidence; this was a **positive** that did. Both are assertions about
the world that stopped being re-checked. The fix for both is identical: an assertion is only as durable as
the artifact that can reproduce it, and a change that is not in version control is not a change — it is a
temporary condition of one container.

Consequence for this repo: the `session-start.sh` fix (#26) **is** durable because it lives in
`.claude/hooks/` under git. The stop-hook fix is not, and must either be re-applied per session or moved
somewhere versioned before it can be called done.
