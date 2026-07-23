# Real-build validation — acceptance checklist

Every "core proven, integration pending" feature has a concrete acceptance test that a **real Linux
build box** can run. This maps each pending item to its test and the tier of environment it needs, and
`verification/realbuild/acceptance.sh` mechanizes the Tier-2 ones. The verification suite
(`build_and_verify.sh`) proves the *crypto*; this proves the *product*.

## How to run

```sh
cd src && make NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1
sudo bash verification/realbuild/acceptance.sh          # loopback create/mount round-trips
```

The harness is self-gating: it builds if it can, runs Tier-2 round-trips only with root + a loop
device, prints `SKIP` for anything the environment can't do, and `PENDING-INTEGRATION` for features
whose CLI/mount glue is the remaining work (so it doubles as a live checklist).

## Tiers

- **Tier 0 — any box:** the fork builds with the feature flags; a plain `make` stays stock.
- **Tier 2 — rootful Linux VM (no special hardware):** loopback volume create/mount/dismount.
- **Tier 3 — physical devices/desktop:** USB tokens, logind/udev, TPM.

## Checklist

| # | Item | Tier | Acceptance test | Status |
|---|---|---|---|---|
| 1 | Default build stays stock | 0 | `make` (no flags) → binary identical behaviour to upstream | wired |
| 2 | Fork builds with all flags | 0 | `make NOGUI=1 KEYSLOTS=1 …` links (this is where the AF-split link gap was caught) | wired |
| 3 | Balloon as `--hash` | 2 | create + mount + dismount a `--hash=Balloon` volume | **create proven**; mount blocked only by kernel dm-crypt |
| 4 | Argon2 explicit params | 2 | create + mount with `--argon2-memory/-iterations`; **mount with different params must fail** | **PROVEN to the kernel boundary** (see below) |
| 5 | HKF factor (simulator) | 2 | create + mount with `--hkf-backend simulator`; wrong secret fails | **PROVEN to the kernel boundary** (same secret → key OK; wrong secret AND password-alone → rejected) |
| 6 | Multiple keyslots enroll/open/rotate/revoke | 2 | `--keyslot-add/open/rotate/kill/list` round-trip; duress-slot hook | **PROVEN** — CLI lifecycle + all 3 backends + **mount-time auto-search** (plain `--mount` tries slots; normal slot rebuilds the header & reaches dm-crypt, duress slot fires the safe duress action). Only the final dm-crypt table load needs a real kernel |
| 7 | Duress-dismount end-to-end | 2 | mounted volumes + `--duress-dismount` + duress passphrase → all dismount + scrub | **registration + recognition-routing PROVEN** (`--duress-register`; duress pass routes to the action, real pass mounts, wrong tag falls through). Force-dismount of live mounts needs kernel dm-crypt |
| 8 | Network-share (MR) unlock | 2+ | enroll against a Tang-style server, unlock; off-network stays locked | **transport round-trip PROVEN** over a real socket to a forked server (step `[49]`); off-network + wrong-server fail. Remaining: HTTP(S) to a *live* Tang server + CLI wiring |
| 9 | OPRF / threshold / VOPRF unlock | 2+ | blind→evaluate→finalize against a rate-limited server | **PENDING** — server + transport (`OPRF-SPEC.md`) |
| 10 | Keyslot deniable backend multi-snapshot | 2 | before/after images over many writes: location leak bounded as documented | **PENDING** — real-media validation |
| 11 | AF-split real-flash remnant | 3 | partial remnant of a revoked slot is unrecoverable on real SSD | **PENDING** — hardware |
| 12 | YubiKey / FIDO2 USB round-trip | 3 | real token challenge-response mixes into the key; no token = fails safe | **PENDING** — hardware |
| 13 | KeyScrub OS triggers | 3 | logind screen-lock / udev new-device fire the scrub | **PENDING** — desktop session |
| 14 | TPM PCR-sealing | 3 | a share sealed to PCR state; wrong measured boot fails | **PENDING** — TPM/hardware |

"wired" = the CLI/mount path exists and the harness exercises it. "PENDING" = the crypto core is proven
(see the linked spec + verification step) but the integration glue is the remaining real-build work.

## Build prerequisites (learned from a real build)

The fork builds on a stock Ubuntu 24.04 image that already has wxWidgets 3.2, libfido2, and FUSE. Two
*stock VeraCrypt* build tools are additionally required (neither is a fork dependency):

- **`libpcsclite-dev`** — the PC/SC smartcard headers (`pcsclite.h`, `winscard.h`, `wintypes.h`,
  `reader.h`), included by VeraCrypt's EMV/smartcard code (`Common/SCardLoader.h`). The runtime lib is
  `dlopen`ed, so only the headers are needed at compile time. `sudo apt-get install libpcsclite-dev`.
- **`yasm`** — assembler for the optimized x86-64 AES (`Crypto/Aes_x64.asm`). Either install it, or
  build with **`NOASM=1`** to use the portable C implementations.

Confirmed working invocation (all fork features, no GUI):

```sh
sudo apt-get install -y libwxgtk3.2-dev libpcsclite-dev libfido2-dev libfuse-dev yasm
cd src && make NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1
```

(YubiKey support additionally needs `libykpers-1-dev` + `YUBIKEY=1`.)

## Full-featured build + Tier-2 run (this environment) — three real defects fixed

A complete `veracrypt` binary now links with every feature flag
(`NOGUI KEYSLOTS KEYSCRUB DURESS ARGON2PARAMS BALLOON SHAMIRMAC SHARECODE HKF`,
`CC=clang CXX=clang++`) and runs. The fork CLI is live (`--keyscrub`,
`--duress-dismount`, `--argon2-memory/-iterations/-parallelism`). `--test` passes all
algorithm KATs and the self-contained verification suite stays green (48/48).

Running the Tier-2 acceptance path surfaced and fixed **three defects that only a full
product build can reach — the in-process verification suite cannot, by construction**:

1. **Build wiring** — `chacha256.c` dispatches to `chacha_ECRYPT_encrypt_bytes` (an SSSE3
   SIMD inner loop) but that translation unit (`chacha-xmm.c`) was in no makefile; and
   `KeyScrubEvents.cpp` calls `HKFScrubActiveConfig()` whose only definition is HKF-gated.
   A `KEYSCRUB`/`KEYSLOTS` build failed to link. Fixed: `chacha-xmm.ossse3` via the
   existing `.ossse3` (`-mssse3`) object convention, and a same-linkage no-op
   `HKFScrubActiveConfig` fallback under `!VC_ENABLE_HKF`.

   *Guard-complementarity (ROI item 1 follow-up).* The fallback stub alone was necessary but
   not sufficient: the *real* `HKFScrubActiveConfig` in `HardwareKeyFactor.c` was guarded on
   `VC_ENABLE_KEYSCRUB` only, while the stub is guarded on `VC_ENABLE_KEYSCRUB && !VC_ENABLE_HKF`.
   Those are **not** complementary — a `KEYSCRUB`-on/`HKF`-off build compiled *both*, so the
   symbol was multiply defined (the exact class this section warns about). The real definition
   is now guarded on `VC_ENABLE_KEYSCRUB && VC_ENABLE_HKF`, the precise complement of the stub:
   exactly one definition exists whenever `KEYSCRUB` is on, none when it is off. The in-process
   verification harness reproduced this (step 6 was *silently skipping* on the link failure until
   the suite gained a coverage line + `--strict` mode); it now builds the HKF path and reports
   `48/48 steps verified, 0 skipped`. See `patches/harness-strict-mode.patch`.

2. **Self-test contamination** — with an Argon2 parameter override active
   (`--argon2-memory/-iterations`), the startup KAT `EncryptionTest::TestPkcs5` derived its
   fixed PIM-1 vector through the *overridden* costs and threw `TestFailed`, so **every
   create with explicit params aborted**. Fixed: snapshot/suspend/restore the override
   (RAII) around the Argon2 KAT so it validates the algorithm against canonical params.

3. **The override never reached the actual Linux derivation** — the C++
   `Pkcs5Argon2::DeriveKey` (the path the Linux app uses for *both* create and mount)
   computed iterations + memory from stock `get_argon2_params(pim)`, ignoring the override;
   only parallelism leaked through. So `--argon2-memory/-iterations` were effectively
   **no-ops** for the volume key on Linux, and — separately — the override is a process
   global set *after* the privileged `CoreService` child forks, so it did not cross to the
   child that performs mount-time derivation. Fixed both: resolve via
   `Argon2GetResolvedParams` in the C++ KDF, and serialize the override on every
   `CoreServiceRequest` (re-applied in the child before any derivation).

**Round-trip result (proven up to the kernel boundary):** create a volume with
`--argon2-memory=64 --argon2-iterations=3`, then

- mount with the **same** params → key re-derived, header decrypted + authenticated,
  proceeds to `dmsetup` (fails only there — this sandbox kernel has no device-mapper);
- mount with **`--argon2-memory=128`** or **`--argon2-iterations=9`** → `Incorrect password`
  (the header MAC fails because the key genuinely differs).

That difference in failure point *is* the acceptance criterion for item #4: the same params
reproduce the key and different params do not. The only step not exercised here is the final
`dmsetup` device-mapper table load, which needs a kernel with dm-crypt (Tier-2 on a real VM;
this container exposes no `/dev/mapper/control`). Stock SHA-512 create/mount behaves
identically (reaches `dmsetup` with the right password, `Incorrect password` with a wrong
one), confirming no regression.

## Multiple keyslots (item #6) — CLI lifecycle proven on a real volume

The keyslot core (`Common/Keyslot*.{c,h}`, steps `[8]`/`[9]`/`[36]`/`[37]`) is now wired into the
product: a C++ mount-path binding (`Volume/KeyslotVolumeBinding.h`) exposes the header-slack
`KeyslotArea` over the app's `File` class, `VolumeHeader::GetMasterKeys()` surfaces the VMK (the header
key area) on a successful open, and five CLI verbs drive the proven `KeyslotStore` ops:

```
--keyslot-add    volume --password <existing> --new-password <new> [--keyslot-duress]
--keyslot-open   volume --password <existing> --new-password <probe>
--keyslot-rotate volume --password <opens-a-slot> --new-password <new>
--keyslot-kill=N volume
--keyslot-list   volume
```

Every op recovers the VMK with `--password` (via the native header **or** an existing keyslot — so a
slot passphrase is a first-class opener) and works on the primary header slack `[512, 64K)`; slot 0 and
the body are never touched. Because the ops are pure header-region file I/O, the **entire lifecycle is
provable without the kernel** — `--keyslot-open` reports whether the passphrase recovers the *exact*
master key, which is the mount capability itself.

Proven end-to-end on a real 10 MiB container (mechanised in `verification/realbuild/acceptance.sh`):

- enroll a slot under a second passphrase → it opens and the recovered master key **matches the native
  header byte-for-byte** (this passphrase mounts the volume);
- a wrong passphrase opens no slot;
- add a third, revoke the first → the revoked passphrase no longer opens, the survivor still does;
- rotate using a slot passphrase as the opener → the old slot is retired and the new one installed;
- a `--keyslot-duress` slot round-trips its flag (open reports `[DURESS slot]`);
- the native 512-byte header and the whole data body are **byte-identical** before and after.

`KeyslotOpenAt` (a per-index admin open, distinct from the constant-time `KeyslotOpen` mount path) was
added to let rotation locate the slot to retire. Two build-integration issues surfaced and were fixed:
the RNG must be `Start()`ed and `GetData` called with `allowAnyLength` for the 1 KiB slot fills, and
the VMK size is `DataKeyAreaMaxSize` (exposed as `GetMasterKeyDataSize()`), not the
smaller `GetLargestSerializedKeySize()` — using the latter made a slot probe mis-sized.

The one piece that still needs a real kernel is the **mount-time convenience**: having a plain `--mount`
automatically try keyslots after the native header fails (and invoke the duress action on a duress
slot). The key-recovery half of that is exactly what `--keyslot-open` proves here; only the final
dm-crypt table load is unexercised, the same universal Tier-2 boundary as items #3/#4/#5.

## HKF simulator round-trip (item #5) — proven, four more defects fixed

Wiring the flagship 2FA feature into the product build surfaced that **`make HKF=1` had never
existed**: no knob in `src/Makefile`, and no makefile compiled `HardwareKeyFactor.o`/`Shamir.o`
(CLAUDE.md documented the object-list addition as a manual step). The knobs now exist:
`HKF=1`, `HKF_SIMULATOR=1` (testing only — never ship), `YUBIKEY=1` (`-lykpers-1`),
`FIDO2=1` (`-lfido2`); the objects are wired in `Core/Core.make`. Fixes found on the way:

1. **Stale-object trap (build system, twice):** VeraCrypt's make does not rebuild objects when
   only `-D` feature flags change, so a rebuild with new flags silently produced a **mixed
   binary** — the CLI had the `--hkf-*` options but `VolumeCreator`/`VolumeHeader` had the
   hooks compiled out, creating volumes that ignored the factor. gdb (breakpoint on
   `HKFShouldApply` never firing during a create) pinned it. Rule adopted, and mechanized in
   the acceptance harness: **treat any feature-flag change as a clean build**.
2. **Self-test contamination (HKF edition):** with a factor active, the startup KAT's header
   encrypt/decrypt round-trip mixed the factor into its fixed password and threw `TestFailed`,
   aborting every create/mount. Fixed with an RAII suspend/restore of `g_hkfActiveConfig`
   around `EncryptionTest::TestPkcs5` — the same pattern as the Argon2 override.
3. **CoreService gap (HKF edition):** the factor config is a process global set after the
   privileged child forks; mount-time derivation in the child never saw it. The config now
   travels on every `CoreServiceRequest` (raw POD blob — parent and child are the same binary;
   the pipe already carries the volume password, so no new exposure class) and is re-applied in
   the child, which wipes its copy when a request carries no factor.

**Round-trip result** (create `--hkf-backend=simulator --hkf-sim-secret=<64-hex>`):
- mount with the **same** secret → factor mixed, key re-derived, header authenticated → `dmsetup`;
- mount with a **wrong** secret → `Incorrect password`;
- mount with **no factor at all** → `Incorrect password` — the password alone is insufficient,
  which is precisely the 2FA property;
- stock volumes and `--test` (factor configured) unaffected.

The default build (no flags) was rebuilt from clean and links — all gated code compiles out.
Harness: `pass=9 fail=0` in this environment (`stock`/`balloon`/`argon2`/`hkf-simulator`
positives + 4 wrong-key negatives, each classified by failure signature).

## Real-build attempt result (earlier, superseded by the section above)

A real build **was** attempted here, and it materially corrected an earlier assumption: this image
already ships wxWidgets 3.2, libfido2, and FUSE, and has root + loop devices — so it **is**
build-capable. `make NOASM=1 NOGUI=1 KEYSLOTS=1 …` compiled the fork's own code cleanly (Platform, the
Volume ciphers, the Crypto layer with `NOASM`, and — with hand-written stub PC/SC headers — the
smartcard loader). The build did **not** reach a finished binary, for one reason only: stock
VeraCrypt's EMV/PC-SC smartcard support (`Common/SCard*.cpp`, `Common/EMV*.cpp`) needs the real
`libpcsclite-dev` headers, which are **not apt-installable in this particular image** (the mirror's
PPAs 403). Hand-stubbing the full PC/SC dev-header surface is an unbounded stock-dependency yak-shave
and was deliberately stopped.

**What this proves:** the fork's own code (including the AF-split Makefile fix and every gated feature
object) is build-clean; the remaining gap is a packaging issue, not a code issue. On any box with a
working apt:

```sh
sudo apt-get install -y libwxgtk3.2-dev libpcsclite-dev libfido2-dev libfuse-dev yasm
cd src && make NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1
sudo bash verification/realbuild/acceptance.sh
```

(The AF-split link fix was independently reproduced and verified: the pre-fix KEYSLOTS object set fails
with `undefined reference to AfSplit`, the post-fix set links clean — see the build-wiring commit.)

## Note on the harness's own findings

Writing this surfaced a real product-build break: `Common/KeyslotStore.c` calls `AfSplit`/`AfMerge`, but
`Core/Core.make`'s `KEYSLOTS` object list omitted `AfSplit.o`, so `make KEYSLOTS=1` failed to link. Fixed
(commit adds `AfSplit.o` + `KeyslotAreaFile.o` and `BALLOON`/`SHAMIRMAC`/`SHARECODE` make knobs). The
verification suite never caught it because it compiles the Common objects individually — exactly the gap
this real-build layer exists to close.

## Boundary fact — what the sandbox CAN and CANNOT do for the HKF v2 (Rank-1) wiring

*Recorded 2026-07-23 from a timeboxed compile probe, so no future session re-derives it.*

**Sandbox CAN (verified):** the C++ Volume/Core sources that carry the derivation seam **compile clean
in this environment** with the project's own flags + `wx-config`:

```sh
cd src; WX=$(wx-config --cxxflags)
BASE="-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -DARGON2_NO_THREADS \
      -DTC_NO_GUI -DwxUSE_GUI=0 -DVC_ENABLE_HKF -I. -ICrypto -ICrypto/Argon2/include -IVolume -ICore -IPlatform"
g++ -std=c++11 -c        $BASE $WX Volume/VolumeHeader.cpp -o /tmp/VolumeHeader.o   # -> rc 0, 367 KB object
g++ -std=c++11 -fsyntax-only $BASE $WX Core/VolumeCreator.cpp                        # -> rc 0
```

So a **compile-clean check of the C++ wiring edits** — `VolumeHeader::Decrypt` (the compute-once v2→v1
loop + the extracted `DecryptWithEffectivePassword` helper), both `VolumeCreator.cpp` create sites, and
the `HKFMixPasswordWithResponse` / `HKFMixPasswordVer` overloads in `Volume/HardwareKeyFactorMix.h` — IS
sandbox-feasible across stock / `VC_ENABLE_HKF` / `+VC_ENABLE_HKF_MIX_V2` flag sets, and was run
(`g++ -std=c++14 -fsyntax-only`, both clean).

**The C path (`Common/Volumes.c`) is a special case — corrected finding.** An earlier draft of this
note claimed Volumes.c "compiles as a Common object and is covered by the flag matrix." **That was
wrong.** Confirmed 2026-07-23: `Common/Volumes.c` is **not compiled by the Linux build at all** — it is
in **no** `.make` `OBJS` list (`Core.make`, `Common.make`, `Volume.make`, `Main.make`), and it is **not**
in `flag_matrix.sh`'s `MODULES` list. It is Windows-driver / shared-format code: it `#include <io.h>` and
uses `WORD` / `TC_EVENT` / `HANDLE`, all Windows types. On Linux the mount/create path runs entirely
through the **C++** path (`VolumeHeader.cpp` + `VolumeCreator.cpp`). Consequence: the Volumes.c v2 wiring
(the `ReadVolumeHeaderWithAbort` compute-once wrapper + `CreateVolumeHeaderInMemory` v2 create) **cannot
be compiled in this Linux sandbox and can only build under the Windows driver toolchain.** What the
sandbox does verify for the C path: the **new wrapper's logic** (constants, seam-function signatures,
control flow) compiles clean against the real `Common/HardwareKeyFactor.h` in an isolated micro-TU on
gcc + clang; the pattern mirrors the pre-existing `#if defined(VC_ENABLE_HKF)` block two lines above.

**Sandbox CANNOT (permanent — real-build only):** a behavioural **header round-trip** through the real
`CreateVolumeHeaderInMemory` → `ReadVolumeHeader` (C path, Windows) or `VolumeHeader::Decrypt` (C++ path).
That requires *linking the whole mount/create pipeline* — every cipher, `EncryptionModeXTS`, `Pkcs5`, the
`EncryptionThreadPool` runtime — which the verification suite has never done and is not its convention.
Confirmed: `build_and_verify.sh` references `Volumes.c` only in a comment (never links it); `hkf_cpp.cpp`
is a reference-only harness ("needs the compiled VeraCrypt C++ objects"). Therefore the v2/v1 version-try
**mount round-trip, the wrong-factor rejection end-to-end, and real-token round-trips are REAL-BUILD
acceptance items**, not suite steps. The sandbox proof stops at the **seam level** (suite step `[81]`,
`hkf_mixv2_wiring_test.c`): the process-wide active-config seam (`HKFSetActiveConfig`), compute-once
(`HKFComputeActiveResponse`, one backend query across both version attempts), v2-first/v1-fallback
dispatch over the real `HKFApplyIfConfiguredVer`, wrong-factor-opens-neither, and cross-path
byte-identity (C create path == the C++ overload's operations) — all over the real compiled
`HardwareKeyFactor.o`, with the v2-enrolled key additionally cross-checked against the independent
python HKDF.

Acceptance items to run on a real build for the Rank-1 wiring:
1. Create a factored volume with the flag on (⇒ v2); mount it — succeeds on the **first** (v2) attempt.
2. Create a factored volume with the flag off / forced v1; mount with the flag on — succeeds via the
   **v1 fallback** (v2 tried first and failed).
3. Wrong factor: mount opens **neither** version.
4. No factor configured: single-pass mount, derived header key byte-identical to a control build without
   `VC_ENABLE_HKF_MIX_V2`.
5. YubiKey/FIDO2: the try loop performs **one** token round-trip per mount attempt, not two (compute the
   response once, mix v2 then v1 over the same bytes).
6. **Key hygiene (Windows-build acceptance item):** every return path out of the `ReadVolumeHeaderWithAbort`
   v2 wrapper burns `hkfResp` — including the `HKFComputeActiveResponse` failure exit (a backend may write
   response bytes and *then* fail on a short/truncated token) and the no-factor early return. Verified in
   the sandbox only by inspection (3 returns, each immediately preceded by `burn (hkfResp, sizeof hkfResp)`)
   plus an isolated-TU gcc+clang syntax check against the real `Common/HardwareKeyFactor.h`; the file itself
   is Windows-only (see above), so a compiled/ASan confirmation is a Windows-driver-build item.
