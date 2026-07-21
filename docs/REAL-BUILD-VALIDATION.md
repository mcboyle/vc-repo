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
| 3 | Balloon as `--hash` | 2 | create + mount + dismount a `--hash=Balloon` volume | **wired** (harness) |
| 4 | Argon2 explicit params | 2 | create + mount with `--argon2-memory/-iterations`; **mount with different params must fail** | **wired** (harness) |
| 5 | HKF factor (simulator) | 2 | create + mount with `--hkf-backend simulator`; wrong secret fails | wired CLI; harness marks PENDING until confirmed |
| 6 | Multiple keyslots enroll/open/rotate/revoke | 2 | `--keyslot-add/open/rotate/kill/list` round-trip; duress-slot hook | **PENDING** — C++ stream adapters + CLI (`KEYSLOTS-SPEC.md §9`) |
| 7 | Duress-dismount end-to-end | 2 | mounted volumes + `--duress-dismount` + duress passphrase → all dismount + scrub | **PENDING** — wx orchestration (`DURESS-DISMOUNT-SPEC.md`) |
| 8 | Network-share (MR) unlock | 2+ | enroll against a Tang-style server, unlock; off-network stays locked | **PENDING** — client transport + `C`-blob format + CLI (`NETWORK-SHARE-SPEC.md`) |
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

## Real-build attempt result (this environment)

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
