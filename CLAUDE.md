# CLAUDE.md — context for continuing this project

This repo is a **private fork of VeraCrypt 1.26.29** that hardens the *key-derivation* path with
optional hardware/threshold factors and a factor-gated decoy. It is defensive disk-encryption work:
strengthening password entropy (the real weak link), not the cipher.

## Scope & boundary (read first)

Everything here is **access-control cryptography** — protecting data the user holds. That is in
scope. **One thing is deliberately out of scope and must stay out:** an automated tool that
*fabricates a false record of computer activity* (forged timestamps, synthetic browser/history
artifacts) to deceive a forensic examiner. That is evidence fabrication, not confidentiality, and it
was declined on purpose (see `ROADMAP.md` → DESCOPED and `docs/DECOY-VOLUME-SPEC.md §6`). Keep the
line where it is: build confidentiality/deniability *storage* and access control; do not build
tooling whose function is to manufacture fake evidence. Everything the users actually want
(coercion resistance, split trust, safe dead-man) is achievable with the threshold/split-key design
already here — no fabrication required.

## Architecture: the one seam everything hangs off

VeraCrypt derives a header key as `PBKDF2/Argon2(password, salt)` and encrypts the volume under keys
stored (encrypted) in the header. **All of this project's factors work by mixing an extra secret into
the password *before* PBKDF2**, using VeraCrypt's exact keyfile pool method (rolling CRC-32 into a
128-byte pool, then `password[i] += pool[i]`). Consequence: **no header-format change** — a factored
volume behaves like one with a dynamically-computed keyfile.

There are **two derivation code paths**, and both are hooked:
- **C path** — `src/Common/Volumes.c` (`ReadVolumeHeader` mount, and the format path). Used by the
  **Windows driver** and shared code.
- **C++ path** — `src/Volume/VolumeHeader.cpp::Decrypt` (mount) and `src/Core/VolumeCreator.cpp`
  (create). Used by the **Linux/macOS application** (the CLI and GUI). *This is the one that runs on
  Linux — C-path hooks alone do not fire there.*

The mixing math is identical across both, so keys are **byte-identical cross-platform** (proven).

## Module map (the new/changed files)

```
src/Common/HardwareKeyFactor.{c,h}   the factor module: backends + mixing + gating
   backends: YK_HMAC_SHA1 (libykpers), FIDO2_HMAC_SECRET (libfido2), SIMULATOR, RAW_SECRET
   HKFComputeResponse()  -> response from (challenge=salt); HKFMixResponseIntoPassword() -> pool mix
   HKFApplyIfConfigured() -> compute+mix in one call (used at the derivation sites)
   HKFShouldApply(cfg, isHidden) -> factor-gating decision (HKF_APPLY_ALL / HKF_APPLY_HIDDEN_ONLY)
   g_hkfActiveConfig / HKFSetActiveConfig() -> process-wide active config (set by CLI before op)
   rawSecretBindSalt (gated -DVC_ENABLE_HKF_SALT_BIND) -> RAW_SECRET returns HMAC-SHA256(secret,salt);
     CLI --hkf-bind-salt; binds a reconstructed/threshold secret to the volume (docs/SALT-BINDING-SPEC.md)
   HKFComputeResponse length conditioning (gated -DVC_ENABLE_HKF_LEN_CONDITION) -> folds any response
     >32 bytes through sha256()->32, keeping a raw 33..64-byte Shamir RAW_SECRET inside the CRC pool's
     proven-injective regime (wrap begins at 33 bytes). No-op for <=32 (all HW backends + salt-bound).
     Security-analysis addendum §6; docs/CRC-SEAM-ADDENDUM.md; changes derived key for >32B factors.
   HKFApplySaltBindDefault (gated -DVC_ENABLE_HKF_SALT_BIND_DEFAULT) -> salt-binding ON by default for
     RAW_SECRET (opt-out rawSecretNoBindSalt / CLI --hkf-no-bind-salt); addendum Rec 1.
   HKFMixResponseIntoPasswordV2 / ...Ver (gated -DVC_ENABLE_HKF_MIX_V2) -> Rank-1 mix: HKDF-SHA256 over
     password||response (info "VeraCrypt/HKF/mix/v2") replacing the CRC pool; mount tries v2 then v1
     (version-try loop, no header-format change). docs/HKF-MIX-V2-SPEC.md; addendum §7.
src/Common/Shamir.{c,h}              Shamir M-of-N over GF(2^8); shamir_split/shamir_combine
src/Common/ShamirMac.{c,h}           keyed per-share MAC (gated -DVC_ENABLE_SHAMIR_MAC): adversarial
   share tamper/fabrication detection = HMAC-SHA256(macKey,"VCSMshare1"||x||len||y) over Sha2.c [40]
   (dealer-consistency VSS stays the prime-field Feldman/Pedersen scheme [31]/[32]; no GF(2^8) analogue)
src/Common/ShareCode.{c,h}           transcribable recovery encoding (gated -DVC_ENABLE_SHARECODE):
   bech32/BIP-173 checksummed "vcs1..." string for a share (+optional MAC), typo-detecting [42]
src/Volume/HardwareKeyFactorMix.h    C++ glue: HKFMixPassword(VolumePassword, salt) for Volume/Core
src/Volume/EncryptionModeAdiantum.{h,cpp}  wide-block EncryptionMode over Crypto/Adiantum (gated
   -DVC_ENABLE_ADIANTUM_MODE / make ADIANTUM_MODE=1). Tweak = data-unit number as 8 LE bytes + SectorOffset;
   refuses partial units and oversized sectors. Proven by verification/realbuild/adiantum_mode.sh (17/17;
   a 1-bit plaintext flip changed 509 of 512 ciphertext bytes — XTS would change 16).
   NOT registered in EncryptionMode::GetAvailableModes() — deliberate: it bundles its own AES-256/
   XChaCha12/NH-Poly1305, IGNORES the CipherList, and does NOT compose into cascades, so it must never be
   offered in a cascade UI. GetKeySize() is its own 32 bytes, not a sum over Ciphers.
src/Main/HardwareKeyFactorCli.h      wx-free option-string -> HKFConfig parser (BuildHKFConfig)
src/Crypto/Sha3.{c,h}                from-scratch FIPS-202 (for the SHA3-512 PRF)
src/Common/KeyScrub.{c,h}            cross-platform RAM key hygiene (gated -DVC_ENABLE_KEYSCRUB)
   VcSecureWipe() -> barrier-hardened zeroize; scrub registry -> VcScrubAll() erases all live secrets
   VcKsRamTransform()/VcKsRamProtect() -> ChaCha-at-rest for secrets (mirrors Common/Crypto.c VcProtectMemory)
   HKFScrubActiveConfig() (in HardwareKeyFactor.c) -> wipe+detach the active factor secret
src/Core/KeyScrubEvents.{h,cpp}      C++ event manager: scrub on unmount/idle/screen-lock/new-device
src/Common/DuressToken.{c,h}         duress-passphrase recognition (gated -DVC_ENABLE_DURESS)
   DuressTokenDerive() -> HMAC-SHA256(salt,passphrase) over in-tree Sha2; DuressTokenMatch() const-time
   used by UserInterface::DuressDismount (Main) = dismount all + KeyScrub ScrubNow(), mount nothing
src/Common/Keyslot.{c,h}             per-slot VMK wrap/unwrap (gated -DVC_ENABLE_KEYSLOTS; fork-only)
   KeyslotWrapWithDK/UnwrapWithDK -> KDF(pluggable)->ChaCha20 wrap + HMAC-SHA256 selector; proven [8]
src/Common/KeyslotStore.{c,h}        3 backends over a KeyslotArea (KSB_HEADER/SIDECAR labeled table,
   KSB_DENIABLE bare records at a passphrase-derived slot); KeyslotAdd/Open/Revoke/Count; lifecycle [9]
src/Common/KeyslotKdf.c              shipping KeyslotKdfSha512 = in-tree derive_key_sha512 (PBKDF2-512)
src/Common/AfSplit.{c,h}             LUKS/TKS1 anti-forensic split/merge (arbitrary n, partial diffuse
   section); KeyslotStoreCfg.afStripes wires it into records (labeled v2, authenticated s) [36]
src/Common/KeyslotAreaFile.{c,h}     file-backed KeyslotArea bindings: header-slack [512,64K),
   sidecar whole-file, deniable free-extent clamped below hidden start; bounds-checked stdio [37]
```
Keyslots model: one master key (VMK), many independent wrappings. Slot 0 = untouched native header;
slots 1..N wrap the same VMK, so add/rotate/revoke never re-encrypts the body. Payload = flags[1]||vmk
(duress bit encrypted). CLI + mount-time slot search remain (docs/KEYSLOTS-SPEC.md §9).

src/Common/NetShare.{c,h}            network-bound share, McCallum-Relyea (gated -DVC_ENABLE_NETSHARE;
   `make NETSHARE=1`) -> Ed25519 group + RFC 8032 s5.1.3 COMPRESSED-POINT DECOMPRESSION (the wire format
   every PoC deferred); transport is INJECTED (NetShareTransportFn) so Common/ has no sockets — the POSIX
   TCP client lives in Main/NetShareTransport.h. Credential blob NSC||ver||S||C||cksum holds no secret.
   Off-network returns NETSHARE_ERR_TRANSPORT, never a share, so "unreachable" != "wrong password".
   CLI --ns-server/--ns-cred/--ns-enroll/--ns-server-key/--ns-timeout; steps [102] + netshare_cli.sh

src/Common/Pkcs5.c (gated -DVC_ENABLE_ARGON2_PARAMS) — explicit Argon2id memory/iterations/parallelism
   Argon2SetParamsOverride()/Argon2GetResolvedParams()/Argon2GetParallelism(); CLI --argon2-memory/
   -iterations/-parallelism. Not stored (supplied like PIM at create+mount). docs/ARGON2-PARAMS-SPEC.md

Config: `HKFConfig` (in `HardwareKeyFactor.h`) carries the backend, YubiKey slot, FIDO2 rp/credid/pin,
simulator secret, `rawSecret` (Shamir reconstruction), and `applyPolicy`.

## Build (Linux)

```sh
# COMPLETE dep set, learned from an actual build (scripts/build-product.sh DEPS is authoritative).
# build-essential/yasm/libpcsclite-dev are STOCK VeraCrypt deps: without them the build fails inside
# UPSTREAM code, which reads like the fork is broken. Do not trim this list.
sudo apt-get update && sudo apt-get install -y \
  build-essential pkg-config yasm libwxgtk3.2-dev libpcsclite-dev \
  libfuse-dev libfido2-dev libykpers-1-dev
# libwxgtk3.2-dev is named differently on older releases — fall back to libwxgtk3.0-gtk3-dev.
# No yasm? add NOASM=1 to the make/build-product line (drops the x86-64 AES assembler, not the fork).
# feature flags (opt-in; a build with none is behaviourally stock):
#   -DVC_ENABLE_HKF            derivation hooks + CLI options
#   -DVC_ENABLE_YUBIKEY_HMAC   YubiKey backend   (link -lykpers-1)
#   -DVC_ENABLE_FIDO2          FIDO2 backend     (link -lfido2)
#   -DVC_ENABLE_HKF_SIMULATOR  software token    (testing only — never ship)
cd src && make CC=clang CXX=clang++ HKF=1            # or HKF_SIMULATOR=1 / YUBIKEY=1 / FIDO2=1
```
The make knobs are wired (top-level `Makefile` + `Core/Core.make`): `HKF=1` compiles
`HardwareKeyFactor.o` + `Shamir.o` and exposes the `--hkf-*` CLI; `YUBIKEY=1`/`FIDO2=1` add the
backend + `-lykpers-1`/`-lfido2`; `HKF_SIMULATOR=1` adds the software token (testing only — never
ship). Either compiler works — `Crypto/chacha256.c` + `chachaRng.c` had a redundant `static VC_INLINE`
(VC_INLINE already expands to `static inline` on GCC → "duplicate 'static'") that made them clang-only
where a feature build pulls them in; that redundant `static` is now removed, so **gcc and clang both
build the full feature set**. Still **`make clean` when changing feature
flags** — make does not rebuild objects on `-D` changes, and a mixed binary silently drops hooks
(see docs/REAL-BUILD-VALIDATION.md). **A mixed build does not fail loudly — it fails as wrong behaviour**
(a volume that will not open), which reads exactly like a crypto bug; that misdiagnosis cost a session.
`scripts/build-product.sh` now stamps the resolved `-D` set into `src/.build-flags` and
`verification/realbuild/open_roundtrip.sh` refuses to run against archives whose stamp disagrees with its
own flags. Prefer `scripts/build-product.sh` (true clean) over bare `make`. Windows: add the sources to `Common.vcxproj` manually.

## Which environment are you in? (this changes what is testable)

**Check before inheriting any "not testable here" claim.** Much of this repo's language was written from a
container where `/dev/mapper/control` is absent, so nothing could ever kernel-mount. Several of those
claims have since been **tested and settled** (2026-07-25) — do not re-inherit them as open.

**Probe the box, not one capability.** "Has dm-crypt" does not mean "is a full VM": one environment used
here had a kernel device-mapper but **no systemd/logind seat, no udev, and no USB**, so it could mount
volumes but could not test the KeyScrub OS triggers at all. Check each axis you actually need:

```sh
[ -e /dev/mapper/control ] && echo "dm-crypt: yes (Tier 2 mounts testable)" || echo "dm-crypt: no"
loginctl list-seats >/dev/null 2>&1 && echo "logind seat: yes" || echo "logind seat: no (KeyScrub screen-lock untestable)"
udevadm control --ping >/dev/null 2>&1 && echo "udev: yes" || echo "udev: no (KeyScrub device-connect untestable)"
[ -d /dev/bus/usb ] && echo "USB: yes (Tier 3 possible)" || echo "USB: no (YubiKey/FIDO2 untestable)"
```

| | container, no dm | dm-crypt but no seat | full desktop VM + USB |
|---|---|---|---|
| verification suite, product build, `open_roundtrip.sh` | yes | yes | yes |
| `acceptance.sh` Tier 2 — **loopback create/mount/dismount** | SKIPs (no dm) | **yes — run it** | yes |
| kernel dm-crypt mount · keyslot auto-search · duress e2e · live flash warning | no | **yes** | yes |
| KeyScrub logind screen-lock / udev device-connect triggers | no | **no — needs a real seat** | **yes — still open** |
| YubiKey / FIDO2 hardware backends | no | no | **only with USB passthrough (Tier 3) — still open** |

**Already settled — do NOT list these as untested** (`docs/CANT-CLAIMS-AUDIT.md`, 2026-07-25):
**kernel dm-crypt mount** · **keyslot mount-time auto-search on real media** (normal slot mounts, duress
slot fires the duress action and mounts nothing) · **duress end-to-end** (dismount-all on real mounted
volumes) · **live flash-media warning** · **true power-loss recovery on a raw block device** ·
**network-share over a genuine two-host TCP link**. The genuinely open items are the last two table rows
plus **SSD/FTL remnant behaviour** (needs raw flash) and the **Windows C-path header round-trip**.

On a VM: `sudo bash verification/realbuild/acceptance.sh` after a build. It is self-gating and prints
SKIP rather than FAIL for anything the box cannot do, and it is non-destructive — every volume is a file
container inside a `mktemp -d`; nothing in the tree writes to a real block device (the `/dev/sd*` strings
in `verification/flash_probe_test.c` are string-parsing unit tests, not device access).

**The session-start hook does not provision a non-container box.** `.claude/hooks/session-start.sh` gates
its dep install on `CLAUDE_CODE_REMOTE=true` so it never mutates someone's own machine uninvited. On a
dedicated/disposable VM, opt in with `VC_PROVISION=1` in the environment, or just run the apt line above
by hand.

## Verification methodology (the project's convention — keep it)

**Every crypto change is proven two ways before it's considered done:**
1. byte-for-byte against an **independent Python reimplementation** of the same math, and
2. against **real compiled VeraCrypt objects** (e.g. the actual `derive_key_sha3_512` /
   `Pkcs5HmacSha3_512`), so the integration — not just the algorithm — is exercised.

**3. And if it claims to implement a published standard, it MUST also be anchored to an artifact we did
not author** — official test vectors (RFC/NIST/BIP/upstream KATs) or a mature third-party implementation
(libsodium, OpenSSL/hashlib). This is non-negotiable and was learned the hard way: step `[94]` found the
from-scratch ristretto255 hash-to-group was **non-conformant to RFC 9496/9497**, and rules 1+2 had passed
it for months. A Python twin *we* write encodes the same reading of the spec as the C, so when our reading
is wrong both are wrong identically and they agree for the same wrong reason; rule 2 proves integration,
not interpretation. Twins catch implementation slips, never interpretation errors. Where no standard
exists (fork-specific formats, the decoy layout, ORAM), a twin + properties is correct and sufficient —
but then don't call the result "conformant". Classify every step's anchor in
`docs/VERIFICATION-ANCHORS.md` and state the class in the step comment.

**Fetching official vectors: use `curl`, not `WebFetch`.** The sandbox *can* reach the open web — this was
mis-diagnosed once and cost a round-trip asking the user to paste specs by hand. `WebFetch` returns 403
for `rfc-editor.org` and `datatracker.ietf.org`, but plain `curl` to the same URLs succeeds. Two gotchas:
piping `curl` straight into `sed`/`grep` can truncate at 4096 bytes, so **fetch to a file first, then
slice it**; and CFRG/IETF machine-readable vectors (e.g. `cfrg/draft-irtf-cfrg-voprf`
`poc/vectors/allVectors.json`) are usually easier to parse than the RFC text.

```sh
curl -sS -o /tmp/rfc8439.txt https://www.rfc-editor.org/rfc/rfc8439.txt   # then sed the file
```

**Same lesson for `apt`: it works — install the dep instead of declaring the build impossible.** The
session-start hook used to report *"product build NOT fully provisionable (apt offline/locked)"*, which was
a **false negative from a shell bug**: `ls a b` exits non-zero if *either* path is missing, so the pcsclite
probe failed whenever `/usr/include/PCSC/pcsclite.h` existed but `/usr/include/pcsclite.h` (which never
exists) did not. Fixed in `.claude/hooks/session-start.sh`. `libpcsclite-dev`, `libsodium-dev`,
`libfido2-dev` and `libwxgtk3.2-dev` all install fine here. **Before concluding the environment cannot do
something, try it** — two capability mis-diagnoses in one session (WebFetch→"no web", one bad `ls`→"no
product build") each cost real work that was available all along.
Real hardware backends are additionally **compiled and linked against the real libraries**
(`-lykpers-1 -lfido2`) and shown to fail safe with no device.

Self-contained checks (no VeraCrypt build needed):
```sh
cd verification && ./build_and_verify.sh
```
covers: HMAC-SHA1 (RFC 2202), FIDO2-profile HMAC-SHA256, keyfile-pool mixing, CLI parsing, the
factor-gated decoy property, and Shamir (GF(2⁸) KATs + threshold + Python cross-check). Harnesses that
need compiled VeraCrypt objects (`htest.c`, `hkf_cpp.cpp`, `hkf_decoy.cpp`, `shamir_chain.c`,
`verification/prf/*`) are included for reference; their expected results are in the docs.

Key proven values (regression anchors): mixed password `f965c9e3…`; SHA3-512 header key `628882be…`;
Shamir 3-of-5 header key `a8b0cbb7…`; wrong secret / below-threshold flips 64/64 header-key bytes.
Fork feature anchors: KeyScrub RAM-protect `d28b461b…` [6]; duress tag `3d874ea9…` [7]; keyslot record
`56434b53…` [8]; MR network-share `cc288fab…` [10]; Argon2 RFC-9106 `0d640df5…` [11]; salt-bind
`4619ed18…` [12]; write-only ORAM state `203b068d…` [13]; decoy-fragment `47067dd6…`/`a52a1326…` [14];
AF-split keyslot record `76b60553…` [36] (`Common/AfSplit.{c,h}` + `KeyslotStore.c` `afStripes`);
KeyslotArea file bindings behavioural [37] (`Common/KeyslotAreaFile.{c,h}`); Balloon mountable PRF
[38] (`-DVC_ENABLE_BALLOON_KDF`: `derive_key_balloon` in Pkcs5.c + `Pkcs5Balloon`, dk-expansion
vectors chained to the [16] anchor); MR at production params over full Ed25519 `ab8b717f…` [39]
(`verification/netshare_ed25519_poc.c`, from-scratch group vs RFC 8032 §7.1 KAT + Python); Shamir
GF(2^8) dudect timing screen [41] (self-validating: flags a leaky ref, clears real gf_mul/gf_inv);
transcribable share code bech32/BIP-173 [42] (`Common/ShareCode.{c,h}`); OPRF at production params
over full ristretto255 [43] (`verification/oprf_ristretto_poc.c`, RFC 9496 A.1 KAT + Python);
threshold OPRF/PPSS over ristretto255 [44] (`verification/toprf_ristretto_poc.c`, Shamir over Z_L +
Lagrange-in-the-exponent reconstructs the single-key output); McCallum–Relyea network-share END TO END
over a real socket transport [49] (`verification/netshare_transport_poc.c`, forked server + C-blob;
enroll share `edf4bd73…` == python; off-network + wrong-server fail).
`verification/build_and_verify.sh` runs all.

## Conventions

- Gate all additions behind `#if defined(VC_ENABLE_HKF*)` so the default build is byte-for-byte stock.
- Never change the on-disk header format; mix into the password pool instead.
- Keep docs honest: state the multi-snapshot / SSD / imaged-first / share-distribution limitations
  rather than overselling deniability (`docs/THREAT-MODEL.md`).
- Match VeraCrypt's existing style in each file; C for `Common/Crypto`, C++ for `Volume/Core/Main`.

## Good next tasks (see ROADMAP.md)

1. ~~**Multiple keyslots — CLI + header-backend integration**~~ — **DONE, including the mount-time
   auto-search.** The `--keyslot-add/open/rotate/kill/list` CLI, the C++ mount-path binding
   (`Volume/KeyslotVolumeBinding.h`), and VMK recovery via native-header-or-keyslot are proven on real
   volumes; **all three backends** (header / sidecar / deniable) open, revoke and rotate with slot 0 and
   the data region byte-untouched. The auto-search is **verified on real dm-crypt** (2026-07-25): a
   plain `--mount` with a normal slot passphrase mounts via the slot, and with a **duress** slot
   passphrase fires the duress action and mounts nothing. Remaining: backup-header table mirroring, and
   multi-snapshot validation of the deniable backend (needs real media over two images).
2. ~~**Network-bound share source — finish the integration**~~ — **DONE.** MR proven at production
   Ed25519 params [39], cross-host over real TCP [101], shippable `Common/NetShare.{c,h}` with RFC 8032
   §5.1.3 compressed-point decompression [102], and the `--ns-*` CLI proven end to end against a live
   server (`verification/realbuild/netshare_cli.sh`, 8/8; `make NETSHARE=1`). Note the scope lesson:
   "only the CLI remains" was wrong — every PoC put raw coordinates on the wire, so the real gap was a
   missing wire format needing new crypto. Remaining: a Tang/HTTPS endpoint and a constant-time group.
3. ~~**End-to-end validate the explicit Argon2id params on a real build**~~ — **DONE, and it was always
   sandbox-testable.** Create with `--hash=Argon2id --argon2-memory/-iterations/-parallelism`, then
   `Volume::Open` in-process via `verification/realbuild/open_roundtrip.sh`: same params open (positive
   control), and wrong memory / wrong iterations / wrong parallelism / no override / wrong password all
   reject. 11/11, CI-gated. The "not sandbox-testable" claim was inherited, never tested — see
   `docs/CANT-CLAIMS-AUDIT.md`. The kernel dm-crypt mount has since been verified too.
4. ~~**End-to-end duress-dismount test on a real build**~~ — **DONE (2026-07-25).** Two volumes mounted
   via kernel dm-crypt, then `--duress-dismount` → all dismounted (`--list` empty, 0 dm mappings); and
   separately, entering the *registered duress passphrase* at `--mount` dismounted everything and
   mounted nothing. The coupled `KeyScrub ScrubNow()` runs in the same path but the RAM scrub is not
   independently observable from userspace — that part remains unverified, not proven.

**Actually open now, in rough priority order:**

5. **V2-format mount side** — `DiscoverMode` call site, populating the reserved MAC table, backup-header
   mirroring. ROADMAP T1-1 named the missing wide-block `EncryptionMode` as its blocker; that blocker is
   gone (`Volume/EncryptionModeAdiantum`). **Do #6 first**: `V2Mode` is `{HCTR2, ADIANTUM, NONE}` and
   `V2FormatDiscoverMode` picks by trying each mode's MAC key, so with only one mode implemented you
   cannot prove discovery *discriminates* — only the `NONE` negative.
6. **HCTR2 `EncryptionMode` class** — the other half of T2-4; algorithm already KAT-proven [28]. Same
   shape as `EncryptionModeAdiantum`, and the prerequisite for testing #5 properly.
7. **Register Adiantum in `EncryptionMode::GetAvailableModes()`** — deliberately NOT done. It bundles
   its own primitives and does not compose into cascades, so "AES-Adiantum" and "Serpent-Adiantum" would
   be the same construction; offering it in a cascade UI would lie. This is a format/UI decision, not an
   oversight.
8. **Validate the KeyScrub OS triggers** (logind screen-lock, udev device-connect) — needs a real
   desktop seat, which a dm-crypt-only box does *not* provide. Separately, the kernel-side dm-crypt
   master-key scrub the user-space scrub cannot reach.
9. **YubiKey / FIDO2 on real hardware** — two of the four HKF backends have only ever been shown to link
   and fail safe with no device. Needs USB passthrough. This is the largest untested surface in the fork.
```
```
