# Ideas backlog — advanced security, algorithms, UX

Candidate work beyond `ROADMAP.md`. Nothing here is committed to; it is a menu with enough context to
pick from. Companion to `CLAUDE.md` (architecture + conventions) and `docs/THREAT-MODEL.md`.

**Conventions that apply to everything below** (from `CLAUDE.md`):
- Gate every addition behind a `VC_ENABLE_*` macro; a default build stays byte-for-byte stock.
- Prove every crypto-relevant change **two ways**: against an independent Python/reference
  implementation *and* against real compiled VeraCrypt objects.
- Do not change the on-disk format unless the item is tagged `[FORMAT]`, and then spec it first.

**Tags** — `[S/M/L]` effort · `[FORMAT]` touches on-disk layout · `[HW]` needs real hardware ·
`[SANDBOX-OK]` fully verifiable without a real build · `[RESEARCH]` open problem, expect a literature
review before code.

---

## P0 — correctness and hardening of what already exists

Do these before adding surface area.

1. **Constant-time GF(2⁸) in Shamir** `[S] [SANDBOX-OK]` — **DONE** (ROADMAP DONE #13,
   `patches/shamir-constant-time.patch`). Replaced the table+branch `gf_mul`/`gf_inv` with a branchless
   Russian-peasant multiply and `a^254` fixed-exponent square-multiply — no tables, no secret-dependent
   control flow. Proven byte-identical to the table version over all 65536 inputs (step `[5]`). A
   `dudect`/`ctgrind` timing test in CI remains the recommended follow-up.
   ~~the shipped `gf_mul` does `gf_exp[gf_log[a] + gf_log[b]]` plus an `if (a==0||b==0)` early-out.~~
2. **Constant-time keyslot search** `[S]` — **DONE** (`KeyslotUnwrapCT` + rewritten `KeyslotOpen` in
   `Common/Keyslot*.c`): scans a fixed slot count, runs the KDF + MAC + decrypt on EVERY slot
   (regardless of the `VCKS` marker), uses config cost/length not the stored bytes, and selects in
   constant time with no early return — leaking neither which slot matched nor how many are populated.
   Cost: one KDF per slot per open (the LUKS trade-off). Lifecycle unchanged (step `[9]`).
3. **Anti-forensic (AF) splitting for keyslots** `[M] [FORMAT]` — **core proven** (step `[15]`,
   `docs/AF-SPLIT-SPEC.md`): LUKS/TKS1 split/merge diffuses a slot's key across s stripes so a *partial*
   recovery (SSD wear-leveling remnant) yields nothing — round-trip + any-missing-stripe-defeats-recovery
   verified vs. real `Sha2.c` and an independent Python ref (anchor `ddb23937…`). Remaining: wire the s
   stripes into the keyslot record (`[FORMAT]`) and validate against real flash.
4. **Swap / hibernate / core-dump lockdown** `[S]` — **DONE** (`VcKeyMemoryLockdown` in
   `Common/KeyScrub.c`, called from `KeyScrubManager::Enable`): `mlockall`, `RLIMIT_CORE=0`,
   `PR_SET_DUMPABLE=0`; verified at runtime in step `[6]` `[G]`; hibernation hazard documented loudly
   in `docs/MEMORY-SCRUB.md`. (Yama `PR_SET_PTRACER` scoping can still be added.)
5. **Authenticate the keyslot area** `[M] [FORMAT]` — XTS provides no integrity; a MAC over header +
   keyslot region (keyed from the master key) turns silent tampering into a detected error.
   *MAC construction proven* (step `[20]`, `docs/KEYSLOT-MAC-SPEC.md`): ChaCha20-Poly1305 one-time MAC
   over the area (`otk = ChaCha20(mac_key, nonce)[0..32]`, `tag = Poly1305(otk, area)`), driving the
   real in-tree ChaCha20 + the step-`[18]` Poly1305 — tamper, truncation, and wrong-key all rejected by
   a constant-time check, nonce binds, no volume-format change. Remaining is only where the
   `(nonce, tag)` trailer lives per `KeyslotArea` backend and calling the check before the mount-time
   slot search (rides with the keyslot volume-I/O bindings, `docs/KEYSLOTS-SPEC.md §9`).
6. **Zeroization tests** `[S] [SANDBOX-OK]` — **DONE** (step `[6]` `[H]`): `VcSecureWipe` asserted to
   zero across every size/alignment and survive `-O2` dead-store elimination (observed through a
   separate alias). Broader per-module scratch-wipe assertions can still be added.

---

## A. Integrity and tamper-evidence (biggest structural gap in all FDE)

XTS is malleable at 16-byte granularity: an attacker who can write to the disk can flip ciphertext
bits and produce controlled plaintext garbage without detection. Every item here addresses that.

- **Per-sector authentication (dm-integrity style)** `[L] [FORMAT] [RESEARCH]` — a MAC per sector in a
  separate area/journal. Costs space and write amplification; the payoff is that silent data tampering
  becomes impossible. The honest tradeoff to document is crash-consistency. *Construction + integrity
  properties proven* (step `[21]`, `docs/PERSECTOR-AUTH-SPEC.md`): index-bound one-time MAC
  (`nonce = sector_index`, `otk = ChaCha20(smk, nonce)[0..32]`, `tag = Poly1305(otk, ciphertext)`) on
  the real in-tree ChaCha20 + step-`[18]` Poly1305 — per-sector independence, relocation resistance,
  and wrong-key detection all hold. Open work is only the tag-area layout `[FORMAT]` and crash-consistent
  tag/data updates (could share a journal with the Merkle-path work).
- **Merkle tree over the volume with the root held off-disk** `[L] [FORMAT]` — root stored in the
  header, on the hardware token, or in TPM NV. Detects *any* offline modification, which is the data
  half of evil-maid that the bootloader fingerprint does not cover. *Tree core proven* (step `[19]`,
  `docs/MERKLE-SPEC.md`): RFC 6962 domain separation, index-bound leaves, O(log N) authentication
  paths, single-bit tamper changes the root and rejects the stale proof — vs the real in-tree SHA-256.
  Open work is where the root lives (TPM/token/MAC'd header), the on-disk tree layout `[FORMAT]`, and
  crash-consistent path updates.
- **Rollback / replay protection via a monotonic counter** `[M] [HW]` — TPM NV counter or a
  token-backed counter, so restoring an older snapshot of the volume is detectable. Directly counters
  the snapshot-*replay* variant of the multi-snapshot problem. *Binding construction + replay properties
  proven* (step `[22]`, `docs/ROLLBACK-COUNTER-SPEC.md`): the monotonic counter doubles as the one-time
  nonce (`otk = ChaCha20(commit_key, le64(counter))[0..32]`, `tag = Poly1305(otk, state_root)`) on the
  real in-tree ChaCha20 + step-`[18]` Poly1305 — rollback, forged counter marker, tamper, and wrong-key
  all rejected; the modeled NV counter is increment-only. Open work is the `[HW]` counter source
  (TPM2_NV_Increment / token), commit granularity, and the bricking-recovery path.
- **Header version + anti-downgrade binding** `[S]` — bind the KDF/parameters into the MAC so an
  attacker cannot silently downgrade a volume to weaker parameters. *Binding construction + downgrade
  detection proven* (step `[23]`, `docs/ANTI-DOWNGRADE-SPEC.md`): fixed-width canonical serialization of
  version/prf/cipher/mode/Argon2-mem/iters/parallelism into `HMAC-SHA256(header_key, canon(params))` on
  the real in-tree SHA-256 — every single-parameter downgrade rejected, wrong password rejected,
  encoding proven unambiguous. Open work is only folding `canon(params)` into the keyslot-area MAC's
  covered region (`docs/KEYSLOT-MAC-SPEC.md`) — mostly serialization + coverage, not a new authenticator.

## B. Cipher modes (slow is acceptable — correctness first)

- **Wide-block tweakable modes: HCTR2, AEZ, EME2** `[L] [RESEARCH]` — make the whole sector atomic, so
  flipping a single ciphertext bit randomizes the entire sector rather than 16 bytes. HCTR2 (XCTR +
  POLYVAL) is already used in the Linux kernel for filename encryption and is the most practical
  starting point. This is the single strongest *cryptographic* upgrade available to a disk encryptor.
  *HCTR2 core proven* (step `[26]`, `docs/HCTR2-SPEC.md`): all 35 official google/hctr2 vectors
  (16–512 B × 0/1/16/32/47 B tweaks) reproduced on the real in-tree AES + an RFC-8452-anchored POLYVAL,
  and by an independent python — whole-sector diffusion both directions. With Adiantum (step `[24]`)
  the fork now has both wide-block cores; remaining is the shared `EncryptionMode` seam + benchmarks.
- **Adiantum** `[M]` — XChaCha12 + NH + Poly1305, length-preserving; designed for devices without AES
  acceleration. Relevant if mobile or low-end hardware ever enters scope. *Full construction proven*
  (step `[24]`, `docs/ADIANTUM-SPEC.md`): all 18 official google/adiantum vectors (16–4096 B × 0/17/32 B
  tweaks) reproduced by the C PoC on the real in-tree ChaCha/AES objects AND an independent python;
  single-bit flips randomize the whole sector both directions. Remaining is the `EncryptionMode` wiring
  (mode id rides the step-`[23]` anti-downgrade binding), new-volume-only.
- **Large-block ciphers: Threefish-1024, Rijndael-256 (256-bit block)** `[M]` — larger blocks push out
  birthday-bound concerns at very large data volumes. Rijndael-256 is not AES; document the interop
  consequences.
- **Independent keys and distinct modes per cascade layer** `[M]` — current cascades share structure;
  diversifying modes reduces correlated-failure risk.

## C. KDF and password hardening

- **Memory-hard alternatives to benchmark against Argon2id** `[M] [SANDBOX-OK]` — **Balloon hashing
  algorithm PROVEN** (step `[16]`, `docs/BALLOON-SPEC.md`): expand/mix(delta=3)/extract over the in-tree
  SHA-256, deterministic + salt/space/time-dependent, real `Sha2.c` vs. independent Python byte-for-byte
  (anchor `635ebeac…`). Remaining: wire it as a selectable PRF and benchmark vs Argon2id at equal time
  budgets. Still to survey: **yescrypt** (ROM-hard), **Lyra2**, **Catena**, **scrypt**; and exposing
  Argon2**d** where side-channel exposure is not a concern (a local disk header) for max GPU resistance.
- **ROM-hard KDF with a large local ROM file** `[M]` — derivation reads pseudo-randomly from a
  multi-GB file the user keeps (external disk, second device). An attacker must exfiltrate the ROM as
  well as the header; brute forcing without it is infeasible. Effectively "a keyfile that also imposes
  memory-bandwidth cost." Pairs naturally with the existing keyfile/factor seam.
- **Argon2id auto-calibration to a time budget** `[S]` — benchmark the machine and target e.g. 2 s
  (`cryptsetup --iter-time` model). You exposed the parameters; most users will pick badly.
- **Two-stage derivation** `[S]` — cheap check on the token/slot factor first so a missing token fails
  fast instead of after a full expensive KDF; must not leak *which* factor failed on a real volume.
- **Oblivious PRF (OPRF) password hardening** `[L] [RESEARCH]` — **protocol PROVEN** (step `[17]`,
  `docs/OPRF-SPEC.md`): 2HashDH/CFRG DH-OPRF, output = `SHA256(pw || H2(pw)^k)` with the server holding
  `k`; deterministic + blind-independent, server sees only a blinded element, wrong `k` → different
  output, real `Sha2.c` vs. independent Python byte-for-byte (anchor `ca5691bd…`). Remaining: a real
  CFRG group (ristretto255/P-256), the rate-limited server, and the **threshold OPRF / PPSS** split of
  `k` across servers (composes with the Shamir factor). The most powerful realistic anti-brute-force
  primitive available — offline guessing on a seized disk is impossible without the server.
- **Time-lock / VDF unlock delay** `[L] [RESEARCH]` — a volume that provably cannot be opened faster
  than N hours of sequential computation (RSW time-lock puzzles, Sloth, Wesolowski/Pietrzak VDFs).
  Slow *is* the feature: a coercive encounter with a hard time limit (border stop, short detention)
  cannot succeed, and unlike a wipe nothing is destroyed. Needs careful UX so the owner is not equally
  locked out; consider a delay applied only to specific slots.

## D. Key architecture and multi-party

- **Per-slot policy metadata** `[M] [FORMAT]` — mount read-only, "this slot is decoy", "this slot is
  duress", force hidden-volume protection, max attempts, expiry. Cheap fields in a record you already
  wrap; converts a lot of desired behavior into configuration.
- **Verifiable secret sharing / share checksums** `[M] [SANDBOX-OK]` — **checksum DONE** (step `[5]`):
  `shamir_secret_checksum` (CRC-32) in `Common/Shamir.c` verifies a reconstruction — a below-threshold
  or wrong-share combine is detected instead of returning garbage; matches Python `zlib.crc32`
  byte-for-byte (`3b8cfe40` for the test secret), `patches/shamir-verifiable-shares.patch`. Detects
  accidental corruption/transcription; a **keyed per-share MAC** (adversarial tamper) and full
  Feldman/Pedersen VSS (needs a prime-order group — a second sharing scheme) are the remaining, larger
  steps. Pairs with the SLIP-39 encoding below for the recovery kit.
- **SLIP-39 style share encoding** `[M] [SANDBOX-OK]` — standardized mnemonic words with checksums and
  two-level groups ("2 of 3 family shares AND 1 of 2 lawyer shares"). Solves both transcription errors
  and group policy in one move; the natural encoding for the recovery kit below.
- **TPM holds one share, not the key** `[M] [HW]` — seal a single Shamir share to PCR state instead of
  sealing the master key. Gives measured-boot binding *without* making TPM compromise sufficient,
  which is the standard objection to TPM-based FDE.
- **Information dispersal (Rabin IDA) across devices** `[L] [RESEARCH]` — split the *ciphertext*, not
  just the key, so seizing one device yields nothing reconstructable. Complements Shamir (which splits
  the key) and is a genuinely different guarantee.
- **Online master-key re-encryption** `[L] [FORMAT]` — LUKS2-style, for true post-compromise recovery
  without a full restore cycle.
- **PKCS#11 / PIV smartcard as a fourth HKF backend** `[M] [HW]` — VeraCrypt already speaks PKCS#11
  for keyfiles; a card-decrypt factor covers issued/enterprise credentials and hardware many users
  already carry.

## E. Memory, side-channel, and physical

- **Keys in registers, never in RAM (TRESOR / PRIME model)** `[L] [RESEARCH]` — hold the master key in
  debug or AVX registers so a cold-boot capture of DRAM yields nothing. Strong result, invasive
  implementation, and it constrains the cipher; treat as research.
- **Extend the ChaCha RAM-encryption to all sensitive buffers** `[M]` — passwords, reconstructed
  shares, token responses, not just master keys. Add guard pages and canaries around them.
- **IOMMU / Thunderbolt DMA posture check** `[S]` — detect and warn when DMA protection is off, which
  is the practical delivery route for a live-memory key grab.
- **Bitsliced constant-time fallbacks** `[M]` — for platforms without AES-NI, so timing behavior does
  not depend on the host.
- **Anti-debugging / ptrace hardening** `[S]` — cheap, and it closes trivial live-key extraction.

## F. Boot and platform

- **Measured boot with a PCR-bound share** `[L] [HW]` — see the TPM item in §D; this is the sound
  formulation.
- **Secure Boot signing of the bootloader** `[M] [HW]` — first-class signing rather than relying on
  the fingerprint check alone.
- **Heads / coreboot integration** `[L] [HW] [RESEARCH]` — token-attested boot integrity: the token
  displays or verifies a value only a legitimate boot could produce, which is the strongest available
  evil-maid answer.
- **UEFI/GPT hidden OS** `[L] [FORMAT] [RESEARCH]` — upstream restricts hidden-OS creation to
  MBR/legacy BIOS; every modern machine is UEFI. Large, separate bootloader project.

## G. Deniability

- **Free-space chaff** `[M] [RESEARCH]` — continuously write indistinguishable random data into unused
  space so that hidden-volume writes are not distinguishable from background churn. A cheaper
  approximation of ORAM against the multi-snapshot attack. *This is padding/uniformization of free
  space — a technical countermeasure. It is not, and must not become, synthesis of a false record of
  human activity (see Scope boundary).*
- **Decoy-fragments by default** `[M]` — write hidden-volume-creation-shaped artifacts on *every*
  volume so their presence proves nothing. Partial answer to the SSD remnant tell.
- **Steganographic filesystem** `[L] [RESEARCH]` — Anderson–Needham–Shamir / StegFS lineage; stronger
  hiding than the free-space model, with real capacity and reliability costs.
- **Formal deniable encryption** `[RESEARCH]` — Canetti-style sender/receiver-deniable schemes.
  Mostly theoretical today; worth tracking rather than building.

## H. Post-quantum — the correct framing

The earlier conclusion stands: password-derived **symmetric** disk encryption is already effectively
post-quantum (no key exchange for Shor to break, no ciphertext-in-transit to harvest; Grover only
halves an already-256-bit key). PQ matters **exactly where asymmetric crypto is introduced** — which
this project is now doing:

- **Hybrid KEM for any public-key recovery/escrow slot** `[M]` — X25519 + **ML-KEM-768** (FIPS 203). A
  recovery slot encrypted to an offline public key *is* harvest-now-decrypt-later exposed.
  *KEM + combiner proven* (step `[25]`, `docs/PQ-HYBRID-SPEC.md`): full ML-KEM-768 (keyGen/encaps/
  decaps incl. the implicit-rejection tamper path) reproduces the NIST ACVP FIPS-203 vectors in both C
  (Keccak anchored to the in-tree `Sha3.c`, combiner on the in-tree `Sha2.c`) and independent python;
  the transcript-bound HMAC combiner needs BOTH secrets. Remaining is the transport wiring.
- **Hybrid for the network-bound share exchange** `[M]` — the McCallum–Relyea exchange is
  Diffie–Hellman based; a stored transcript is quantum-exposed. Hybridize it. *The same step-`[25]`
  KEM/combiner is the building block; feed the MR/OPRF output in as the classical secret.*
- **Hash-based signatures for boot/header signing** `[M]` — **SLH-DSA** (FIPS 205) if signature
  verification enters the trust path; conservative and quantum-safe.
- Skip PQ entirely for the password→volume path. Adding Kyber there is theater.

---

## New algorithms worth adding — quick reference

Slow is acceptable per the brief; the constraint is that each must be verifiable two ways.

Every row now has at least one member built + proven two ways (✅ = proven PoC + spec, step noted):

| Class | Candidates | Why | Proven |
|---|---|---|---|
| Wide-block modes | HCTR2, AEZ, EME2, Adiantum | sector-atomic; kills XTS malleability | ✅ Adiantum [24], HCTR2 [26] |
| Memory-hard KDF | Balloon, yescrypt, Lyra2, Catena, scrypt, Argon2d | diversity + ROM-hardness | ✅ Balloon [16] (+ Argon2 params [11]) |
| Large-block ciphers | Threefish-1024, Rijndael-256 | birthday-bound headroom | ✅ Threefish-512/1024 [29] |
| Hashes | BLAKE3, KangarooTwelve, Ascon-Hash | fast tree/parallel; Ascon = NIST LWC winner | ✅ BLAKE3 [27], Ascon-Hash256 [28] |
| PQ (asymmetric parts only) | ML-KEM-768, SLH-DSA, Classic McEliece | hybrid recovery/network slots | ✅ ML-KEM-768 + hybrid [25] |
| Password protocols | OPRF, threshold OPRF/PPSS, OPAQUE (aPAKE) | rate-limited guessing, headless unlock | ✅ OPRF [17] |
| Delay functions | RSW time-lock, Sloth, Wesolowski/Pietrzak VDF | coercion cooling-off | ✅ Sloth VDF [30] |
| Sharing | Feldman/Pedersen VSS, SLIP-39 encoding | verifiable, transcribable shares | ✅ Shamir [5] + Feldman VSS [31] |

Remaining candidates in each row (AEZ/EME2, yescrypt/Lyra2, Rijndael-256, K12, SLH-DSA/McEliece,
threshold-OPRF/OPAQUE, RSW/Wesolowski VDF, Pedersen/SLIP-39) are documented alternatives, not gaps —
each row's core property is proven.

---

## UX — what users actually ask for

Security features that nobody can operate are not security features. Several of these are worth more
real-world protection than another primitive.

### Onboarding and hardware tokens
- **Token enrollment wizard** `[M]` — currently CLI-only. Programming a YubiKey slot or creating a
  FIDO2 credential is the highest-friction step in the whole feature set.
- **Multi-token enrollment, prominently** `[M]` — FIDO2 credentials *cannot be cloned*, so a backup
  authenticator must be enrolled at creation time or the user is one lost key from losing everything.
  This deserves to be a forced step, not a docs footnote.
- **Touch prompts and device state** `[S]` — a clear "touch your key now" indicator; users otherwise
  interpret the blocking wait as a hang.
- **Dry-run / test-mount before committing** `[S]` — prove the token+password combination works
  *before* data is written. Prevents the worst class of user disaster.

### Recovery (the most likely real-world failure)
- **Printable recovery kit** `[M]` — QR + SLIP-39 mnemonic shares, with an import path and a "verify my
  kit" mode. Lockout is a bigger practical risk to these users than cryptanalysis.
- **Header backup UX with verification** `[S]` — reminders, integrity check, guided restore.
- **Share inventory** `[S]` — where each share lives, when it was last verified. No secrets stored.

### Keyslot management
- **GUI/CLI for list, add, name, rotate, revoke** `[M]` — with human labels and creation dates.
  Keyslots are inert without this.
- **Per-slot policy UI** `[M]` — surface the §D metadata (read-only, duress, attempt limits).
- **Duress-alarm (owner-notified)** `[M]` — optionally record locally, or beacon to an owner-controlled
  endpoint, that a duress slot was used. Standard practice for physical duress codes; must fail safe
  and never block the dismount.

### Daily driver
- **Panic hotkey** `[S]` — global shortcut: dismount all + scrub. Pairs with the duress work already
  landed.
- **Per-volume settings and favorites** `[S]` — idle auto-dismount, read-only default, mount point.
- **PRF/algorithm hint cache** `[S]` — remember which KDF and cipher succeeded for a given volume so
  mounts stop trial-and-erroring through the list. Large perceived speed win; document the minor
  local-metadata tradeoff and make it opt-out.
- **Argon2 calibration slider with real time estimates** `[S]` — "this will take ~2 s to mount on this
  machine, ~N years to brute force at X guesses/s."
- **Password strength meter tied to actual KDF cost** `[S]` — not generic entropy theater.
- **Better failure disambiguation** `[S]` — distinguish "token missing" from "wrong password" *where
  it does not leak* (e.g. safe on a volume the user just created with a factor).
- **Sync-friendly containers** `[M] [FORMAT] [RESEARCH]` — chunked/sparse layout so a cloud-sync tool
  does not re-upload a 10 GB container after a one-byte change. Frequently requested; note the
  deniability and metadata implications of chunking before designing.
- **Volume shrink** `[L]` — expansion exists, shrinking does not; long-standing request.
- **Encrypted volume labels** `[S] [FORMAT]` — human names without leaking anything to an examiner.

### CLI and automation
- **`--json` machine-readable output and exit codes** `[S]` — makes scripting and CI possible.
- **Shell completions and config profiles** `[S]` — the `--hkf-*` option set is long enough to warrant
  both.
- **systemd unit + udisks integration** `[M]` — automount on token insert, dismount on removal/lock;
  the lock/idle triggers already exist from the KeyScrub work.

### Platform and packaging
- **Reproducible builds + signed releases** `[M]` — essential credibility for a security tool.
- **Flatpak/AppImage, HiDPI, dark mode, screen-reader labels, localization** `[M]` — Linux GUI parity
  lags the Windows one.

---

## Assurance and process

- **CI running a real full `make`** `[M]` — with wxWidgets present. This closes the exact gap that
  caused a false-negative security result during development (stub objects neutered a hash, making a
  gating test look broken). Run `verification/build_and_verify.sh` on every push.
- **Fuzzing the untrusted-input parsers** `[M]` — keyslot records, header parsing, share
  deserialization all consume attacker-supplied bytes from a malicious volume. libFuzzer/AFL++ here is
  where memory-safety bugs will be.
- **Randomized differential testing** `[S] [SANDBOX-OK]` — beyond fixed KATs: zero-length and maximum
  length passwords, boundary salt sizes, degenerate thresholds (t=n, t=2), duplicate share x-coords.
- **Constant-time verification in CI** `[M]` — `dudect`/`ctgrind` over the Shamir and keyslot paths.
- **Formal methods** `[L] [RESEARCH]` — symbolic analysis (Tamarin/ProVerif) for the network-share and
  OPRF protocols; verified primitives (HACL*/Fiat-Crypto) for new algorithms.
- **Audit preparation** `[M]` — a threat-model-to-control map and a stable public API surface, so an
  external reviewer has something to review.

---

## Suggested sequencing

1. **P0 items 1–4** — constant-time Shamir, constant-time slot search, swap/hibernate lockdown, AF
   splitting. Cheap, high assurance, and one of them fixes a real defect in merged code.
2. **CI with a real build + fuzzing** — everything after this is safer to land.
3. **Recovery kit (SLIP-39 + QR) and keyslot management UX** — addresses the most probable real-world
   loss event and makes the keyslot work usable.
4. **Per-sector integrity or HCTR2** — the largest remaining *cryptographic* gap; pick one and spec it
   properly, since both are `[FORMAT]`.
5. **Threshold OPRF / PPSS** — the strongest anti-brute-force primitive still unbuilt, and it composes
   with the Shamir factor already shipped.

---

## Scope boundary — unchanged

Everything above is confidentiality, integrity, access control, or deniable **storage**. The DESCOPED
item stands: no tooling whose function is to manufacture a false record of human activity in order to
deceive a forensic examiner. Two items here sit near that line and are deliberately drawn on the safe
side — **free-space chaff** (uniformizing unused space; padding, not fabricated history) and
**decoy-fragments by default** (making an artifact's presence uninformative, rather than staging a
fictional past). Keep them there. If a future item requires generating fake user activity to work, it
is out of scope by design, and the honest alternatives are ORAM-style access-pattern hiding plus
candid documentation of the limits.
