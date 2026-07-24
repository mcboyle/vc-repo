# Independent verification of the VeraCrypt-fork research pack

**Subject repo:** `github.com/mcboyle/vc-repo` @ `665b4b8` (post-PR #9), cloned fresh; all repo claims
re-derived from that tree.
**Scope:** 18 reports, 6 prior analyses (`addenda/`), 3 audits — the latter two treated as *subjects*.
**Ceiling, stated once:** this pass had **no web access**. Every class-2 (published-source) and class-3
(patent / licence / 2025–26 vendor) claim is therefore **flagged, not resolved**. Where I write
UNVERIFIABLE it means "not settleable from the repo or from anything inside this pack," never "false."

---

## 1. Headline results

| # | Finding | Type | Where |
|---|---|---|---|
| 1 | **R21's AF-stripe claim was wrongly marked REFUTED.** The pack's own index refutes a claim R21 never made. R21 is correct and matches the repo's own spec verbatim. | **Disputed prior finding** | §4.1 |
| 2 | **The as-built HKF v2 mix drops the volume salt from HKDF-Extract**, so it does *not* deliver R27's "fixes factor-reuse for free" property. Missed by the addendum and all three audits. | **New finding** | §4.2 |
| 3 | **R13 and the repo give opposite guidance on ORAM** — a scheduled, "flagship" item. R13's strongest objection (the mandatory public-write cloak) is absent from `ORAM-SPEC.md`. | **New finding / conflict** | §4.3 |
| 4 | **MAC-bearing recovery share codes (~118 chars) fall outside bech32's 90-char detection guarantee**; the module's own reassurance covers only the no-MAC case. Also BIP-173, not bech32m. | **New finding** | §4.4 |
| 5 | **The suspend-hook status is misstated by the addendum *and* by its correction**, in opposite directions. `PrepareForSleep` exists only in comments; re-auth-on-resume is the genuinely missing piece. | **Disputed prior finding** | §4.5 |
| 6 | **The EME2 remediation landed only halfway.** "IBM" is gone from the tree, but `RESEARCH-NOTES.md:95` still asserts "Patent encumbrance" over a group including EME2. | **New finding** | §4.6 |
| 7 | **R17 is correct throughout on code** — all five review claims independently re-confirmed, plus the `gf_dot` fix. | **Confirmation** | §3.1 |
| 8 | **R27's construction facts are confirmed**, discharging its own "I did not review the source" caveat. | **Confirmation** | §3.4 |

**Status update — PR #10 (draft, 3 commits) closes three of the gaps this pack listed as open.** Reviewed
separately below (§9): the blessed-module CI rule, `KeyslotConstTimeEqual` in the ctgrind sweep, and AES
as a constant-time *subject* are all now implemented. None of the findings in §4 are affected by it.

Two prior-analysis claims I could **not** discharge because the artefacts do not exist in this tree:
`ROADMAP-SANDBOXABLE-01.md` (R25 addendum's propagation site #2) and `docs/DELAY-VDF-SPEC.md`
(actual file is `DELAY-SPEC.md`). See §6.

---

## 2. Method and what I did differently

I followed `METHOD.md`, with one deliberate strengthening: **every absence claim was re-derived by
reading the module end-to-end**, and I recorded the *shape* of each prior claim before checking it, so
that a refutation could be tested against what the report actually said rather than against a
paraphrase. That single step produced findings 1 and 5.

Search was used only to locate. Where I state a negative, I name the file I read.

---

## 3. Per-report verdicts — repo-checkable claims

### 3.1 R17 — Side-channel hardening — **CORRECT THROUGHOUT (code claims)**

All five code-review claims re-confirmed by reading source, not grep:

| Claim | Verdict | Evidence |
|---|---|---|
| `gf_mul` constant-time | CONFIRMED | `Shamir.c:20–32` — fixed 8 iterations; `mask = 0u-(b&1)`; `hi = (0u-((a>>7)&1)) & 0x1b`; no branch on `a`/`b`; no table |
| `gf_inv` constant-time | CONFIRMED | `Shamir.c:37–49` — schedule `(254u>>i)&1` driven by the *public* constant 254; calls `gf_mul` (single source of truth) |
| `KeyslotConstTimeEqual` | CONFIRMED | `Keyslot.c:56–63` — OR-accumulate `d |= a[i]^b[i]` |
| `KeyslotUnwrapCT` | CONFIRMED | `Keyslot.c:99–122` — KDF+HMAC every call, CT compare, **decrypts unconditionally**, no early return |
| `KeyslotOpen` slot search | CONFIRMED | `KeyslotStore.c:218–270` — fixed `ns = n_slots(cfg,area)` from public config; `UnwrapCT` per slot; byte-mask select `selp[b]=(selp[b]&~mask)|(tmp[b]&mask)`; `sel = m & (found^1)`; full scan |
| `KeyslotOpenAt` non-CT admin exception | CONFIRMED as documented | `KeyslotStore.c:297–332` — comment states it "deliberately reveals per-index success"; early `return 0` on the `VCKS` marker; `if (m)` branch |

**`gf_dot` fix — CONFIRMED branch-free.** `verification/hctr2_poc.c:42–59`: arithmetic mask
`m = 0ULL - ((a[i>>6] >> (i&63)) & 1ULL)`, fixed 128 iterations. The `s ? … : 0` guards are on
`s = i & 63`, a **public loop index** — exactly as R17 and the R01 addendum both state. Matches
CLAIMS-STATUS's "fixed in PR #7."

**Header-comment nit R17 raised is real and both readings are right.** `Shamir.c:8` says "reduction
polynomial 0x11B (AES)"; lines 15/18 say "reduction 0x1b." 0x11B is the full 9-bit polynomial, 0x1B the
constant applied after the high bit. R17's suggestion to say so explicitly is sound.
**CLOSED by PR #10 item A5** — a comment now states both are correct and must not be unified. I checked
the maths: 0x11B = x⁸+x⁴+x³+x+1 = 0b100011011; 0x1B is the same with the x⁸ term dropped, XORed back after
the shift has already carried the high bit out. Comment-only; the Shamir anchor is unaffected.

**"Primary gate" dispute — the CLAIMS-STATUS resolution HOLDS.** R17 recommends promoting ctgrind to
"primary gate" meaning *claim authority*; the repo kept dudect as the `--strict` step, meaning *CI
composition*. Different questions; genuine terminology collision, not a contradiction.
*Update (PR #10, item A4):* this is now written into `docs/CT-HARDENING-R17.md` under "The two senses of
'gate' — reconciled (do not 'fix' this later)", stating both senses explicitly and marking the composition
settled. My finding is unchanged; the citation moves from the old `:88` line to that new section.

*Unverifiable here (agreeing with CLAIMS-STATUS):* the ctgrind generalization (one machine, one Valgrind
version, one container, exercised paths only). Class-2 citations listed in §5.

---

### 3.2 R01 — Wide-block and robust-AE modes

Addendum findings re-checked against the **current** tree:

| Addendum finding | Status now | Evidence |
|---|---|---|
| F1 — `gf_dot` had two secret-dependent branches | **Was real; now FIXED** | Current `gf_dot` is branch-free and matches the addendum's proposed masking fix verbatim |
| F2 — "the mode you already have" overstates deployment | **STILL HOLDS** | `grep -rln "hctr2\|POLYVAL\|XCTR" src/` returns nothing. HCTR2 exists only under `verification/` |

**New consequence for F2, from PR #10 (item A1).** Promoting HCTR2 into `src/` now carries a *measured*
cost that was previously only presumed. PR #10 makes the table-based AES fallback a ctgrind subject and
finds it measurably cache-timing-leaky (secret-dependent addressing localized to `aes_encrypt`,
`aes_decrypt`, `aes_encrypt_key256`, `aes_decrypt_key256`). HCTR2 is AES-based, so on any machine without
AES-NI — or with hardware encryption disabled by the user, `Crypto.c:1179`
`HasAESNI() && !HwEncryptionDisabled` — it inherits that leak. The clean `gf_dot` result says nothing
about the cipher underneath. This strengthens R01's Stage-1 caveat and should be read alongside its
"ensure GF(2¹²⁸) multiply is constant-time via CLMUL/PMULL" pitfall, which addresses only the hash half.

| F3 — vectors are AES-256 only | **STILL HOLDS** | `hctr2_kats.h` header cites `HCTR2_AES256.json`; `HCTR2_NKATS 35`; `hctr2_poc.c` uses `aes_encrypt_key256` exclusively; no AES-128/192 sets |

R01 carries **both** deliverable sections the brief required (`Ranked shortlist` :95, `Full citations`
:104) — confirming audit Phase 6's compliance verdict for R01.

**R01's EME2/IBM patent claim is still present and uncorrected in the report.** I cannot adjudicate the
patent fact (class 3). I *can* confirm the structural tell that KNOWN-ERRORS #1 describes: R01 asserts
the patent **without a patent number or citation**, while its neighbouring claims carry precise
references. That is the verdict-without-citation shape.

---

### 3.3 R02 — Per-sector authentication — **recommendation adopted**

CLAIMS-STATUS's entry is confirmed in the spec text. `docs/PERSECTOR-AUTH-SPEC.md:7–16` records the
original defect verbatim — `otk_i = ChaCha20(sector_mac_key, le64(index))[0..32]` made the one-time
Poly1305 key "a pure function of the sector index, so **every rewrite of sector *i* reuses the same
one-time Poly1305 key**" — and :34 shows the replacement, `tag_i = keyed_BLAKE3(K_mac, le64(index) ||
ct_i)[0..16]`. R02's PRF-over-one-time-MAC argument is the stated rationale (:43–48), with KMAC256 named
as the conservative alternative exactly as R02 ranks it.

Worth preserving: the spec's own methodological note that **two-way verification did not catch this**
("the old PoC and Python reference agreed with each other"). That is a real limit of the project's
headline convention and deserves to stay visible.

---

### 3.4 R27 — CRC-32 keyfile-pool seam — **stated facts CONFIRMED**

R27 explicitly disclaims having read the source. I discharged that caveat directly against
`HardwareKeyFactor.c:38–79`:

| R27 premise | Verdict | Evidence |
|---|---|---|
| Pool starts zeroed (so `+=` is `=`) | CONFIRMED | `memset (pool, 0, sizeof (pool));` line 49 |
| 4 CRC state bytes per input byte, `writePos += 4`, wrap at 128 | CONFIRMED | lines 55–60, `if (writePos >= HKF_POOL_SIZE) writePos = 0;` |
| Pool is 128 bytes | CONFIRMED | `HardwareKeyFactor.h:44` `#define HKF_POOL_SIZE 128` |
| CRC init `0xFFFFFFFF`, poly `0xEDB88320` | CONFIRMED | line 42; table init at line 16 ff. |
| Final add + length extension to 128 | CONFIRMED | lines 64–72 |
| No wrap for ≤32-byte inputs; wrap begins at 33 | CONFIRMED | 32×4 = 128 exactly; the wrap test fires only after the last write |

So R27's injectivity conclusion rests on premises that hold. Its central claim — injective, hence exact
min-entropy preservation, for the fork's ≤32-byte near-uniform inputs — is sound *as stated*.

**Recommendation-already-implemented check (all three R27 items shipped, gated):**
`HKFApplySaltBindDefault` (`HardwareKeyFactor.c:629`, `VC_ENABLE_HKF_SALT_BIND_DEFAULT`);
`HKFMixResponseIntoPasswordV2` (`c:113 ff.`, `VC_ENABLE_HKF_MIX_V2`, `docs/HKF-MIX-V2-SPEC.md`);
length conditioning (`c:599–607`, `VC_ENABLE_HKF_LEN_CONDITION`). This is R27 being *acted on*, not
under-crediting — but see §4.2 for how the v2 build diverges from what R27 specified.

**The R27 addendum re-verified independently and is accurate**, including its §3 catch that the >32-byte
backend "is already present": `HKF_MAX_RESPONSE 64` (`h:45`), `SHAMIR_MAX_SECRET 64` (`Shamir.h:22`),
`rawSecret[64]` (`h:87`).

---

### 3.5 R16 — Keys outside RAM

Central conclusion (decline TRESOR/TEE/memory-encryption dependency) **not disputed**.

**Under-crediting (KNOWN-ERRORS #3) — CONFIRMED against code.** The fork ships, and R16 does not mention:
`VcSwapHibernateStatus()` (`KeyScrub.h:79`, bits `VC_HIBERNATE_SWAP_ACTIVE` / `_SUPPORTED`) with the
fixture variant `VcSwapHibernateStatusFrom()` (`h:84`) — and it is *actively used*, printing loud
warnings at `KeyScrubEvents.cpp:86–95`; `VcKeyMemoryLockdown()` (`h:62`, called at `cpp:80`); and
`VcKsRamTransform()`, ChaCha-at-rest for in-RAM secrets (`KeyScrub.c:251`). For a brief titled "Keys
Outside RAM," the last is the project's own software answer to the brief's title.

The suspend-hook question is a three-way disagreement — see §4.5.

---

### 3.6 R21 — Reading other encryption formats

All R21 code claims survive checking (contra the prior synthesis — §4.1): `af_of()` reads
`cfg->afStripes` (`KeyslotStore.c:76`); stripe count recorded via `put_u16` at `L_RSV` and authenticated
through the AAD (`c:181`, `c:450`); per-slot Encrypt-then-MAC (`Keyslot.c:65–97`); constant-time slot
search exceeding LUKS practice (§3.1); duress flag encrypted inside the wrapped payload
(`flags[1]||vmk`, `c:260–263`); backup-header table mirroring still listed as unfinished (`CLAUDE.md`).
R21's "don't call `KSB_SIDECAR` a detached header" is fair and the synthesis agrees.

---

### 3.7 R12 — Rollback / replay / freshness — **PARTIALLY CORRECT**

"the fork already has [a signed epoch counter + Merkle root]" overstates slightly.
`docs/ROLLBACK-COUNTER-SPEC.md` exists and the binding construction is proven two ways
(`verification/monotcounter_poc.c` + `monotcounter_reference.py`, step `[22]`, anchor
`commit_tag_0 = e8bbc4f0…`), but the spec's own status line reads "**the counter source is
`[HW]`/real-build**," and the PoC uses a *modelled* increment-only `NvCounter`. The fork has the
construction, not a working non-rewindable anchor.

R12's **fail-warn-not-fail-stop** recommendation is **already adopted**: the spec's "Operational policy —
the central design decision (was open) … Fixed here. ### 1. Fail-WARN, not fail-stop (default)," citing
the same van Dijk et al. STC '07 impossibility result R12 cites.

**Checked and *not* a defect:** the commit tag uses one-time Poly1305 (`otk = ChaCha20(commit_key,
le64(counter))`), structurally the shape that *was* broken in the per-sector spec. Here it is correct —
the counter is a genuine never-repeating nonce, and the spec argues exactly that. **Residual:** that
safety rests entirely on the counter never repeating, which is the unimplemented `[HW]` part. The
real-build acceptance test should cover counter *reuse after crash* — R12's own "increment-then-store vs
store-then-increment" window — not only monotonic advance.

---

### 3.8 R13 / R14 / R15a / R15b — deniability pack

**R15a vs R15b consistency check (the free check the README invites): they agree.** Both conclude that
hidden-volume deniability fails below the block interface on commodity flash, that no block-layer tool
can fix it, and that the honest response is a runtime warning rather than a claim. `b` adds quantitative
depth (Wei et al. FAST 2011 stale-copy and over-provisioning figures, TRIM/DZAT reasoning) without
contradicting `a`. No conflict found.

**R15's recommendation has shipped.** `src/Common/FlashProbe.{c,h}` exists and implements precisely what
both runs asked for: warn reasons `VC_FLASH_WARN_ROTATIONAL / _TRIM / _THIN / _UNKNOWN` (`h:35–38`),
with an explicit **fail-closed contract** (`h:10–12`: "unreadable values, unparseable buffers,
reserved/unknown encodings, and unsupported platforms all" warn), gated behind `VC_ENABLE_FLASH_WARN`.
The header even names its origin ("research batch-2 C3"). The earlier synthesis line "R15: no runtime
flash/rotational detection — confirmed absent" was true when written and is now superseded, as
CLAIMS-STATUS records.

**R14 — consistent with the repo, correctly credited.** Its claim that VeraCrypt's header is already an
indistinguishable-from-random keyslot matches the fork's core design premise, and its "ship it as
convenience, not as a deniability claim" is consistent with the batch-2 StegFS don't-build entry. No
scope drift: R14 recommends documentation/UX, not fabrication.

**R13 — conflicts with the repo on ORAM. See §4.3.** Its free-space-chaff verdict *is* consistent with
the repo's existing don't-build entry.

---

### 3.9 R08 / R09 / R18 / R19 / R24 — consistency pass

| Report | Verdict | Notes |
|---|---|---|
| R08 — ciphertext dispersal | **Consistent; correctly credits the fork** | "the information-theoretic key split you already ship" is accurate (Shamir GF(2⁸), `SPLIT-KEY-SPEC.md`, `VSS-SPEC.md`). Matches the repo's batch-2 "Ciphertext dispersal — don't build" entry |
| R09 — social / notarized recovery | **Consistent; correctly credits the fork** | "M-of-N Shamir split … which you already have as a constant-time GF(2⁸) module" is accurate. Matches "Guardian / notary social recovery — don't build." Its local delay/cooldown suggestion aligns with the existing `DELAY-SPEC.md` + `rsw_poc.c` / `sloth_poc.c` |
| R18 — boot integrity | **Consistent** | "buy a Heads-supported machine" sits alongside `RESEARCH-NOTES.md` §5, which independently flags the TPM/deniability tension. No repo claim to check |
| R19 — storage-stack hazards | **Consistent; one rec NOT yet landed** | dm-crypt/LUKS-compat and DIF/DIX don't-build verdicts are both already in `RESEARCH-NOTES.md`. **But R19's own highest-value action — CoW guidance (`chattr +C`, non-CoW container placement, versioned-snapshot warning) — is absent from `docs/`.** It was also BATCH2-SYNTHESIS "Do" item #4. Confirmed open gap |
| R24 — key-disclosure law | **Substance landed** | `docs/KEY-DISCLOSURE-LEGAL.md` exists with the `[COUNSEL-REVIEW]` tagging convention R24 uses (`:7`, `:23`), the RIPA s.49/s.53 entry (`:29`), the US act-of-production/foregone-conclusion entry (`:42`) and Germany's *nemo tenetur* (`:43`). All legal content remains class-3 — flagged, not verified |

**R10 — recovery-code encoding.** R10 recommends SLIP-39 as the default with codex32 as a high-assurance
export, and ranks "bech32-style" only third ("acceptable only as a fallback … and only with a real
checksum"). The fork ships `Common/ShareCode.{c,h}` — bech32. R10 never mentions it. This is a **third
under-crediting instance**, milder than the two already recorded: R10's proposal is a genuine upgrade
rather than duplicated work, but it should have started from what exists. Examining that module produced
finding §4.4.

---

## 4. New findings and disputed prior findings

### 4.1 R21's AF-stripe claim was wrongly marked REFUTED — the refutation is a strawman

**What the pack says.** `CLAIMS-STATUS.md`, under *"Already REFUTED — do not treat these as true"*:

> R21's claim about a hardcoded AF stripe count | `af_of()` in `KeyslotStore.c` reads a config field; no
> hardcoded value | `BATCH2-SYNTHESIS.md`

`BATCH2-SYNTHESIS.md:103` grades it "**Partly mistaken** … no hardcoded 14," and :107–108 escalates:
"R21's stripe point is the one place across the eight reports where a claim about your code does not
survive checking. Everything else held."

**What R21 actually says (§8, verbatim):**

> Your spec bounds labeled-record stripes at s ≤ 14 (**from `46 + s·plen + 32 ≤ 1024` at vmk=64**)

R21 never claims the count is hardcoded. It derives a **ceiling from slot geometry** — the very
reasoning the synthesis then presents as a refutation.

**Evidence R21 is right:**

1. **The arithmetic is exact.** `KeyslotStore.c:38` `#define L_CT (L_SALT + KEYSLOT_SALT_SIZE) /* 46 */`
   (14 + 32); `KEYSLOT_TAG_SIZE` 32; `KeyslotStore.h:73` `#define KEYSLOT_TABLE_STRIDE 1024`;
   `plen_of()` = `vmkLen + 1` = 65 at vmk = 64. `rec_fits()` (`c:89–92`) enforces
   `base + ct_of(cfg) + KEYSLOT_TAG_SIZE <= KEYSLOT_TABLE_STRIDE` with `ct_of = plen × af`.
   ⇒ 46 + 65s + 32 ≤ 1024 ⇒ 65s ≤ 946 ⇒ **s ≤ 14**. Exactly R21's figure.
2. **R21 is quoting the repo's own spec.** `docs/AF-SPLIT-SPEC.md:55` reads verbatim: *"`s` is bounded by
   the record stride: `46 + s·plen + 32 ≤ 1024` labeled (s ≤ 14 at vmk = 64)."*
3. **R21's remedy is the spec's own remedy.** R21 Rec 4: "decouple the AF area from the 1024-byte slot
   stride … exactly as your spec's 'future work' note anticipates." `AF-SPLIT-SPEC.md:57`: "stride
   growth is future work, not this format."
4. **The synthesis's substitute explanation *is* R21's explanation** ("emergent from slot geometry,"
   "can be raised by enlarging the slot record"), restated as though it contradicted R21.

**Verdict: R21's AF-stripe claim is CONFIRMED, not refuted.** This is the KNOWN-ERRORS family — a
negative asserted from a paraphrase rather than the text — and it has propagated into the pack's index
as a standing instruction not to trust a correct claim. Recommend striking the row from CLAIMS-STATUS,
correcting `BATCH2-SYNTHESIS.md:103`, and withdrawing the :107–108 boast: on my checking, **all** of
R21's code claims survive.

---

### 4.2 NEW — the as-built v2 mix drops the volume salt, so Rank-1 does not close factor reuse

**What R27 specified:**

> `password' = HKDF-Expand(PRK = HKDF-Extract(salt = volume_salt_64B, IKM = password || factor), …)`
> … "**Fixes factor-reuse for free (salt in Extract makes every volume's PRK unique)**"

**What was built** (`HardwareKeyFactor.c:117–128`; `HardwareKeyFactor.h:148`;
`docs/HKF-MIX-V2-SPEC.md:24–31`):

```c
static const unsigned char HKF_V2_ZERO_SALT[HKF_HMAC_DIGEST] = { 0 };
/* Extract: PRK = HMAC(salt=0^32, IKM = password || response). */
```

with the spec stating `HKDF-SHA256(salt = <empty>, …)`. The mix never receives the salt:
`HKFApplyIfConfiguredVer` (`c:180–188`) computes the response *from* the salt, then calls
`HKFMixResponseIntoPasswordVer(version, userKey, keyLength, resp, rlen)` — no salt argument.

**Consequences, each stated at the level the evidence supports:**

1. **v2 alone does not close cross-volume factor reuse.** The same `(password, response)` yields the same
   128-byte mixed password on every volume. For `RAW_SECRET` with salt-binding **off**, reuse persists
   under v2 exactly as under v1. `HKF-MIX-V2-SPEC.md` justifies v2 solely on entropy/injectivity grounds
   ("removes the concern *structurally* … preserves min-entropy with no wrap-around") and is **silent on
   factor reuse**.
2. **Reuse is still closed in practice — but by Rec 1, not Rank-1.** Hardware backends use the volume
   salt as the challenge, so their responses are already volume-unique; salt-bound `RAW_SECRET` becomes
   `HMAC-SHA256(secret, volume_salt)`. Un-salt-bound `RAW_SECRET` remains reused.
3. **R27's secondary Rank-1 claim is weakened, not broken.** RFC 5869 permits omitting the salt (set to
   `HashLen` zeros), and HKDF-Extract with a fixed public salt remains a computational extractor;
   Krawczyk's analysis is that an independent salt buys a stronger guarantee. A nuance to record, not an
   error.

**Recommended action —** either (a) pass the 64-byte volume salt into Extract as R27 specified, restoring
the "for free" property and making v2 self-sufficient; or (b) state explicitly in `HKF-MIX-V2-SPEC.md`
that v2 deliberately uses an empty salt and that cross-volume uniqueness is delegated to salt-binding.
(b) is cheap and prevents a future reader assuming Rank-1 closed it. **(a) is not free** — it changes the
derived value again and would need a further version in the mount-time try loop.

---

### 4.3 NEW — R13 and the repo give opposite guidance on ORAM, on a scheduled item

**R13:** "the one that comes closest — a write-only ORAM whole-device redesign … requires an on-disk
format change, a mandatory public-volume 'cloak' of continuous writes, and a 10–14× SSD write penalty
that itself becomes a detectable anomaly. The honest recommendation is: do NOT productionize any of
them."

**The repo, in three places:** `RESEARCH-NOTES.md` §1 — "ORAM access-pattern hiding — **flagship; core
property proven** … the **real** mitigation for the multi-snapshot attack"; the same file's *Recommended
order* item 2 — "**ORAM integration — highest security value**"; `ORAM-SPEC.md` — "This is the **real**
mitigation."

R13's verdict is **not recorded** in the repo's batch-2 don't-build list, which covers StegFS,
ciphertext dispersal, free-space chaff and LUKS-compat but **not ORAM** — while §1 of that same file
promotes it. A planner reading the repo would schedule precisely the work R13 argues against.

**What R13 supplies that `ORAM-SPEC.md` does not.** The spec's "Costs and honest limits (state these)"
section is genuinely candid about write amplification, position-map storage, free-slot guarantees,
snapshot-model-only scope and SSD/TRIM leakage. It omits:

1. **The mandatory public-write "cloak."** DataLair's PD-CPA game fixes φ = 1: each hidden write must
   ride on a real public write, so deniability holds only while the user is *continuously* doing
   plausible public writes — "a device that sits idle but whose 'free' space keeps changing is itself the
   anomaly." Structural, and the objection most likely to invalidate the feature for these users.
2. **Measured throughput.** R13 cites DataLair hidden-write 2.92 MB/s against dm-crypt's 210.10 MB/s
   (~72×) and HIVE at 0.60 MB/s. The spec says only "heavy for write-intensive workloads."
3. **Both reference systems had implementation breaks** — HIVE broken by Paterson–Strefler via RC4
   keystream bias *in the free-block fill*, DataLair's DL-ORAM carrying an O(1/N) free-block-selection
   bias needing correction. Directly relevant, since the fork's PoC also fills unused blocks.

**I am not asserting R13 is right and the repo wrong** — R13's quantitative claims are class-2 and
unverified here. I am asserting that two documents give opposite guidance on a scheduled item, and that
the repo's version omits the strongest counter-arguments. Resolve explicitly before scheduling; at
minimum fold points 1–3 into `ORAM-SPEC.md` and record R13's verdict next to the flagship framing.

---

### 4.4 NEW — MAC-bearing share codes fall outside bech32's detection guarantee

`Common/ShareCode.{c,h}` encodes a Shamir share, optionally with its 32-byte per-share MAC, as a
`vcs1…` bech32 string. Two issues, both code-verifiable:

**(a) The 90-character guarantee window is exceeded whenever a MAC is attached.**
`ShareCode.h:10` states the property correctly — "≤ 4 substitution errors detected while the string is
≤ 90 chars" — and reassures at `:14`: "A single share of a 256-bit secret encodes to ~65 chars, well
inside the 90-char guarantee window." That computation is for the **no-MAC** case only.

From `ShareCodeEncode` (`c:95–131`) the payload is `version(1) ‖ x(1) ‖ len(1) ‖ y[len]` plus
`SHARECODE_MAC_SIZE = 32` when a MAC is supplied, then 8→5-bit expanded, with total length
`3 (hrp) + 1 + n5 + 6`:

| Case | payload | n5 | total string |
|---|---|---|---|
| 256-bit share, no MAC | 35 B | 56 | **66 chars** ✓ (matches the header's "~65") |
| 256-bit share **+ MAC** | 67 B | 108 | **118 chars** ✗ |
| 512-bit share + MAC | 99 B | 159 | **169 chars** ✗ |

`SHARECODE_MAX_LEN` is **200**, so all of these are accepted on decode. Beyond 90 characters bech32's
BCH parameters no longer guarantee detection of ≤4 substitutions; the residual random-error detection
(~2⁻³⁰) still applies, but the *guarantee* the header relies on does not. The MAC-bearing form is the
security-relevant one (`ShamirMac` exists for adversarial share tamper/fabrication detection), so the
variant that matters most is the one outside the window.

**(b) It is BIP-173 bech32, not bech32m.** `ShareCode.c:2` states "Straight BIP-173 bech32," and `c:119`
uses `pm = sc_polymod(...) ^ 1u` — the bech32 constant, not bech32m's `0x2bc830a3`. BIP-173's checksum
has a documented weakness (the motivation for BIP-350): when the final data character is `p`, inserting
or deleting `q` characters immediately before it does not invalidate the checksum. For a code designed
for **hand transcription**, insertion/deletion is exactly the error class at issue. *Marked class-2 —
I could not fetch BIP-350 to quote it; confirm in the web pass before acting.*

**Suggested actions:** cap `SHARECODE_MAX_LEN` at the 90-char guarantee (or split long shares into
guaranteed-length chunks); correct `ShareCode.h:14` to state the MAC-bearing length; and evaluate
bech32m. R10's own sharpest warning — that naive correction can silently yield the *wrong* secret —
argues for keeping detection strictly inside its proven regime.

---

### 4.5 The suspend hook — the addendum *and* its correction are both imprecise

Reading `Core/KeyScrubEvents.{h,cpp}` end-to-end:

- **Three** `On*()` entry points exist: `OnVolumeDismounted` → `"unmount"`, `OnScreenLocked` →
  `"screen-lock"`, `OnNewDeviceConnected` → `"new-device-connect"` (`cpp:124–126`).
- **Six** distinct `ScrubNow` reason strings exist: `unmount`, `idle-timeout`, `screen-lock`,
  `new-device-connect`, `shutdown`, `duress`.
- **Four** are actually wired and reachable in a default `VC_ENABLE_KEYSCRUB` build: unmount
  (`CoreUnix.cpp:299,449`), duress (`UserInterface.cpp:195`), idle-timeout (`IdleThreadEntry`),
  shutdown (`Shutdown()`).
- **Two are inert stubs.** `StartScreenLockMonitor()` under `VC_KEYSCRUB_LOGIND` calls
  `StartLogindScreenLockMonitor()` — **called but never defined** (`grep` finds exactly one occurrence,
  the call site at `cpp:177`). Same for `StartUdevDeviceMonitor()`. The default build prints
  "screen-lock monitor not compiled in" and stays inert.
- **`PrepareForSleep` appears only in comments** — `KeyScrubEvents.h:12` (design comment),
  `cpp:175` ("Sketch"), `MEMORY-SCRUB.md:102`. There is **no** suspend entry point and **no**
  `ScrubNow("suspend"/"sleep"/"resume")`.

**Adjudication:**

- **R16-ADDENDUM Finding 1** ("no suspend/sleep/resume hook anywhere") — literally over-broad, since the
  screen-lock stub is *documented* to subscribe to `PrepareForSleep`; but **operationally correct**: no
  working suspend→scrub hook exists in any buildable configuration, because the function that would
  provide it is undefined and would not link.
- **The KNOWN-ERRORS / CLAIMS-STATUS correction** ("`KeyScrubEvents.h:12` routes logind
  `PrepareForSleep` … five triggers exist") — imprecise in the **opposite** direction. Line 12 is a
  *comment*; nothing routes `PrepareForSleep` in compiled code. And there are six reason strings, only
  four wired, with `PrepareForSleep` not among them.
- **AUDIT Phase 10a** — correct in core, overstated in detail. It enumerates "**five** events … unmount,
  idle timeout, screen lock, **`PrepareForSleep`**, and new-device-connect," but screen-lock and
  `PrepareForSleep` are *the same single undefined stub*, so this double-counts; and "all four triggers
  R16 asks for are designed and routed" is too generous for the lock/suspend pair. The audit's own
  **narrower** finding is the accurate one and survives intact.

**Net, more precise than any prior statement:** four wired triggers; two specified-but-inert stubs; and
the genuinely missing items in order of actionability are (a) definitions for
`StartLogindScreenLockMonitor()` / `StartUdevDeviceMonitor()`, (b) a suspend path — subsumed under (a),
not a separate hook, and (c) **re-authentication on resume**, which is routed nowhere and which no prior
document pinned down. (c) is the cleanly missing piece of R16's recommendation 2.

---

### 4.6 NEW — the EME2 remediation landed only halfway

`R25-ADDENDUM` Action 1: correct `RESEARCH-NOTES.md:95` — keep EME2 don't-build on **security** grounds,
**remove the patent claim**. Current tree:

- ✅ "IBM" no longer appears anywhere in `docs/` or `src/` except unrelated libzip constants
  (`src/Common/libzip/zip.h:194–195`, "IBM TERSE" / "IBM LZ77"). The false attribution is gone.
- ❌ `docs/RESEARCH-NOTES.md:95–98` still reads: "**AEZ, FAST, XCB, EME2** … **don't build.** Patent
  encumbrance **and/or** known side-channel and analysis concerns." The vague patent claim survives and
  still attaches to a group **including EME2** — which R25 says carries no live patent. The "and/or"
  makes the sentence unfalsifiable rather than corrected.

Recommend splitting the line as the addendum proposed: EME2 → security grounds only (birthday bound +
data-dependent GF-multiply side channel); XCB → 2024 cryptanalytic break, patent point moot; AEZ →
non-selection + published attacks; FAST → paper-only.

**Related open dispute — VDFs.** R25's "do not pursue VDFs — they … do not provide confidentiality,
integrity, access control, or deniability" is a scope-drift error of the KNOWN-ERRORS #4 shape: a patent
brief issuing an applicability verdict outside its remit, justified by what the technique is *normally*
for. Against the repo: `docs/DELAY-SPEC.md` exists and the PoCs are built —
`verification/rsw_poc.c`, `rsw_reference.py`, `sloth_poc.c`, `sloth_reference.py`. A coercion cooling-off
delay *is* access control, and RSW time-lock was designed for time-release cryptography, not consensus.
**I side with the repo on applicability.** R25's *patent* conclusion (Chia's filings target consensus
applications; the core math is unpatented) is untouched by this and remains unverifiable-but-plausible.
The two verdicts should be separated so the patent finding is not discarded along with the applicability
one. R6 remains unrun.

---

## 5. Flagged for a separate web-enabled pass (class 2 / class 3)

**All patent, licence and jurisdiction facts in R25** — US 2004/0131182 abandonment (2007), Cisco
US 7,418,100 lapse and 2026-09-09 adjusted expiry, Schnorr US 4,995,082 (2008 vs Wikipedia's 2010),
Joye–Libert, Chia provisionals, CN108173643 / CN107566121, the NIST abeyance §2.9 wording,
EP 2,537,284 / US 9,094,189 / US 9,246,675. Also confirmed: **R25 omits both a ranked shortlist and a
full-citations section** (its structure is TL;DR → Key Findings → Details → Recommendations → Caveats),
so audit Phase 6's compliance finding is correct — the report that corrected an uncited verdict is
itself missing its citations.

**Vendor / very-recent (2025–26):** R16's AMD TSME narrative (AGESA 1.2.7.0 silent disable, April 2026
discovery, June 2026 reinstatement statement, July 2026 BIOS, ASUS first); WireTap and Battering RAM
cost/time figures; BadRAM CVE-2024-21944 / AMD-SB-3015; Heracles (CCS 2025); EUCLEAK firmware-5.7
threshold and the "14 years / ~80 CC evaluations" characterization; 3mdeb 2024–25 remanence figures
including the ~1-minute Kingston DDR4 outlier; Windows 11 24H2 auto-encryption and the Microsoft
statement to *Windows Latest*.

**Academic citations to confirm say what is claimed:** "Breaking Bad" (ASIA CCS 2025 / arXiv:2410.13489)
and its HACL* `cmovznz` finding; Käsper–Schwabe cycle counts; Fixslicing (TCHES 2021); Hertzbleed;
MemJam; Bhati–Andreeva XCB two-query break; the AEZ attack chain (ePrint 2015/1193, ToSC 2016(1),
SAC 2017) that underpins R01's security-grounds rejection; Fredrickson–Barker–Long recall/FPR figures;
HIVE / DataLair throughput tables and the Paterson–Strefler break; Wei et al. (FAST 2011) percentages;
Quarkslab 16-08-215-REP and the NCC/iSec OCAP Phase II verdicts; Krawczyk (CRYPTO 1994/2010);
Stigge et al. (`CRCINV = 0x5B358FD3`); Bellare–Ristenpart–Tessaro; the LUKS1/LUKS2 constants and the
LUKS2 v1.1.4 AF-splitter obsolescence quote; SLIP-0039 RS1024 and BIP-93 codex32 parameters;
**BIP-350 / bech32m** (needed for §4.4b).

**Structurally unresolvable here:** R17's ctgrind generalization beyond one machine/toolchain; whether
any target user stores on magnetic media (R21's threshold for raising the AF ceiling); and every
`[COUNSEL-REVIEW]` item in R24.

---

## 6. Residue — what I could not resolve, and why

1. **`ROADMAP-SANDBOXABLE-01.md` does not exist** in this tree. The R25 addendum names it (item `01-3`)
   as the second propagation site of the EME2 error, and its Action 2 targets it. I can neither confirm
   nor refute; Action 2 cannot be discharged as written.
2. **`docs/DELAY-VDF-SPEC.md` does not exist**; the actual file is `docs/DELAY-SPEC.md`. The substance
   (a delay/VDF spec plus built PoCs) is present, so this is a filename error, not a missing artefact.
3. **Commit provenance.** The addenda reference `7c08337` (post-PR #8); HEAD is `665b4b8` (post-PR #9),
   and the shallow clone cannot resolve `7c08337`. Some drift between what the addenda saw and what I
   read is expected — I verified against the current tree throughout and flagged where a prior finding
   has since been fixed (R01 F1) versus still standing (R01 F2/F3).
4. **Build health not exercised.** I did not run `verification/build_and_verify.sh --strict`; every
   verdict above rests on reading source and specs, not on execution.
5. **Whether the v2 zero-salt choice was deliberate.** §4.2 establishes *what* was built and that it
   diverges from R27's Rank-1 design; the spec's silence on factor reuse suggests oversight rather than
   a recorded trade-off, but I cannot establish intent from the tree.

---

## 7. Corrections recommended to the pack's own control documents

| Document | Change |
|---|---|
| `CLAIMS-STATUS.md` | **Strike** the "R21 hardcoded AF stripe count" row from *Already REFUTED* (§4.1). Amend the suspend-hook row: `.h:12` is a comment, six reason strings exist, four are wired, `PrepareForSleep` is not among them (§4.5) |
| `BATCH2-SYNTHESIS.md` | Correct `:103`; withdraw the `:107–108` claim that R21's stripe point is the one code claim that fails checking |
| `KNOWN-ERRORS.md` | Narrow error #2's correction to the audit's accurate form; add re-auth-on-resume as the genuinely missing item |
| `docs/RESEARCH-NOTES.md:95` | Finish the EME2 correction — split the four-item line by actual reason (§4.6) |
| `docs/ORAM-SPEC.md` | Add the cloak requirement, measured throughput, and HIVE/DataLair implementation-break history; record R13's verdict beside the flagship framing (§4.3) |
| `docs/HKF-MIX-V2-SPEC.md` | State that v2 uses an empty Extract salt by design and that cross-volume uniqueness is delegated to salt-binding — or adopt R27's specified salt (§4.2) |
| `src/Common/ShareCode.h:14` | Correct the length reassurance for the MAC-bearing case; consider capping `SHARECODE_MAX_LEN` to the guarantee window (§4.4) |

---

## 8. Scope-boundary check

No report in this pack recommends anything in the direction of fabricating a false record of user
activity. R16 and R01 both close by explicitly disclaiming it; R14's recommendations are
documentation/UX; R13 recommends warnings and honest documentation. The audit's Phase 7 clean pass is
confirmed. Nothing here should be developed in that direction, and nothing above does.

---

## 9. Review of PR #10 (`ct-primitive-guard` / batch 3-A) — added after the main pass

**Verdict: sound work, correct in substance, recommend merge after one wording fix.** 3 commits,
+328/−21 across 6 files. Nothing in it changes any finding in §4. It closes three gaps this pack had
listed as open.

### 9.1 What I verified myself (not taken from the PR description)

| Item | Check | Result |
|---|---|---|
| A5 — `Shamir.c` comment | Read the diff; re-derived the maths | **Correct.** 0x11B = x⁸+x⁴+x³+x+1 = `0b100011011`; 0x1B is the same with x⁸ dropped, XORed after the shift carries the high bit out. Comment-only |
| A3 — guard self-test | Ran `./scripts/ct-primitive-guard.sh --self-test` | **PASS** |
| A3 — full scan | Ran `./scripts/ct-primitive-guard.sh` | **PASS**, and *not vacuous*: the `git ls-files 'src/*.c' …` pathspec does match nested paths (689 files scanned, 201 under `src/Common/`, `Keyslot.c` included) |
| A3 — does the scan path have teeth? | Planted an unblessed `gf_mul` in a new `src/Common/EvilTest.c` | **Caught**, exit 1, with a correct remediation message. Worth doing because the self-test only exercises the definition *heuristic*, not `scan()`/`is_blessed()` |
| A1/A2 — harness build | Compiled the harness with the new keyslot + Sha2 + chacha256 objects and `--gc-sections`, then ran all three subjects | **Builds and runs clean**; the no-valgrind graceful path still performs the functional-agreement check (`gf_mul vs leaky agree on 65536 products = YES`) |
| Driver polarity | Read `ct_ctgrind_check.sh` | **Correct.** `real` must be 0, `leaky` must be >0, and `aes == 0` sets `ok=0` with "UNEXPECTED — suspect the harness". Treating an absent AES finding as a failure is the right self-validating design |
| Subject isolation | Read `main()` | **Correct.** The `aes` subject returns early, so A1's expected positives run in a separate process and cannot mask an A2 regression |
| A1 doc claim about the dispatch | `grep` `src/Common/Crypto.c` | **Verified verbatim** at `Crypto.c:1179`: `return (HasAESNI() && !HwEncryptionDisabled)? TRUE : FALSE;` |
| CI wiring | Read `.github/workflows/flag-matrix.yml:111` | **Correct.** `--self-test && ` full scan, so a broken heuristic fails loudly instead of silently passing everything |

**Could not verify:** valgrind is not installed in my container, so I could **not** reproduce the
408 / 1000+ error counts or the function-level localization in the A1 table. Those remain the author's
measurement, on one machine — the same ceiling §5 already records for the ctgrind result generally.

### 9.2 One thing to fix before merge (wording, but it matters here)

`scripts/ct-primitive-guard.sh` ends its failure message with:

> This is the mechanism that would have caught the original `gf_dot` branch defect automatically.

**That over-claims, and I tested it.** I re-introduced a branch-on-secret into `gf_dot` inside
`verification/hctr2_poc.c` — the exact original defect — and the guard **passed** (exit 0), because
`hctr2_poc.c` is now on `GF_BLESSED`. The guard is a **location** guard ("does this operation live in a
blessed module?"), not a **correctness** guard ("is this implementation constant-time?"). Branchiness is
detected by ctgrind/dudect, not by this script.

What the guard *would* actually have done is flag `hctr2_poc.c`'s `gf_dot` as unblessed **at the point the
file was introduced**, forcing a review before allowlisting. That is real and worth stating — it is just a
different claim. Suggested replacement: *"This is the mechanism that would have forced a review of the
second `gf_dot` when it was introduced."*

This is worth fixing rather than waving through because `CT-HARDENING-R17.md` is otherwise scrupulous
about stating claims only at the level each tool licenses (Q4, and the new A4 section). An over-claiming
guard message cuts against exactly that discipline, and a future reader could reasonably infer the guard
covers regressions in blessed files. It does not.

### 9.3 Minor / optional (non-blocking)

1. **The `leaky` exemption is line-scoped, not identifier-scoped.** `grep -viE 'leaky'` exempts any
   matched line containing the word anywhere. Confirmed: `unsigned char gf_mul (…) { /* not leaky at all */ … }`
   is silently exempt. Fine as a false-negative-preferring heuristic (the script says so), but tightening
   it to the identifier (`_leaky`/`leaky_`) would cost nothing.
2. **The self-test doesn't cover `scan()`/`is_blessed()`** — only `find_defs_abs`. I covered that gap
   manually above and it works; a planted-file case in `--self-test` would make it permanent.
3. **`scan()` returns the violation count as an exit status** — ≥256 violating files would wrap to 0.
   Theoretical only.
4. **Nit in `ct_ctgrind_test.c`:** the comment calls `b[31] ^= 0x01` "worst case for an early-out." That is
   the worst case for *timing* (dudect); for taint-tracking the leaky compare branches on secret data at
   `i = 0` regardless of where the difference sits. Harmless — it maximizes the leaky error count — but the
   stated rationale is slightly off.

### 9.4 The most valuable part of the PR

The A1 write-up in `CT-HARDENING-R17.md`, which now states plainly that the project's constant-time claims
apply to the field arithmetic and keyslot logic **and not** to the table-based AES fallback, and draws the
consequence for HCTR2 promotion. That is a decision-relevant finding, it is correctly reasoned, and it
converts "presumably leaky" into measured and localized. It also correctly declines to fix AES, citing
R17's explicit "do not build a bespoke bitsliced AES."

I would merge on that basis once 9.2 is reworded.

### 9.5 Effect on this report

Updated in place: §3.1 (the A4 gate reconciliation is now the citation for the primary-gate resolution;
the A5 comment nit is marked closed) and §3.2 (new HCTR2 consequence from A1). **No finding in §4 is
affected** — the AF-stripe strawman, the v2 zero-salt, the ORAM conflict, the ShareCode 90-char gap, the
suspend hook and the EME2 half-fix all stand unchanged, and none of them is touched by this PR.
