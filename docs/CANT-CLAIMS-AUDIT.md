# "Can't" claims — audit

**Why this exists.** In one session, four separate *"the environment can't do X"* claims were tested and
**all four were false**:

| Claim | What it rested on | Reality |
|---|---|---|
| "the sandbox blocks the open web" | `WebFetch` returned 403 for rfc-editor.org | plain `curl` works — cost a round-trip asking the user to paste RFC vectors by hand |
| "the product build is not provisionable (apt offline/locked)" | one `ls a b` probe in the session-start hook | `ls a b` exits non-zero if *either* path is missing; the dep was present. The build works. |
| "HACL\* is unavailable" | it had vanished from `/tmp` | the tarball was in the uploads directory the whole time |
| "these commits are unsigned" | local `git log %G?` printed `N` | `N` means *cannot verify* (no `allowedSignersFile`), not *unsigned*; the commits carry `gpgsig` SSH signatures |

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

### VERIFIED-TRUE

*(none yet — the genuinely-impossible claims below have not been individually tested, and are listed as
UNTESTED rather than assumed true. Kernel dm-crypt mount is the most likely to survive testing: it needs
a VM, which this container does not provide.)*

### UNTESTED

Not yet checked; **do not treat as either true or false**:

| Claim | Location |
|---|---|
| C-path (Windows driver) header round-trip | `docs/REAL-BUILD-VALIDATION.md:294` |
| kernel dm-crypt mount | `docs/KEYSLOTS-SPEC.md:272`, CLAUDE.md |
| duress end-to-end (wx orchestration) | `CLAUDE.md:211` |
| keyslot mount-time auto-search on real media | `docs/KEYSLOTS-SPEC.md:272` |
| network-share against a live external server | `docs/NETWORK-SHARE-SPEC.md:114` |
| SSD/FTL remnant behaviour | `docs/DECOY-FRAGMENTS-SPEC.md:58,72` |
| true power-loss (vs torn-write, which is proven) | `docs/TIER5-FORMAT-DESIGN.md:106` |
| flash-media warning firing on a live mounted session | `docs/ROI-TOP-50.md:115` |
| ORAM wiring into VeraCrypt | `docs/ORAM-SPEC.md:105` |
| Adiantum `EncryptionMode` shim on non-AES-NI hardware | `docs/ADIANTUM-SPEC.md:68,98` |
| HKF v2 wiring / different-volume-salt behaviour | `docs/HKF-MIX-V2-SPEC.md:71,172` |
| whether GitHub marks this session's commits Verified | stop-hook warning |

Several of these are *probably* true — a VM genuinely is absent. The point is that "probably true" is
what the four falsified claims also looked like, so each gets tested before it is written down as fact.
