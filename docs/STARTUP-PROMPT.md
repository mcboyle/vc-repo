# In-depth startup prompt

Paste the block below into a fresh Claude Code session on this repo to bring it fully up to speed and
working the right way. (It is written as an instruction to the assistant.)

---

You are continuing work on a **private fork of VeraCrypt 1.26.29** that hardens the *key-derivation*
path. Before doing anything, read, in order: `CLAUDE.md` (architecture + the hard scope boundary),
`docs/SESSION-STARTUP.md` (where everything stands), `ROADMAP.md`, and `docs/SESSION-SUMMARY.md` (the
index of every proven anchor and its verification step). Then treat the following as your operating
contract.

**What the project is.** Defensive disk encryption: it strengthens password entropy with optional
hardware/threshold factors and a factor-gated decoy, by mixing an extra secret into the password
*before* PBKDF2/Argon2 using VeraCrypt's exact keyfile-pool method — so there is **no on-disk header
format change**. It is access-control cryptography for data the user holds.

**The scope boundary (do not cross it).** Everything here is confidentiality / deniability *storage* and
access control. One thing is deliberately **out of scope and must stay out**: any tool whose function is
to *fabricate a false record of computer activity* (forged timestamps, synthetic browser/history
artifacts) to deceive a forensic examiner. That is evidence fabrication, not confidentiality. The
acceptable residue (indistinguishable-random decoy storage) is already built; never build the
fabrication half. If asked, decline and explain, per `CLAUDE.md` and `docs/DECOY-VOLUME-SPEC.md §6`.

**The one methodological rule.** Prove every crypto change **two ways**: (1) byte-for-byte against an
*independent* Python reimplementation, and (2) against *real compiled VeraCrypt objects* — and anchor to
an **official KAT** whenever one exists (RFC/NIST/published vectors). Add a numbered step to
`verification/build_and_verify.sh` for each change; the whole suite (currently steps [1]–[48]) must stay
green (`cd verification && ./build_and_verify.sh`). Never call something done on assertion alone.

**Engineering conventions.** Gate every addition behind `#if defined(VC_ENABLE_*)` so a default build is
byte-for-byte stock (verify: 0 new symbols without the flag). Never change the on-disk header format.
Match the per-file style (C for `Common`/`Crypto`, C++ for `Volume`/`Core`/`Main`). Add a `make` knob +
the object to the right `*.make` for any new gated module, and verify the product link (not just the
isolated object — a link gap is how a real build breaks). Keep docs honest: state the
multi-snapshot / SSD / imaged-first / not-constant-time limitations rather than overselling.

**Honesty about what the work is.** The verification suite proves the crypto is correct and matches the
standards — the easy part. The hard part (mount-path wiring, CLI, on-disk-format decisions, UX,
real-device testing) is tracked as "real-build" and is *not* done. From-scratch EC/group code in
`verification/` is validation-only: correct-against-KAT but **not constant-time**, never to ship. Do not
present green checkmarks as shipped features. When the sandbox genuinely can't validate something
(needs a real build, hardware, a server, or a prover), say so plainly and scope it — do not manufacture
low-confidence artifacts to look productive.

**Where to work next.** Consult `docs/SESSION-STARTUP.md §5` and `ROADMAP.md`. In a plain sandbox, the
sandbox-provable backlog is exhausted; the highest-leverage remaining work needs a **rootful Linux build
box** (Tier 2), where you build the fork and run `verification/realbuild/acceptance.sh` to turn proven
cores into working features (`docs/REAL-BUILD-VALIDATION.md` maps each pending item to its acceptance
test). If you *do* have a build box, start there. If you're asked for more crypto PoCs in a plain
sandbox, push back honestly: more PoCs is motion, not progress.

**Workflow hygiene.** Work on branch `claude/project-structure-review-5p44w9` (or a fresh branch off
`master` if that one is merged). Commit each self-contained change with a descriptive message + the
`Co-Authored-By`/`Claude-Session` trailers, keep the suite green before committing, and push. If a PR is
open, a self-check-in loop may be watching it — follow through on CI/review events.

Start by running the verification suite to confirm a green baseline, then tell me the current state and
your proposed next step before making changes.

---

**Tip:** `.claude/hooks/session-start.sh` already installs the toolchain on web sessions, and `.env`
documents every build knob — so in a fresh web session you can go straight to
`cd verification && ./build_and_verify.sh`.
