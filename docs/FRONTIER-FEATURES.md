# Frontier features — deliberately deferred, not forgotten

**What this list is for.** Some ideas in this project are sound, specced, and even partly proven, but
are **research-grade**: wiring them in is a project in its own right, not a change you land between
other work. Left in `ROADMAP.md` next to ordinary tasks they behave badly — they read as "next up",
they make the roadmap look stalled, and sooner or later someone starts one under time pressure and
produces a large speculative change to a data path in a disk encryptor.

So they live here instead. An item on this list is **parked on purpose**. It is not blocked, not
abandoned, and not waiting on anything external. It comes off the list when someone decides to run it
as its own project with its own schedule — a deliberate act, not a default.

## Entry criteria

An item belongs here if **any** of these hold:

1. Its own spec says integration is a major effort or should be scheduled separately.
2. It changes the **data path** (block I/O, cipher mode plumbing, on-disk layout) rather than the
   key-derivation seam this fork is organised around.
3. Validating it needs conditions this project cannot currently reproduce — real media over multiple
   snapshots, specific hardware, or a multi-week soak.
4. A required part of its own design is still unbuilt, so "wiring it in" would ship a known-incomplete
   security property.

## What this list is NOT

It is not a place to put things that are merely hard, unproven, or unfashionable. It is also not a way
to retire an *honest limitation*: anything users are told about stays in `docs/THREAT-MODEL.md` and the
relevant spec regardless of what is parked here. Parking the work does not park the caveat.

---

## PARKED — write-only ORAM integration

**Status:** core property proven (`verification/oram_poc.c` + `oram_reference.py`, step `[13]`, anchor
`203b068d…`). Integration parked.

**What it would defend against.** The multiple-snapshot attack (Fredrickson, Barker & Long, 2021): an
adversary who images the disk twice diffs the snapshots and sees which "free" blocks changed, which
betrays hidden-volume activity no matter how strong the cipher is. Write-only ORAM (HIVE; DataLair)
answers exactly that adversary, and is much cheaper than full ORAM because reads do not modify the disk
and so are invisible to a snapshot adversary.

**Why it is parked — from the project's own spec, not from reluctance.** `docs/ORAM-SPEC.md §6` already
says it plainly:

> *"wiring it into VeraCrypt is a major effort and is **not sandbox-testable**"* … *"This is a
> research-grade feature; the value delivered here is the **proven core property** and a concrete
> construction to build it from. It should be scheduled as its own project, not folded into a routine
> change."*

It meets all four entry criteria above:

1. The spec says schedule it separately.
2. It is a block layer between the filesystem and the encrypted data area — squarely the data path.
3. Validation requires a real two-snapshot experiment on real media, and the SSD/FTL behaviour it
   interacts with is one of the two claims in `docs/CANT-CLAIMS-AUDIT.md` that remain genuinely
   environment-blocked.
4. `ORAM-SPEC.md` line 8 records that a **required countermeasure — the mandatory public-write cloak —
   is not yet built**. Integrating before that exists would ship an incomplete security property while
   looking finished, which is worse than not shipping it.

**What the work actually is** (from `ORAM-SPEC.md §6`), so a future scheduler can size it honestly:
a write-only-ORAM block layer over the hidden volume's physical extent; position-map storage as
recursive ORAM or hidden encrypted header state under the same write discipline; filesystem tolerance
of remapping and write amplification against VeraCrypt's sector model; parameter selection (`N/B`, `K`,
stash size) with a written security/overhead analysis; and the two-snapshot validation above.

**The one bounded piece that could be done first, independently.** The **mandatory public-write cloak**
is named in the spec as missing and is provable in isolation — the same shape as the RFC 8032 wire
format that turned out to be the real gap under "network-share only needs CLI wiring". Building and
anchoring it would make the rest meaningful and is a normal-sized change. It is *not* parked; it simply
has not been scheduled.

**Do not, while this is parked:** describe ORAM as available, imply the multiple-snapshot attack is
mitigated, or soften the deniability limitations in `docs/THREAT-MODEL.md`. The attack is real and this
fork does not currently answer it. `ROADMAP.md` T0-4 already demoted ORAM from "flagship" to opt-in
experimental with documented limits; this list is where that demotion is made permanent until someone
chooses otherwise.
