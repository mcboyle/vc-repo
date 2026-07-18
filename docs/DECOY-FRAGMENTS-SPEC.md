# Decoy-fragments-by-default — design & status

**Status: DESIGN — the indistinguishability core is proven; the write-into-real-volumes integration
and the SSD/FTL behaviour are the real-build/real-hardware part.** Addresses upstream issue #1072 and
the SSD-deniability gap in `docs/THREAT-MODEL.md`: on flash, hidden-volume *creation* can leave
remnants, and the mere presence of a "second header slot full of random data" can hint at a hidden
volume. The fix is to write plausible decoy fragments on **every** volume by default, so their presence
proves nothing.

## Scope line (read first)

This is **indistinguishable-random storage** — writing random-looking artifacts where a hidden-volume
header/creation trace would sit. It is **not** a synthesized record of user activity (forged
timestamps, fake history). That latter thing is the DESCOPED evidence-fabrication tool
(`ROADMAP.md`, `CLAUDE.md`) and stays out. The whole point here is that the artifact carries **no
information at all** (it is uniform random) — the opposite of fabricated evidence.

## The idea

A real hidden-volume header is `salt || ChaCha20/AES(header_key, header_plaintext)`. Since the body is
encrypted under a key the observer does not have, it is **indistinguishable from random**; the salt is
random too. So a real hidden header is, to anyone without the password, just `random_salt ||
random-looking bytes`.

A **decoy fragment** is built to the same shape: `salt || ChaCha20(random_key, zeros)` = `salt ||
keystream`. Same length, same structure, same uniform distribution — and the random key is discarded,
so it decrypts to nothing and reveals nothing.

Writing a decoy fragment at the candidate hidden-header offset (and, optionally, scattered creation
remnants) on **every** volume means: a volume that HAS a hidden volume and one that does NOT are
**identical to a free-space scanner**. Finding a "random second header" no longer implies a hidden
volume, because every volume has one.

## What the PoC proves (`verification/decoyfrag_poc.c` + `decoyfrag_reference.py`, step `[14]`)

Proven two ways — the C PoC drives the **real in-tree ChaCha20 (`chacha256.c`)**, an independent Python
reference reproduces it **byte-for-byte** (same deterministic `xorshift64*` PRNG; anchors
`47067dd6…` real header, `a52a1326…` decoy fragment):

- **[A] Identical layout** — a real hidden header and a decoy fragment are both 512 bytes = 64-byte
  salt + 448-byte body. A scanner sees the same shape.
- **[B]/[C] Same uniformity, same test result** — over 64 samples each, an integer byte-uniformity
  statistic (`sum (count − expected)²`, no floats so C and Python agree exactly) is computed for the
  real-header batch and the decoy batch. **Both pass the same uniformity bound** — the real hidden
  headers and the decoy fragments are drawn from the same uniform distribution, so no byte-frequency
  test distinguishes a with-hidden volume from a decoy-only volume.

Because both are `random_salt || PRF_output`, any statistic has the same distribution on both; a
distinguisher does no better than chance. Confidentiality of a *real* hidden volume is unaffected — its
body is still encrypted; the decoy simply removes the *presence* signal.

## Honest limits (state these)

- **Not a multi-snapshot fix.** Decoy fragments hide the *presence* of a hidden volume in a single
  image. They do **not** hide *usage* across two images — that is the write-only **ORAM** item
  (`docs/ORAM-SPEC.md`). The two are complementary: ORAM hides which blocks change; decoy-fragments
  hide that a hidden structure exists at all.
- **SSD/FTL is the real target and is not sandbox-testable.** The value on flash depends on where the
  FTL actually places these writes and what remnants persist — that needs experiments on real hardware.
  The PoC proves the artifacts are indistinguishable-random; it cannot prove the drive scatters them
  usefully.
- **Must match VeraCrypt's real creation artifacts.** To be convincing, the decoy fragments have to sit
  at exactly the offsets and sizes a genuine hidden-volume creation would touch (the 64 KiB hidden
  header region, and any creation-time writes). Getting that mapping right is the integration work.
- **Imaged-first / coercion unaffected.** As always, an adversary who copied the disk earlier, or who
  simply compels the password, is not addressed by any on-disk measure.

## Remaining (real build)

Wire decoy-fragment generation into volume creation (write a decoy hidden-header + optional creation
remnants on every non-hidden volume, at the real offsets), using VeraCrypt's RNG and the same layout as
a genuine hidden volume; then validate remnant behaviour on real SSDs. Not sandbox-testable beyond the
proven indistinguishability core above.
