# Write-only ORAM — access-pattern hiding for multi-snapshot deniability

**Status: DESIGN — the access-pattern-hiding property is proven in a PoC; integration into the volume
layout is a large, real-build effort (see §6).** This is the **real** mitigation for the
multi-snapshot attack that `docs/THREAT-MODEL.md` names as the #1 limitation of hidden volumes — and
which no factor, decoy, or scrub in this fork addresses.

## The attack it answers

A hidden volume lives in the "free" space of a decoy. Using it **writes** into that free space.
An adversary who **images the disk twice** (before and after) diffs the two snapshots: in a plain
hidden-volume system the changed blocks betray hidden-volume activity, because normal decoy operation
would not have touched exactly those free blocks in that pattern (Fredrickson, Barker & Long, *A
Multiple Snapshot Attack on Deniable Storage Systems*, 2021). This defeats deniability for a repeat-
imaging adversary regardless of how strong the crypto is.

## The idea: make every write look the same

Write-only ORAM (HIVE — Blass et al. 2014; DataLair — Chakraborti et al. 2017) targets exactly the
**snapshot** adversary and is much cheaper than full ORAM because of one observation: **reads do not
modify the disk, so a snapshot adversary never sees them** — only writes must be hidden.

The construction makes **every logical write touch the same distribution of physical blocks**:

- The volume's data area is a pool of `N` physical blocks holding `B` logical blocks (`N > B`, e.g.
  2–4×). A **position map** records logical → physical.
- Each block is stored IND-CPA encrypted (here ChaCha20 with a fresh per-write nonce).
- **write(L, data):** pick `K` uniformly-random physical positions *from a PRNG, independent of L*;
  re-encrypt all `K` with fresh ciphertext — the target's new data goes into one free position among
  the `K`, the others are re-encryptions of their existing contents (or fresh randomness). Update the
  position map.
- **read(L):** decrypt the one physical block the position map points at. **No disk write** → invisible
  to a snapshot adversary.

Because the `K` touched positions are drawn from the PRNG **before and independently of** which logical
block (public or hidden) is being written, two disk snapshots reveal only *"K uniformly-random blocks
changed, with fresh ciphertext, per write."* That distribution is **identical whether or not the hidden
volume was touched** — so the repeat-imaging adversary learns nothing about hidden activity.

## What the PoC proves (`verification/oram_poc.c` + `oram_reference.py`, step `[13]`)

Proven two ways — the C PoC drives the **real in-tree ChaCha20 (`chacha256.c`) and SHA-256 (`Sha2.c`)**,
and an independent Python reference reproduces the whole run **byte-for-byte** (same deterministic
`xorshift64*` PRNG; state digest anchor `203b068d…`):

- **Correctness** — after an arbitrary write sequence, every logical read returns the last value
  written (the ORAM is a correct block store).
- **Access-pattern indistinguishability (the deniability property)** — a **public-only** workload and a
  **public+hidden** workload of the same length produce a **byte-identical observable access trace**
  (the set of physical blocks changed per write is the same), because the touched positions depend only
  on the PRNG, not on the logical target. A snapshot adversary sees the same pattern either way.
- **Confidentiality is orthogonal** — the encrypted contents of course differ between the two workloads
  (different data was written); that is the block cipher's job. Deniability comes from the *identical
  access pattern*, confidentiality from the *ciphertext*. The PoC shows both hold simultaneously.

PoC parameters (illustrative): `B=8` logical, `N=24` physical, `K=10` touched/write, 32-byte blocks.

## Costs and honest limits (state these)

- **Write amplification.** Every logical write costs `K` physical block writes (plus reads to
  re-encrypt). This is the price of hiding the pattern; `K` and `N/B` trade security margin against
  overhead. Not free, and heavy for write-intensive workloads.
- **Position map storage.** The map is small trusted state. In a real deployment it cannot sit in the
  clear — it must live in a recursive ORAM or in encrypted header state, itself updated under the same
  write-hiding discipline. Getting the map storage right (and deniable) is a substantial part of the
  real work, not shown in the PoC.
- **Free-slot guarantee.** A write needs a free position among its `K` samples; with `N/B` and `K`
  chosen well this holds with overwhelming probability, but the real implementation must handle the
  rare miss (resample / stash) — the PoC asserts the PoC parameters never miss.
- **Snapshot model only.** Write-only ORAM defends the *multi-snapshot* adversary. It does **not** help
  against an adversary with **live** access (RAM/DMA — that is the KeyScrub item) or one who **images
  first** and coerces later (no on-disk measure helps a copy already taken).
- **SSD/TRIM.** The flash translation layer can still leak through wear-leveling/TRIM independently of
  the logical write pattern; write-only ORAM assumes it controls the physical block mapping, which is
  truer on a raw partition than on a consumer SSD.
- **In scope.** This is access-pattern-hiding **storage** — confidentiality/deniability, not evidence
  fabrication. It stays firmly on the right side of the project's scope boundary.

## §6 — Integration (the large, real-build part)

The PoC proves the mechanism; wiring it into VeraCrypt is a major effort and is **not sandbox-testable**
(it needs the real volume layout and block I/O):

- A **write-only-ORAM block layer** between the filesystem and the encrypted data area, over the hidden
  volume's physical extent (respecting the decoy/hidden layout).
- **Position-map storage** as recursive ORAM or hidden encrypted header state, updated under the same
  write discipline.
- **Filesystem interaction** — the FS above must tolerate the block layer's remapping and the write
  amplification; alignment with VeraCrypt's sector model.
- **Parameter selection** (`N/B`, `K`, stash size) with a written security/overhead analysis, and
  validation against an actual two-snapshot experiment on real media.

This is a research-grade feature; the value delivered here is the **proven core property** and a
concrete construction to build it from. It should be scheduled as its own project, not folded into a
routine change.
