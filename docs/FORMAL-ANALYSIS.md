# Formal security analysis — arguments, assumptions, and a mechanization plan

**Status: written (pen-and-paper) analysis + mechanization plan; a mechanized proof is NOT done here
and is pending an appropriate tool + environment.** This addresses `IDEAS-BACKLOG.md`
§"Formal methods" for the network-share (McCallum–Relyea) and OPRF protocols, honestly: it does the
reasoning and specification part that is possible in this sandbox, and is explicit about why the
mechanized part is not.

## 0. Why there is no mechanized proof in this repo (two independent reasons)

1. **No tool is installable in this environment.** `proverif`, `tamarin-prover`, `verifpal`,
   `cryptoverif` are absent; there is no `opam`/`ocaml`/`ghc`/`maude` to build them from source; and
   the session's network policy blocks the release downloads (only `mcboyle/vc-repo` is enabled).
2. **The standard *symbolic* provers are a poor fit for these protocols even when available.** Both MR
   and the OPRF rely on the group's **own** operation — MR blinds with `X = C · gᵉ` (multiplying two
   group elements), the OPRF unblinds with `EE^{r⁻¹}` (an exponent inverse). ProVerif's and Tamarin's
   built-in Diffie–Hellman equational theories model **exponentiation** soundly but not the free
   **composition of two independent group elements**; encoding it needs a custom AC theory that these
   tools handle unsoundly or non-terminatingly. The right tool is a **computational** one
   (CryptoVerif or EasyCrypt) reasoning under DDH / one-more-DH — more expert-intensive and equally
   un-installable here.

So the mechanized proof is treated like the project's other **real-tool / real-build** items: scoped
and specified, not claimed. What *is* already machine-checked in this repo is the **functional
correctness and the algebraic security properties** of each protocol — see §6.

## 1. Model & assumptions

- **Groups.** ristretto255 (prime order `L`, `docs/OPRF-SPEC.md`, steps `[43]`–`[47]`) and the
  Ed25519 prime-order subgroup (`docs/NETWORK-SHARE-SPEC.md`, step `[39]`). Write `G` for the
  generator, scalars mod `L`.
- **Hardness assumptions.** CDH/DDH in the group; for the OPRF, the **One-More-Gap-DH** assumption
  (Jarecki–Kiayias–Krawczyk); hashes (`HashToGroup`, `expand_message_xmd`, the finalize hash) modeled
  as random oracles (ROM).
- **Adversary.** Active network (Dolev–Yao) attacker for secrecy/authentication; for the OPRF's
  offline-guessing goal, an adversary that may make bounded *online* server queries.

## 2. Network-bound share — McCallum–Relyea (`[10]`, `[39]`)

- **Protocol.** Server secret `s`, public `S = s·G`. Provision: ephemeral `c`, store `C = c·G`,
  `K = c·S = (sc)·G`, discard `c, K`. Recover: ephemeral `e`, send `X = C + e·G = (c+e)·G`; server
  returns `Y = s·X`; client computes `K = Y − e·S = (sc)·G`. Share = `H(K)`.
- **Goal 1 — key secrecy vs. a network eavesdropper.** An attacker sees `S, C, X, Y` but not `s`
  (server-held) nor the client's fresh `e`. Recovering `K = (sc)·G` from `(S=s·G, C=c·G)` is exactly
  **CDH**. Argument: an algorithm that outputs `K` from the transcript is a CDH solver for `(s·G, c·G)`;
  `X, Y` add nothing an eavesdropper couldn't simulate given a DDH oracle (they are `(c+e)·G` and its
  `s`-multiple for attacker-unknown `e`).
- **Goal 2 — the server learns nothing.** For fresh uniform `e`, `X = (c+e)·G` is uniformly
  distributed and independent of `C`; so the server's view is independent of `C` and `K`. This is an
  information-theoretic (perfect-blinding) argument, not a computational one.
- **Residual (real-build).** Holds in the algebraic model; a deployment must also bind the server
  identity/endpoint (pin `S`) to stop an enroll-time key substitution — an authentication property for
  the transport, out of scope of the algebra (`docs/NETWORK-SHARE-SPEC.md`).

## 3. OPRF — 2HashDH (`[17]`, `[43]`)

- **Protocol.** Server key `k`. `HashToGroup(x) = M`; client blind `r`, `BE = r·M`; server
  `EE = k·BE`; client `N = r⁻¹·EE = k·M`; output `F_k(x) = H(x, k·M)`.
- **Goal — pseudorandomness / offline-guessing resistance.** `F_k` is a PRF whose evaluation requires
  the server: under **One-More-Gap-DH** in the ROM, an adversary making `q` online queries can compute
  `F_k` on at most `q` inputs; every additional guess needs another online (rate-limitable) query. This
  is the JKK reduction; `HashToGroup` and `H` are the two random oracles ("2Hash").
- **Goal — obliviousness.** For fresh uniform `r`, `BE = r·M` is uniform and independent of `x`; the
  server's view is independent of the input. Perfect blinding, as in MR Goal 2.

## 4. Threshold OPRF / PPSS (`[35]`, `[44]`)

- **Protocol.** `k` Shamir-split over `Z_L` into `k_1..k_n` (degree `t−1`); server `i` returns
  `k_i·BE`; client combines any `t` by Lagrange-in-the-exponent to `k·BE`.
- **Goal — key secrecy under a corrupt minority.** Any `t−1` shares are, by **Shamir perfect
  privacy** over `Z_L`, information-theoretically independent of `k`; combined with the OPRF argument
  (now under a *threshold* one-more-gap-DH), a coalition below threshold cannot evaluate `F_k`. The
  Lagrange reconstruction is exact (`[44]` shows the byte-identical single-key output), so correctness
  and the `t`-privacy boundary are both witnessed.

## 5. Verifiable OPRF — DLEQ / Chaum–Pedersen (`[47]`)

- **Protocol.** Server commits `pk = k·G` and proves `EE = k·BE ∧ pk = k·G` via a Σ-protocol
  (`a1 = rr·G, a2 = rr·BE, c = H(transcript), s = rr − c·k`); Fiat–Shamir makes it non-interactive.
- **Soundness (verifiability).** The Σ-protocol is **special-sound**: two accepting transcripts with
  the same commitments but different challenges yield `k = (s−s')·(c'−c)⁻¹`, so a prover who convinces
  the verifier on a fresh challenge knows the *committed* `k` — a server cannot pass off `EE' = k'·BE`
  under the committed `pk`. In the ROM, Fiat–Shamir preserves soundness (the challenge is `H`-bound to
  the statement, as encoded in step `[47]`). `[47]` witnesses the concrete rejections (tampered `EE`,
  wrong `pk`).
- **Zero-knowledge.** The proof is HVZK (simulate by sampling `s, c` and back-computing `a1, a2`), so
  it leaks nothing about `k` beyond `pk`.

## 6. What IS already machine-checked in this repo

The functional and *algebraic-security* properties above are exercised by the verification suite —
not a substitute for a mechanized secrecy proof, but concrete evidence the algebra is right:

- MR: recovered `K` == provisioned `K`, server sees only the blinded `X`, a wrong server key changes
  the share (`[10]`, `[39]`).
- OPRF: the OPRF identity, blind-independence (fresh `r` → same output), wrong-key-differs (`[43]`);
  threshold reconstructs the single-key output and `t−1` differ (`[44]`); DLEQ valid-verifies /
  tampered-`EE`-rejected / wrong-`pk`-rejected (`[47]`).
- Groups anchored to official KATs: RFC 8032 §7.1 (Ed25519, `[39]`), RFC 9496 §A.1 (ristretto255,
  `[43]`/`[44]`/`[47]`).

## 7. Mechanization plan (turnkey when an environment exists)

1. **Computational (recommended), CryptoVerif or EasyCrypt.**
   - MR: game-hopping proof of `K`-indistinguishability under DDH; encode `X`'s uniform blinding.
   - OPRF: encode 2HashDH; reduce PRF-security to one-more-gap-DH with the two ROs; obliviousness as a
     perfect-blinding hop. Threshold: add Shamir `t`-privacy over `Z_L`.
   - VOPRF: special-soundness + HVZK of the Σ-protocol; Fiat–Shamir in the ROM.
2. **Symbolic (partial), Tamarin.** Usable for the *authentication/transport* properties (server
   identity binding, replay of `X`/`BE`) where the DH-*exponent* theory suffices; **not** for the
   group-composition blinding (§0.2) — do not model `C + e·G` in the built-in DH theory.
3. **Exact lemmas** to state are §§2–5's "Goal" lines; the concrete transcripts/values to assert
   against are the step `[39]`/`[43]`/`[44]`/`[47]` REF outputs.

Until then, this file is the pen-and-paper analysis; the mechanized proof is pending an appropriate
tool and environment, and is not claimed.
