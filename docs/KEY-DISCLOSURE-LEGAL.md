# Key-disclosure & jurisdiction considerations

> **NOT LEGAL ADVICE.** This document describes the *technical* project's understanding of the legal
> landscape around compelled key/password disclosure and deniable-storage features, so that users and
> integrators know the questions to ask. It is written by software authors, not lawyers, and is
> necessarily incomplete and time-sensitive. **Consult local counsel** before relying on any of it.
> Items whose answer is fact-specific or unsettled are tagged `[COUNSEL-REVIEW]`.

## Why a technical tool ships this document

This fork ships features — duress-dismount (`docs/DURESS-DISMOUNT-SPEC.md`), decoy/hidden volumes
(`docs/DECOY-VOLUME-SPEC.md`), factor-gated slots — whose *use* can carry legal consequences that are
independent of whatever the encryption protects. Handing over only a decoy, or declining to disclose a
key, **may itself be a criminal offence** in disclosure-mandate jurisdictions, and doing so under a legal
process can expose the user to obstruction / perverting-the-course-of-justice / false-statement charges
that are separate from the underlying data. A tool that offers these capabilities without saying so
would be doing its users a disservice. None of these mechanisms is a *legal* defence; they are technical
constructs.

## Jurisdiction matrix (settled / unsettled / hostile)

The three columns are **how compelled disclosure is treated**, not a ranking of countries. Laws change;
every entry is `[COUNSEL-REVIEW]` for current text and application.

### Disclosure-mandate (hostile) — refusing, or handing over only a decoy, can be a distinct offence

| Jurisdiction | Instrument | Exposure (as understood; verify) |
|---|---|---|
| United Kingdom | RIPA 2000 Part III **s.49** (notice to disclose), **s.53** (offence of failing to comply) | Up to **2 years**; **5 years** for national-security or child-indecency cases. A s.49 notice can compel the key or the plaintext; failure is the offence, independent of the data. |
| France | Code pénal **Art. 434-15-2** | Up to **3 years** and **€270,000**, rising to **5 years and €450,000** if disclosure would have prevented or limited a crime. Amounts per **Conseil constitutionnel décision 2018-696 QPC**, quoting the text as amended by loi 2016-731. `[COUNSEL-REVIEW]` |
| Australia | Crimes Act 1914 **s.3LA** (assistance order) | **Tiered** penalty (not a single ceiling): **5 years / 300 penalty units**, rising to **10 years / 600 penalty units** for aggravated cases, per the current AustLII text of s.3LA (raised from 2 years). The *Assistance and Access Act 2018* separately compels providers, not end users, but is part of the same posture. `[COUNSEL-REVIEW]` |

In these jurisdictions a **decoy handed over as if it were the whole volume** is not a safe move: if the
existence of a hidden volume is later established (see the multi-snapshot / media limits in
`docs/THREAT-MODEL.md`), the act of surrendering only the decoy can be charged as the offence rather than
excusing it.

### More protective — a right against compelled disclosure may apply

| Jurisdiction | Basis | Note |
|---|---|---|
| United States (federal) | **Fifth Amendment** privilege against self-incrimination, via the **act-of-production** doctrine | Compelling a *password from the mind* is more likely testimonial and protected; the **"foregone conclusion"** exception can defeat the privilege when the government already knows the data exists and can describe it with reasonable particularity. `[COUNSEL-REVIEW]` |
| Germany | **nemo tenetur se ipsum accusare** | A suspect generally cannot be compelled to actively cooperate against themselves; scope for passwords is fact-specific. `[COUNSEL-REVIEW]` |

### Genuinely unsettled — say so plainly

- **United States, state level** `[COUNSEL-REVIEW]` — the courts are **split at the state supreme court
  level**. Roughly protective (privilege upheld): **Pennsylvania, Indiana, Utah**. Roughly compelling
  (privilege overcome, often via foregone conclusion): **New Jersey, Massachusetts**. The fight turns on
  **how broadly the "foregone conclusion" exception applies** to a password — whether the state must
  already know what is on the device, or merely that the suspect knows the password. There is no
  settled national rule; do not represent one.
- **United States — biometric unlock is a live circuit split** `[COUNSEL-REVIEW]` — compelling a
  *biometric* (thumbprint / face) to unlock is being treated differently from compelling a password, and
  the federal circuits now disagree: **United States v. Payne, 99 F.4th 495 (9th Cir. 2024)** held a
  compelled thumbprint **not** testimonial; **United States v. Brown, 125 F.4th 1186 (D.C. Cir. 2025)**
  held a compelled unlock **testimonial**. **No SCOTUS merits ruling** resolves the split. This
  materially changes the threat model for a user who unlocks **biometrically** rather than by
  passphrase — the password-in-the-mind protection above may not carry over. Feeds the counsel brief
  (`docs/COUNSEL-BRIEF.md`).
- Any jurisdiction not listed above: **treated as unknown here.** A missing row is not "no law" — it is
  "the authors did not verify it." Leave the gap rather than guessing.

## Guidance the tool can honestly give

- **Duress-dismount is a technical mechanism, not a legal shield.** It dismounts and scrubs; it does not
  change what you are legally obliged to disclose, and in a disclosure-mandate jurisdiction *using* it in
  response to a lawful notice may itself be chargeable. See the "Legal considerations" section of
  `docs/DURESS-DISMOUNT-SPEC.md`.
- **A decoy/hidden volume is not a get-out.** Its deniability is empirical and defeatable (media residue,
  multi-snapshot imaging — `docs/THREAT-MODEL.md`), and against an adversary who knows the feature exists
  it can *aggravate* rather than help. It provides no protection recognised by any disclosure-mandate
  statute.
- **Know your jurisdiction before you rely on any of this.** The same act (refusing disclosure; handing
  over a decoy) can be lawful self-incrimination protection in one place and a multi-year offence in
  another.

## External corroboration of the permanent DESCOPE

The same batch-2 research that produced this landscape independently identified **automated
activity-fabrication** — generating a synthetic record of computer use (forged timestamps, fake
browser/history artifacts) to deceive a forensic examiner — as **the single feature most likely to
convert a defensive storage tool into an obstruction / evidence-tampering charge**. That is external
support for this project's standing decision to keep evidence-fabrication permanently out of scope
(`ROADMAP.md` → DESCOPED; `docs/DECOY-VOLUME-SPEC.md §6`; `docs/IDEAS-BACKLOG.md` scope-boundary). The
line stays where it is: build confidentiality / deniable **storage** and access control; never build
tooling whose function is to manufacture a false record of activity.

## Scope

Describing the legal landscape so users can ask the right questions is documentation, not legal practice
and not a code feature. This document **advises no one to take or refuse any action**; it points at the
questions and says, for each, consult counsel.
