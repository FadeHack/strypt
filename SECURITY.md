# Security Policy

strypt is used by people for whom a metadata leak can be a physical safety event. Security
reports are treated accordingly.

---

> ## ⚠️ Placeholder — requires owner action before this policy is real
>
> **The contact details below are not yet configured.** Until the project owner fills them
> in, there is no working private reporting channel and this document promises something the
> project cannot currently deliver.
>
> **Owner checklist:**
> - [ ] Create a dedicated security contact address, and publish a PGP key for it.
> - [ ] Enable GitHub Private Vulnerability Reporting on the repository (preferred primary
>       channel — it requires no key management from the reporter).
> - [ ] Name a **backup contact**, so reports do not depend on one person being reachable.
>       `docs/ROADMAP.md` Phase 7 makes this an exit criterion.
> - [ ] Replace this block with the real details and remove the placeholder warning.

---

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Preferred: GitHub's private vulnerability reporting on this repository *(to be enabled — see
above)*.

Alternative: email `[SECURITY CONTACT — TO BE CONFIGURED]`, encrypted to
`[PGP KEY FINGERPRINT — TO BE CONFIGURED]` if the report is sensitive.

Please include: affected version and platform, what you observed and what you expected, steps
to reproduce, and a sample file if one is involved — **sanitised of any real personal data**,
or reproduced synthetically. We will not ask you to send a file containing someone's real
location or identity.

## What counts as a vulnerability

Alongside the obvious categories (memory corruption, code execution, privilege escalation),
these are treated as security issues in strypt specifically:

- **Silent incomplete removal.** strypt reports a file clean or successfully stripped while
  metadata remains. This is the highest-severity class in the project: the user acts on that
  report by publishing. It is a vulnerability, not a defect.
- **Panic, crash, hang, or unbounded memory growth on a crafted input file.** For a
  `forbid(unsafe_code)` codebase these are the realistic exploitation surface.
- **Leakage through strypt's own outputs** — metadata appearing in logs, error messages, or
  temp files that survive.
- **Any network connection made by strypt**, from any code path or dependency. This violates
  a core project invariant (ADR-0004) and is severe regardless of what the connection does.
- **Supply-chain issues** — a compromised or malicious dependency in the tree.

Not vulnerabilities: metadata strypt has never claimed to remove (see
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §4), content that is visible in the file
itself, and fingerprinting through encoder characteristics or sensor noise. If the threat
model is unclear or misleading on one of these, though, **that** is worth reporting — a
document that causes over-trust is its own hazard (threat model §5.6).

## Response process

| Stage | Target |
|---|---|
| Acknowledgement of report | 72 hours |
| Initial assessment and severity | 7 days |
| Fix or documented mitigation for high severity | 30 days |
| Public disclosure | Coordinated with the reporter, normally after a fix ships |

These targets reflect a small volunteer maintainer team. If you have not heard back within
the acknowledgement window, please chase — assume an unread message rather than a decision to
ignore you.

Every accepted security fix ships with a regression test and its triggering input in the test
corpus, per [`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) §2.6.

## Disclosure

Security fixes are announced in [`CHANGELOG.md`](CHANGELOG.md) under `Security`, stating
which versions and formats were affected — **specifically so users can determine whether
files they already published need re-checking.** For a metadata tool this is the whole point
of disclosure: the harm may already be in the world, and a vague advisory leaves people
unable to assess their own exposure.

Reporters are credited unless they prefer otherwise. Given who works on and with this tool,
requests for anonymity are honoured without question or explanation.

## Supported versions

Until v1.0, only the latest release receives security fixes. A support policy for older
releases will be defined at v1.0.

## Scope

In scope: `strypt-core`, `strypt-cli`, this repository's CI and release tooling, and the
published release artefacts.

Out of scope: vulnerabilities in third-party dependencies (report upstream, and tell us so we
can pin or replace), and issues in mat2 or ExifTool (report to those projects).
