# Security Policy

strypt is used by people for whom a metadata leak can be a physical safety event. Security
reports are treated accordingly.

---

> ## What this policy can and cannot deliver today
>
> **This is a single-maintainer project with no external audit.** Be aware of three limits
> before relying on anything below. They are stated here rather than discovered later:
>
> - **There is no backup contact.** If the maintainer is unreachable, a report waits. Naming
>   one is a `docs/ROADMAP.md` Phase 7 exit criterion and it is not met.
> - **Reports arrive over ordinary email, unencrypted.** No PGP key is published, because a
>   key the maintainer cannot reliably use would be worse than none — a reporter would encrypt
>   a real finding into something unreadable. Assume the mail provider can read what you send,
>   and see the note below on what not to attach.
> - **GitHub Private Vulnerability Reporting is not available.** GitHub offers it on public
>   repositories only, and this repository is private. It will be enabled if and when that
>   changes, and will become the preferred channel at that point.

---

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Email **`fadehack.dev@gmail.com`**, with `strypt security` in the subject line.

Please include: affected version and platform, what you observed and what you expected, steps
to reproduce, and a sample file if one is involved — **sanitised of any real personal data**,
or reproduced synthetically. We will not ask you to send a file containing someone's real
location or identity.

That request matters more than usual here, because the channel is unencrypted. If a finding
can only be demonstrated with a file carrying someone's real data, say so in the mail and send
the description alone; we will work out a safer way to exchange the sample rather than have it
sitting in two mailboxes.

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

**These are targets, not guarantees, and they rest on one person being reachable.** strypt has
a single maintainer and no backup contact, so a holiday or an illness is the realistic failure
mode for the acknowledgement window — not a decision about your report. If you have not heard
back within it, please chase; assume an unread message rather than a judgement.

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

There have been no releases. `strypt` and `strypt-core` are published on crates.io at `0.0.1`,
which exists to hold the names and is not a release — see the [README](README.md) status block.
Only the latest published version receives fixes; a support policy for older releases will be
defined at v1.0.

## Scope

In scope: `strypt-core`, `strypt` (the CLI crate, published as `strypt-cli` before
2026-08-23), this repository's CI and release tooling, and the
published release artefacts.

Out of scope: vulnerabilities in third-party dependencies (report upstream, and tell us so we
can pin or replace), and issues in mat2 or ExifTool (report to those projects).
