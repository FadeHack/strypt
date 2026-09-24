# Contributing to strypt

Thanks for considering it. Please read this first — strypt has a few expectations that differ
from a typical Rust CLI project, because of who relies on it.

**Status: `0.2.0` (2026-09-24).** Phases 0–5 are complete, the last
being the desktop app. There has been no external audit; the [README status block](README.md)
says what that means.

**The format list is closed.** [ADR-0027](docs/DECISIONS.md) fixed it and
[ADR-0043](docs/DECISIONS.md) keeps it closed, so a pull request adding a format is likely to be
declined on scope regardless of its quality. Please open an issue first.

The most valuable contributions right now are adversarial: review of
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), attempts to find metadata that survives a
strip, and fuzzing findings. A file strypt reports as clean that still carries identifying
data is the most valuable bug report this project can receive. No Rust is needed for the other
thing the project lacks: reports of installing and running strypt on your own machine, working or
not. Issues labelled [good first issue](https://github.com/FadeHack/strypt/labels/good%20first%20issue)
say what is missing.

---

## How strypt is developed

strypt is developed with the help of an AI coding agent, and nothing is trusted on that basis.
CI gates over the dependency graph and the `unsafe` ban are each proven to fail, and
[`docs/DECISIONS.md`](docs/DECISIONS.md) records why each decision was made. Every contribution,
however it was written, is held to the same standard: passing tests are not a review.

## Before you start

- **Security vulnerabilities do not go in issues or pull requests.** Follow
  [`SECURITY.md`](SECURITY.md).
- **Read [`CLAUDE.md`](CLAUDE.md).** Despite the name it is the working agreement for all
  contributors. The hard constraints in §3 are non-negotiable.
- **Read [`docs/DECISIONS.md`](docs/DECISIONS.md)** before proposing an architectural change.
  Most "why is it like this?" questions are answered there, and a proposal that engages with
  the recorded reasoning will get a much better reception than one that does not.
- **Open an issue before a large change.** Especially for a new format handler — the format
  list is closed, and a handler outside it is likely to be declined however good it is. That is a scoping decision, not a judgement of the work.

## The constraints that will get a pull request rejected

Not style preferences. Each has an ADR.

1. **Any network access, anywhere, including a transitive dependency that opens a socket.**
   (ADR-0004)
2. **`unsafe` without a `// SAFETY:` comment and an ADR in the same commit.** (ADR-0007)
3. **Panicking code in a parsing path** — `unwrap`, `expect`, `panic!`, direct slice
   indexing, unchecked arithmetic. Malformed input is expected input. (ADR-0006)
4. **CLI logic in `strypt-core`.** The core returns structured data; front-ends format it.
   (ADR-0003)
5. **A new dependency without an ADR justifying it.** (ADR-0008)
6. **A format handler without a fuzz target and seed corpus in the same pull request.**
7. **Logging or printing metadata values.** Field names and counts only.

## Parsing changes get extra scrutiny

Changes to parsing logic are reviewed harder and merged slower than anything else. A parser
bug in strypt can mean someone publishes a file believing it is clean when it is not.

Expect: line-by-line review, questions about every boundary condition, a request for
additional fuzz seeds, and a request for a test proving the specific failure mode you are
fixing. This is not distrust of you. It is the standard the project applies to itself, and
the reason anyone should trust the output.

If a change is urgent and correct but the review is slow, that trade is deliberate.

## Pull request checklist

The [pull request template](.github/pull_request_template.md) carries it. Exact commands: [`INSTRUCTIONS.md`](INSTRUCTIONS.md). Full testing expectations:
[`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md).

## Test files must not contain real personal data

Test fixtures are committed publicly and permanently. A corpus file carrying someone's actual
GPS coordinates would be an unusually embarrassing failure for a project like this one.

Generate fixtures synthetically, or use files whose metadata you deliberately authored. If
you are reporting a bug found with a real file, **sanitise it first** — and if it cannot be
sanitised without losing the bug, describe the structure and we will reproduce it
synthetically. Never attach a file containing someone else's personal data to an issue.

## Commit messages

State what changed and why. For parser changes, cite the spec section or the real-world quirk
being handled — a future contributor cannot re-derive "this vendor writes a malformed length
field" from the diff.

## Response times

A small volunteer project. Rough expectations: issues acknowledged within a week, pull
requests given initial review within two. Security reports move much faster — see
[`SECURITY.md`](SECURITY.md). If something has gone quiet, please chase it; that is almost
always an oversight rather than a decision.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licensing

Contributions are accepted under the project's dual `MIT OR Apache-2.0` licence, per the
Apache-2.0 contribution clause, unless you state otherwise. Do not contribute code copied
from GPL or LGPL projects — including mat2 — as its licence is incompatible with this
project's (ADR-0002). Being *inspired* by how another tool solves a problem is fine and
encouraged; copying its code is not.
