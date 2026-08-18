# Contributing to strypt

Thanks for considering it. Please read this first — strypt has a few expectations that differ
from a typical Rust CLI project, because of who relies on it.

**Current status: Phase 0.** There is no code yet. The most valuable contributions right now
are review of the design documents in [`docs/`](docs/) — particularly
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/PRD.md`](docs/PRD.md) §0, which
questions the project's own founding premise.

---

## Before you start

- **Security vulnerabilities do not go in issues or pull requests.** Follow
  [`SECURITY.md`](SECURITY.md).
- **Read [`CLAUDE.md`](CLAUDE.md).** Despite the name it is the working agreement for all
  contributors, human or AI. The hard constraints in §3 are non-negotiable.
- **Read [`docs/DECISIONS.md`](docs/DECISIONS.md)** before proposing an architectural change.
  Most "why is it like this?" questions are answered there, and a proposal that engages with
  the recorded reasoning will get a much better reception than one that does not.
- **Open an issue before a large change.** Especially for a new format handler — scope is
  phase-locked and an unsolicited handler for an out-of-phase format is likely to be declined
  however good it is. That is a scoping decision, not a judgement of the work.

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

- [ ] `cargo test` passes on your platform
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo fmt` has been run
- [ ] New tests cover the change, including error paths
- [ ] Fuzz corpus updated if a parser changed
- [ ] A regression test exists if this fixes a bug, with the triggering input in the corpus
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] An ADR added for any new dependency, `unsafe` block, or architectural change
- [ ] `docs/THREAT_MODEL.md` updated if a format handler was added or changed
- [ ] `INSTRUCTIONS.md` updated if any command changed

Exact commands: [`INSTRUCTIONS.md`](INSTRUCTIONS.md). Full testing expectations:
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
