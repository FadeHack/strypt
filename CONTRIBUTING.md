# Contributing to strypt

Thanks for considering it. Please read this first — strypt has a few expectations that differ
from a typical Rust CLI project, because of who relies on it.

**Current status: Phases 1 and 2 complete (2026-08-22, 2026-09-05); Phase 3 — hardening —
opened 2026-09-05.** Twenty-two formats are handled and every other format is reported as
unsupported rather than passed through; `strypt` is installable from crates.io at `0.0.1`.
There has been no external audit, **none of Phase 3 is delivered yet**, and `0.0.1` is not a
release — see the [README status block](README.md) for what that does and does not mean.

**Phase 3 adds no formats, and the scope stays locked** by
[ADR-0043](docs/DECISIONS.md) and [ADR-0042](docs/DECISIONS.md) until a superseding ADR opens
it deliberately. A pull request adding a new format is therefore likely to be declined on
scope regardless of its quality — please open an issue first.

The most valuable contributions right now are adversarial: review of
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), attempts to find metadata that survives a
strip, and fuzzing findings. A file strypt reports as clean that still carries identifying
data is the most valuable bug report this project can receive.

---

## Development process: AI-assisted, under constraints

**strypt is developed with substantial use of Claude Code, an AI coding agent.** Disclosed
because a tool asking at-risk people to trust its output should not be quiet about how it is
built — and because the failure mode is specific here: an agent asserts a library's behaviour
from stale training data, the parser misses a field, and the tool reports success to someone
who then publishes.

The response is to constrain the process rather than trust the output, and all of it is
verifiable in the repository:

- **Hard invariants in [`CLAUDE.md`](CLAUDE.md) §3** applying to every session, and a standing
  requirement to verify claims against primary sources rather than recall them — which has
  already caught the project's founding premise about mat2 ([`docs/PRD.md`](docs/PRD.md) §0).
- **Enforcement that does not depend on an agent behaving well:** CI gates over the resolved
  dependency graph and the `unsafe` ban, each proven to fail when deliberately violated.
  [`.claude/HOOKS.md`](.claude/HOOKS.md) states what the editor hooks *cannot* catch.
- **[`docs/DECISIONS.md`](docs/DECISIONS.md)** records why, not just what. ADR-0015 and
  ADR-0016 exist because two CI gates were caught passing while testing nothing.

**None of this makes AI-written code trustworthy, and it is not offered as an argument that
it does.** Constraints catch categories of error, not individual bugs; they do not verify that
a parser handles a malformed JPEG APP1 segment. Human review of every line of parsing logic
and an external audit do not yet exist. If that is disqualifying for your use, it is a
reasonable conclusion to reach.

Contributions from humans and AI-assisted humans are held to the same standard: parsing
changes get extra scrutiny, and "an agent wrote it and the tests pass" is not a review.

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
