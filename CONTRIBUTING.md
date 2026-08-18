# Contributing to strypt

Thanks for considering it. Please read this first — strypt has a few expectations that differ
from a typical Rust CLI project, because of who relies on it.

**Current status: Phase 0 complete, Phase 1 not started.** The workspace and CI gates exist;
no format handler does. The most valuable contributions right now are review of the design
documents in [`docs/`](docs/) — particularly [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
and [`docs/PRD.md`](docs/PRD.md) §0, which questions the project's own founding premise.

---

## Development process: AI-assisted, under constraints

**strypt is developed with substantial use of Claude Code, an AI coding agent.** This is
deliberate and disclosed rather than incidental, because a tool asking at-risk people to
trust its output should not be quiet about how it is built.

For a security tool, that fact deserves scrutiny. AI agents produce plausible-looking code
confidently, are prone to inventing API details, and will happily assert a version number or
a library's behaviour from stale training data. In a metadata scrubber, a plausible-looking
parser that misses a field is exactly the failure mode that gets someone hurt — the tool
reports success, the user publishes, and the leak is already in the world.

The project's response is to constrain the process rather than trust the output. What is
actually in place, all of it verifiable in this repository:

- **Hard invariants in [`CLAUDE.md`](CLAUDE.md)** that apply to every session: no network
  access in any code path, no `unsafe`, no panics in parsing, fail-closed behaviour, and a
  ban on overclaiming in user-facing text.
- **A standing verification requirement.** Any dependency, version, or claim about an
  external project must be checked against a primary source before it is written down, not
  recalled. This has already caught real errors: the project's founding premise about mat2
  being unmaintained was wrong ([`docs/PRD.md`](docs/PRD.md) §0), and a widely-cited
  third-party source reported a stale Rust stable version that would have set the MSRV
  incorrectly.
- **Enforcement that does not depend on an agent behaving well.** The no-network rule is a CI
  gate that walks the fully resolved dependency graph and has been proven to fail by
  deliberate violation. `unsafe` is rejected by the compiler via `forbid(unsafe_code)`, by a
  pre-commit hook, and by requiring a decision record. [`.claude/HOOKS.md`](.claude/HOOKS.md)
  states plainly what the editor-level hooks *cannot* catch and why CI is authoritative.
- **[`docs/DECISIONS.md`](docs/DECISIONS.md)** records why each choice was made, not just
  what was chosen — so a reviewer can audit the reasoning, including where it was wrong.
  ADR-0015 and ADR-0016 exist because two CI gates were found to be passing while testing
  nothing.
- **No `unsafe` merges without an ADR in the same commit**, enforced at pre-commit and in
  review.
- **Fuzzing and dependency-audit gates** defined in [`docs/ROADMAP.md`](docs/ROADMAP.md)
  Phase 3: per-handler fuzzing budgets with crash, hang, and OOM findings triaged to zero,
  and `cargo-deny` as a hard merge gate.

### What this does not establish

**None of the above makes AI-written code trustworthy, and this section is not an argument
that it does.** These are process safeguards. They constrain what can be committed and make
reasoning auditable; they do not verify that a parser correctly handles a malformed
JPEG APP1 segment. Constraints catch categories of error, not individual bugs.

What the project still needs, and does not yet have:

- **Human review of every line of parsing logic.** Phase 1 has not started; no parser has
  been written, let alone reviewed.
- **The Phase 3 fuzzing work actually performed**, not merely specified. A budget written in
  a roadmap has found nothing.
- **External security audit.** None has taken place and none is scheduled. The threat model
  is self-assessed, which is the weakest form of threat model.
- **Differential validation against mat2 and ExifTool** on a real corpus, which is the
  strongest correctness signal available and is Phase 1 work.

Until those exist, the honest position is the one in the README: do not rely on strypt for
anything that matters. If you are evaluating this project and the AI involvement is
disqualifying for your use, that is a reasonable conclusion and we would rather you reach it
from a clear statement than discover it later.

Contributions from humans and from AI-assisted humans are equally welcome, and are held to
exactly the same standard: parsing changes get extra scrutiny (see above), and "an agent
wrote it and the tests pass" is not a review.

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
