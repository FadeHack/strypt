# CI workflows

CI is the project's real enforcement layer (`CLAUDE.md` §6), and every gate is proven to fail
([`INSTRUCTIONS.md`](../../INSTRUCTIONS.md#proving-the-gates-fail)).

| Workflow | What it enforces | When |
|---|---|---|
| `ci.yml` | fmt, clippy `-D warnings`, tests on Linux, macOS and Windows; MSRV build (ADR-0013); filesystem matrix; a 60-second fuzz run per target (ADR-0049) | push to `main`, pull requests |
| `no-network.yml` | no networking crate in the resolved dependency graph (ADR-0004) | push to `main`, pull requests |
| `deny.yml` | `cargo deny check`, and `prove-gates.sh` (ADR-0045) | push to `main`, pull requests, weekly |
| `release.yml` | five targets built twice, failing unless each pair is byte-identical; tags are attested (ADR-0050) | tags, manual |

Every job except MSRV uses the toolchain `rust-toolchain.toml` pins. Sustained fuzzing (ADR-0046)
and the mat2/ExifTool differentials run locally.
