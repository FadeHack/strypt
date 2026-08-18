# Project commands

Slash commands for repeated strypt workflows. **Empty during Phase 0** — there is no code to
operate on yet, and a command written before the workflow it automates exists would encode a
guess.

## Planned, once Phase 1 is underway

| Command | Purpose |
|---|---|
| `/new-format-handler <format>` | Scaffold a handler: module in `crates/strypt-core/src/formats/`, registry entry, unit test skeleton, fuzz target, corpus directory, and the `docs/THREAT_MODEL.md` reminder. The point is that the fuzz target and threat-model update cannot be forgotten — they are the steps most likely to be skipped under time pressure. |
| `/verify-strip <file>` | Run strypt, then check the output with ExifTool and mat2, and report any difference. The differential loop from `docs/TESTING_STRATEGY.md` §2.5 in one step. |
| `/fuzz <target>` | Bounded fuzz run with the project's standard flags, reporting new findings against known artefacts. |
| `/adr <title>` | Append a correctly-formatted ADR skeleton to `docs/DECISIONS.md` with the next sequential number. |

## Guidance for writing these

Write a command only after doing the task manually enough times to know the real steps. A
command that encodes a guessed workflow is worse than no command: it will be trusted and it
will be wrong.

Any command that scaffolds a format handler must include its fuzz target and corpus in the
same output — per `CLAUDE.md` §3, a handler without a fuzz target is not a complete handler.
