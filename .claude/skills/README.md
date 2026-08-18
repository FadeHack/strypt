# Project skills

Project-specific skills for strypt. **Deliberately empty during Phase 0.**

A skill encodes hard-won knowledge about how to do something correctly in this codebase.
There is no codebase yet, so there is no such knowledge — anything written here now would be
speculation dressed up as expertise, which is precisely the failure mode this project's
documentation standards exist to prevent.

## Candidates, once there is real implementation experience

- **Adding a format handler correctly** — the full path: trait implementation, the invariants
  from `docs/ARCHITECTURE.md` §3, registry wiring, fuzz target, seed corpus, differential
  verification, threat-model update. Write this after the *second* handler, not the first:
  one handler teaches you the steps, two teach you which parts generalise.
- **Writing a fuzz target for a new parser** — structure-aware fuzzing with `Arbitrary`,
  what to assert beyond "did not crash", how to build a seed corpus that reaches deep paths.
- **Triaging a metadata-leak report** — the process from `SECURITY.md`: reproduce, assess
  severity, write the regression test first, then fix, then write a disclosure that tells
  users whether files they already published are affected.
- **Auditing a candidate dependency** — the checks behind ADR-0008: maintenance status,
  licence compatibility, transitive dependency count, `unsafe` usage, advisory history.

## Rule

Write a skill from experience, never from anticipation. If you cannot point at the commits
where you learned the lesson, the skill is not ready.
