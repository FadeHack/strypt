# Seed corpora

The **curated** starting inputs for each fuzz target, committed as part of the test suite.

Keep this separate from `../corpus/`, which is where libFuzzer accumulates its own inputs
while running. That directory reaches thousands of machine-generated files within minutes, and
git history is forever — so it is ignored, and only what a human chose lives here.

- `pdf/` — copies of `corpus/pdf/`, the documented fixtures. Refresh after regenerating them.
- `detect/` — one specimen of every signature the detector knows, plus an empty file and a
  plain-text file. Coverage-guided fuzzing explores outward from what it is given, so the
  seeds decide which regions it can reach at all.

**A crashing input found by fuzzing gets committed too** — but deliberately, as a regression
fixture with a test naming it, never by leaving the working corpus tracked
(`docs/TESTING_STRATEGY.md` §2.6).
