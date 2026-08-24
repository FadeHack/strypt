# Seed corpora

The **curated** starting inputs for each fuzz target, committed as part of the test suite.

Keep this separate from `../corpus/`, which is where libFuzzer accumulates its own inputs
while running. That directory reaches thousands of machine-generated files within minutes, and
git history is forever — so it is ignored, and only what a human chose lives here.

- `pdf/` — copies of `corpus/pdf/`, the documented fixtures. Refresh after regenerating them.
- `jpeg/` — copies of `corpus/jpeg/`, valid and malformed alike. Refresh after regenerating
  them.
- `png/` — copies of `corpus/png/`, valid and malformed alike. Refresh after regenerating
  them.
- `webp/` — copies of `corpus/webp/`, valid and malformed alike. Refresh after regenerating
  them.
- `ooxml/` — copies of `corpus/ooxml/`, valid and malformed alike. Refresh after regenerating
  them.
- `odf/` — copies of `corpus/odf/`, valid and malformed alike. Refresh after regenerating them.
- `zip/` — the same OOXML and ODF packages, seeding the container target rather than either
  handler. Deliberately the same files: the ZIP target's job is to explore *outward* from a real
  archive into malformed ones, and a container fuzzer seeded only with hand-written stubs never
  reaches the structures a real producer writes. The ODF packages add a shape no OOXML package
  has — a stored first entry followed by deflated ones.
- `detect/` — one specimen of every signature the detector knows, plus an empty file and a
  plain-text file. Coverage-guided fuzzing explores outward from what it is given, so the
  seeds decide which regions it can reach at all.

**A crashing input found by fuzzing gets committed too** — but deliberately, as a regression
fixture with a test naming it, never by leaving the working corpus tracked
(`docs/TESTING_STRATEGY.md` §2.6).
