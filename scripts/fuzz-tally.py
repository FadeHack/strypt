#!/usr/bin/env python3
"""Per-handler fuzzing certification under ADR-0044 — Phase 3 deliverable 1.

Reads fuzz-runs/*/summary.md and each run's cov-<target>.tsv. A handler certifies on its
most recent complete run of at least 24 hours, since its sources last changed, whose curve
fuzz-plateau.py classifies saturated.

Two rules this encodes, both learned rather than assumed:

  * A run counts only if it postdates the handler's last source change, shared modules included —
    a run against superseded code proves nothing about the code in the tree.
  * The most recent qualifying run decides, never "saturated once". png and jpeg both plateaued
    inside eight hours and then climbed again on larger corpora (docs/ROADMAP.md).
"""

import collections
import datetime
import importlib.util
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
RUNS = REPO / "fuzz-runs"
BASE = "crates/strypt-core/src/"

_spec = importlib.util.spec_from_file_location("plateau", REPO / "scripts" / "fuzz-plateau.py")
plateau = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plateau)

# Target -> the sources whose change resets its clock. Shared modules are listed against every
# target that reaches them, which is what makes container/package.rs reset odf and ooxml.
SRC = {
    "pdf": ["formats/pdf.rs"],
    "jpeg": ["formats/jpeg.rs"],
    "png": ["formats/png.rs"],
    "webp": ["formats/webp.rs", "container/riff.rs"],
    "tiff": ["formats/tiff.rs"],
    "gif": ["formats/gif.rs"],
    "heif": ["formats/heif.rs", "container/bmff.rs"],
    "bmff": ["container/bmff.rs"],
    "svg": ["formats/svg.rs"],
    "jxl": ["formats/jxl.rs"],
    "flac": ["formats/flac.rs", "formats/tags.rs", "formats/vorbis.rs"],
    "wav": ["formats/wav.rs", "container/riff.rs"],
    "riff": ["container/riff.rs"],
    "mp3": ["formats/mp3.rs", "formats/tags.rs"],
    "tags": ["formats/tags.rs"],
    "ogg": ["formats/ogg.rs", "container/ogg.rs", "formats/vorbis.rs"],
    "oggpage": ["container/ogg.rs"],
    "mp4": ["formats/mp4.rs", "formats/mp4/boxes.rs"],
    "ooxml": ["formats/ooxml.rs", "container/zip.rs", "container/package.rs"],
    "odf": ["formats/odf.rs", "container/zip.rs", "container/package.rs"],
    "zip": ["container/zip.rs"],
    "detect": ["detect.rs"],
}

MIN_SECONDS = 24 * 3600  # ADR-0044 decision 3

ROW = re.compile(r"^\|\s*([a-z0-9]+)\s*\|\s*(\d+)\s*\|.*?\|\s*(\d+)s of (\d+)s\s*\|[^|]*\|\s*(\d+)\s*\|")
DATE = re.compile(r"^- Date:\s*(\S+)", re.M)
DURATION = re.compile(r"^- Duration:\s*(\d+)s", re.M)


def last_change(target):
    newest = None
    for rel in SRC.get(target, []):
        path = BASE + rel
        if not (REPO / path).exists():
            continue
        out = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", path],
            cwd=REPO,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if out:
            when = datetime.datetime.fromisoformat(out)
            if newest is None or when > newest:
                newest = when
    return newest


def collect():
    runs = []
    if not RUNS.is_dir():
        sys.exit(f"no runs found at {RUNS}")
    for run_dir in sorted(RUNS.iterdir()):
        summary = run_dir / "summary.md"
        if not summary.is_file():
            continue
        text = summary.read_text(errors="replace")
        stamp, duration = DATE.search(text), DURATION.search(text)
        if not (stamp and duration):
            continue
        when = datetime.datetime.fromisoformat(stamp.group(1).replace("Z", "+00:00"))
        # An aborted run's numbers describe a harness fault, not the handler (ROADMAP, 2026-08-26).
        aborted = "aborted" in run_dir.name.lower()
        for line in text.splitlines():
            match = ROW.match(line)
            if not match:
                continue
            target, _cov, _gain, secs, crashes = match.groups()
            runs.append(
                dict(
                    target=target,
                    when=when,
                    secs=int(secs),
                    duration=int(duration.group(1)),
                    crashes=int(crashes),
                    aborted=aborted,
                    tsv=run_dir / f"cov-{target}.tsv",
                )
            )
    return runs


def main():
    by_target = collections.defaultdict(list)
    for run in collect():
        by_target[run["target"]].append(run)

    print(f"{'target':9} {'CPU-h':>7}  {'deciding run':16} verdict")
    print(f"{'':9} {'current':>7}")
    print("-" * 78)

    certified, owed, punctuated = [], [], []
    for target in sorted(by_target):
        changed = last_change(target)
        current = [
            r for r in by_target[target] if not r["aborted"] and changed and r["when"] > changed
        ]
        banked = sum(r["secs"] for r in current) / 3600
        # The runner's own completeness guard: a run killed early cannot answer the question.
        qualifying = [
            r
            for r in current
            if r["duration"] >= MIN_SECONDS and r["secs"] >= 0.9 * r["duration"] and r["tsv"].is_file()
        ]
        deciding = max(qualifying, key=lambda r: r["when"], default=None)
        if deciding is None:
            verdict, where = "owes a 24h run", "—"
            owed.append(target)
        else:
            verdict = plateau.verdict_for(deciding["tsv"], deciding["duration"])
            where = f"{deciding['when']:%Y-%m-%d} {deciding['duration'] // 3600}h"
            (certified if verdict == "saturated" else punctuated).append(target)
            verdict = "CERTIFIED" if verdict == "saturated" else verdict
        print(f"{target:9} {banked:7.1f}  {where:16} {verdict}")

    print("\n" + "=" * 78)
    print(f"Certified under ADR-0044 ({len(certified)}): {' '.join(certified) or '(none)'}")
    print(f"Owe a 24h run ({len(owed)}): {' '.join(owed) or '(none)'}")
    print(f"Punctuated on their deciding run ({len(punctuated)}): {' '.join(punctuated) or '(none)'}")
    print(f"\nOutstanding: {24 * len(owed)} CPU-hours for the targets owing a run. A punctuated target")
    print("is not owed hours — ADR-0044 decision 5 says more hours are not its remedy.")
    crashes = sum(r["crashes"] for runs in by_target.values() for r in runs if not r["aborted"])
    print(f"Crash rows in the record: {crashes}. Each is historical and carries a regression test;")
    print("a new one is a Phase 3 deliverable-3 finding.")


if __name__ == "__main__":
    main()
