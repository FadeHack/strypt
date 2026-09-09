#!/usr/bin/env python3
"""Per-handler fuzzing tally across every recorded run — Phase 3 deliverable 1 (ADR-0043).

Reads target/fuzz-runs/*/summary.md and reports, per target, CPU-hours banked since its last
substantive source change and whether its most recent run plateaued. That pair is ADR-0014's
bar, and this is the instrument its revision must be built on.

Two rules this encodes, both learned rather than assumed:

  * Hours count only since the handler's source last changed, shared modules included — a run
    against superseded code proves nothing about the code in the tree.
  * A plateau is read from the MOST RECENT run, never from "plateaued once". png and jpeg both
    plateaued inside eight hours and then climbed again on larger corpora (docs/ROADMAP.md).
"""

import collections
import datetime
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
RUNS = REPO / "target" / "fuzz-runs"
BASE = "crates/strypt-core/src/"

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

BUDGET_HOURS = 100  # ADR-0014, provisional and expected to be revised by this very report

ROW = re.compile(
    r"^\|\s*([a-z0-9]+)\s*\|\s*(\d+)\s*\|.*?\|\s*(\d+)s of (\d+)s\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|"
)
DATE = re.compile(r"^- Date:\s*(\S+)", re.M)


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
        stamp = DATE.search(text)
        if not stamp:
            continue
        when = datetime.datetime.fromisoformat(stamp.group(1).replace("Z", "+00:00"))
        # An aborted run's numbers describe a harness fault, not the handler (ROADMAP, 2026-08-26).
        aborted = "aborted" in run_dir.name.lower()
        for line in text.splitlines():
            match = ROW.match(line)
            if not match:
                continue
            target, _cov, gain, secs, plateau, crashes = match.groups()
            runs.append(
                dict(
                    target=target,
                    when=when,
                    gain=int(gain),
                    secs=int(secs),
                    plateau=plateau.strip().lower().startswith("yes"),
                    crashes=int(crashes),
                    aborted=aborted,
                )
            )
    return runs


def main():
    runs = collect()
    by_target = collections.defaultdict(list)
    for run in runs:
        by_target[run["target"]].append(run)

    print(
        f"{len(runs)} target-runs across "
        f"{len({(r['target'], r['when']) for r in runs})} recorded results, "
        f"{len(by_target)} targets.\n"
    )

    rows = []
    for target, all_runs in by_target.items():
        changed = last_change(target)
        current = [r for r in all_runs if not r["aborted"] and changed and r["when"] > changed]
        banked = sum(r["secs"] for r in current) / 3600
        latest = max(current, key=lambda r: r["when"], default=None)
        worst = max((r["gain"] / r["secs"] for r in current if r["secs"]), default=0.0)
        rows.append(
            dict(
                target=target,
                banked=banked,
                lifetime=sum(r["secs"] for r in all_runs if not r["aborted"]) / 3600,
                runs=len(current),
                plateau=bool(latest and latest["plateau"]),
                worst=worst,
                crashes=sum(r["crashes"] for r in all_runs if not r["aborted"]),
            )
        )

    print(f"{'target':9} {'CPU-h':>7} {'CPU-h':>7} {'runs':>5} {'latest':>7} {'last gain':>10}  verdict")
    print(f"{'':9} {'lifetime':>7} {'current':>7} {'now':>5} {'plateau':>7} {'(worst)':>10}")
    print("-" * 82)

    met, hours_only, no_plateau = [], [], []
    for row in sorted(rows, key=lambda r: (-r["worst"], r["target"])):
        owed = BUDGET_HOURS - row["banked"]
        if row["banked"] >= BUDGET_HOURS and row["plateau"]:
            verdict, bucket = "MEETS ADR-0014", met
        elif row["plateau"]:
            verdict, bucket = f"plateau yes, owes {owed:.0f}h", hours_only
        else:
            verdict, bucket = f"owes {owed:.0f}h AND plateau", no_plateau
        bucket.append(row["target"])
        print(
            f"{row['target']:9} {row['lifetime']:7.1f} {row['banked']:7.1f} {row['runs']:5} "
            f"{('yes' if row['plateau'] else 'NO'):>7} {row['worst'] * 100:9.1f}%  {verdict}"
        )

    print("\n" + "=" * 82)
    print(f"Meets ADR-0014 as written ({len(met)}): {' '.join(sorted(met)) or '(none)'}")
    print(f"Plateaued, short on hours ({len(hours_only)}): {' '.join(sorted(hours_only)) or '(none)'}")
    print(f"No plateau on current code ({len(no_plateau)}): {' '.join(sorted(no_plateau)) or '(none)'}")

    outstanding = sum(max(0.0, BUDGET_HOURS - r["banked"]) for r in rows)
    print(f"\nOutstanding under ADR-0014 as written: {outstanding:,.0f} CPU-hours.")
    print("Crashes in the record are historical and each carries a regression test; a new one")
    print("is a Phase 3 deliverable-3 finding. Totals here are not a substitute for reading")
    print(f"the run's own summary.md. Crash rows seen: {sum(r['crashes'] for r in rows)}.")


if __name__ == "__main__":
    main()
