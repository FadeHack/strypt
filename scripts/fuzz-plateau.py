#!/usr/bin/env python3
"""Classify a coverage curve as saturated or punctuated — ADR-0044's plateau test.

Reads target/fuzz-runs/*/cov-<target>.tsv and splits each run into six equal windows. Window 1
is initial exploration and is never tested. A run is PUNCTUATED if any later window's gain both
exceeds 1% of final coverage and at least doubles its predecessor; otherwise it is SATURATED if
the final window's gain is under 1% of final coverage.

The 1% floor is what keeps a +17 on a 2229-edge corpus from reading as a breakthrough. Without
it the doubling test fires on noise, because a window that gained 0 doubles to anything.

Why windows rather than ADR-0014's "no new edge in the final 25%": pdf's 48h run found one edge
at 47h07m after being flat since 12h, which the old rule failed and this one passes. ogg's went
flat for 32 hours and then gained 140 in one window, which the old rule would have passed at 24h.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
RUNS = REPO / "target" / "fuzz-runs"
WINDOWS = 6
MATERIAL = 0.01  # of final coverage; both the breakthrough floor and the saturation ceiling


def gains(points, duration):
    width = duration / WINDOWS
    out = []
    for i in range(WINDOWS):
        start = max([c for e, c in points if e <= i * width], default=points[0][1])
        end = max([c for e, c in points if e <= (i + 1) * width], default=start)
        out.append(end - start)
    return out


def classify(windows, total):
    floor = MATERIAL * total
    breaks = [
        i + 1
        for i in range(2, WINDOWS)
        if windows[i] > floor and windows[i] >= 2 * max(windows[i - 1], 1)
    ]
    if breaks:
        return "PUNCTUATED w" + ",".join(str(b) for b in breaks)
    return "saturated" if windows[-1] < floor else "climbing"


def curves():
    if not RUNS.is_dir():
        sys.exit(f"no runs found at {RUNS}")
    for run in sorted(RUNS.iterdir()):
        summary = run / "summary.md"
        if not summary.is_file():
            continue
        text = summary.read_text(errors="replace")
        date = re.search(r"^- Date:\s*(\S+)", text, re.M)
        duration = re.search(r"^- Duration:\s*(\d+)s", text, re.M)
        if not (date and duration) or int(duration.group(1)) < 3600:
            continue
        for tsv in sorted(run.glob("cov-*.tsv")):
            points = [
                (int(a), int(b))
                for a, b in (
                    line.split("\t")
                    for line in tsv.read_text().splitlines()
                    if line.count("\t") == 1
                )
                if a.isdigit()
            ]
            if points:
                yield tsv.stem[4:], date.group(1)[:10], int(duration.group(1)), points


def main():
    only = sys.argv[1:]
    rows = []
    for target, date, duration, points in curves():
        if only and target not in only:
            continue
        window = gains(points, duration)
        rows.append((target, date, duration // 3600, points[-1][1], window,
                     classify(window, points[-1][1])))

    if not rows:
        sys.exit("no curves matched")

    rows.sort(key=lambda r: (r[0], r[1]))
    print(f"{'target':9}{'date':12}{'h':>3}{'cov':>6}   {'six equal windows':^35} verdict")
    for target, date, hours, cov, window, verdict in rows:
        cells = " ".join(f"{g:>5}" for g in window)
        print(f"{target:9}{date:12}{hours:3}{cov:6}   {cells}   {verdict}")

    print()
    for label in ("PUNCTUATED", "climbing", "saturated"):
        hit = sorted({r[0] for r in rows if r[5].startswith(label)})
        print(f"{label:11} ({len(hit)}): {' '.join(hit) or '(none)'}")

    # ADR-0044 certifies on a run of at least 24h that classifies saturated.
    long_runs = [r for r in rows if r[2] >= 24]
    certified = sorted({r[0] for r in long_runs if r[5] == "saturated"})
    blocked = sorted({r[0] for r in long_runs} - set(certified))
    print(f"\nCertified under ADR-0044 ({len(certified)}): {' '.join(certified) or '(none)'}")
    print(f"Punctuated at 24h or longer ({len(blocked)}): {' '.join(blocked) or '(none)'}")


if __name__ == "__main__":
    main()
