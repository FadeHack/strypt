#!/usr/bin/env python3
"""Render docs/assets/demo.svg from the real binary run on a committed synthetic fixture.

Re-run whenever the CLI's output changes, so the README never shows output strypt does not
print. Both README images are then stripped by strypt itself (ROADMAP Phase 4).
"""

import html
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
BIN = REPO / "target" / "release" / "strypt"
FIXTURE = REPO / "corpus" / "jpeg" / "exif-gps.jpg"
ASSETS = REPO / "docs" / "assets"
STEPS = [(["strip", "photo.jpg"], 0), (["show", "photo.stripped.jpg"], 0)]

FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"
SIZE, CHAR, LINE, PAD, BAR = 14, 8.43, 20, 24, 36


def session(tmp):
    shutil.copy(FIXTURE, tmp / "photo.jpg")
    lines = []
    for args, want in STEPS:
        run = subprocess.run([BIN, *args], cwd=tmp, capture_output=True, text=True)
        if run.returncode != want:
            sys.exit(f"strypt {' '.join(args)} exited {run.returncode}, expected {want}")
        out = (run.stdout + run.stderr).rstrip("\n")
        # The image is published; a tool quoting a path would put this machine into it.
        if str(tmp) in out or "/Users/" in out or "/home/" in out:
            sys.exit("output contains a local path; refusing to render")
        lines += [("cmd", "strypt " + " ".join(args))] + [("out", l) for l in out.splitlines()]
        lines.append(("out", ""))
    return lines[:-1]


def svg(lines):
    width = round(PAD * 2 + CHAR * max(len(t) + 2 for _, t in lines))
    height = BAR + PAD + LINE * len(lines) + PAD - 6
    rows = []
    for i, (kind, text) in enumerate(lines):
        y = BAR + PAD + LINE * i + SIZE - 2
        t = html.escape(text)
        if kind == "cmd":
            rows.append(f'<text x="{PAD}" y="{y}"><tspan fill="#7ee787">$</tspan> '
                        f'<tspan fill="#f0f6fc" font-weight="600">{t}</tspan></text>')
        elif t:
            rows.append(f'<text x="{PAD}" y="{y}">{t}</text>')
    removed = sum(t.lstrip().startswith("removed ") for _, t in lines)
    dots = "".join(f'<circle cx="{20 + 18 * i}" cy="18" r="6" fill="{c}"/>'
                   for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="t">\n'
        f'<title id="t">strypt strip removes {removed} metadata fields from a photo, '
        f'and strypt show then finds none</title>\n'
        f'<rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>\n'
        f'<rect width="{width}" height="{BAR}" rx="10" fill="#161b22"/>'
        f'<rect y="{BAR - 10}" width="{width}" height="10" fill="#161b22"/>{dots}\n'
        f'<g font-family="{FONT}" font-size="{SIZE}" fill="#c9d1d9" xml:space="preserve">\n'
        + "\n".join(rows) + "\n</g>\n</svg>\n"
    )


def main():
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "strypt"], cwd=REPO, check=True)
    with tempfile.TemporaryDirectory() as tmp:
        lines = session(pathlib.Path(tmp).resolve())
    (ASSETS / "demo.svg").write_text(svg(lines))
    for name in ("banner.svg", "demo.svg"):
        subprocess.run([BIN, "strip", "--in-place", ASSETS / name], check=True,
                       stdout=subprocess.DEVNULL)
    print(f"wrote {ASSETS / 'demo.svg'}; stripped banner.svg and demo.svg")


if __name__ == "__main__":
    main()
