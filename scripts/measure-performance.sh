#!/usr/bin/env bash
# strypt — performance measurement (docs/PRD.md §9)
#
# PRD §9 carried order-of-magnitude intentions labelled as such: "startup under ~50 ms",
# "a typical 5 MB JPEG stripped in well under a second", "batches of thousands of files without
# unbounded memory growth". This script replaces guesses with numbers, and exists as a script
# rather than a one-off session so the numbers can be re-taken on other hardware and after any
# change that might move them.
#
# Two rules, because a benchmark that lies is worse than no benchmark:
#
#   1. It refuses to run against a debug binary. Debug Rust is often 10-50x slower, and a
#      number taken from one would understate the tool by an order of magnitude.
#   2. It warns when the machine is busy. Measuring while the fuzzers saturate several cores
#      produces numbers that are wrong in the pessimistic direction, which is the direction
#      nobody double-checks.
#
# Requires ImageMagick to synthesise realistically-sized inputs — a dev-time tool already used
# by real-producer-corpus/build_real_corpus.py, not a dependency of strypt itself.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/release/strypt}"
REPS=${REPS:-10}
BATCH=${BATCH:-1000}
WORK="${TMPDIR:-/tmp}/strypt-perf-$$"

command -v magick >/dev/null 2>&1 || { echo "error: ImageMagick (magick) is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }

if [ ! -x "$BIN" ]; then
  echo "error: no release binary at $BIN" >&2
  echo "       build it first: cargo build --release" >&2
  echo "       (a debug binary must never be used for these numbers)" >&2
  exit 2
fi

# Guard against publishing a number taken under load. 0.75 x cores is a deliberately generous
# threshold: some background noise is normal, several busy cores is not.
cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
load=$(uptime | sed 's/.*averages*: *//' | awk '{print $1}' | tr -d ',')
busy=$(awk -v l="$load" -v c="$cores" 'BEGIN{print (l > 0.75*c) ? 1 : 0}')

trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/batch"

echo "strypt performance measurement"
echo "  binary : $BIN ($(wc -c < "$BIN" | tr -d ' ') bytes)"
echo "  host   : $(uname -sm), ${cores} cores, load ${load}"
echo "  reps   : $REPS per case, batch of $BATCH"
[ "$busy" = "1" ] && echo "  WARNING: load is high relative to core count — numbers will be pessimistic."
echo

# --- inputs -----------------------------------------------------------------------------
# Sized to the claims in PRD §9 rather than to whatever is convenient: the JPEG is the ~5 MB
# case the PRD names. Fixtures in corpus/ are deliberately tiny and would measure nothing but
# process startup.
#
# Random noise, not a gradient. A gradient compresses to a few hundred KB at any pixel
# dimension, so a "3000x2000 JPEG" built from one is a 0.2 MB file — it would have measured
# process startup while appearing to measure a 5 MB image. Noise is incompressible and gives a
# file whose size is what it looks like.
magick -size 2600x1800 xc:gray +noise Random -quality 92 \
  -set exif:GPSLatitude "51/1 30/1 0/1" -set exif:Make "SYNTHETIC" \
  -set exif:Model "perf-fixture" "$WORK/big.jpg" 2>/dev/null
magick -size 1800x1200 xc:gray +noise Random "$WORK/big.png" 2>/dev/null
magick -size 1800x1200 xc:gray +noise Random "$WORK/big.webp" 2>/dev/null
cp "$REPO_ROOT/corpus/pdf/info-dictionary.pdf" "$WORK/small.pdf"

for i in $(seq 1 "$BATCH"); do cp "$REPO_ROOT/corpus/jpeg/exif-gps.jpg" "$WORK/batch/f$i.jpg"; done

# --- timing helper ----------------------------------------------------------------------
# Median, not mean: one scheduler hiccup should not move the reported number. Best is also
# reported because on a shared machine it is the closest thing to the uncontended truth.
time_it() {
  python3 - "$REPS" "$@" <<'PY'
import subprocess, sys, time, statistics
reps = int(sys.argv[1]); cmd = sys.argv[2:]
times = []
for _ in range(reps):
    t = time.perf_counter()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    times.append((time.perf_counter() - t) * 1000)
print(f"{statistics.median(times):.1f}\t{min(times):.1f}")
PY
}

size_of() { python3 -c "import os,sys;print(f'{os.path.getsize(sys.argv[1])/1048576:.1f} MB')" "$1"; }

printf "%-26s %10s %10s %10s\n" CASE INPUT "MEDIAN ms" "BEST ms"
printf -- "%.0s-" {1..60}; echo

read -r med best <<<"$(time_it "$BIN" --version)"
printf "%-26s %10s %10s %10s\n" "startup (--version)" "—" "$med" "$best"

read -r med best <<<"$(time_it "$BIN" show "$WORK/big.jpg")"
printf "%-26s %10s %10s %10s\n" "show JPEG" "$(size_of "$WORK/big.jpg")" "$med" "$best"

for f in big.jpg big.png big.webp small.pdf; do
  read -r med best <<<"$(time_it "$BIN" strip --force "$WORK/$f")"
  printf "%-26s %10s %10s %10s\n" "strip ${f##*.}" "$(size_of "$WORK/$f")" "$med" "$best"
done

# --- batch: wall time and peak memory ---------------------------------------------------
# The PRD's claim is about memory not growing without bound across a large batch, so peak RSS
# is the number that matters, not throughput.
echo
echo "Batch: $BATCH files, one process"
batch_failed() { echo "error: the batch failed, so its numbers measure nothing" >&2; exit 1; }
if /usr/bin/time -l true >/dev/null 2>&1; then
  /usr/bin/time -l "$BIN" strip --force "$WORK/batch" -r >/dev/null 2>"$WORK/time.txt" || batch_failed
  wall=$(awk '/real/{print $1}' "$WORK/time.txt" | head -1)
  rss=$(awk '/maximum resident set size/{printf "%.1f", $1/1048576}' "$WORK/time.txt")
  echo "  wall: ${wall}s   peak RSS: ${rss} MB   per file: $(python3 -c "print(f'{float('$wall')*1000/$BATCH:.2f} ms')")"
else
  /usr/bin/time -v "$BIN" strip --force "$WORK/batch" -r >/dev/null 2>"$WORK/time.txt" || batch_failed
  grep -E "Elapsed|Maximum resident" "$WORK/time.txt" | sed 's/^/  /'
fi

echo
[ "$busy" = "1" ] && echo "Reminder: taken under load — re-run on an idle machine before publishing."
exit 0
