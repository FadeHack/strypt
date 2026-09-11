#!/usr/bin/env bash
# strypt — sustained fuzzing runner
#
# This script serves TWO DIFFERENT BARS IN TWO DIFFERENT PHASES. Do not conflate them; an
# earlier version of this header did, and it led to Phase 1 being assessed against a Phase 3
# number.
#
#   Phase 1, exit criterion 2 — "Zero panics, crashes, hangs, or OOMs across all four fuzz
#   targets after a sustained run — no known-failing input set aside as 'not worth fixing'."
#   That is the whole criterion. It names no CPU-hour figure and requires no plateau. What
#   satisfies it is a sustained run that produces NO CRASH ARTEFACT. This script's exit code
#   answers it directly: exit 0 means criterion 2 held for the targets that ran.
#
#   Phase 3, ADR-0044 — a complete run of at least 24 hours whose coverage curve classifies
#   saturated under scripts/fuzz-plateau.py. The `plateau` column and the coverage curves exist
#   for THIS bar; scripts/fuzz-tally.py decides certification across runs. Summaries written
#   before 2026-09-11 print ADR-0014's superseded rule in that column instead.
#
# The 300-second commands in INSTRUCTIONS.md are smoke tests: they prove a target still builds
# and runs. They satisfy neither bar.
#
# Every log line is prefixed with elapsed seconds so coverage can be plotted against time.
# This is the whole point of the run; without it there is no plateau evidence, only a
# duration.
#
# Exit 0 = every target ran to completion with no crash artefact.
# Exit 1 = at least one target crashed, hung, or OOMed. Inputs land in fuzz/artifacts/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/crates/strypt-core/fuzz"
ALL_TARGETS=(pdf jpeg png webp tiff gif heif bmff svg jxl flac wav mp3 tags ogg oggpage mp4 riff ooxml odf zip detect)

DURATION=7200
OUT_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/fuzz-sustained.sh [-d SECONDS] [-o OUTDIR] [target ...]

  -d SECONDS  wall-clock seconds per target (default 7200 = 2h)
  -o OUTDIR   where to write logs (default target/fuzz-runs/<timestamp>)

Targets default to all twenty-two: pdf jpeg png webp tiff gif heif bmff svg jxl flac wav mp3 tags ogg oggpage mp4 riff ooxml odf zip detect

Targets run in PARALLEL, one process each, so wall time is SECONDS regardless of how many
targets are selected — but CPU-hours are SECONDS x TARGETS. Budget accordingly.

Examples:
  scripts/fuzz-sustained.sh -d 300                 # smoke test, all twenty-two
  scripts/fuzz-sustained.sh -d 28800 pdf           # 8h on PDF alone
  scripts/fuzz-sustained.sh -d 14400 png webp      # 4h each, in parallel

Stopping early is safe and loses nothing but the remaining time: the corpus is written to
disk as it is discovered, so the next run resumes from it rather than starting over.
EOF
}

while getopts ":d:o:h" opt; do
  case "$opt" in
    d) DURATION="$OPTARG" ;;
    o) OUT_DIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "error: -$OPTARG requires an argument" >&2; exit 2 ;;
    \?) echo "error: unknown option -$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -lt 1 ]; then
  echo "error: -d must be a positive integer number of seconds" >&2
  exit 2
fi

TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=("${ALL_TARGETS[@]}")

for t in "${TARGETS[@]}"; do
  case " ${ALL_TARGETS[*]} " in
    *" $t "*) ;;
    *) echo "error: unknown target '$t' (have: ${ALL_TARGETS[*]})" >&2; exit 2 ;;
  esac
done

# cargo-fuzz needs nightly, and is unsupported on Windows (INSTRUCTIONS.md).
command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found" >&2; exit 2; }
rustup toolchain list 2>/dev/null | grep -q '^nightly' \
  || { echo "error: rust nightly is required (rustup toolchain install nightly)" >&2; exit 2; }
cargo +nightly fuzz --version >/dev/null 2>&1 \
  || { echo "error: cargo-fuzz not installed (cargo install cargo-fuzz)" >&2; exit 2; }
command -v perl >/dev/null 2>&1 || { echo "error: perl is required for log timestamping" >&2; exit 2; }

[ -n "$OUT_DIR" ] || OUT_DIR="$REPO_ROOT/target/fuzz-runs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_DIR"
# Resolve to an absolute path. This script cd's to the fuzz directory below, so a relative -o
# — `-o target/fuzz-runs/tonight`, the obvious thing to type from the repo root — would be
# created here and then written to somewhere else entirely, killing the run at its first
# redirect.
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

# libFuzzer writes discoveries to the FIRST directory given and only reads the rest, so the
# working corpus must come first and the committed seeds after. WebP carries a second seed
# directory; see INSTRUCTIONS.md.
corpus_args() {
  case "$1" in
    webp) echo "corpus/webp seeds/webp seeds/webp/malformed" ;;
    tiff) echo "corpus/tiff seeds/tiff seeds/tiff/malformed" ;;
    gif)  echo "corpus/gif seeds/gif seeds/gif/malformed" ;;
    heif) echo "corpus/heif seeds/heif seeds/heif/malformed" ;;
    svg)  echo "corpus/svg seeds/svg seeds/svg/malformed" ;;
    jxl)  echo "corpus/jxl seeds/jxl seeds/jxl/malformed" ;;
    flac) echo "corpus/flac seeds/flac seeds/flac/malformed" ;;
    wav)  echo "corpus/wav seeds/wav seeds/wav/malformed" ;;
    mp3)  echo "corpus/mp3 seeds/mp3 seeds/mp3/malformed" ;;
    ogg)  echo "corpus/ogg seeds/ogg seeds/ogg/malformed" ;;
    oggpage) echo "corpus/oggpage seeds/oggpage seeds/oggpage/malformed" ;;
    *)    echo "corpus/$1 seeds/$1" ;;
  esac
}

cd "$FUZZ_DIR"
for t in "${TARGETS[@]}"; do mkdir -p "corpus/$t"; done

# Count only artefacts THIS run produced. artifacts/ is not cleared between runs, so counting
# every file there would report a crash fixed and triaged months ago as a fresh failure — and
# a runner that cries wolf is one whose next real finding gets waved through.
RUN_MARKER="$OUT_DIR/.started"
: > "$RUN_MARKER"
new_artifacts() {
  [ -d "$FUZZ_DIR/artifacts/$1" ] || { echo 0; return; }
  find "$FUZZ_DIR/artifacts/$1" -type f -newer "$RUN_MARKER" | wc -l | tr -d ' '
}

echo "strypt sustained fuzzing"
echo "  targets   : ${TARGETS[*]}"
echo "  duration  : ${DURATION}s per target, in parallel"
echo "  cpu-hours : $(awk -v d="$DURATION" -v n="${#TARGETS[@]}" 'BEGIN{printf "%.2f", d*n/3600}') budgeted"
echo "  logs      : $OUT_DIR"
echo

pids=()
for t in "${TARGETS[@]}"; do
  # shellcheck disable=SC2046  # deliberate word splitting: corpus_args returns a path list
  (
    start=$(date +%s)
    cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$t" $(corpus_args "$t") -- \
        -max_total_time="$DURATION" -print_final_stats=1 2>&1 \
      | perl -ne 'BEGIN{$|=1; $s=shift} printf "%d %s", time()-$s, $_' "$start" \
      > "$OUT_DIR/$t.log"
  ) &
  pids+=("$!")
done

# Do not let one target's failure abort the wait; every target's result is wanted.
failed=0
for i in "${!pids[@]}"; do
  wait "${pids[$i]}" || { echo "target ${TARGETS[$i]} exited non-zero" >&2; failed=1; }
done

# ---------------------------------------------------------------------------
# Analysis. Two questions per target: where did coverage end up, and had it stopped
# climbing? The second is ADR-0044's plateau test and is the reason for the timestamps.
# It is PHASE 3 evidence — Phase 1 criterion 2 is answered by the crash count alone.
# ---------------------------------------------------------------------------
# Per-target coverage curve, thinned to the points where coverage actually moved. Written
# before the summary, because the plateau column is read from it.
for t in "${TARGETS[@]}"; do
  awk '{ for (i=1;i<=NF;i++) if ($i=="cov:" && $(i+1)+0 > last) { last=$(i+1)+0; print $1 "\t" last } }' \
    "$OUT_DIR/$t.log" > "$OUT_DIR/cov-$t.tsv"
done

# Budgeted CPU-hours are what was asked for; DELIVERED is what the targets actually ran. They
# differ whenever a target stops early on a crash, so reporting the budget as though it were
# delivered would credit the run with time it never spent. Sum each log's largest
# elapsed-second prefix instead.
delivered_cpu_hours() {
  for t in "${TARGETS[@]}"; do
    awk '$1+0 > m { m = $1+0 } END { print m+0 }' "$OUT_DIR/$t.log"
  done | awk '{ s += $1 } END { printf "%.2f", s/3600 }'
}

{
  echo "# Sustained fuzzing run"
  echo
  echo "- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Duration: ${DURATION}s per target (parallel)"
  echo "- Targets: ${TARGETS[*]}"
  echo "- CPU-hours budgeted: $(awk -v d="$DURATION" -v n="${#TARGETS[@]}" 'BEGIN{printf "%.2f", d*n/3600}')"
  echo "- CPU-hours delivered: $(delivered_cpu_hours)"
  echo
  echo "| target | cov | ft | corpus | exec/s | last cov gain | plateau (ADR-0044) | crashes |"
  echo "|---|---|---|---|---|---|---|---|"
  for t in "${TARGETS[@]}"; do
    artifacts=$(new_artifacts "$t")
    awk -v t="$t" -v dur="$DURATION" -v art="$artifacts" \
        -v classify="python3 '$REPO_ROOT/scripts/fuzz-plateau.py' --verdict '$OUT_DIR/cov-$t.tsv' $DURATION" '
      # Track the last elapsed time at which cov increased, and the final values seen.
      {
        for (i = 1; i <= NF; i++) {
          if ($i == "cov:")   { c = $(i+1); if (c > maxcov) { maxcov = c; lastgain = $1 } }
          if ($i == "ft:")     ft = $(i+1)
          if ($i == "corp:")   cp = $(i+1)
        }
        if ($0 ~ /average_exec_per_sec/) eps = $NF
        if ($1 > tmax) tmax = $1
      }
      END {
        if (tmax == 0) { printf "| %s | — | — | — | — | — | no data | %s |\n", t, art; exit }
        # Only meaningful over a run that actually finished. A target killed early by a crash
        # is measured against the truncated length, so a short run trivially "plateaus": PDF
        # died at 2834s on 2026-08-21 with its last gain at 1912s and this column said "yes",
        # which was read as evidence and was not. Refuse to answer rather than mislead.
        if (tmax < 0.9 * dur)
          plateau = "n/a — ran " int(tmax) "s of " int(dur) "s"
        else {
          plateau = "classifier failed"
          classify | getline plateau
          close(classify)
        }
        printf "| %s | %s | %s | %s | %s | %ds of %ds | %s | %s |\n",
               t, maxcov, ft, cp, (eps == "" ? "—" : eps), lastgain, tmax, plateau, art
      }
    ' "$OUT_DIR/$t.log"
  done
  echo
  echo "Coverage curves: cov-<target>.tsv (elapsed_seconds<TAB>cov), one row per increase."
  echo
  echo "The 'crashes' column answers ROADMAP Phase 1 exit criterion 2: zero across every"
  echo "handler after a sustained run, with nothing set aside as not worth fixing. Criterion 2"
  echo "was written when there were four targets; there are now twenty-two. The ooxml and zip"
  echo "targets cleared their sustained-run debt on 2026-08-24, odf and pdf cleared theirs on"
  echo "2026-08-25, tiff and detect cleared theirs on 2026-08-26, and gif cleared its on"
  echo "2026-08-27. The same run put pdf, jpeg, png and webp — the four the criterion actually"
  echo "names — clean in a single run for the first time, which closed the standing caveat that"
  echo "criterion 2 rested on one run plus standing evidence for the rest."
  echo "heif, bmff and detect cleared theirs on 2026-08-27 as well, svg on 2026-08-29, and jxl"
  echo "on 2026-08-30, flac on 2026-09-01, and wav and riff on 2026-09-02 — that run took webp"
  echo "with them, because ADR-0039 moved its chunk walk into shared code. mp3 and tags cleared"
  echo "theirs on 2026-09-03 — that run took flac and detect with them, because ADR-0040 put an"
  echo "ID3 reader in front of both. ogg and oggpage cleared theirs on 2026-09-04 — that run"
  echo "took flac again, because ADR-0041 shares its Vorbis comment reader. mp4 cleared its on"
  echo "2026-09-05 — that run took bmff and heif with it, because ADR-0042 extended the"
  echo "shared ISO-BMFF walk."
  echo "Every target now stands on a clean sustained run. A new"
  echo "handler adds its own debt, so update this paragraph when one lands rather than leaving"
  echo "it to read as blanket coverage."
  echo
  echo "The 'plateau' column is ADR-0044's curve test (scripts/fuzz-plateau.py) and is Phase 3"
  echo "evidence, not a Phase 1 gate. 'PUNCTUATED' means coverage broke through late, so a flat"
  echo "tail cannot be trusted; it does not mean the run failed. An 'n/a' means the target ended"
  echo "early, so the question cannot be answered from this run. Whether a handler certifies"
  echo "is scripts/fuzz-tally.py's answer, across runs, not this column's."
} > "$OUT_DIR/summary.md"

cat "$OUT_DIR/summary.md"

total_artifacts=0
for t in "${TARGETS[@]}"; do
  total_artifacts=$((total_artifacts + $(new_artifacts "$t")))
done
rm -f "$RUN_MARKER"

if [ "$total_artifacts" -gt 0 ]; then
  echo
  echo "FAIL: $total_artifacts crash artefact(s) in $FUZZ_DIR/artifacts/." >&2
  echo "Reproduce with: cargo +nightly fuzz run <target> artifacts/<target>/<file>" >&2
  echo "Every one needs a fix AND a regression test before this criterion is met (CLAUDE.md §9)." >&2
  exit 1
fi

exit "$failed"
