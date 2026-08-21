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
#   Phase 3, ADR-0014 — a per-handler CPU-hour budget AND a coverage plateau (no new edge
#   coverage in the final 25% of the run), both required, because CPU-hours alone can be burned
#   on a target that stopped exploring long ago and a plateau alone can mean a harness too
#   narrow to reach anything new. The `plateau` column and the coverage curves exist for THIS
#   bar. They are Phase 3 evidence and are not needed to leave Phase 1.
#
# The 300-second commands in INSTRUCTIONS.md are smoke tests: they prove a target still builds
# and runs. They satisfy neither bar.
#
# ADR-0014's 100 CPU-hours per handler is explicitly PROVISIONAL: it was written before any
# parser existed, and the ADR itself says it is a hypothesis to revise once real coverage data
# exists. That data is what this script produces. Run it, read the curves, then supersede
# ADR-0014 with measured per-handler numbers — the handlers differ by more than an order of
# magnitude in both state space and throughput, so one flat number for all five is very
# unlikely to be the right answer.
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
ALL_TARGETS=(pdf jpeg png webp detect)

DURATION=7200
OUT_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/fuzz-sustained.sh [-d SECONDS] [-o OUTDIR] [target ...]

  -d SECONDS  wall-clock seconds per target (default 7200 = 2h)
  -o OUTDIR   where to write logs (default target/fuzz-runs/<timestamp>)

Targets default to all five: pdf jpeg png webp detect

Targets run in PARALLEL, one process each, so wall time is SECONDS regardless of how many
targets are selected — but CPU-hours are SECONDS x TARGETS. Budget accordingly.

Examples:
  scripts/fuzz-sustained.sh -d 300                 # smoke test, all five
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

# libFuzzer writes discoveries to the FIRST directory given and only reads the rest, so the
# working corpus must come first and the committed seeds after. WebP carries a second seed
# directory; see INSTRUCTIONS.md.
corpus_args() {
  case "$1" in
    webp) echo "corpus/webp seeds/webp seeds/webp/malformed" ;;
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
# climbing? The second is ADR-0014's plateau condition and is the reason for the timestamps.
# It is PHASE 3 evidence — Phase 1 criterion 2 is answered by the crash count alone.
# ---------------------------------------------------------------------------
# Budgeted CPU-hours are what was asked for; DELIVERED is what the targets actually ran. They
# differ whenever a target stops early on a crash — and ADR-0014's exit criterion is stated in
# CPU-hours, so reporting the budget as though it were delivered would credit the run with time
# it never spent. Sum each log's largest elapsed-second prefix instead.
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
  echo "| target | cov | ft | corpus | exec/s | last cov gain | plateau (ADR-0014) | crashes |"
  echo "|---|---|---|---|---|---|---|---|"
  for t in "${TARGETS[@]}"; do
    artifacts=$(new_artifacts "$t")
    awk -v t="$t" -v dur="$DURATION" -v art="$artifacts" '
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
        # Plateau: no new edge coverage in the final 25% of the run (ADR-0014, Phase 3).
        #
        # Only meaningful over a run that actually finished. A target killed early by a crash
        # is measured against the truncated length, so a short run trivially "plateaus": PDF
        # died at 2834s on 2026-08-21 with its last gain at 1912s and this column said "yes",
        # which was read as evidence and was not. Refuse to answer rather than mislead.
        if (tmax < 0.9 * dur)
          plateau = "n/a — ran " int(tmax) "s of " int(dur) "s"
        else
          plateau = (lastgain < 0.75 * tmax) ? "yes" : "NO — still climbing"
        printf "| %s | %s | %s | %s | %s | %ds of %ds | %s | %s |\n",
               t, maxcov, ft, cp, (eps == "" ? "—" : eps), lastgain, tmax, plateau, art
      }
    ' "$OUT_DIR/$t.log"
  done
  echo
  echo "Coverage curves: cov-<target>.tsv (elapsed_seconds<TAB>cov), one row per increase."
  echo
  echo "The 'crashes' column answers ROADMAP Phase 1 exit criterion 2: zero across all four"
  echo "handlers after a sustained run, with nothing set aside as not worth fixing. Nothing"
  echo "else in this table is needed to leave Phase 1."
  echo
  echo "The 'plateau' column is Phase 3 evidence for ADR-0014 and is not a Phase 1 gate. A"
  echo "'NO — still climbing' means this target needs a longer run before its number can be"
  echo "set; it does not mean the run failed. An 'n/a' means the target ended early, so the"
  echo "question cannot be answered from this run at all — do not read it as either result."
} > "$OUT_DIR/summary.md"

# Per-target coverage curve, thinned to the points where coverage actually moved.
for t in "${TARGETS[@]}"; do
  awk '{ for (i=1;i<=NF;i++) if ($i=="cov:" && $(i+1)+0 > last) { last=$(i+1)+0; print $1 "\t" last } }' \
    "$OUT_DIR/$t.log" > "$OUT_DIR/cov-$t.tsv"
done

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
