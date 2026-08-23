#!/usr/bin/env bash
# strypt — live status for an in-progress sustained fuzzing run.
#
# `scripts/fuzz-sustained.sh` redirects every target's output to its own log and prints nothing
# until all of them finish, so a 12-hour run looks identical to a hung one from the outside.
# This reads those logs and refreshes a one-line-per-target table.
#
# It is a VIEWER. It does not decide anything: the run's own summary.md and exit code answer
# ROADMAP exit criterion 2, not this table.
#
# The artefact count is deliberately restricted to files newer than the run's .started marker,
# matching fuzz-sustained.sh. artifacts/ is not cleared between runs and currently holds
# triaged findings from August 2026; counting those would report a long-fixed crash as a live
# failure every time, and a status board that cries wolf gets ignored when it is finally right.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/crates/strypt-core/fuzz"
INTERVAL=10

usage() {
  cat <<'EOF'
Usage: scripts/fuzz-status.sh [-n SECONDS] [RUN_DIR]

  -n SECONDS  refresh interval (default 10)
  RUN_DIR     a target/fuzz-runs/<name> directory (default: most recently modified)

Ctrl-C stops watching. It does not stop the fuzz run — that is a separate process.
EOF
}

while getopts ":n:h" opt; do
  case "$opt" in
    n) INTERVAL="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "error: -$OPTARG requires an argument" >&2; exit 2 ;;
    \?) echo "error: unknown option -$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
  echo "error: -n must be a positive integer number of seconds" >&2
  exit 2
fi

RUN_DIR="${1:-}"
if [ -z "$RUN_DIR" ]; then
  RUN_DIR="$(ls -dt "$REPO_ROOT"/target/fuzz-runs/*/ 2>/dev/null | head -1 || true)"
  [ -n "$RUN_DIR" ] || { echo "error: no run found under target/fuzz-runs/" >&2; exit 2; }
fi
[ -d "$RUN_DIR" ] || { echo "error: not a directory: $RUN_DIR" >&2; exit 2; }
RUN_DIR="${RUN_DIR%/}"

MARKER="$RUN_DIR/.started"

# Which targets this run covers, taken from the logs it actually created rather than from a
# hardcoded list — the list has changed once already (ooxml and zip, 2026-08-23) and a viewer
# that disagrees with the run about what ran is worse than no viewer.
# No `mapfile`/`readarray` here: macOS still ships bash 3.2, where both are absent and the
# script would die on the first run on the maintainer's own machine.
TARGETS=()
while IFS= read -r t; do
  TARGETS+=("$t")
done < <(find "$RUN_DIR" -maxdepth 1 -name '*.log' -exec basename {} .log \; | sort)
[ ${#TARGETS[@]} -gt 0 ] || { echo "error: no target logs in $RUN_DIR" >&2; exit 2; }

new_artifacts() {
  [ -d "$FUZZ_DIR/artifacts/$1" ] || { echo 0; return; }
  if [ -f "$MARKER" ]; then
    find "$FUZZ_DIR/artifacts/$1" -type f -newer "$MARKER" | wc -l | tr -d ' '
  else
    # The marker is removed when the run finishes, so its absence means "no longer running".
    echo "-"
  fi
}

while :; do
  printf '\033[H\033[2J'
  echo "strypt fuzz status — $RUN_DIR"
  [ -f "$MARKER" ] && echo "  state: RUNNING" || echo "  state: finished (see summary.md)"
  echo "  time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  printf "%-8s %9s %8s %9s %13s %9s %10s\n" TARGET ELAPSED COV FT CORPUS EXEC/S ARTEFACTS
  for t in "${TARGETS[@]}"; do
    art="$(new_artifacts "$t")"
    line="$(grep -a 'cov:' "$RUN_DIR/$t.log" 2>/dev/null | tail -1 || true)"
    if [ -z "$line" ]; then
      printf "%-8s %9s %8s %9s %13s %9s %10s\n" "$t" "starting" "-" "-" "-" "-" "$art"
      continue
    fi
    echo "$line" | awk -v t="$t" -v a="$art" '
      {
        e = $1
        for (i = 1; i <= NF; i++) {
          if ($i == "cov:")    c = $(i+1)
          if ($i == "ft:")     f = $(i+1)
          if ($i == "corp:")   p = $(i+1)
          if ($i == "exec/s:") x = $(i+1)
        }
        printf "%-8s %6dh%02dm %8s %9s %13s %9s %10s\n", t, e/3600, (e%3600)/60, c, f, p, x, a
      }'
  done
  echo
  echo "COV/FT climbing = still finding new structure. ARTEFACTS > 0 = a crash THIS run; the"
  echo "input is in crates/strypt-core/fuzz/artifacts/<target>/ and needs a fix and a"
  echo "regression test (CLAUDE.md §9). Refreshing every ${INTERVAL}s; Ctrl-C exits the viewer only."
  sleep "$INTERVAL"
done
