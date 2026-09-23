#!/usr/bin/env bash
# strypt — prove every supply-chain gate fails when violated (ADR-0045).
#
# A gate that has never been seen failing is confidence without protection. Each case copies
# the tree, plants one violation in the copy, runs only the check that should catch it, and
# requires that check's own diagnostic — failing for the wrong reason, such as a network error
# or an unrelated check, proves nothing.
#
# Run in CI, this also catches the gate being weakened: set `yanked = "warn"` and the yanked
# case stops failing, which fails this script.
#
# Exit 0 = the clean tree passes and every violation is caught. Needs network: the violations
# are real crates, and the advisory and yank cases depend on RustSec and crates.io.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
CORE="$TREE/crates/strypt-core/Cargo.toml"
CLI="$TREE/crates/strypt/Cargo.toml"
GUI="$TREE/crates/strypt-gui/Cargo.toml"
failed=0

# Tracked and untracked-but-not-ignored files, so uncommitted gate changes are what gets tested. The
# corpora are 1.6GB and irrelevant to dependency resolution; the fuzz crate is its own workspace.
fresh_tree() {
  rm -rf "$TREE"
  python3 - "$ROOT" "$TREE" <<'PY'
import pathlib, shutil, subprocess, sys
root, tree = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
files = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root, capture_output=True, check=True).stdout
for rel in filter(None, files.decode().split("\0")):
    if rel.startswith(("corpus/", "crates/strypt-core/fuzz/")) or not (root / rel).is_file():
        continue
    (tree / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / rel, tree / rel)
PY
}

# add_dep LINE [MANIFEST] — MANIFEST defaults to strypt-core's.
add_dep() {
  python3 - "${2:-$CORE}" "$1" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2]
text = open(path).read()
if "\n[dependencies]\n" not in text:
    sys.exit("no [dependencies] table in " + path)
open(path, "w").write(text.replace("\n[dependencies]\n", "\n[dependencies]\n" + line + "\n", 1))
PY
}

in_tree() { (cd "$TREE" && "$@"); }

# expect_fail NAME PATTERN CMD... — CMD must exit non-zero AND print PATTERN.
expect_fail() {
  local name=$1 pattern=$2 out
  shift 2
  if out=$(in_tree "$@" 2>&1); then
    echo "✗ $name — the gate PASSED a planted violation"
    failed=1
  elif grep -qE -- "$pattern" <<<"$out"; then
    echo "✓ $name"
  else
    echo "✗ $name — failed, but without '$pattern', so not for the planted reason:"
    tail -15 <<<"$out" | sed 's/^/    /'
    failed=1
  fi
}

# expect_admit NAME CMD... — CMD must pass a planted tree its policy allows: the gate is not broader
# than it says.
expect_admit() {
  local name=$1 out
  shift
  if out=$(in_tree "$@" 2>&1); then
    echo "✓ $name"
  else
    echo "✗ $name — refused what its policy admits:"
    tail -15 <<<"$out" | sed 's/^/    /'
    failed=1
  fi
}

expect_pass() {
  local name=$1 out
  shift
  if out=$(in_tree "$@" 2>&1); then
    echo "✓ $name"
  else
    echo "✗ $name — fails on the unmodified tree, so no other result here means anything:"
    tail -15 <<<"$out" | sed 's/^/    /'
    exit 1
  fi
}

echo "== baseline"
fresh_tree
expect_pass "cargo-deny passes the clean tree" cargo deny check
expect_pass "no-network passes the clean tree" ./scripts/check-no-network.sh

echo "== one violation each"

fresh_tree; add_dep 'ureq = "3"'
expect_fail "bans: networking crate on the deny list" 'error\[banned\]' cargo deny check bans
expect_fail "no-network: networking crate in the graph" 'ADR-0004 VIOLATION' ./scripts/check-no-network.sh

# ADR-0058 decision 3: the gate is per crate, and only strypt-gui admits the AT-SPI and Wayland
# reactors, only through zbus or calloop. HTTP stays denied there too.
fresh_tree; add_dep 'ureq = "3"' "$GUI"
expect_fail "no-network: HTTP client in strypt-gui" 'strypt-gui: denied crate in dependency graph: ureq' ./scripts/check-no-network.sh
fresh_tree; add_dep 'async-io = "2"'
expect_fail "no-network: admitted reactor in strypt-core" 'strypt-core: denied crate in dependency graph: async-io' ./scripts/check-no-network.sh
fresh_tree; add_dep 'polling = "3"' "$CLI"
expect_fail "no-network: admitted reactor in strypt" 'strypt: denied crate in dependency graph: polling' ./scripts/check-no-network.sh
fresh_tree; add_dep 'polling = "3"' "$GUI"
expect_fail "no-network: reactor reaching strypt-gui outside zbus and calloop" 'strypt-gui: polling .* another path reaches it' ./scripts/check-no-network.sh

# tokio is guarded by enabled feature. `io-std` pulls no `mio`, so only the guard can catch it; `rt`
# alone must pass, or the guard is an outright ban.
fresh_tree; add_dep 'tokio = { version = "1", default-features = false, features = ["io-std"] }'
expect_fail "no-network: tokio with a guarded feature" "strypt-core: tokio enables networking features: \['io-std'\]" ./scripts/check-no-network.sh
fresh_tree; add_dep 'tokio = { version = "1", default-features = false, features = ["rt"] }'
expect_admit "no-network: tokio without a guarded feature" ./scripts/check-no-network.sh

fresh_tree; add_dep 'rand = "0.8"'
expect_fail "bans: duplicate versions" 'error\[duplicate\]' cargo deny check bans

fresh_tree; add_dep 'itoa = "*"'
expect_fail "bans: wildcard version" 'error\[wildcard\]' cargo deny check bans

fresh_tree
sed -i.bak 's/^license = "MIT OR Apache-2.0"$/license = "GPL-3.0-only"/' "$TREE/Cargo.toml"
expect_fail "licenses: copyleft licence" 'error\[rejected\]' cargo deny check licenses

fresh_tree; add_dep 'itoa = { git = "https://github.com/dtolnay/itoa" }'
expect_fail "sources: git dependency" 'error\[source-not-allowed\]' cargo deny check sources

# RUSTSEC-2021-0145, an unaligned read in `atty`, which is unmaintained and will never be fixed.
# Not smallvec's RUSTSEC-2021-0003 any more: egui needs smallvec ^1.15, so =1.6.0 cannot resolve.
fresh_tree; add_dep 'atty = "=0.2.14"'
expect_fail "advisories: known unsound crate" 'RUSTSEC-2021-0145' cargo deny check advisories

# The crate this gate first caught for real, on 2026-09-11. Cargo will select a yanked version
# only by --precise; if this case breaks, check it has not been un-yanked before anything else.
fresh_tree
in_tree cargo update -p chacha20 --precise 0.10.1 >/dev/null 2>&1
expect_fail "advisories: yanked crate" 'error\[yanked\]' cargo deny check advisories

echo
if [ "$failed" -ne 0 ]; then
  echo "At least one gate did not fail when it should have. It is providing confidence without"
  echo "protection — fix the gate, not this script."
  exit 1
fi
echo "Every gate failed when violated, and passed when not."
