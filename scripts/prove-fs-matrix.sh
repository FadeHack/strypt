#!/usr/bin/env bash
# strypt — prove the filesystem-constraints matrix fails when the fail-closed contract breaks.
#
# Each mutant breaks `io.rs` in a copy of the tree the way a plausible future change could, and
# must be caught by the named matrix case. A mutant whose pattern no longer matches fails this
# script: io.rs was refactored and the mutant needs rewriting, not deleting.
#
# Same requirements as scripts/fs-matrix.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
export CARGO_TARGET_DIR="$WORK/target" RUSTFLAGS=""
failed=0

# Tracked files from the working tree, less the corpora, so uncommitted io.rs changes are tested.
mkdir "$TREE"
git -C "$ROOT" ls-files -z | grep -zv -e '^corpus/' -e '^crates/strypt-core/fuzz/' \
  | (cd "$ROOT" && xargs -0 cp --parents -t "$TREE")
IO="$TREE/crates/strypt-core/src/io.rs"
cp "$IO" "$WORK/io.rs.orig"

# mutant NAME CASE OLD NEW — CASE is the fs-matrix line that must go red.
mutant() {
  local name=$1 case=$2 out
  cp "$WORK/io.rs.orig" "$IO"
  python3 - "$IO" "$3" "$4" <<'PY' || { echo "✗ $name — pattern not found in io.rs"; failed=1; return; }
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
if old not in text:
    sys.exit(1)
open(path, "w").write(text.replace(old, new, 1))
PY
  (cd "$TREE" && cargo build -q -p strypt) || { echo "✗ $name — mutant did not build"; failed=1; return; }
  if out=$("$ROOT/scripts/fs-matrix.sh" "$CARGO_TARGET_DIR/debug/strypt" 2>&1); then
    echo "✗ $name — the matrix PASSED a broken write path"; failed=1
  elif grep -qF "✗ $case" <<<"$out"; then
    echo "✓ $name — caught by '$case'"
  else
    echo "✗ $name — the matrix failed, but not on '$case':"; grep '✗' <<<"$out" | sed 's/^/    /'; failed=1
  fi
}

echo "== baseline"
(cd "$TREE" && cargo build -q -p strypt)
"$ROOT/scripts/fs-matrix.sh" "$CARGO_TARGET_DIR/debug/strypt" >/dev/null \
  || { echo "✗ the unmodified tree fails the matrix, so no result below means anything"; exit 1; }
echo "✓ unmodified tree passes"

echo "== mutants"
mutant "temporary leaked on failure" "full volume: existing file survives" \
  'let _ = std::fs::remove_file(&self.temporary);' \
  'let _ = &self.temporary;'

mutant "write error swallowed" "full volume: existing file survives" \
  'file.write_all(bytes).map_err(' \
  'Ok::<(), std::io::Error>({ let _ = file.write_all(bytes); }).map_err('

mutant "temporary placed in TMPDIR" "cross-mount: TMPDIR elsewhere" \
  'destination.parent().unwrap_or(Path::new(".")).join(name)' \
  '{ let _ = destination; std::env::temp_dir().join(name) }'

mutant "in-place fallback when the temporary cannot be created" "locked dir: in place" \
  'let temporary = temporary_path_for(destination);
        let file = create_private(&temporary, permissions)?;' \
  'let mut temporary = temporary_path_for(destination);
        let file = match create_private(&temporary, permissions) {
            Ok(file) => file,
            Err(_) => {
                temporary = destination.to_path_buf();
                std::fs::OpenOptions::new().write(true).truncate(true).open(destination)
                    .map_err(|source| StryptError::Io { action: IoAction::CreatingTemporary, source })?
            }
        };'

# ADR-0043's hypothesis, planted: permissions checked after the rename, which FAT cannot honour.
mutant "error when owner-only is not applied" "vfat: new file" \
  '    let _ = (path, permissions);
    Ok(())' \
  '    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
        if permissions == Permissions::OwnerOnly && mode != 0o600 {
            return Err(StryptError::Io { action: IoAction::SettingPermissions, source: std::io::Error::other("mode not applied") });
        }
    }
    let _ = (path, permissions);
    Ok(())'

echo
[ "$failed" -eq 0 ] || { echo "At least one broken write path got past the matrix."; exit 1; }
echo "Every mutant was caught by its case."
