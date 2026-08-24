#!/usr/bin/env bash
# LibreOffice import validation for stripped OpenDocument packages.
#
# The question this answers is the one docs/THREAT_MODEL.md §7.7 recorded as **owed**: does a
# package strypt has stripped still open in the application that writes this format? Until this
# ran, the only evidence was structural — an independent ZIP reader over every output, the
# manifest checked against the entries present, the `mimetype` entry checked against ODF Part 2
# §3.3. That says the archive is well-formed. It does not say LibreOffice will load it.
#
# Two things are checked per fixture, and they are separate claims:
#
#   1. **Import.** The stripped package is loaded by LibreOffice and re-exported to flat XML,
#      which forces a full import of every part rather than a header sniff. A package that
#      fails to load produces no output file and is a failure.
#
#   2. **Body survival.** The document body of the original and of the stripped copy are
#      compared. This catches the case that matters and that step 1 alone would miss: a file
#      that opens cleanly but lost content, because strypt removed something load-bearing.
#      Bodies that differ *deliberately* are listed in EXPECT_BODY_DIFF below — strypt empties
#      cached author fields and removes comment and revision authorship, all of which live in
#      the body — so an unexpected difference fails and an unexpected *match* fails too.
#
# **What this does NOT check.** LibreOffice's repair prompt is a GUI path; headless import
# cannot raise a dialog, so "loads headlessly" is a strong proxy for "opens without a repair
# prompt" and not the same claim. A handful of files still need opening by hand in the GUI, and
# §7.7 records the two checks separately rather than letting this one stand in for both.
#
# Requires LibreOffice on PATH (`brew install --cask libreoffice`). Refuses to run without it
# rather than reporting a clean sweep it did not perform — the mistake the WebP differential
# made for two days (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Overridable so the same checks can be pointed at the real-producer corpus, whose files are
# fetched rather than committed (docs/TESTING_STRATEGY.md §3). EXPECT_BODY_DIFF is keyed on the
# committed fixture names, so an override reports body differences as failures unless the list is
# overridden too — which is correct: an unexplained body change in a real document is a finding.
CORPUS="${CORPUS:-$ROOT/corpus/odf}"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

# Fixtures whose body is expected to differ after stripping, each because strypt deliberately
# edits something the body carries. Determined by running this script, not predicted from the
# spec: an entry here without a reason is how a real regression gets waved through.
#
#   author-fields.odt    cached text:creator / text:initial-creator values are emptied (§7.7)
#   comments.odt         office:annotation authorship removed from the body
#   tracked-changes.odt  office:change-info authorship removed from the body
#   everything.odt       all three of the above in one file
#
# embedded-image.odt is deliberately NOT in this list, and the reason is a limit of this method
# rather than a fact about the handler. strypt does strip that picture — `strypt show` reports
# GPS, a body serial and an Artist name in Pictures/image1.jpg, and they are gone afterwards —
# but the fixture's content.xml never references the picture, so LibreOffice's flat-XML export
# drops it and both bodies come out identical. **A body comparison can only see what LibreOffice
# round-trips.** Picture stripping is covered by the differential and the integration tests, not
# by this script.
EXPECT_BODY_DIFF="author-fields.odt comments.odt tracked-changes.odt everything.odt"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
note() { printf '    %s\n' "$1"; }
fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

command -v soffice >/dev/null 2>&1 \
  || fail "LibreOffice is not installed; a check that cannot run must not report a clean sweep"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:      %s\n' "$("$STRYPT" --version)"
printf 'LibreOffice: %s\n\n' "$(soffice --version 2>/dev/null | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PROFILE="file://$WORK/profile"

# Convert one document to its flat-XML equivalent. Echoes the produced path, or nothing.
#
# soffice exits 0 even when the import fails outright — verified against
# corpus/odf/malformed/truncated.odt, which prints "source file could not be loaded" and still
# returns 0. So the existence of the output file is the only trustworthy signal, and gating on
# $? here would have reported every broken package as a success.
convert() {
    local input="$1" outdir="$2" ext filter target
    case "${input##*.}" in
        odt) ext=fodt; filter="OpenDocument Text Flat XML" ;;
        ods) ext=fods; filter="OpenDocument Spreadsheet Flat XML" ;;
        odp) ext=fodp; filter="OpenDocument Presentation Flat XML" ;;
        *)   return 1 ;;
    esac
    rm -rf "$outdir" && mkdir -p "$outdir"
    soffice --headless --norestore --invisible -env:UserInstallation="$PROFILE" \
        --convert-to "$ext:$filter" --outdir "$outdir" "$input" >/dev/null 2>&1 || true
    target="$outdir/$(basename "${input%.*}").$ext"
    [ -s "$target" ] && printf '%s' "$target"
}

# The document body alone, with office:meta and office:settings dropped. Those two are *supposed*
# to differ — removing them is the point of the tool — so including them would make every file
# differ and the comparison would say nothing.
body() {
    python3 - "$1" <<'PY'
import sys, xml.etree.ElementTree as ET
NS = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}"
try:
    root = ET.parse(sys.argv[1]).getroot()
except ET.ParseError as e:
    sys.exit(f"unparseable flat XML: {e}")
body = root.find(f"{NS}body")
if body is None:
    sys.exit("no office:body in the flat XML")

# LibreOffice stamps the absolute path of the file it converted into a form's "Referer"
# property. The original and the stripped copy are necessarily converted from different
# directories, so that property differs on every run and has nothing to do with what strypt
# did — leaving it in made this harness report its own temp-directory names as content loss.
# Dropped rather than the paths normalised, because the value is LibreOffice's, not the
# document's.
for parent in body.iter():
    for child in list(parent):
        if child.get(f"{{urn:oasis:names:tc:opendocument:xmlns:form:1.0}}property-name") == "Referer":
            parent.remove(child)

print(ET.tostring(body, encoding="unicode"))
PY
}

failures=0
checked=0

for input in "$CORPUS"/*.odt "$CORPUS"/*.ods "$CORPUS"/*.odp; do
    [ -e "$input" ] || continue
    name="$(basename "$input")"
    checked=$((checked + 1))
    printf '%s\n' "$name"

    # 1. Strip it. A refusal is a correct outcome for this handler and leaves nothing to open.
    rm -rf "$WORK/s" && mkdir -p "$WORK/s"
    if ! "$STRYPT" strip --output-dir "$WORK/s" "$input" >/dev/null 2>&1; then
        note "strypt refused this file — a refusal is a correct outcome, nothing to validate"
        continue
    fi
    stripped="$(find "$WORK/s" -type f | head -1)"

    # 2. Baseline: the original must import, or the fixture proves nothing about the stripping.
    original_xml="$(convert "$input" "$WORK/a" || true)"
    if [ -z "$original_xml" ]; then
        bad "LibreOffice cannot import the ORIGINAL fixture — the fixture is the problem, not strypt"
        failures=$((failures + 1))
        continue
    fi

    # 3. The check that was owed.
    stripped_xml="$(convert "$stripped" "$WORK/b" || true)"
    if [ -z "$stripped_xml" ]; then
        bad "LibreOffice CANNOT import the stripped package"
        failures=$((failures + 1))
        continue
    fi
    pass "imports"

    # 4. Body survival.
    if ! body "$original_xml" > "$WORK/a.body" 2>"$WORK/a.err"; then
        bad "could not read the original's body: $(cat "$WORK/a.err")"
        failures=$((failures + 1))
        continue
    fi
    if ! body "$stripped_xml" > "$WORK/b.body" 2>"$WORK/b.err"; then
        bad "could not read the stripped body: $(cat "$WORK/b.err")"
        failures=$((failures + 1))
        continue
    fi

    expected_diff=false
    case " $EXPECT_BODY_DIFF " in *" $name "*) expected_diff=true ;; esac

    if cmp -s "$WORK/a.body" "$WORK/b.body"; then
        if $expected_diff; then
            bad "body is UNCHANGED but was expected to change — strypt stopped removing something"
            failures=$((failures + 1))
        else
            pass "body identical"
        fi
    else
        if $expected_diff; then
            pass "body differs, as intended for this fixture"
        else
            bad "body CHANGED and was not expected to — content was lost"
            note "$(diff <(fold -w120 "$WORK/a.body") <(fold -w120 "$WORK/b.body") | head -6 | tr '\n' ' ')"
            failures=$((failures + 1))
        fi
    fi
done

printf '\n%d fixtures checked, %d failures\n' "$checked" "$failures"
if [ "$failures" -eq 0 ]; then
    printf '\033[32mAll stripped packages import into LibreOffice.\033[0m\n'
    printf 'This is the headless-import claim only. The GUI repair-prompt check is separate —\n'
    printf 'see docs/THREAT_MODEL.md §7.7.\n'
    exit 0
fi
exit 1
