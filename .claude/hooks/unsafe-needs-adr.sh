#!/usr/bin/env bash
# strypt — unsafe-code guard (ADR-0007)
#
# PreToolUse hook. Escalates any edit that appears to introduce an `unsafe` block or
# weaken the crate-level `forbid(unsafe_code)` attribute.
#
# LIMITATION: a PreToolUse hook cannot verify that a matching ADR lands in the SAME COMMIT,
# because no commit exists yet at this point. It escalates for human confirmation instead.
# The same-commit requirement is enforced by the git pre-commit hook and by CI.
# See .claude/HOOKS.md.

set -uo pipefail

payload="$(cat)"
tool="$(printf '%s' "$payload" | jq -r '.tool_name // ""')"

case "$tool" in Write|Edit) ;; *) exit 0 ;; esac

path="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // ""')"
case "$path" in *.rs) ;; *) exit 0 ;; esac

content="$(printf '%s' "$payload" | jq -r '[.tool_input.file_content // "", (.tool_input.edits // [] | tostring)] | join("\n")')"

# `unsafe` as a block/fn/impl/trait keyword, or removal of the forbid attribute.
if printf '%s' "$content" | grep -Eq '(^|[^[:alnum:]_])unsafe[[:space:]]*(\{|fn |impl |trait |extern)' \
   || printf '%s' "$content" | grep -Eq 'allow\([[:space:]]*unsafe_code|deny\([[:space:]]*unsafe_code'; then
  jq -n '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "escalate",
      permissionDecisionReason: "ADR-0007: this edit appears to introduce `unsafe` code or weaken `#![forbid(unsafe_code)]`. strypt'"'"'s memory-safety argument — its strongest differentiator — is void inside an unsafe block. This requires: (1) a `// SAFETY:` comment stating the invariants relied upon and why they hold, and (2) a new ADR in docs/DECISIONS.md in the SAME commit. This hook cannot verify the ADR (no commit exists yet); the git pre-commit hook and CI enforce that. Confirm only if both conditions are being met."
    }
  }'
  exit 0
fi

exit 0
