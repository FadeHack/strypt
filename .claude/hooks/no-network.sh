#!/usr/bin/env bash
# strypt — no-network guard (ADR-0004)
#
# PreToolUse hook. Blocks edits that look like they introduce a networking dependency
# or a network call into strypt-core / strypt-cli.
#
# THIS IS AN EARLY WARNING, NOT THE REAL GATE. See .claude/HOOKS.md for its limits.
# The authoritative gate is the CI dependency-graph check.

set -uo pipefail

payload="$(cat)"

tool="$(printf '%s' "$payload" | jq -r '.tool_name // ""')"

# Crates that open sockets, plus the obvious std/network call shapes.
NET_CRATES='reqwest|hyper|ureq|curl|isahc|attohttpc|surf|awc|native-tls|rustls|openssl|tokio-tungstenite|tungstenite|websocket|socket2|trust-dns|hickory-dns|quinn|axum|actix-web|warp|rocket|tiny_http|minreq|http-body|reqwest-middleware'
NET_CALLS='TcpStream|TcpListener|UdpSocket|std::net|tokio::net|SocketAddr::|\.connect\(|to_socket_addrs'

deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

case "$tool" in
  Write|Edit)
    path="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // ""')"
    # Content: Write exposes file_content; Edit exposes an edits array.
    content="$(printf '%s' "$payload" | jq -r '[.tool_input.file_content // "", (.tool_input.edits // [] | tostring)] | join("\n")')"

    case "$path" in
      # Hook config and CI are allowed to *mention* networking crates — that is their job.
      */.claude/*|*/deny.toml|*/.github/*|*/docs/*|*CLAUDE.md|*README.md) exit 0 ;;
    esac

    case "$path" in
      *Cargo.toml)
        # Match the crate name as a whole word. Edit payloads arrive JSON-stringified on a
        # single line, so line-anchored patterns miss them.
        if printf '%s' "$content" | grep -Eq "(^|[^a-zA-Z0-9_-])($NET_CRATES)([^a-zA-Z0-9_-]|$)"; then
          deny "ADR-0004 (no network access, ever): this edit appears to add a networking crate to $path. strypt must make no network calls in any code path, and no socket-opening crate may appear in the dependency tree — including transitively. If you believe this is a false positive, or you are deliberately revisiting this invariant, that requires a new ADR in docs/DECISIONS.md and a conversation with the project owner. See .claude/HOOKS.md."
        fi
        ;;
      *.rs)
        if printf '%s' "$content" | grep -Eq "$NET_CALLS"; then
          deny "ADR-0004 (no network access, ever): this edit to $path appears to introduce a network call. strypt makes no network connections in any code path — no update checks, no telemetry, no crash reporting. See docs/DECISIONS.md ADR-0004 and .claude/HOOKS.md."
        fi
        ;;
    esac
    ;;

  Bash)
    cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // ""')"
    if printf '%s' "$cmd" | grep -Eq "cargo[[:space:]]+add.*($NET_CRATES)"; then
      deny "ADR-0004 (no network access, ever): this command appears to add a networking crate as a dependency. See docs/DECISIONS.md ADR-0004."
    fi
    ;;
esac

exit 0
