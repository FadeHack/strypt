#!/usr/bin/env bash
# strypt — no-network dependency gate (ADR-0004)
#
# THIS IS THE REAL GATE. The Claude Code hooks in .claude/hooks/ are early local warnings
# that only see edits made through those tools and cannot see transitive dependencies.
# This script walks the FULLY RESOLVED dependency graph and is the only layer that cannot be
# bypassed by a contributor who has never read the project's documentation.
#
# Exit 0 = clean. Exit 1 = a networking crate is present anywhere in the graph.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required by this check" >&2
  exit 2
fi

# Resolve the graph across ALL targets and ALL features. Restricting to the default feature
# set would miss a networking crate reachable only via an optional feature — which is exactly
# how one would arrive in practice.
cargo metadata --format-version 1 --all-features > /tmp/strypt-metadata.json

python3 - /tmp/strypt-metadata.json <<'PY'
import json, sys

# Crates that open sockets or exist to perform network I/O. Extend deliberately; every
# addition is a policy decision.
DENIED = {
    "reqwest", "hyper", "hyper-util", "h2", "h3", "ureq", "curl", "curl-sys", "isahc",
    "attohttpc", "surf", "awc", "actix-web", "axum", "warp", "rocket", "tiny_http",
    "minreq", "native-tls", "rustls", "openssl", "openssl-sys", "schannel",
    "security-framework", "tungstenite", "tokio-tungstenite", "websocket", "socket2",
    "trust-dns-resolver", "hickory-resolver", "hickory-proto", "quinn", "quinn-proto",
    "mio", "polling", "async-io", "smoltcp", "ipnet", "url",
}

# Crates that are fine in themselves but must not enable networking features.
FEATURE_GUARDS = {"tokio": {"net", "full", "io-std", "process"}}

meta = json.load(open(sys.argv[1]))
violations = []

for pkg in meta.get("packages", []):
    name = pkg.get("name", "")
    if name in DENIED:
        violations.append(f"denied crate in dependency graph: {name} {pkg.get('version','')}")
    guard = FEATURE_GUARDS.get(name)
    if guard:
        enabled = set(pkg.get("features", {}).keys())
        bad = enabled & guard
        if bad:
            violations.append(f"{name} enables networking features: {sorted(bad)}")

# Also check declared dependencies, to catch an optional dependency that is declared but not
# currently resolved into the graph.
for pkg in meta.get("packages", []):
    if not pkg.get("manifest_path", "").startswith(str(meta.get("workspace_root", ""))):
        continue
    for dep in pkg.get("dependencies", []):
        if dep.get("name") in DENIED:
            violations.append(
                f"denied crate declared by {pkg.get('name')}: {dep.get('name')} "
                f"(optional={dep.get('optional', False)})"
            )

if violations:
    print("=" * 78)
    print("ADR-0004 VIOLATION — strypt must make no network calls in any code path.")
    print("=" * 78)
    for v in sorted(set(violations)):
        print(f"  ✗ {v}")
    print()
    print("The entire trust model of this tool rests on this invariant. strypt's users")
    print("include people for whom an outbound connection at the moment they sanitise a")
    print("document is itself a disclosure.")
    print()
    print("If this is a false positive, or you are deliberately revisiting the invariant,")
    print("that requires a new ADR in docs/DECISIONS.md and a conversation with the owner.")
    print("Do not silence this check by editing the deny list without one.")
    sys.exit(1)

print("✓ no-network gate: clean — no networking crates in the resolved dependency graph")
PY
