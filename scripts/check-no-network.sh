#!/usr/bin/env bash
# strypt — no-network dependency gate (ADR-0004), per workspace crate (ADR-0058 decision 3)
#
# THIS IS THE REAL GATE. The Claude Code hooks in .claude/hooks/ are early local warnings
# that only see edits made through those tools and cannot see transitive dependencies.
# This script walks the FULLY RESOLVED dependency graph and is the only layer that cannot be
# bypassed by a contributor who has never read the project's documentation.
#
# Exit 0 = clean. Exit 1 = a networking crate is reachable from a workspace crate that does
# not admit it.

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

# ADR-0058 decision 3. Only these crates, only in strypt-gui, and only when every path to them
# runs through a carrier: zbus is AT-SPI over the D-Bus session bus, calloop is winit's Wayland
# event loop. Every other workspace crate admits nothing. HTTP, TLS and DNS are never admitted.
ADMITTED = {"strypt-gui": {"async-io", "polling"}}
CARRIERS = {"strypt-gui": {"zbus", "calloop"}}

meta = json.load(open(sys.argv[1]))
packages = {p["id"]: p for p in meta["packages"]}
edges = {n["id"]: [d["pkg"] for d in n["deps"]] for n in meta["resolve"]["nodes"]}
# Enabled, not defined: a package's own "features" is the table it declares, every guarded name included.
enabled = {n["id"]: set(n.get("features", [])) for n in meta["resolve"]["nodes"]}
violations = []

def reach(root, stop=frozenset()):
    seen, todo = set(), [root]
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if packages[pid]["name"] not in stop:
            todo.extend(edges.get(pid, []))
    return seen

for member in meta["workspace_members"]:
    crate = packages[member]["name"]
    admitted = ADMITTED.get(crate, set())
    everything = reach(member)
    # Reachable without passing through a carrier: an admitted crate found here was pulled in
    # by something else, which is exactly the route decision 3 does not forgive.
    uncarried = reach(member, frozenset(CARRIERS.get(crate, set())))
    for pid in everything:
        pkg = packages[pid]
        name, version = pkg["name"], pkg["version"]
        if name in DENIED:
            if name not in admitted:
                violations.append(f"{crate}: denied crate in dependency graph: {name} {version}")
            elif pid in uncarried:
                violations.append(
                    f"{crate}: {name} {version} is admitted only through "
                    f"{sorted(CARRIERS[crate])}, but another path reaches it"
                )
        bad = enabled.get(pid, set()) & FEATURE_GUARDS.get(name, set())
        if bad:
            violations.append(f"{crate}: {name} enables networking features: {sorted(bad)}")

    # Declared dependencies too, to catch one that is optional and not currently resolved.
    for dep in packages[member].get("dependencies", []):
        if dep.get("name") in DENIED:
            violations.append(
                f"{crate}: denied crate declared: {dep.get('name')} "
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

for member in meta["workspace_members"]:
    crate = packages[member]["name"]
    extra = f"; admits {sorted(ADMITTED[crate])} via {sorted(CARRIERS[crate])}" if crate in ADMITTED else ""
    print(f"✓ no-network gate: {crate} clean{extra}")
PY
