# `.claude/` tooling notes

`settings.json` is JSON and cannot carry comments, so the notes that belong with it live
here. **Read this before trusting the hooks to protect anything.**

Hook schema verified against the Claude Code hooks reference on **2026-08-19**. Re-verify if
hooks stop firing — the schema has changed before and will again.

---

## What is configured

| Hook | Event / matcher | Purpose |
|---|---|---|
| `hooks/no-network.sh` | `PreToolUse` on `Write\|Edit\|Bash` | Blocks edits that appear to add a networking crate or a network call (ADR-0004) |
| `hooks/unsafe-needs-adr.sh` | `PreToolUse` on `Write\|Edit` | Escalates edits that appear to introduce `unsafe` or weaken `forbid(unsafe_code)` (ADR-0007) |

Both were tested against 12 synthetic tool payloads on 2026-08-19 covering true positives,
true negatives, and both `Write` (`file_content`) and `Edit` (`edits` array) payload shapes.
**If you change either script, re-run equivalent tests.** An untested guard provides
confidence without protection, which is worse than no guard at all.

## What these hooks genuinely cannot do

Stated plainly, because the project's most important invariant depends on knowing where the
real protection lives.

1. **They only see edits made through Claude Code's tools.** A human editing in vim, a merge
   commit, a `git apply`, or any contributor who does not use Claude Code bypasses them
   entirely. Over a project's lifetime that is most changes.
2. **They cannot see transitive dependencies.** A crate that itself depends on `reqwest`
   passes this check cleanly. Only a resolved dependency-graph walk catches that, and the
   hook does not have one.
3. **`PreToolUse` cannot verify same-commit requirements.** The `unsafe` rule requires an ADR
   in the same commit; at `PreToolUse` time no commit exists. The hook escalates for human
   confirmation rather than pretending to verify. Actual enforcement is the git pre-commit
   hook and CI.
4. **Content inspection is partial by design of the tool schema.** `Write` payloads carry
   `file_content` and `Edit` payloads carry an `edits` array, so both are inspectable — but
   a tool that modifies files another way (a `Bash` heredoc, `sed -i`, a script) is only
   caught if the *command text* happens to match. `sed -i` writing a networking dependency
   into `Cargo.toml` would not be caught.
5. **They are regex heuristics, not semantic analysis.** They will occasionally produce false
   positives (a crate name in a string literal) and can be evaded trivially by anyone who
   wants to (string concatenation, an unlisted crate name). They are a guardrail against
   *accident*, not a control against *intent*.

## Where the real enforcement lives

The hooks are the weakest of three layers, and deliberately so — they are the fastest and the
most easily bypassed. In increasing order of authority:

1. **These hooks** — immediate local feedback while working.
2. **The git pre-commit hook** *(to be added in Phase 0 scaffolding)* — catches non-Claude
   edits before they leave the machine, and can verify the same-commit ADR requirement.
3. **CI — the actual gate.** A dependency-graph check that walks the *fully resolved* tree
   (`cargo metadata`) and fails on any networking crate, transitive ones included, plus
   `cargo-deny`'s `bans` list. This is the only layer that cannot be bypassed by a
   contributor who has never read these documents.

**The CI gate is authoritative. Everything else is convenience.** If you have to choose where
to spend effort, spend it there.

Per `docs/ROADMAP.md` Phase 0 exit criterion 3, the CI gate must be **proven** to fail by
deliberately adding a networking crate on a throwaway branch. `INSTRUCTIONS.md` has the
procedure. Repeat it whenever the CI configuration changes.

## Permissions in `settings.json`

- `allow` — routine read-only and build commands, so ordinary work is not interrupted.
- `ask` — anything that changes the dependency graph (`cargo add`, editing `Cargo.toml`,
  `Cargo.lock`, `deny.toml`) or publishes. These deserve a human look every time.
- `deny` — `curl`, `wget`, `nc`. Not because they would end up in the shipped binary, but
  because a project whose defining property is "makes no network connections" should not
  normalise reaching for network tools inside its own workspace. Fetching something
  legitimately (a spec document, a test fixture) is a deliberate, explained exception.
