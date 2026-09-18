<!-- What changed and why. For a parser change, cite the spec section or the quirk. -->

- [ ] `cargo test` passes on your platform
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo fmt` has been run
- [ ] New tests cover the change, including error paths
- [ ] Fuzz corpus updated if a parser changed
- [ ] A regression test exists if this fixes a bug, with the triggering input in the corpus
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] An ADR added for any new dependency, `unsafe` block, or architectural change
- [ ] `docs/THREAT_MODEL.md` and `docs/KNOWN_LIMITATIONS.md` updated if a format handler changed
- [ ] `INSTRUCTIONS.md` updated if any command changed
- [ ] No test file carries real personal data
