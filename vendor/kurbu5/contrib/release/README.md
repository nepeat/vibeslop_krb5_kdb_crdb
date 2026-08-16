# release.py — kurbu5 release automation

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Options](#options)
- [Commit scoring](#commit-scoring)
- [publish-order](#publish-order)
- [First release checklist](#first-release-checklist)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

Automates changelog generation, version bumping, tagging, and publishing all
kurbu5 crates to crates.io in the correct dependency order.

## Quick start

```
# Preview what would happen (no files written, no git changes):
./contrib/release/release.py

# Preview a version bump:
./contrib/release/release.py 0.2.0

# Execute the release (current version, no bump):
./contrib/release/release.py --do-run

# Bump version and release:
./contrib/release/release.py --do-run 0.2.0
```

## How it works

Each run goes through these stages in order:

1. **Pre-flight** — asserts a clean working tree, warns if not on `main`/`master`,
   validates all crate paths from `publish-order`
2. **Changelog generation** — for every crate, scores commits since the last tag
   using keyword and size heuristics, categorises them into `Added / Changed /
   Fixed / Removed / Security`, and writes the results into the crate's
   `CHANGELOG.md`:
   - If the file has an `## [Unreleased]` section, its body is replaced with
     the generated entries and the header is renamed to `## [VERSION] — DATE`;
     a fresh empty `## [Unreleased]` section is prepended for future work
   - If the file already has an `## [VERSION]` section (e.g. first release),
     its body is replaced in-place
   - Predecessor paths are detected automatically via `git log --follow` on
     `Cargo.toml`, so crates that were moved (e.g. `kdb/` → `kurbu5-kdb/`)
     include their pre-move history
3. **Version bump** *(only when a new version is supplied)* — updates
   `version` in the workspace `Cargo.toml` and the `version =` field on all
   inter-crate path dependencies
4. **`cargo check --workspace`** — ensures the workspace still compiles after
   any edits
5. **CI** *(skippable with `--skip-ci`)* — runs `contrib/ci/local-ci.sh --no-deps all`
6. **Dry-run publish check** — runs `cargo publish --dry-run` for the first
   crate in `publish-order` to catch packaging errors early
7. **Summary** — prints what would be committed, tagged, and published, then
   exits if `--do-run` was not given
8. **Confirm → commit → tag** — asks for confirmation, commits all changed
   files (changelogs + Cargo.tomls), and creates an annotated tag `vVERSION`
9. **Publish** — publishes each crate in dependency order with a configurable
   delay between calls for crates.io index propagation

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `VERSION` | current workspace version | Target version; omit to release without bumping |
| `--do-run` | off | Actually write files, commit, tag, and publish |
| `--no-publish` | off | With `--do-run`: commit and tag, but skip `cargo publish` |
| `--skip-ci` | off | Skip `local-ci.sh` (CI assumed green) |
| `--no-sign` | off | Create an unsigned annotated tag instead of a GPG-signed one |
| `--delay SECS` | 30 | Seconds to wait between `cargo publish` calls |

Without `--do-run` the script runs in **preview mode**: changelogs are written
to disk (inspect with `git diff`) but no commit, tag, or publish occurs.  Run
`git checkout -- .` to discard the preview changes.

## Commit scoring

Commits are scored to decide which ones are worth including in the changelog.
Commits below a threshold of 5 points are omitted (style fixes, doc tweaks,
CI changes).

| Condition | Points |
|-----------|--------|
| Breaking change (`!` in conventional commit prefix) | +50 |
| High-importance keyword: `security`, `fix`, `feat`, `implement`, `rewrite`, … | +30 |
| Medium-importance keyword: `refactor`, `add`, `remove`, `migrate`, … | +15 |
| Low-importance keyword: `perf`, `test`, `bench`, … | +5 |
| Style/chore penalty: `rustfmt`, `clippy`, `typo`, `readme`, `chore`, … | −25 |
| Doc penalty: `doc`, `docs` | −20 |
| CI penalty: `ci`, `cd` | −15 |
| ≥ 10 files changed | +20 |
| ≥ 5 files changed | +12 |
| ≥ 2 files changed | +4 |
| ≥ 500 lines changed | +20 |
| ≥ 100 lines changed | +12 |
| ≥ 30 lines changed | +4 |

Surviving commits are categorised by their conventional commit type (`feat:` →
Added, `fix:` → Fixed, etc.) with keyword fallback, then deduplicated and
written as bullet points under the appropriate `### Section`.

## publish-order

The sibling file `publish-order` lists one workspace-relative crate path per
line (blank lines and `#` comments ignored).  The order must respect dependency
constraints — each crate must appear after all workspace crates it depends on.

```
kurbu5-sys
kurbu5-derive
kurbu5-rs
kurbu5-kdb/kurbu5-kdb-sys
kurbu5-kdb/kurbu5-kdb-derive
kurbu5-kdb/kurbu5-kdb-rs
kadm5/kurbu5-kadm5-sys
kadm5/kurbu5-kadm5-derive
kadm5/kurbu5-kadm5-rs
```

The package name is derived from the directory basename and must match
`[package] name` in that crate's `Cargo.toml`.  The changelog is expected at
`{path}/CHANGELOG.md`.

## First release checklist

- [ ] Ensure `cargo login` has been run with a valid crates.io token
- [ ] Run `./contrib/release/release.py --skip-ci` and review `git diff`
- [ ] Fix any issues flagged by the dry-run publish check
- [ ] Run `./contrib/release/release.py --do-run --skip-ci` (CI already known green)
- [ ] Push: `git push origin main v0.1.0`
