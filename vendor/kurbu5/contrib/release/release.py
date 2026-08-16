#!/usr/bin/env python3
"""
release.py — update changelogs, optionally bump version, and publish a Rust workspace.

Runs in two phases:

  Phase 1 (prepare):        update changelogs, optionally bump the version,
                             run cargo check + local-ci.sh, then commit and
                             tag.  Run this on a release branch before
                             opening a PR.

  Phase 2 (--publish-only): publish every crate in publish-order to
                             crates.io.  Run this on main after the release
                             PR has merged.

By default the script runs in preview mode: it validates inputs and prints
what it would do, but makes no commits, tags, or publishes.  Pass --do-run
to execute the phase for real.

Usage:
    ./contrib/release/release.py [VERSION] [OPTIONS]

    VERSION   Version to release (default: current workspace version).
              When omitted the script releases whatever version is already
              set in [workspace.package] — no Cargo.toml changes are made.
              When supplied and different from the current version, the
              workspace version and all inter-crate dep specs are bumped.

Options:
    --do-run          Execute the phase (default: preview only)
    --publish-only    Phase 2: skip prepare, publish crates to crates.io
    --skip-ci         Phase 1: skip running contrib/ci/local-ci.sh
    --no-sign         Phase 1: create an unsigned annotated tag
    --delay SECS      Phase 2: seconds between cargo publish calls for
                      crates.io index propagation (default: 30)

Crate publish order and changelog locations are read from the sibling file
'publish-order' in the same directory as this script.
"""

from __future__ import annotations

import argparse
import contextlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE   = "\033[0;34m"
BOLD   = "\033[1m"
NC     = "\033[0m"


def _use_color() -> bool:
    import os
    return sys.stdout.isatty() and os.environ.get("NO_COLOR", "") != "1"


def _c(code: str) -> str:
    return code if _use_color() else ""


def step(msg: str) -> None:
    print(f"\n{_c(BOLD)}{_c(BLUE)}▶ {msg}{_c(NC)}", flush=True)


def ok(msg: str) -> None:
    print(f"  {_c(GREEN)}✔{_c(NC)}  {msg}", flush=True)


def warn(msg: str) -> None:
    # Intentionally stdout so output stays ordered when piped.
    print(f"  {_c(YELLOW)}!{_c(NC)}  {msg}", flush=True)


def die(msg: str) -> None:
    print(f"\n{_c(RED)}error:{_c(NC)} {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def info(msg: str) -> None:
    print(f"  {msg}", flush=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_repo_root() -> Path:
    """Walk upward from the script location to the Cargo.toml workspace root."""
    candidate = Path(__file__).resolve().parent.parent.parent
    if (candidate / "Cargo.toml").exists():
        return candidate
    p = Path.cwd().resolve()
    while p != p.parent:
        if (p / "Cargo.toml").exists():
            return p
        p = p.parent
    die("Could not locate workspace root (no Cargo.toml found).")


def load_publish_order(script_dir: Path) -> list[tuple[str, Path]]:
    """
    Parse the 'publish-order' file next to this script.

    Returns a list of (package_name, crate_path) pairs where:
      - package_name is the directory basename (matches [package] name)
      - crate_path   is the workspace-relative Path to the crate directory

    Blank lines and lines starting with '#' are ignored.
    """
    order_file = script_dir / "publish-order"
    if not order_file.exists():
        order_file = Path.cwd() / "publish-order"
    if not order_file.exists():
        die(f"Publish order file not found: {order_file}")

    entries: list[tuple[str, Path]] = []
    for raw in order_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        crate_path = Path(line)
        pkg_name = crate_path.name
        entries.append((pkg_name, crate_path))

    if not entries:
        die(f"No crate entries found in {order_file}")
    return entries


def run(cmd: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def capture(cmd: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, text=True,
                          capture_output=True).stdout.strip()


def confirm(prompt: str) -> bool:
    try:
        answer = input(f"\n{_c(BOLD)}{prompt}{_c(NC)} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def parse_version(v: str) -> tuple[int, int, int]:
    if not _VERSION_RE.match(v):
        die(f"Invalid version '{v}'; expected MAJOR.MINOR.PATCH (e.g. 0.2.0)")
    major, minor, patch = (int(x) for x in v.split("."))
    return major, minor, patch


def version_spec(version: str) -> str:
    """
    Cargo version requirement for inter-crate deps.

    Pre-1.0 (0.x.y): minor is a breaking boundary → spec is "0.MINOR".
    1.0+ (x.y.z):    major is the boundary         → spec is "MAJOR".
    """
    major, minor, _ = parse_version(version)
    return f"{major}.{minor}" if major == 0 else str(major)


def get_current_version(root: Path) -> str:
    text = (root / "Cargo.toml").read_text()
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        die("Could not find version = \"...\" in [workspace.package]")
    return m.group(1)


def get_workspace_name(root: Path) -> str:
    """Return the workspace name from [workspace.package] or the directory name."""
    text = (root / "Cargo.toml").read_text()
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else root.name


# ---------------------------------------------------------------------------
# Commit scoring and changelog generation
# ---------------------------------------------------------------------------

def _kw_re(*keywords: str) -> re.Pattern:
    return re.compile(r'\b(?:' + '|'.join(re.escape(kw) for kw in keywords) + r')\b')


_KW_HIGH_RE = _kw_re(
    "security", "vulnerability", "critical", "breaking",
    "feat", "feature", "implement", "introduce",
    "initial", "fix", "bug", "rewrite", "redesign",
)
_KW_MED_RE = _kw_re(
    "refactor", "rework", "migrate", "remove", "delete", "deprecate",
    "add", "new",
)
_KW_LOW_RE = _kw_re(
    "perf", "optimize", "bench", "benchmark",
    "test", "tests", "spec",
)
_KW_PENALTY_RE = _kw_re(
    "whitespace", "indent", "typo", "spelling",
    "rustfmt", "clippy", "fmt", "format", "style",
    "readme", "comment", "chore", "bump", "workflow",
)
_DOC_RE  = re.compile(r'\b(docs?|documentation)\b')
_CI_RE   = re.compile(r'\b(ci|cd)\b')
_CONV_RE = re.compile(r'^(\w+)(?:\([^)]+\))?(!)?:\s+')

_SCORE_MIN = 5
_CATEGORY_ORDER = ["Security", "Added", "Changed", "Fixed", "Removed"]


def _score(subject: str, files: int, lines: int) -> int:
    subj = subject.lower()
    score = 0
    m = _CONV_RE.match(subject)
    if m and m.group(2):            # breaking change (!)
        score += 50
    if _KW_HIGH_RE.search(subj):
        score += 30
    elif _KW_MED_RE.search(subj):
        score += 15
    elif _KW_LOW_RE.search(subj):
        score += 5
    if _KW_PENALTY_RE.search(subj):
        score -= 25
    elif _DOC_RE.search(subj):
        score -= 20
    elif _CI_RE.search(subj):
        score -= 15
    if files >= 10:   score += 20
    elif files >= 5:  score += 12
    elif files >= 2:  score += 4
    if lines >= 500:  score += 20
    elif lines >= 100: score += 12
    elif lines >= 30:  score += 4
    return score


def _categorize(subject: str) -> str:
    subj = subject.lower()
    m = _CONV_RE.match(subject)
    if m:
        t = m.group(1).lower()
        if t in ("fix", "bugfix"):                 return "Fixed"
        if t in ("feat", "feature"):               return "Added"
        if t in ("refactor", "rework"):            return "Changed"
        if t in ("remove", "delete", "deprecate"): return "Removed"
        if t == "security":                        return "Security"
    if re.search(r'\b(?:fix(?:es|ed)?|bug|error|crash|broken)\b', subj):  return "Fixed"
    if re.search(r'\b(?:remov|delet|deprecat)', subj):                     return "Removed"
    if re.search(r'\b(?:security|vulnerabilit|cve)\b', subj):              return "Security"
    if re.search(r'\b(?:refactor|rework|migrat|reorgan|clean)\b', subj):   return "Changed"
    return "Added"


def _strip_pkg_prefix(subject: str, pkg_name: str) -> str:
    """Strip '<pkg-name>[/submod]: ' or '<dir>/<pkg-name>[/submod]: ' prefix."""
    pat = re.compile(
        r'^(?:[^/:]+/)?' + re.escape(pkg_name) + r'(?:/[^:]+)?:\s+',
        re.IGNORECASE,
    )
    return pat.sub('', subject)


def _find_predecessor_paths(root: Path, rel_path: Path) -> list[Path]:
    """
    Return old directory paths that git renamed into rel_path.

    Uses the Cargo.toml inside the crate as a representative file to find
    rename records (R-status lines) in git history.  --follow works for
    individual files, so this gives us the pre-move directory root.
    """
    probe = rel_path / "Cargo.toml"
    result = subprocess.run(
        ["git", "log", "--follow", "--name-status", "--diff-filter=R",
         "--format=", "--", str(probe)],
        cwd=root, capture_output=True, text=True,
    )
    depth = len(rel_path.parts)
    predecessors: list[Path] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("R"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        old_file = Path(parts[1])
        if len(old_file.parts) < depth:
            continue
        old_dir = Path(*old_file.parts[:depth])
        key = str(old_dir)
        if key not in seen and old_dir != rel_path:
            seen.add(key)
            predecessors.append(old_dir)
    return predecessors


def _git_log_commits(
    root: Path, rel_path: Path, since_ref: str | None
) -> list[tuple[str, str]]:
    """
    Return [(hash, subject)] for non-merge commits that touch rel_path,
    including any predecessor paths found via rename detection.
    """
    paths = [rel_path] + _find_predecessor_paths(root, rel_path)
    range_arg = f"{since_ref}..HEAD" if since_ref else "HEAD"
    seen_hashes: set[str] = set()
    commits: list[tuple[str, str]] = []
    for path in paths:
        result = subprocess.run(
            ["git", "log", "--no-merges", "--format=%H\t%s",
             range_arg, "--", str(path)],
            cwd=root, capture_output=True, text=True,
        )
        for line in result.stdout.splitlines():
            if "\t" not in line:
                continue
            h, subj = line.split("\t", 1)
            h = h.strip()
            if h not in seen_hashes:
                seen_hashes.add(h)
                commits.append((h, subj.strip()))
    return commits


def _git_numstat(
    root: Path, rel_path: Path, since_ref: str | None
) -> dict[str, tuple[int, int]]:
    """
    Return {hash: (files_changed, total_lines)} for commits touching rel_path,
    including any predecessor paths found via rename detection.
    """
    paths = [rel_path] + _find_predecessor_paths(root, rel_path)
    range_arg = f"{since_ref}..HEAD" if since_ref else "HEAD"
    stats: dict[str, tuple[int, int]] = {}
    for path in paths:
        result = subprocess.run(
            ["git", "log", "--no-merges", "--numstat", "--format=__C__ %H",
             range_arg, "--", str(path)],
            cwd=root, capture_output=True, text=True,
        )
        current: str | None = None
        files = added = removed = 0
        for line in result.stdout.splitlines():
            if line.startswith("__C__ "):
                if current is not None and current not in stats:
                    stats[current] = (files, added + removed)
                current = line[6:].strip()
                files = added = removed = 0
            elif current and "\t" in line:
                parts = line.split("\t", 2)
                if len(parts) == 3:
                    a_s, r_s, _ = parts
                    added   += int(a_s) if a_s.isdigit() else 0
                    removed += int(r_s) if r_s.isdigit() else 0
                    files   += 1
        if current is not None and current not in stats:
            stats[current] = (files, added + removed)
    return stats


def generate_changelog_entries(
    root: Path, crate_rel_path: Path, pkg_name: str, since_ref: str | None
) -> dict[str, list[str]]:
    """Return {category: [bullet, ...]} for commits that score >= _SCORE_MIN."""
    commits = _git_log_commits(root, crate_rel_path, since_ref)
    if not commits:
        return {}
    numstat = _git_numstat(root, crate_rel_path, since_ref)

    entries: dict[str, list[str]] = {}
    seen: set[str] = set()
    for h, subject in commits:
        files, lines = numstat.get(h, (0, 0))
        if _score(subject, files, lines) < _SCORE_MIN:
            continue
        clean = _strip_pkg_prefix(subject, pkg_name)
        clean = _CONV_RE.sub('', clean)      # strip "feat: " / "fix(scope): "
        clean = clean[:1].upper() + clean[1:] if clean else clean
        if not clean or clean in seen:
            continue
        seen.add(clean)
        cat = _categorize(subject)
        entries.setdefault(cat, []).append(clean)
    return entries


def format_changelog_body(entries: dict[str, list[str]]) -> str:
    """Format categorized entries as Keep-a-Changelog ### sections."""
    lines: list[str] = []
    for cat in _CATEGORY_ORDER:
        if cat not in entries:
            continue
        lines += [f"### {cat}", ""]
        lines += [f"- {b}" for b in entries[cat]]
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n" if lines else ""


def _fill_section_body(text: str, header_pat: re.Pattern, new_body: str) -> str:
    """
    Replace the body of the first section matched by header_pat with new_body.
    The section runs from the line after the header to the next '## ' or EOF.
    """
    m = header_pat.search(text)
    if m is None:
        return text
    pos = m.end()                   # right after the header line (past its \n)
    nxt = text.find('\n## ', pos)
    body_end = nxt if nxt >= 0 else len(text)
    return text[:pos] + "\n" + new_body.rstrip("\n") + "\n" + text[body_end:]


# ---------------------------------------------------------------------------
# File mutation helpers
# ---------------------------------------------------------------------------

def bump_workspace_version(root: Path, old: str, new: str) -> None:
    path = root / "Cargo.toml"
    text = path.read_text()
    new_text = re.sub(
        r'^(\s*version\s*=\s*)"' + re.escape(old) + r'"',
        lambda m: m.group(1) + f'"{new}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if new_text == text:
        die(f"Could not replace version '{old}' in Cargo.toml")
    path.write_text(new_text)


def bump_dep_version_specs(root: Path, old_spec: str, new_spec: str) -> list[Path]:
    """
    In every crate Cargo.toml, update lines that carry both path = and
    version = "OLD_SPEC" to version = "NEW_SPEC".  Returns changed files.
    """
    if old_spec == new_spec:
        return []

    # Match any line containing 'path =' and 'version = "OLD_SPEC"'.
    line_pat = re.compile(
        r'^(.*\bpath\s*=\s*"[^"]*".*\bversion\s*=\s*)"'
        + re.escape(old_spec) + r'"(.*)',
    )
    changed: list[Path] = []
    for toml in root.rglob("Cargo.toml"):
        if any(part in ("target", ".cargo", "vendor") for part in toml.parts):
            continue
        if toml == root / "Cargo.toml":
            continue  # workspace root handled separately
        text = toml.read_text()
        new_lines = []
        modified = False
        for line in text.splitlines(keepends=True):
            m = line_pat.match(line)
            if m:
                new_lines.append(m.group(1) + f'"{new_spec}"' + m.group(2) + "\n")
                modified = True
            else:
                new_lines.append(line)
        if modified:
            toml.write_text("".join(new_lines))
            changed.append(toml)
    return changed


def bump_crate_spec_versions(root: Path, new_version: str) -> list[Path]:
    """
    Update the Version: field in every rust2rpm-generated rust-kurbu5*.spec
    file found in a crate directory.  Returns the list of changed files.
    """
    changed: list[Path] = []

    for spec in sorted(root.glob("**/rust-kurbu5*.spec")):
        if any(part in ("target", ".cargo", "vendor") for part in spec.parts):
            continue
        text = spec.read_text()
        new_text = re.sub(
            r'^(Version:\s*)\S+',
            lambda m: m.group(1) + new_version,
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if new_text != text:
            spec.write_text(new_text)
            changed.append(spec)

    return changed


def update_changelog(
    path: Path,
    new_version: str,
    today: str,
    root: Path,
    crate_rel_path: Path,
    pkg_name: str,
    since_ref: str | None,
) -> str:
    """
    Generate changelog entries from git history, then either:
      - Rename [Unreleased] → [new_version] — today and fill its body, or
      - Fill the body of an existing [new_version] section.

    Returns "renamed" | "filled" | "pre_filled" | "no_unreleased" | "missing".
    """
    if not path.exists():
        return "missing"

    entries = generate_changelog_entries(root, crate_rel_path, pkg_name, since_ref)
    body = format_changelog_body(entries) if entries else ""

    text = path.read_text()
    unreleased_pat = re.compile(r"^##\s+\[[Uu]nreleased\][^\n]*\n", re.MULTILINE)
    versioned_pat  = re.compile(
        r"^##\s+\[" + re.escape(new_version) + r"\][^\n]*\n", re.MULTILINE
    )

    has_unreleased = bool(unreleased_pat.search(text))
    has_versioned  = bool(versioned_pat.search(text))

    if has_unreleased and not has_versioned:
        # Normal path: rename [Unreleased] → [new_version] — today and fill it.
        if body:
            text = _fill_section_body(text, unreleased_pat, body)
        new_header = f"## [{new_version}] — {today}\n"
        text = unreleased_pat.sub(new_header, text, count=1)
        # Prepend a fresh empty [Unreleased] section
        text = text.replace(new_header, f"## [Unreleased]\n\n\n{new_header}", 1)
        path.write_text(text)
        return "renamed"

    if has_versioned and has_unreleased:
        # Both sections present: the versioned section was pre-populated
        # (hand-written or by a previous script run).  Leave the file
        # untouched — creating another [new_version] block would duplicate it.
        return "pre_filled"

    if has_versioned:
        # Versioned section exists with no [Unreleased] above it; fill if empty.
        if body:
            text = _fill_section_body(text, versioned_pat, body)
            path.write_text(text)
            return "filled"
        return "no_unreleased"

    return "no_unreleased"


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def find_last_tag(root: Path) -> str | None:
    """Return the most recent annotated/lightweight tag, or None if none exist."""
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=root, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None

def assert_clean_tree(root: Path) -> None:
    # Only tracked changes (M, A, D, R, C, U) matter for the release commit.
    # Untracked files (??) and ignored files (!!) do not affect what gets
    # committed or published, so we skip them.
    status = capture(["git", "status", "--porcelain"], cwd=root)
    tracked = [l for l in status.splitlines() if not l.startswith("??") and not l.startswith("!!")]
    if tracked:
        die(
            "Working tree has uncommitted changes.\n"
            "  Commit or stash them before running release.py.\n"
            + "\n".join(tracked)
        )


def git_commit(root: Path, version: str, files: list[Path]) -> bool:
    """Stage files and commit. Returns True if a commit was made, False if nothing changed."""
    run(["git", "add", "--"] + [str(f) for f in files], cwd=root)
    lock = root / "Cargo.lock"
    if lock.exists():
        run(["git", "add", str(lock)], cwd=root)
    staged = capture(["git", "diff", "--cached", "--name-only"], cwd=root)
    if not staged:
        return False
    run(["git", "commit", "-s", "-m", f"release: v{version}"], cwd=root)
    return True


def tag_exists(root: Path, version: str) -> bool:
    result = subprocess.run(
        ["git", "tag", "-l", f"v{version}"],
        cwd=root, capture_output=True, text=True,
    )
    return bool(result.stdout.strip())


def git_tag(root: Path, version: str, *, sign: bool) -> None:
    tag = f"v{version}"
    flag = "-s" if sign else "-a"
    run(["git", "tag", flag, tag, "-m", f"Release {tag}"], cwd=root)


# ---------------------------------------------------------------------------
# Cargo helpers
# ---------------------------------------------------------------------------

def crate_published(pkg: str, version: str) -> bool:
    """Return True if pkg@version is already visible on crates.io."""
    url = f"https://crates.io/api/v1/crates/{pkg}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": "release.py/1 (crate publish check)"})
    try:
        urllib.request.urlopen(req, timeout=15)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise
    except urllib.error.URLError:
        return False


_DEV_DEPS_RE = re.compile(
    r'\n\[dev-dependencies\].*?(?=\n\[|\Z)',
    re.DOTALL,
)


@contextlib.contextmanager
def _no_dev_deps(root: Path, rel_path: Path):
    """
    Temporarily strip [dev-dependencies] from the crate's Cargo.toml.

    cargo package (called internally by cargo publish) resolves ALL
    dependencies including dev-deps, even though they are stripped from the
    published Cargo.toml.  kurbu5-derive and kurbu5-kadm5-derive dev-depend
    on their own "crate under test" sibling (kurbu5-rs, kurbu5-kadm5-rs),
    which is published *after* them in publish-order, so cargo fails during
    the packaging step because that sibling isn't on crates.io yet.
    Stripping [dev-dependencies] before packaging and restoring it after
    breaks the cycle safely.
    """
    manifest = root / rel_path / "Cargo.toml"
    original = manifest.read_text()
    patched = _DEV_DEPS_RE.sub('', original)
    if patched == original:
        yield
        return
    manifest.write_text(patched)
    try:
        yield
    finally:
        manifest.write_text(original)


def cargo_publish_dry_run(root: Path, pkg: str, rel_path: Path) -> bool:
    with _no_dev_deps(root, rel_path):
        result = subprocess.run(
            ["cargo", "publish", "--dry-run", "--allow-dirty", "-p", pkg],
            cwd=root, check=False,
        )
        return result.returncode == 0


_RATE_LIMIT_RE = re.compile(
    r"Please try again after\s+([A-Za-z]+,\s+\d+\s+[A-Za-z]+\s+\d+\s+[\d:]+\s+GMT)",
    re.IGNORECASE,
)
_MAX_RATE_RETRIES = 3


def cargo_publish_one(root: Path, pkg: str, rel_path: Path) -> None:
    """
    Run cargo publish for a single package, retrying automatically on 429.

    Parses 'Please try again after <RFC 2822 date>' from cargo's output and
    sleeps until that moment before retrying.  Gives up after _MAX_RATE_RETRIES
    attempts and re-raises the last error.
    """
    with _no_dev_deps(root, rel_path):
        for attempt in range(1, _MAX_RATE_RETRIES + 1):
            result = subprocess.run(
                ["cargo", "publish", "-p", pkg],
                cwd=root, stderr=subprocess.PIPE, text=True,
            )
            if result.returncode == 0:
                return

            stderr = result.stderr
            print(stderr, end="", flush=True)   # show cargo's output as usual

            m = _RATE_LIMIT_RE.search(stderr)
            if m and attempt < _MAX_RATE_RETRIES:
                retry_after_str = m.group(1)
                try:
                    retry_at = parsedate_to_datetime(retry_after_str)
                except Exception:
                    retry_at = None

                now = datetime.now(timezone.utc)
                if retry_at and retry_at > now:
                    wait_secs = int((retry_at - now).total_seconds()) + 5
                else:
                    wait_secs = 60

                warn(f"Rate-limited by crates.io; waiting {wait_secs}s before retry "
                     f"({attempt}/{_MAX_RATE_RETRIES})")
                _sleep_with_dots(wait_secs)
                continue

            # Non-recoverable error or retries exhausted
            raise subprocess.CalledProcessError(result.returncode,
                                                ["cargo", "publish", "-p", pkg])


def _sleep_with_dots(seconds: int) -> None:
    print(f"  Sleeping {seconds}s", end="", flush=True)
    for _ in range(0, seconds, 5):
        time.sleep(min(5, seconds))
        print(".", end="", flush=True)
    print(flush=True)


def wait_for_propagation(seconds: int, pkg: str) -> None:
    print(f"  Waiting {seconds}s for crates.io to index {pkg}", end="", flush=True)
    for remaining in range(seconds, 0, -5):
        time.sleep(min(5, remaining))
        print(".", end="", flush=True)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Two-phase release tool: prepare (changelog+tag) then publish to crates.io.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Typical release flow:\n"
            "\n"
            "  Phase 1 — prepare (on release branch):\n"
            "  %(prog)s               # preview: inspect changelog + version changes\n"
            "  %(prog)s 0.2.0         # preview: bump to 0.2.0\n"
            "  %(prog)s --do-run      # commit changelogs + tag; print push instructions\n"
            "  %(prog)s --do-run 0.2.0             # bump version, commit, tag\n"
            "  %(prog)s --do-run --skip-ci          # skip local-ci.sh\n"
            "\n"
            "  Phase 2 — publish (on main, after PR merge):\n"
            "  %(prog)s --publish-only              # preview: show what would be published\n"
            "  %(prog)s --do-run --publish-only     # publish all crates to crates.io\n"
        ),
    )
    p.add_argument("version", nargs="?", default=None,
                   help="Version to release (default: current workspace version)")
    p.add_argument("--do-run",       action="store_true",
                   help="Execute the phase (default: preview only)")
    p.add_argument("--publish-only", action="store_true",
                   help="Phase 2: skip prepare, publish crates to crates.io. "
                        "Run on main after the release PR has been merged and pulled.")
    p.add_argument("--skip-ci",      action="store_true",
                   help="Phase 1: skip running local-ci.sh all")
    p.add_argument("--no-sign",      action="store_true",
                   help="Phase 1: create an unsigned annotated tag (when GPG unavailable)")
    p.add_argument("--delay", type=int, default=30, metavar="SECS",
                   help="Phase 2: seconds between cargo publish calls (default: 30)")
    return p.parse_args()


def _do_publish(
    root: Path,
    publish_order: list[tuple[str, Path]],
    new_version: str,
    workspace_name: str,
    delay: int,
) -> None:
    """Publish all crates in order, skipping those already on crates.io."""
    step(f"Publishing {len(publish_order)} crates to crates.io")
    for i, (pkg, rel_path) in enumerate(publish_order):
        prefix = f"[{i + 1}/{len(publish_order)}]"
        if crate_published(pkg, new_version):
            ok(f"{prefix} {pkg} v{new_version} already on crates.io — skipping")
            continue
        info(f"{prefix} cargo publish -p {pkg}")
        cargo_publish_one(root, pkg, rel_path)
        ok(f"{pkg} published")
        if i < len(publish_order) - 1:
            wait_for_propagation(delay, pkg)

    step("Release complete")
    ok(f"{workspace_name} v{new_version} is live on crates.io")


def main() -> None:
    args = parse_args()

    script_dir = Path(__file__).resolve().parent
    root = find_repo_root()
    today = date.today().isoformat()
    workspace_name = get_workspace_name(root)

    publish_order = load_publish_order(script_dir)

    # ── Pre-flight (both phases) ──────────────────────────────────────────────
    step("Pre-flight checks")

    assert_clean_tree(root)
    ok("Working tree is clean")

    branch = capture(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    if branch in ("main", "master"):
        ok(f"On branch {branch}")
    else:
        warn(f"Current branch is '{branch}', not main/master — proceed with caution")

    old_version = get_current_version(root)
    new_version = args.version if args.version is not None else old_version
    if args.version is not None:
        parse_version(new_version)  # validate format

    # Verify all crate paths exist.
    for pkg, rel_path in publish_order:
        if not (root / rel_path).is_dir():
            die(f"Crate path not found: {rel_path} (package '{pkg}')")
    ok(f"{len(publish_order)} crates verified from publish-order")

    # ═════════════════════════════════════════════════════════════════════════
    # Phase 2 — publish-only
    # ═════════════════════════════════════════════════════════════════════════
    if args.publish_only:
        if branch not in ("main", "master"):
            die(f"--publish-only must run on main/master (currently on '{branch}'). "
                "Pull main after the PR is merged, then retry.")

        if not tag_exists(root, new_version):
            die(f"Tag v{new_version} not found — run the prepare phase first "
                "(release.py --do-run), push the tag, merge the PR, then retry.")
        ok(f"Tag v{new_version} confirmed")

        step("Summary")
        info(f"  Version : {new_version}")
        info(f"  Crates  : {', '.join(p for p, _ in publish_order)}")
        info(f"  Delay   : {args.delay}s between publishes")

        # In preview mode, run a dry-run publish check as a safety net.
        if not args.do_run:
            first_pkg, first_rel = publish_order[0]
            step(f"Verifying {first_pkg} with cargo publish --dry-run")
            if cargo_publish_dry_run(root, first_pkg, first_rel):
                ok(f"{first_pkg}: dry-run publish succeeded")
            else:
                die(f"{first_pkg}: dry-run publish failed — fix before publishing")
            print(f"\n{_c(YELLOW)}Preview only — re-run with --do-run to publish.{_c(NC)}")
            sys.exit(0)

        if not confirm(f"Publish {workspace_name} v{new_version} to crates.io?"):
            print("Aborted.")
            sys.exit(1)

        _do_publish(root, publish_order, new_version, workspace_name, args.delay)
        return

    # ═════════════════════════════════════════════════════════════════════════
    # Phase 1 — prepare: changelogs, version bump, check, CI, tag
    # ═════════════════════════════════════════════════════════════════════════
    bumping = (new_version != old_version)

    if bumping:
        old_spec = version_spec(old_version)
        new_spec = version_spec(new_version)
        ok(f"Version: {old_version} → {new_version}  (dep spec: {old_spec!r} → {new_spec!r})")
    else:
        old_spec = new_spec = version_spec(new_version)
        ok(f"Releasing current version {new_version} (no version bump)")

    # ── Find git range for changelog generation ───────────────────────────────
    since_ref = find_last_tag(root)
    if since_ref:
        ok(f"Changelog range: {since_ref}..HEAD")
    else:
        ok("No previous tag — changelog will use full history")

    # ── Changelog update ──────────────────────────────────────────────────────
    step("Updating changelogs")

    cl_statuses: dict[Path, str] = {}
    for pkg, rel_path in publish_order:
        cl_path = root / rel_path / "CHANGELOG.md"
        status = update_changelog(
            cl_path, new_version, today,
            root, rel_path, pkg, since_ref,
        )
        cl_statuses[cl_path] = status
        rel = cl_path.relative_to(root)
        if status == "renamed":
            ok(f"{rel}: [Unreleased] → [{new_version}] — {today}")
        elif status == "filled":
            ok(f"{rel}: [{new_version}] body generated from git history")
        elif status == "pre_filled":
            ok(f"{rel}: [{new_version}] already present — left unchanged")
        elif status == "no_unreleased":
            warn(f"{rel}: no [Unreleased] or [{new_version}] section — skipping")
        elif status == "missing":
            warn(f"{rel}: CHANGELOG.md not found")

    renamed = [p for p, s in cl_statuses.items() if s in ("renamed", "filled")]
    if not renamed:
        info("No changelogs updated")

    # ── Version bump ──────────────────────────────────────────────────────────
    if bumping:
        step("Bumping version")

        bump_workspace_version(root, old_version, new_version)
        ok(f"Cargo.toml: version = \"{new_version}\"")

        changed_tomls = bump_dep_version_specs(root, old_spec, new_spec)
        if changed_tomls:
            for p in changed_tomls:
                ok(f"{p.relative_to(root)}: dep spec → \"{new_spec}\"")
        else:
            info("Inter-crate dep specs unchanged (patch release)")

        all_specs = bump_crate_spec_versions(root, new_version)
        for p in all_specs:
            ok(f"{p.relative_to(root)}: Version: → \"{new_version}\"")
        changed_tomls = changed_tomls + all_specs
    else:
        changed_tomls = []

    # ── cargo check ───────────────────────────────────────────────────────────
    step("Running cargo check --workspace")
    run(["cargo", "check", "--workspace"], cwd=root)
    ok("cargo check passed")

    # ── CI ────────────────────────────────────────────────────────────────────
    if not args.skip_ci:
        step("Running local-ci.sh all")
        try:
            run(["bash", str(root / "contrib" / "ci" / "local-ci.sh"),
                 "--no-deps", "all"], cwd=root)
        except subprocess.CalledProcessError:
            die("CI failed — fix the failing jobs before releasing\n"
                "  Re-run with --skip-ci to bypass once CI is known green")
        ok("CI passed")
    else:
        warn("Skipping CI (--skip-ci)")

    # ── Dry-run publish check ─────────────────────────────────────────────────
    first_pkg, first_rel = publish_order[0]
    step(f"Verifying {first_pkg} with cargo publish --dry-run")
    if cargo_publish_dry_run(root, first_pkg, first_rel):
        ok(f"{first_pkg}: dry-run publish succeeded")
    else:
        die(f"{first_pkg}: dry-run publish failed — fix before releasing")

    # ── Summary ───────────────────────────────────────────────────────────────
    commit_files = (
        ([root / "Cargo.toml"] if bumping else [])
        + changed_tomls
        + renamed
    )

    already_tagged = tag_exists(root, new_version)

    step("Summary")
    info(f"  Version   : {new_version}" + (f"  (bumped from {old_version})" if bumping else "  (no bump)"))
    info(f"  Date      : {today}")
    if already_tagged:
        info(f"  Tag       : v{new_version}  (already exists — will skip)")
    else:
        info(f"  Tag       : v{new_version}  ({'signed' if not args.no_sign else 'unsigned annotated'})")
    info(f"  Changelogs: {len(renamed)}/{len(publish_order)} updated")
    info(f"  Commit    : {'yes — ' + str(len(commit_files)) + ' file(s)' if commit_files else 'none (tag HEAD directly)'}")
    info(f"  Crates    : {', '.join(p for p, _ in publish_order)}")

    if not args.do_run:
        print(f"\n{_c(YELLOW)}Preview only — re-run with --do-run to commit and tag.{_c(NC)}")
        if bumping or renamed:
            print("  Inspect pending changes with:  git diff")
        sys.exit(0)

    # ── Confirm ───────────────────────────────────────────────────────────────
    if not confirm(f"Commit changelogs and tag v{new_version}?"):
        print("Aborted. Working-tree changes are preserved.")
        sys.exit(1)

    # ── Commit + tag ──────────────────────────────────────────────────────────
    step("Committing and tagging")
    if commit_files:
        if git_commit(root, new_version, commit_files):
            ok(f"Committed: release: v{new_version}")
        else:
            ok("Changelogs already up to date — tagging current HEAD")
    else:
        ok("No file changes — tagging current HEAD")

    if already_tagged:
        warn(f"Tag v{new_version} already exists — skipping")
    else:
        try:
            git_tag(root, new_version, sign=not args.no_sign)
        except subprocess.CalledProcessError:
            die(
                f"Failed to create tag v{new_version}.\n"
                "  If GPG signing failed (expired key or no pinentry), retry with:\n"
                f"    release.py --do-run --no-sign"
            )
        ok(f"Tagged: v{new_version}")

    step("Prepare complete — next steps")
    info(f"  1. Push the branch and tag:")
    info(f"       git push origin {branch} --tags")
    info(f"  2. Open a pull request and wait for it to be merged.")
    info(f"  3. Pull main locally:")
    info(f"       git checkout main && git pull")
    info(f"  4. Publish to crates.io:")
    info(f"       release.py --do-run --publish-only")


if __name__ == "__main__":
    main()
