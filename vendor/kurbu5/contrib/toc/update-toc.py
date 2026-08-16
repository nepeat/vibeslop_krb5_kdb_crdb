#!/usr/bin/env python3
"""
update-toc.py — insert or update a doctoc-compatible Table of Contents in Markdown files.

Usage:
    ./contrib/toc/update-toc.py                      # update all workspace .md files
    ./contrib/toc/update-toc.py kurbu5-kdb/README.md        # update a specific file
    ./contrib/toc/update-toc.py --docs-dir kurbu5-kdb/      # update files in one directory
    ./contrib/toc/update-toc.py --check               # exit 1 if any TOC is outdated
    ./contrib/toc/update-toc.py -v kurbu5-kdb/README.md     # show status for every file

If no FILE.md arguments and no --docs-dir are given, every .md file in the
workspace is processed (the build directory and vendor directory are excluded
automatically).

The script inserts a block bounded by doctoc-compatible HTML comment markers.
Existing markers are updated in-place; files without markers get the block
injected after the first H1 heading (or at the very top if there is no H1).

Headings titled exactly "Table of Contents" or "Contents" are excluded from
the generated TOC so that pre-existing manual sections do not self-reference.
"""

import argparse
import re
import sys
from pathlib import Path

START_MARKER = (
    "<!-- START doctoc generated TOC please keep comment here to allow auto update -->"
)
END_MARKER = (
    "<!-- END doctoc generated TOC please keep comment here to allow auto update -->"
)
DONT_EDIT = (
    "<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->"
)

_SKIP_TITLES = frozenset({"table of contents", "contents"})

# Single-component directory names excluded from the workspace-wide scan.
_EXCLUDED_DIRS = frozenset({'target', '.cargo', 'vendor'})

# File names excluded from the workspace-wide scan regardless of location.
_EXCLUDED_NAMES = frozenset({'CHANGELOG.md'})


# ---------------------------------------------------------------------------
# Repo root and file collection
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    """Return the repository root, detected from the script location."""
    # Script lives at <repo>/contrib/toc/update-toc.py → two parents up.
    candidate = Path(__file__).resolve().parent.parent.parent
    if (candidate / 'Cargo.toml').exists():
        return candidate
    # Fallback: walk upward from cwd.
    p = Path.cwd().resolve()
    while p != p.parent:
        if (p / 'Cargo.toml').exists():
            return p
        p = p.parent
    return Path.cwd()


def _is_excluded(path: Path, repo_root: Path) -> bool:
    """Return True if *path* falls under an excluded directory or has an excluded name."""
    if path.name in _EXCLUDED_NAMES:
        return True
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return False
    return any(part in _EXCLUDED_DIRS or part.startswith('.') for part in rel.parts)


def collect_files(
    explicit: list,
    docs_dir,
    repo_root: Path,
) -> list:
    """
    Resolve the list of Markdown files to process.

    Priority:
      1. Explicit FILE.md arguments — use exactly those.
      2. --docs-dir DIR             — scan that directory.
      3. Neither                    — workspace-wide scan with standard exclusions.
    """
    if explicit:
        paths = []
        for f in explicit:
            p = Path(f)
            if not p.is_file():
                print(f"error: {f}: not found", file=sys.stderr)
                sys.exit(1)
            paths.append(p)
        return paths

    if docs_dir:
        base = Path(docs_dir)
        if not base.is_dir():
            print(f"error: --docs-dir {docs_dir!r}: not a directory", file=sys.stderr)
            sys.exit(1)
        return sorted(base.rglob('*.md'))

    # Default: workspace-wide scan.
    return sorted(
        p for p in repo_root.rglob('*.md')
        if not _is_excluded(p, repo_root)
    )


# ---------------------------------------------------------------------------
# Anchor generation (GitHub / Codeberg flavoured Markdown)
# ---------------------------------------------------------------------------

def make_anchor(title: str) -> str:
    """Convert a heading title to a GitHub-style anchor slug."""
    # Strip inline code — keep the text inside backticks
    title = re.sub(r'`([^`]*)`', r'\1', title)
    # Strip links — keep the display text
    title = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', title)
    # Strip bold / italic markers
    title = re.sub(r'[*_]{1,3}([^*_]+)[*_]{1,3}', r'\1', title)
    # Strip HTML tags
    title = re.sub(r'<[^>]+>', '', title)
    title = title.lower()
    # Drop everything except word characters, whitespace, and hyphens
    title = re.sub(r'[^\w\s-]', '', title)
    # Collapse whitespace runs to a single hyphen
    title = re.sub(r'\s+', '-', title.strip())
    # Collapse consecutive hyphens
    title = re.sub(r'-+', '-', title)
    return title


# ---------------------------------------------------------------------------
# Heading extraction — skips fenced code blocks
# ---------------------------------------------------------------------------

def extract_headings(text: str) -> list:
    """Return (level, title) for every ATX heading outside a fenced code block."""
    headings = []
    in_fence = False
    fence_char = ''
    fence_len = 0

    for line in text.splitlines():
        stripped = line.strip()

        # Detect opening / closing fences (``` or ~~~, 3+ chars)
        fence_m = re.match(r'^(`{3,}|~{3,})', stripped)
        if fence_m:
            fc = fence_m.group(1)[0]
            fl = len(fence_m.group(1))
            if not in_fence:
                in_fence = True
                fence_char = fc
                fence_len = fl
            elif fc == fence_char and fl >= fence_len:
                in_fence = False
                fence_char = ''
                fence_len = 0
            continue

        if in_fence:
            continue

        # ATX heading (leading #s, optional closing #s)
        m = re.match(r'^(#{1,6})\s+(.+?)(?:\s+#+)?\s*$', line)
        if m:
            headings.append((len(m.group(1)), m.group(2).strip()))

    return headings


# ---------------------------------------------------------------------------
# TOC generation
# ---------------------------------------------------------------------------

def generate_toc_lines(headings: list) -> list:
    """Build indented Markdown list items for the TOC."""
    if not headings:
        return []

    # Skip the first H1 — it is the document title
    if headings[0][0] == 1:
        headings = headings[1:]

    # Drop any heading that is itself a "Table of Contents" section
    headings = [
        (lvl, t) for lvl, t in headings
        if t.strip().lower() not in _SKIP_TITLES
    ]

    if not headings:
        return []

    min_level = min(lvl for lvl, _ in headings)
    seen: dict = {}
    lines = []

    for level, title in headings:
        anchor = make_anchor(title)
        if anchor in seen:
            seen[anchor] += 1
            anchor = f"{anchor}-{seen[anchor]}"
        else:
            seen[anchor] = 0
        indent = '  ' * (level - min_level)
        lines.append(f"{indent}- [{title}](#{anchor})")

    return lines


def build_toc_block(toc_lines: list) -> str:
    """Wrap TOC lines in doctoc-compatible marker comments."""
    return '\n'.join([
        START_MARKER,
        DONT_EDIT,
        '**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*',
        '',
        *toc_lines,
        '',
        END_MARKER,
    ])


# ---------------------------------------------------------------------------
# Text manipulation
# ---------------------------------------------------------------------------

def _insert_toc(text: str, toc_block: str) -> str:
    """Insert the TOC block after the first H1 (or at the top if none)."""
    lines = text.splitlines()
    insert_pos = 0

    for i, line in enumerate(lines):
        if re.match(r'^#\s+', line):
            insert_pos = i + 1
            # Consume any blank lines that immediately follow the title
            while insert_pos < len(lines) and not lines[insert_pos].strip():
                insert_pos += 1
            break

    insertion = [toc_block, '']
    new_lines = lines[:insert_pos] + insertion + lines[insert_pos:]
    result = '\n'.join(new_lines)
    if text.endswith('\n'):
        result += '\n'
    return result


def _update_toc(text: str, toc_block: str) -> str:
    """Replace the content between existing markers with the fresh TOC block."""
    pattern = re.compile(
        re.escape(START_MARKER) + r'.*?' + re.escape(END_MARKER),
        re.DOTALL,
    )
    return pattern.sub(toc_block, text)


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------

def process_file(path: Path, *, check: bool, verbose: bool) -> bool | None:
    """
    Insert or update the TOC in *path*.

    Returns True when the file was modified (or would need modification in
    --check mode), False when up to date, or None when skipped (no headings).
    """
    text = path.read_text(encoding='utf-8')
    headings = extract_headings(text)
    toc_lines = generate_toc_lines(headings)

    if not toc_lines:
        if verbose:
            print(f"  {path}: no headings — skipped")
        return None

    toc_block = build_toc_block(toc_lines)
    has_markers = START_MARKER in text

    new_text = _update_toc(text, toc_block) if has_markers else _insert_toc(text, toc_block)

    if new_text == text:
        if verbose:
            print(f"  {path}: up to date")
        return False

    if check:
        print(f"  {path}: TOC outdated (run update-toc.py to fix)")
        return True

    path.write_text(new_text, encoding='utf-8')
    print(f"  {path}: updated")
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Insert or update a doctoc-compatible TOC in Markdown files.',
        epilog=(
            'Examples:\n'
            '  %(prog)s                         # update all workspace .md files\n'
            '  %(prog)s kurbu5-kdb/README.md README.md # update specific files\n'
            '  %(prog)s --docs-dir kurbu5-kdb/         # update files in one directory\n'
            '  %(prog)s --check                 # CI check — exit 1 if any TOC outdated\n'
            '  %(prog)s -v kurbu5-kdb/README.md        # verbose: show status for every file'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('files', nargs='*', metavar='FILE',
                        help='Markdown files to process (default: all workspace .md files)')
    parser.add_argument('--docs-dir', metavar='DIR',
                        help='Search for .md files in DIR instead of the whole workspace')
    parser.add_argument('--check', action='store_true',
                        help='Exit 1 if any TOC is outdated; do not write files')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print a status line for every file, including up-to-date ones')
    args = parser.parse_args()

    repo_root = _find_repo_root()
    md_files = collect_files(args.files, args.docs_dir, repo_root)

    if not md_files:
        print("error: no Markdown files found", file=sys.stderr)
        sys.exit(1)

    updated = skipped = up_to_date = 0
    for path in md_files:
        result = process_file(path, check=args.check, verbose=args.verbose)
        if result is None:
            skipped += 1
        elif result:
            updated += 1
        else:
            up_to_date += 1

    print(
        f"\nResults: {updated} updated, {up_to_date} up to date, {skipped} skipped"
        + (" (--check mode, no files written)" if args.check and updated else "")
    )

    if args.check and updated:
        sys.exit(1)


if __name__ == '__main__':
    main()
