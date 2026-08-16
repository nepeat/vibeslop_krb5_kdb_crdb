#!/usr/bin/env python3
"""doc-rust-samples.py — extract and wrap Rust code blocks from kurbu5 docs.

Called by doc-rust-samples.sh with:
    python3 doc-rust-samples.py <work_dir> <file1.md> [file2.md ...]

Outputs to stdout a single line:
    total_blocks<TAB>skip_blocks

Writes to <work_dir>:

  raw/NNNNN.rs          — raw extracted code (no wrapper)
  src/NNNNN.rs          — wrapped, ready-to-compile translation unit
  src/NNNNN.combined.rs — preceding toplevel/program blocks prepended before
                          the current block (only when preceding blocks exist
                          in the same doc file); used for the retry step
  manifest.tsv          — tab-separated, one row per compilable block:
      doc_file  start_line  lang  src_file  kind  raw_file  combined_file

kind values
-----------
  skip_annotated — fenced block has ``ignore`` or ``compile_fail`` annotation
  skip_nonkdb    — no kurbu5_kdb_rs identifier found; skip
  program        — has ``fn main()``; main is renamed, compiled as lib
  toplevel       — top-level fn/struct/impl/type/etc definition
  fragment       — standalone statements; wrapped in a harness function
"""

import os
import re
import sys


# ── Regexps ──────────────────────────────────────────────────────────────────

# Block must reference a kurbu5 crate identifier to be worth compiling.
# Matches KDB crate identifiers and KADM5 crate identifiers.
KDB_RE = re.compile(
    r"\bkurbu5_kdb_rs\b|\bKdbModule\b|\bkdb_plugin\b"
    r"|\bkurbu5_kadm5_rs\b|\bkurbu5_kadm5_sys\b"
    r"|\bAdminHandle\b|\bKadm5AuthModule\b|\bKadm5HookModule\b"
)

FENCE_RE = re.compile(r"^```rust(?:,(\S+))?\s*$", re.IGNORECASE)

# fn main() → complete program block.
MAIN_RE = re.compile(r"\bfn\s+main\s*\(\s*\)")

# Top-level Rust item definitions that begin at column 0 (possibly prefixed
# with a visibility modifier and/or qualifiers).  Covers:
#   fn, async fn, unsafe fn, extern "C" fn,
#   struct, enum, impl (including impl Trait for Type),
#   type alias, const, static, trait, macro_rules!
TOPLEVEL_RE = re.compile(
    r"^(?:pub(?:\s*\([^)]*\))?\s+)?"  # optional visibility (pub / pub(crate) / …)
    r"(?:async\s+)?(?:unsafe\s+)?"  # optional qualifiers
    r'(?:extern\s+"[^"]+"\s+)?'  # optional extern ABI
    r"(?:fn|struct|enum|impl|type|const|static|trait|macro_rules!)\b",
    re.MULTILINE,
)

# Fenced-block annotations that mean "this block is deliberately not
# compilable" and should be skipped entirely.
#   ignore       — rustdoc explicitly ignores this block
#   compile_fail — block is expected to fail compilation (anti-pattern doc)
SKIP_ANNOTATIONS = frozenset({"ignore", "compile_fail"})


# ── Source wrappers ──────────────────────────────────────────────────────────

# File-level preamble applied to every generated translation unit.
# The glob import brings all publicly re-exported kurbu5_kdb_rs types into
# scope so that snippets using full paths or short forms both resolve.
PREAMBLE = """\
// Auto-generated wrapper for kurbu5 documentation snippet.
#![allow(
    unused_imports,
    unused_variables,
    unused_mut,
    dead_code,
    unused_must_use,
    unreachable_code,
    unused_assignments,
)]
use std::ffi::CStr;
use kurbu5_kdb_rs::*;
use kurbu5_kadm5_rs::*;
use kurbu5_kadm5_rs::sys::*;
"""

# Pre-declared identifiers for fragment harness functions.  These cover
# variables that appear in doc snippets which show partial code assuming
# context supplied by the surrounding prose.
#
# Pre-declarations live in the outer scope; the fragment itself is placed
# in a nested { } block, so re-declaring any of these identifiers inside
# the fragment simply shadows the outer binding rather than causing a
# "duplicate declaration" error.
FRAGMENT_VARS = """\
    // ── pre-declared identifiers for doc fragment compilation ──
    let _conf_section: &str = "kerberos";
    let _db_args: &[&str] = &[];
"""

_HARNESS_RETURN = "std::result::Result<(), Box<dyn std::error::Error>>"

# ── PREAMBLE use-deduplication helpers ────────────────────────────────────────


def _extract_use_bound_names(use_stmt: str) -> set[str]:
    """Return the identifier names bound by a single ``use X;`` statement.

    Examples::
        "use std::ffi::CStr;"                     → {"CStr"}
        "use kurbu5_kadm5_rs::admin::AdminHandle;" → {"AdminHandle"}
        "use kurbu5_kadm5_rs::{A, B, C};"         → {"A", "B", "C"}
        "use foo as bar;"                          → {"bar"}
        "use foo::*;"                              → set()  # glob, skip
    """
    path = use_stmt[len("use ") : -1].strip()
    if path.endswith("::*") or path == "*":
        return set()
    if "{" in path and path.endswith("}"):
        brace_content = path[path.index("{") + 1 : -1]
        names: set[str] = set()
        for item in brace_content.split(","):
            item = item.strip()
            if not item:
                continue
            if " as " in item:
                _, alias = item.rsplit(" as ", 1)
                names.add(alias.strip())
            else:
                names.add(item.split("::")[-1].strip())
        return names
    if " as " in path:
        _, alias = path.rsplit(" as ", 1)
        return {alias.strip()}
    return {path.split("::")[-1].strip()}


# Exact `use X;` lines present in PREAMBLE (single-line forms only).
_PREAMBLE_USES: frozenset[str] = frozenset(
    line.strip()
    for line in PREAMBLE.splitlines()
    if line.strip().startswith("use ") and line.strip().endswith(";")
)

# Names publicly re-exported at the `kurbu5_kadm5_rs` crate root (with the
# features admin + kadm5_auth + kadm5_hook enabled).  These are the names
# that `use kurbu5_kadm5_rs::*;` brings into scope.  Sub-module imports that
# bind one of these names conflict with the PREAMBLE glob (E0255).
#
# NOTE: `AdminHandle` is NOT listed here because it lives in the `admin`
# sub-module and is NOT re-exported at the crate root — so
# `use kurbu5_kadm5_rs::admin::AdminHandle;` must NOT be stripped.
_KADM5_GLOB_EXPORTS: frozenset[str] = frozenset(
    {
        "PluginContext",
        "Krb5Error",
        "Kadm5PrincipalEntry",
        "initvt_plugin",
        # kadm5_auth feature
        "AddPrincRequest",
        "Kadm5AuthModule",
        "ModPrincRequest",
        # kadm5_hook feature
        "ChpassRequest",
        "CreatePrincRequest",
        "HookStage",
        "Kadm5HookModule",
        "ModifyPrincRequest",
    }
)

# All names that PREAMBLE imports bring into scope.  A `use` line in a block
# that binds only names from this set is redundant and will cause E0252/E0255.
_PREAMBLE_BOUND_NAMES: frozenset[str] = (
    frozenset().union(
        *(_extract_use_bound_names(u) for u in _PREAMBLE_USES)
    )
    | _KADM5_GLOB_EXPORTS
)


def _strip_conflicts(code: str, seen_uses: set[str]) -> str:
    """Remove ``use`` lines from *code* that would conflict with *seen_uses*.

    A line is dropped when:
    * It is an exact member of *seen_uses* (E0252 duplicate), OR
    * Every name it binds is already in ``_PREAMBLE_BOUND_NAMES`` (E0255 via
      the PREAMBLE glob import ``use kurbu5_kadm5_rs::*;``).
    """
    out: list[str] = []
    for line in code.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("use ") and stripped.endswith(";"):
            if stripped in seen_uses:
                continue
            names = _extract_use_bound_names(stripped)
            if names and names.issubset(_PREAMBLE_BOUND_NAMES):
                continue
        out.append(line)
    return "".join(out)


def _strip_preamble_conflicts(code: str) -> str:
    """Remove ``use`` lines from *code* that would conflict with PREAMBLE."""
    return _strip_conflicts(code, _PREAMBLE_USES)


# ── Batch compilation support ─────────────────────────────────────────────────
#
# When all samples are compiled as a single lib.rs (each in its own named
# module), cargo is invoked once rather than once per block, which
# substantially reduces wall-clock time on large doc suites.  Blocks that
# fail in the batch are identified via compiler error line numbers and retried
# individually so that error messages remain clean and block-specific.

# File-level header for the combined lib.rs.  Module-level use-imports go
# inside each mod {} block; only crate attributes belong here.
_BATCH_FILE_HEADER = """\
// Auto-generated batch file for kurbu5 documentation sample validation.
#![allow(
    unused_imports,
    unused_variables,
    unused_mut,
    dead_code,
    unused_must_use,
    unreachable_code,
    unused_assignments,
)]
"""

# use-import lines placed at the top of every module (4-space indent).
_MODULE_USES = (
    "    use std::ffi::CStr;\n"
    "    use kurbu5_kdb_rs::*;\n"
    "    use kurbu5_kadm5_rs::*;\n"
    "    use kurbu5_kadm5_rs::sys::*;\n"
)


def _indent4(text: str) -> str:
    """Indent every line of *text* by four spaces."""
    return "\n".join("    " + line for line in text.splitlines())


def wrap_for_batch(code: str, kind: str, n: int) -> str:
    """Wrap *code* as ``mod _sample_NNNNN { … }`` for single-pass compilation.

    Each module is self-contained (includes its own use-imports) so that
    blocks compile in isolation.  Blocks that require types defined in a
    preceding block will fail the batch and be retried via the individual
    combined-file path in the shell driver.
    """
    name = f"_sample_{n:05d}"
    if kind == "program":
        renamed = re.sub(r"\bfn\s+main\s*\(\s*\)", "fn _kdb_doc_main()", code)
        body = _indent4(_strip_preamble_conflicts(renamed).rstrip("\n"))
    elif kind == "toplevel":
        body = _indent4(_strip_preamble_conflicts(code).rstrip("\n"))
    else:  # fragment
        frag_vars = "\n".join(
            "        " + line for line in FRAGMENT_VARS.rstrip("\n").splitlines()
        )
        indented_code = "\n".join("            " + line for line in code.splitlines())
        body = (
            f"    fn _kdb_doc_sample() -> {_HARNESS_RETURN} {{\n"
            + frag_vars + "\n"
            + "        // ── fragment (nested scope allows re-declaration) ──\n"
            + "        {\n"
            + indented_code + "\n"
            + "        }\n"
            + "        Ok(())\n"
            + "    }"
        )
    return f"mod {name} {{\n{_MODULE_USES}\n{body}\n}}\n"


def classify(code: str, annotation: str) -> str:
    """Classify a Rust code block.  Returns one of the kind strings above."""
    if annotation in SKIP_ANNOTATIONS:
        return "skip_annotated"
    if not KDB_RE.search(code):
        return "skip_nonkdb"
    if MAIN_RE.search(code):
        return "program"
    if TOPLEVEL_RE.search(code):
        return "toplevel"
    return "fragment"


def wrap_program(code: str) -> str:
    """Rename fn main() so the snippet compiles as a lib crate."""
    renamed = re.sub(r"\bfn\s+main\s*\(\s*\)", "fn _kdb_doc_main()", code)
    return PREAMBLE + "\n" + _strip_preamble_conflicts(renamed) + "\n"


def wrap_toplevel(code: str) -> str:
    """Place a top-level item block at file scope with the standard preamble."""
    return PREAMBLE + "\n" + _strip_preamble_conflicts(code) + "\n"


def wrap_fragment(code: str) -> str:
    """Wrap standalone statement blocks in a harness function.

    The harness returns ``std::result::Result<(), Box<dyn std::error::Error>>``
    (fully-qualified) so that the ``?`` operator works inside the fragment
    without any additional annotation.  The fragment is placed in a nested
    ``{ }`` scope so that re-declarations of any pre-declared identifier
    simply shadow (rather than conflict with) the outer binding.
    """
    indented = "\n".join("        " + line for line in code.splitlines())
    return (
        PREAMBLE
        + f"\nfn _kdb_doc_sample() -> {_HARNESS_RETURN} {{\n"
        + FRAGMENT_VARS
        + "    // ── fragment (nested scope allows re-declaration) ──\n"
        + "    {\n"
        + indented
        + "\n"
        + "    }\n"
        + "    Ok(())\n"
        + "}\n"
    )


def wrap(code: str, kind: str) -> str:
    """Dispatch to the appropriate wrapper based on kind."""
    if kind == "program":
        return wrap_program(code)
    if kind == "toplevel":
        return wrap_toplevel(code)
    return wrap_fragment(code)


def wrap_combined(prev_codes: list[str], cur_code: str, cur_kind: str) -> str:
    """Combine preceding toplevel/program blocks with the current block.

    Preceding blocks are placed at file scope so that any types, functions,
    or constants they define are visible to the current block.  The current
    block is then wrapped according to its own kind.

    ``fn main()`` in each preceding block is renamed to a unique private
    name so that the combined file never has duplicate ``main`` definitions.
    ``use`` declarations that are already provided by the PREAMBLE glob
    imports are dropped to avoid E0252 redeclaration errors.
    """
    # Pre-seed seen_uses with PREAMBLE lines so that preceding blocks that
    # repeat PREAMBLE imports are also stripped (avoids E0252/E0255).
    seen_uses: set[str] = set(_PREAMBLE_USES)
    prev_parts: list[str] = []
    for i, code in enumerate(prev_codes):
        # Rename fn main() to avoid E0428.
        renamed = re.sub(
            r"\bfn\s+main\s*\(\s*\)",
            f"fn _kdb_doc_prev_{i}()",
            code,
        )
        # Drop `use` lines that duplicate PREAMBLE or an earlier block.
        cleaned = _strip_conflicts(renamed, seen_uses)
        # Accumulate surviving uses so the next block can dedup against them.
        for line in cleaned.splitlines():
            stripped = line.strip()
            if stripped.startswith("use ") and stripped.endswith(";"):
                seen_uses.add(stripped)
        prev_parts.append(cleaned)

    # Dedup the current block against PREAMBLE + all preceding blocks.
    cur_code_cleaned = _strip_conflicts(cur_code, seen_uses)
    prefix = PREAMBLE + "\n" + "".join(prev_parts) + "\n"
    return prefix + wrap(cur_code_cleaned, cur_kind)[len(PREAMBLE):]


# ── Main extraction loop ──────────────────────────────────────────────────────


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(
            f"Usage: {sys.argv[0]} <work_dir> [file.md ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    work_dir = args[0]
    md_files = args[1:]

    raw_dir = os.path.join(work_dir, "raw")
    src_dir = os.path.join(work_dir, "src")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(src_dir, exist_ok=True)

    manifest_rows: list[str] = []
    block_n = 0
    skip_n = 0

    # Batch lib accumulator: all compilable blocks as named modules in one file.
    batch_lines: list[str] = _BATCH_FILE_HEADER.splitlines(keepends=True)
    batch_map_rows: list[str] = []  # block_n \t module_name \t line_start \t line_end

    # Per-file accumulation of raw code from toplevel/program blocks.  When a
    # later block in the same file fails to compile standalone (e.g. it uses a
    # type or helper function defined in an earlier block), the shell script
    # retries with a combined file that prepends ALL preceding toplevel/program
    # blocks from the same document.  Key = md_file path, value = list of raw
    # code strings in document order.
    file_toplevel_history: dict[str, list[str]] = {}

    for md_path in md_files:
        try:
            with open(md_path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            print(f"warning: cannot read {md_path}: {exc}", file=sys.stderr)
            continue

        in_block = False
        annotation = ""
        start_line = 0
        buf: list[str] = []

        for lineno, line in enumerate(lines, 1):
            if not in_block:
                # Match ```rust or ```rust,<annotation> fenced-block openers.
                m = FENCE_RE.match(line)
                if m:
                    annotation = (m.group(1) or "").lower()
                    in_block = True
                    start_line = (
                        lineno + 1
                    )  # +1: opening ``` line is not part of the block
                    buf = []
            else:
                if line.startswith("```"):
                    in_block = False
                    if buf:
                        block_n += 1
                        code = "".join(buf)

                        raw_path = os.path.join(raw_dir, f"{block_n:05d}.rs")
                        with open(raw_path, "w", encoding="utf-8") as fh:
                            fh.write(code)

                        kind = classify(code, annotation)

                        if kind.startswith("skip"):
                            skip_n += 1
                        else:
                            src_path = os.path.join(src_dir, f"{block_n:05d}.rs")
                            with open(src_path, "w", encoding="utf-8") as fh:
                                fh.write(wrap(code, kind))

                            # Append this block as a named module to the batch lib.
                            mod_content = wrap_for_batch(code, kind, block_n)
                            mod_lines = mod_content.splitlines(keepends=True)
                            line_start = len(batch_lines) + 1
                            batch_lines.extend(mod_lines)
                            batch_map_rows.append(
                                f"{block_n}\t_sample_{block_n:05d}"
                                f"\t{line_start}\t{len(batch_lines)}"
                            )

                            # Build a combined file so the shell script can
                            # retry when the current block depends on types or
                            # functions defined in a preceding block of the
                            # same doc file.
                            combined_path = ""
                            prev = file_toplevel_history.get(md_path, [])
                            if prev:
                                combined_path = os.path.join(
                                    src_dir, f"{block_n:05d}.combined.rs"
                                )
                                with open(combined_path, "w", encoding="utf-8") as fh:
                                    fh.write(wrap_combined(prev, code, kind))

                            if kind in ("toplevel", "program"):
                                file_toplevel_history.setdefault(md_path, []).append(
                                    code
                                )

                            # Only compilable blocks appear in the manifest.
                            # Skipped blocks are excluded to avoid empty-field
                            # issues when bash reads tab-separated fields.
                            manifest_rows.append(
                                "\t".join(
                                    [
                                        md_path,
                                        str(start_line),
                                        "rust",
                                        src_path,
                                        kind,
                                        raw_path,
                                        combined_path,
                                    ]
                                )
                            )

                    buf = []
                else:
                    buf.append(line)

    manifest_path = os.path.join(work_dir, "manifest.tsv")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(manifest_rows))
        if manifest_rows:
            fh.write("\n")

    # Write batch lib.rs (all blocks as named modules) and the line-range map
    # that the shell driver uses to identify which modules failed.
    batch_dir = os.path.join(work_dir, "batch")
    os.makedirs(batch_dir, exist_ok=True)
    with open(os.path.join(batch_dir, "lib.rs"), "w", encoding="utf-8") as fh:
        fh.writelines(batch_lines)
    with open(os.path.join(batch_dir, "map.tsv"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(batch_map_rows))
        if batch_map_rows:
            fh.write("\n")

    # Single line on stdout consumed by the shell script:
    # total_blocks<TAB>skip_blocks
    print(f"{block_n}\t{skip_n}")


if __name__ == "__main__":
    main()
