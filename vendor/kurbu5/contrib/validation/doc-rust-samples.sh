#!/usr/bin/env bash
# contrib/validation/doc-rust-samples.sh — validate Rust samples in kurbu5 docs
#
# Extracts every fenced Rust code block from the documentation, wraps each
# one in a compilable translation unit, and reports failures with the
# originating file and line number.
#
# Delegates all markdown parsing, classification, and source-file wrapping to
# the companion script doc-rust-samples.py, then type-checks each generated
# file by writing it to a temporary Cargo project and running `cargo check`.
#
# Usage:
#   ./contrib/validation/doc-rust-samples.sh [OPTIONS] [FILE.md ...]
#
# If no FILE.md arguments and no --docs-dir are given, every .md file in
# the workspace is processed (build directories are excluded automatically).
#
# Options:
#   --docs-dir DIR     Search for .md files in DIR instead of the whole workspace
#   --verbose, -v      Print a line for every block, not just failures
#   --help, -h         Show this message and exit
#
# Exit status: 0 if all samples compiled successfully, 1 if any failed.

# Require bash 4+
if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "error: bash 4 or later is required (you have ${BASH_VERSION:-unknown})" >&2
    exit 1
fi

set -euo pipefail

# ── Colour helpers (honour NO_COLOR=1) ──────────────────────────────────────
if [[ "${NO_COLOR:-}" == "1" ]]; then
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
fi

# ── Locate repo root ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────
DOCS_DIR=""   # empty = workspace-wide scan; set via --docs-dir
VERBOSE=0
EXTRA_MD_FILES=()

# ── Helpers ──────────────────────────────────────────────────────────────────
die()  { printf "${RED}error:${NC} %s\n" "$*" >&2; exit 1; }
info() { printf "${CYAN}%s${NC}\n" "$*"; }

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
}

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --docs-dir)   DOCS_DIR="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=1;     shift   ;;
        --help|-h)    usage; exit 0          ;;
        *.md)         EXTRA_MD_FILES+=("$1"); shift ;;
        *)            die "Unknown option: $1" ;;
    esac
done

# ── Preflight checks ─────────────────────────────────────────────────────────
command -v python3 &>/dev/null || die "python3 is required but not found"
command -v cargo   &>/dev/null || die "cargo is required but not found"

PYTHON_SCRIPT="$SCRIPT_DIR/doc-rust-samples.py"
[[ -f "$PYTHON_SCRIPT" ]] ||
    die "doc-rust-samples.py not found next to this script (expected: $PYTHON_SCRIPT)"

# ── Temp workspace ───────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ── Collect markdown files ───────────────────────────────────────────────────
MD_FILES=()
if [[ ${#EXTRA_MD_FILES[@]} -gt 0 ]]; then
    # Explicit files given on the command line — use exactly those.
    MD_FILES=("${EXTRA_MD_FILES[@]}")
elif [[ -n "$DOCS_DIR" ]]; then
    # --docs-dir was given — restrict search to that directory.
    while IFS= read -r f; do
        MD_FILES+=("$f")
    done < <(find "$DOCS_DIR" -name '*.md' -type f | sort)
else
    # Default: scan all workspace-owned markdown files, excluding build
    # directories and vendor directories.
    while IFS= read -r f; do
        MD_FILES+=("$f")
    done < <(find "$REPO_ROOT" -name '*.md' -type f \
        ! -path '*/target/*' \
        ! -path '*/.cargo/*' \
        ! -path '*/vendor/*' \
        | sort)
fi

[[ ${#MD_FILES[@]} -gt 0 ]] ||
    die "No markdown files found"

# ── Banner ───────────────────────────────────────────────────────────────────
printf '\n'
info "kurbu5 documentation Rust sample validator"
info "==========================================="
printf 'Repo root: %s\n'                 "$REPO_ROOT"
printf 'Sources  : %d markdown file(s)\n' "${#MD_FILES[@]}"
printf '\n'

# ── Run Python extractor ─────────────────────────────────────────────────────
MANIFEST="$WORK_DIR/manifest.tsv"
PY_OUTPUT=$(python3 "$PYTHON_SCRIPT" "$WORK_DIR" "${MD_FILES[@]}")
# Python emits "total<TAB>skipped" on stdout.
# ${var%%pattern}  removes the longest suffix match  → keeps everything before the first tab.
# ${var##pattern}  removes the longest prefix match  → keeps everything after the last tab.
TOTAL_BLOCKS="${PY_OUTPUT%%$'\t'*}"
SKIP="${PY_OUTPUT##*$'\t'}"
printf 'Extracted %s Rust code block(s) (%s skipped)\n\n' \
    "$TOTAL_BLOCKS" "$SKIP"

if [[ ! -s "$MANIFEST" ]]; then
    printf "${YELLOW}No compilable Rust code blocks found in the specified files.${NC}\n"
    exit 0
fi

# ── Build the temporary Cargo check crate ───────────────────────────────────
# All snippets are type-checked by writing them to src/lib.rs of a single
# temporary Cargo project that depends on kurbu5-kdb-rs via a path dependency.
# Using the repo's own target directory means kurbu5-kdb-rs and its dependencies
# (already compiled by the normal workspace build) are reused across all
# snippet checks, keeping per-snippet overhead to just the re-analysis of
# the tiny lib.rs file.
CRATE_DIR="$WORK_DIR/crate"
mkdir -p "$CRATE_DIR/src"

cat > "$CRATE_DIR/Cargo.toml" <<EOF
[package]
name    = "kurbu5-doc-check"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
kurbu5-kdb-rs    = { path = "$REPO_ROOT/kurbu5-kdb/kurbu5-kdb-rs" }
kurbu5-kadm5-rs  = { path = "$REPO_ROOT/kadm5/kurbu5-kadm5-rs", features = ["admin", "kadm5_auth", "kadm5_hook"] }
kurbu5-kadm5-sys = { path = "$REPO_ROOT/kadm5/kurbu5-kadm5-sys" }
kurbu5-sys       = { path = "$REPO_ROOT/kurbu5-sys" }
libc             = "0.2"
EOF

# Cargo writes build artefacts to CARGO_TARGET_DIR.  Pointing it at the
# workspace target directory lets cargo reuse the already-compiled rlibs
# and all transitive dependencies without rebuilding them from scratch.
export CARGO_TARGET_DIR="$REPO_ROOT/target"

# Touch src/lib.rs once so cargo check does not reject a missing source file
# before we fill it in per-snippet.
touch "$CRATE_DIR/src/lib.rs"

# Run one initial cargo check to build kurbu5-kdb-rs and all deps (or confirm
# they are already up to date).  Errors here indicate a problem with the crate
# itself rather than any doc snippet.
#
# Note: --offline is intentionally omitted here.  The kurbu5-doc-check crate
# has no Cargo.lock and its deps may not all be in the registry cache.
# The first check generates Cargo.lock and fetches any missing sources;
# subsequent per-snippet checks run --offline because everything is then
# present in CARGO_TARGET_DIR and the registry cache.
info "Building kurbu5 doc-check crate and dependencies (first-time setup may take a moment)…"
if ! cargo check --manifest-path "$CRATE_DIR/Cargo.toml" --quiet; then
    die "Initial cargo check failed — a kurbu5 crate may have compilation errors"
fi
printf '\n'

# ── Check helpers ────────────────────────────────────────────────────────────

# check_src SRC_RS ERRFILE
#   Copies SRC_RS to the crate's src/lib.rs and runs cargo check.
#   Compiler output is captured in ERRFILE.
#   Returns the cargo check exit code.
check_src() {
    local src="$1" errfile="$2"
    cp "$src" "$CRATE_DIR/src/lib.rs"
    cargo check --offline --manifest-path "$CRATE_DIR/Cargo.toml" --quiet 2>"$errfile"
}

# show_errors ERRFILE SRC_PATH REL_DOC START_LINE
#   Pretty-prints cargo check errors, replacing the generated file path and
#   crate name with a human-readable reference to the originating doc.
show_errors() {
    local errfile="$1" src_path="$2" rel_doc="$3" start_line="$4"
    local ref="<${rel_doc}:${start_line}>"
    # cargo check error lines reference the crate source path and the
    # internal crate name; replace both with the doc reference.
    sed "s|$CRATE_DIR/src/lib.rs|${ref}|g
         s|kurbu5_doc_check|${ref}|g
         s|^|         |" "$errfile" >&2
}

# ── Batch compilation attempt ────────────────────────────────────────────────
# doc-rust-samples.py wrote all compilable blocks as named modules into a
# single batch/lib.rs.  Compiling it once amortises cargo's per-invocation
# overhead across all blocks.  When the batch compile fails, compiler error
# line numbers are mapped back to individual block indices via batch/map.tsv;
# only the affected blocks then go through the slower per-block path.
#
# Blocks that depend on types from a preceding block (and therefore live in
# the combined file) will fail in batch (modules are isolated) and be retried
# via the existing individual+combined-file path.

BATCH_LIB="$WORK_DIR/batch/lib.rs"
BATCH_MAP="$WORK_DIR/batch/map.tsv"
BATCH_ERR="$WORK_DIR/batch/errors.txt"

BATCH_ATTEMPTED=0
BATCH_ALL_PASS=0
declare -A FAIL_BLOCK_SET   # keys are block_n integers that failed in batch

if [[ -s "$BATCH_LIB" ]]; then
    BATCH_ATTEMPTED=1
    cp "$BATCH_LIB" "$CRATE_DIR/src/lib.rs"
    if cargo check --offline --manifest-path "$CRATE_DIR/Cargo.toml" --quiet 2>"$BATCH_ERR"; then
        BATCH_ALL_PASS=1
    else
        # Read block → line-range map (block_n, module_name, line_start, line_end).
        declare -a _BLK_NS=() _BLK_STARTS=() _BLK_ENDS=()
        while IFS=$'\t' read -r blk_n _mod line_start line_end; do
            _BLK_NS+=("$blk_n")
            _BLK_STARTS+=("$line_start")
            _BLK_ENDS+=("$line_end")
        done < "$BATCH_MAP"

        # Parse "  --> src/lib.rs:LINE:COL" lines from compiler output.
        while IFS= read -r errline; do
            if [[ $errline =~ --\>\ src/lib\.rs:([0-9]+): ]]; then
                err_ln="${BASH_REMATCH[1]}"
                for i in "${!_BLK_NS[@]}"; do
                    if (( err_ln >= _BLK_STARTS[i] && err_ln <= _BLK_ENDS[i] )); then
                        FAIL_BLOCK_SET["${_BLK_NS[$i]}"]=1
                        break
                    fi
                done
            fi
        done < "$BATCH_ERR"

        # If no blocks could be mapped (e.g. a crate-wide link error), fall
        # back entirely to individual checks so nothing is silently skipped.
        if [[ ${#FAIL_BLOCK_SET[@]} -eq 0 ]]; then
            BATCH_ATTEMPTED=0
        fi
    fi
fi

# ── Compile loop ─────────────────────────────────────────────────────────────
# Manifest columns (tab-separated, written by doc-rust-samples.py):
#   doc_file  start_line  lang  src_file  kind  raw_file  combined_file
#
# Only compilable blocks appear in the manifest; skipped blocks are filtered
# out by doc-rust-samples.py to avoid bash IFS collapsing of empty tab fields.
# combined_file is an empty string when no combined version was generated.

PASS=0; FAIL=0
declare -a FAIL_MSGS=()

while IFS=$'\t' read -r doc_file start_line lang src_file kind raw_file combined_file; do
    # Derive the integer block index from the source file name (e.g. 00012 → 12).
    # 10# forces decimal so that leading zeros are not misread as octal.
    blk_basename=$(basename "$src_file" .rs)
    blk_n=$((10#$blk_basename))

    rel_doc="${doc_file#"$REPO_ROOT"/}"
    label="${rel_doc}:${start_line}"

    # ── Fast path: batch compilation proved this block compiles ──────────────
    if [[ $BATCH_ATTEMPTED -eq 1 ]] && \
       { [[ $BATCH_ALL_PASS -eq 1 ]] || [[ -z "${FAIL_BLOCK_SET[$blk_n]+x}" ]]; }; then
        PASS=$(( PASS + 1 ))
        if [[ $VERBOSE -eq 1 ]]; then
            printf "  ${GREEN}OK${NC}    %-60s [%s]\n" "$label" "$kind"
        fi
        continue
    fi

    # ── Slow path: individual cargo check ────────────────────────────────────
    err_file="${src_file%.rs}.err"
    if check_src "$src_file" "$err_file" 2>/dev/null; then
        PASS=$(( PASS + 1 ))
        if [[ $VERBOSE -eq 1 ]]; then
            printf "  ${GREEN}OK${NC}    %-60s [%s]\n" "$label" "$kind"
        fi
        continue
    fi

    # ── Retry with combined source (all preceding toplevel blocks prepended) ──
    # Some blocks depend on types or helper functions defined in earlier
    # toplevel/program blocks of the same doc file.  doc-rust-samples.py
    # accumulates ALL such preceding blocks and prepends them; try the
    # combined file before declaring failure.
    if [[ -n "$combined_file" ]]; then
        comb_err="${combined_file%.rs}.err"
        if check_src "$combined_file" "$comb_err" 2>/dev/null; then
            PASS=$(( PASS + 1 ))
            if [[ $VERBOSE -eq 1 ]]; then
                printf "  ${GREEN}OK${NC}    %-60s [%s, with context]\n" "$label" "$kind"
            fi
            continue
        fi
        # Use the combined error output for diagnostics — it has more context.
        err_file="$comb_err"
        src_file="$combined_file"
    fi

    # ── Report failure ────────────────────────────────────────────────────────
    FAIL=$(( FAIL + 1 ))
    FAIL_MSGS+=("$label")

    printf "\n${RED}[FAIL]${NC} %s\n"    "$label"
    printf   "       Language : %s\n"    "$lang"
    printf   "       Kind     : %s\n"    "$kind"
    printf   "       Errors:\n"
    show_errors "$err_file" "$src_file" "$rel_doc" "$start_line"

done < "$MANIFEST"

# ── Summary ──────────────────────────────────────────────────────────────────
printf '\n'
printf -- '──────────────────────────────────────────────────────────\n'
printf 'Results: '
printf "${GREEN}%d passed${NC}, " "$PASS"
printf "${RED}%d failed${NC}, "   "$FAIL"
printf "${YELLOW}%d skipped${NC}\n" "$SKIP"   # $SKIP set by Python extractor

if [[ $FAIL -gt 0 ]]; then
    printf '\nFailed samples:\n'
    for msg in "${FAIL_MSGS[@]}"; do
        printf "  ${RED}%s${NC}\n" "$msg"
    done
    printf '\n'
    exit 1
fi

printf "\n${GREEN}${BOLD}All samples compiled successfully.${NC}\n\n"
exit 0
