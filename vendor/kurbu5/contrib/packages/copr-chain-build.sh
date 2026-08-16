#!/bin/bash
# copr-chain-build.sh — submit all kurbu5 packages to COPR in dependency order.
#
# Build plan (three sequential stages with intra-stage parallelism where safe):
#
#   Stage 1 (parallel) — no kurbu5 inter-deps:
#     rust-kurbu5-sys, rust-kurbu5-derive,
#     rust-kurbu5-kdb-derive, rust-kurbu5-kadm5-derive
#
#   Stage 2 (parallel, after 1) — needs rust-kurbu5-sys-devel:
#     rust-kurbu5-rs, rust-kurbu5-kdb-sys, rust-kurbu5-kadm5-sys
#
#   Stage 3 (parallel, after 2) — needs Stage 2 -devel packages:
#     rust-kurbu5-kdb-rs, rust-kurbu5-kadm5-rs
#
# Usage:
#   copr-chain-build.sh [OPTIONS] COPR_PROJECT
#
# Options:
#   -d, --srpm-dir DIR     Directory containing *.src.rpm files
#                          (default: directory of this script)
#   -r, --chroot CHROOT    Add a chroot to build in (may be repeated;
#                          default: whatever the project has enabled)
#   -n, --dry-run          Print copr-cli commands without running them
#   -w, --wait             Wait for the final stage and report status
#                          (default: submit and exit; COPR runs the chain)
#   -h, --help             Show this help
#
# Examples:
#   copr-chain-build.sh @mygroup/kurbu5
#   copr-chain-build.sh --chroot fedora-42-x86_64 --wait myuser/kurbu5-staging
#   copr-chain-build.sh --srpm-dir /tmp/srpms --dry-run @mygroup/kurbu5

set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[$(date '+%H:%M:%S')] $*"; }
warn() { echo "WARN:  $*" >&2; }

usage() {
    sed -n '/^# Usage:/,/^[^#]/{ /^#/{ s/^# \{0,2\}//; p }; /^[^#]/q }' "$0"
    exit 0
}

# Extract a single build ID from copr-cli --nowait output.
# copr-cli prints: "Created builds: 12345678"
extract_build_id() {
    local output="$1"
    local id
    id=$(echo "$output" | grep -oP '(?<=Created builds: )\d+' | tail -1)
    [[ -n "$id" ]] || die "Could not parse build ID from copr-cli output:\n$output"
    echo "$id"
}

# Find the latest (by version sort) SRPM matching a package name prefix.
find_srpm() {
    local name="$1" dir="$2"
    local found
    # shellcheck disable=SC2012
    found=$(ls -1 "$dir"/"$name"-[0-9]*.src.rpm 2>/dev/null | sort -V | tail -1)
    echo "$found"
}

# Submit one SRPM to COPR (--nowait); echo the build ID to stdout.
# All progress/diagnostic output goes to stderr so $(...) captures only the ID.
submit() {
    local label="$1" srpm="$2"
    shift 2
    # $@ = extra copr-cli options (--with-build-id, --after-build-id, -r ...)

    [[ -f "$srpm" ]] || die "SRPM not found: $srpm"

    local cmd=(copr-cli build --nowait "${CHROOT_ARGS[@]}" "$@" "$COPR_PROJECT" "$srpm")

    info "Submitting $label" >&2
    info "  $(basename "$srpm")" >&2
    if [[ "$DRY_RUN" == 1 ]]; then
        echo "  [dry-run] ${cmd[*]}" >&2
        echo "9999999"   # only line on stdout
        return
    fi

    local out
    out=$("${cmd[@]}" 2>&1) || die "copr-cli failed for $label:\n$out"
    echo "$out" | grep -v '^$' | sed 's/^/  /' >&2
    extract_build_id "$out"
}

# Submit a batch of packages.  The first becomes the batch anchor (returned);
# the rest join via --with-build-id.  Pass the previous stage anchor via
# --after-build-id in EXTRA_ARGS to chain this batch after the previous one.
#
# Usage: submit_batch LABEL EXTRA_ARGS... -- PKG [PKG...]
# Prints the anchor build ID on stdout (capture with $(...)).
# Note: runs in a subshell; cannot modify parent arrays.
submit_batch() {
    local label="$1"; shift
    local -a extra=()
    while [[ "$1" != "--" ]]; do extra+=("$1"); shift; done
    shift   # consume "--"
    local -a pkgs=("$@")

    info "=== $label ===" >&2

    local anchor="" count=0
    for pkg in "${pkgs[@]}"; do
        if [[ ! -v SRPM_PATH[$pkg] ]]; then
            warn "Skipping $pkg (no SRPM)" >&2
            continue
        fi
        local id
        if [[ -z "$anchor" ]]; then
            id=$(submit "$pkg" "${SRPM_PATH[$pkg]}" "${extra[@]}")
            anchor="$id"
        else
            # --with-build-id and --after-build-id are mutually exclusive in copr-cli.
            # The anchor already carries --after-build-id for the previous stage; using
            # --with-build-id here groups this build into the same batch as the anchor
            # (runs in parallel with it, after the same previous stage completes).
            id=$(submit "$pkg" "${SRPM_PATH[$pkg]}" --with-build-id "$anchor")
        fi
        (( count++ ))
        info "  → build ID $id" >&2
    done

    [[ -n "$anchor" ]] || die "No packages submitted for stage: $label"
    echo "" >&2
    info "  Batch anchor: $anchor  ($count build(s))" >&2

    echo "$anchor"   # only the anchor ID on stdout
}

# ── argument parsing ──────────────────────────────────────────────────────────

SRPM_DIR="$(cd "$(dirname "$0")" && pwd)"
CHROOT_ARGS=()
DRY_RUN=0
WAIT=0
COPR_PROJECT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--srpm-dir)   SRPM_DIR="$2"; shift 2 ;;
        -r|--chroot)     CHROOT_ARGS+=(-r "$2"); shift 2 ;;
        -n|--dry-run)    DRY_RUN=1; shift ;;
        -w|--wait)       WAIT=1; shift ;;
        -h|--help)       usage ;;
        -*)              die "Unknown option: $1" ;;
        *)               COPR_PROJECT="$1"; shift ;;
    esac
done

[[ -n "$COPR_PROJECT" ]] || die "COPR_PROJECT is required.  Run with --help for usage."
[[ -d "$SRPM_DIR" ]]     || die "SRPM directory not found: $SRPM_DIR"

# ── locate SRPMs ──────────────────────────────────────────────────────────────

ALL_PKGS=(
    rust-kurbu5-sys
    rust-kurbu5-derive
    rust-kurbu5-kdb-derive
    rust-kurbu5-kadm5-derive
    rust-kurbu5-rs
    rust-kurbu5-kdb-sys
    rust-kurbu5-kadm5-sys
    rust-kurbu5-kdb-rs
    rust-kurbu5-kadm5-rs
)

declare -A SRPM_PATH
for pkg in "${ALL_PKGS[@]}"; do
    path=$(find_srpm "$pkg" "$SRPM_DIR")
    if [[ -z "$path" ]]; then
        warn "SRPM not found for $pkg in $SRPM_DIR — will skip"
    else
        SRPM_PATH[$pkg]="$path"
        info "Found: $(basename "$path")"
    fi
done
echo ""

# ── stage 1: no kurbu5 inter-deps (parallel) ─────────────────────────────────

A1=$(submit_batch \
    "Stage 1 — parallel: sys, derive, kdb-derive, kadm5-derive (no kurbu5 inter-deps)" \
    -- \
    rust-kurbu5-sys rust-kurbu5-derive \
    rust-kurbu5-kdb-derive rust-kurbu5-kadm5-derive)

# ── stage 2: rs, kdb-sys, kadm5-sys (need kurbu5-sys-devel) ──────────────────

A2=$(submit_batch \
    "Stage 2 — parallel: rs, kdb-sys, kadm5-sys (need stage 1)" \
    --after-build-id "$A1" \
    -- \
    rust-kurbu5-rs rust-kurbu5-kdb-sys rust-kurbu5-kadm5-sys)

# ── stage 3: kdb-rs, kadm5-rs (need stage 2 -devel packages) ─────────────────

A3=$(submit_batch \
    "Stage 3 — parallel: kdb-rs, kadm5-rs (need stage 2)" \
    --after-build-id "$A2" \
    -- \
    rust-kurbu5-kdb-rs rust-kurbu5-kadm5-rs)

# ── summary ───────────────────────────────────────────────────────────────────

info "=== Submitted 9 builds to $COPR_PROJECT ==="
info "  S1 (sys,derive,kdb-derive,kadm5-derive): $A1"
info "  S2 (rs,kdb-sys,kadm5-sys):               $A2"
info "  S3 (kdb-rs,kadm5-rs):                    $A3"
echo ""
info "COPR will run each stage after the previous batch succeeds."
info "Monitor at: https://copr.fedorainfracloud.org/coprs/${COPR_PROJECT}/builds/"
echo ""

# ── optional: wait for the final stage ───────────────────────────────────────

if [[ "$WAIT" == 1 ]]; then
    info "Waiting for Stage 3 (copr-cli watch-build $A3)..."
    if [[ "$DRY_RUN" == 1 ]]; then
        info "[dry-run] would run: copr-cli watch-build $A3"
    else
        if copr-cli watch-build "$A3"; then
            info "All builds SUCCEEDED."
        else
            die "Stage 3 build FAILED.  Check the COPR web UI."
        fi
    fi
fi
