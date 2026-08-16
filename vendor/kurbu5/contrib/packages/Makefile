# Makefile — helpers for preparing Fedora package sources and building SRPMs.
#
# SRPM build targets (dependencies fetched from crates.io):
#   make all-srpms                  # build SRPMs for all 9 crates
#   make rust-kurbu5-sys-srpm       # SRPM for rust-kurbu5-sys
#   make rust-kurbu5-derive-srpm    # SRPM for rust-kurbu5-derive
#   make rust-kurbu5-rs-srpm        # SRPM for rust-kurbu5-rs
#   make rust-kurbu5-kdb-sys-srpm   # SRPM for rust-kurbu5-kdb-sys
#   make rust-kurbu5-kdb-derive-srpm  # SRPM for rust-kurbu5-kdb-derive
#   make rust-kurbu5-kdb-rs-srpm    # SRPM for rust-kurbu5-kdb-rs
#   make rust-kurbu5-kadm5-sys-srpm   # SRPM for rust-kurbu5-kadm5-sys
#   make rust-kurbu5-kadm5-derive-srpm  # SRPM for rust-kurbu5-kadm5-derive
#   make rust-kurbu5-kadm5-rs-srpm  # SRPM for rust-kurbu5-kadm5-rs
#
# Requires: git, curl, rpmbuild
# For 'mock': mock package + your user in the 'mock' group
#   sudo usermod -aG mock $$USER   (then log out and back in)

# Enable pipefail so that pipe failures are not silently swallowed.
SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# Delete the target file when a recipe exits with a non-zero status.
.DELETE_ON_ERROR:

# ──────────────────────────────────────────────────────────────────────────────
# Repository and snapshot variables
# ──────────────────────────────────────────────────────────────────────────────

# Absolute path to the git repository root (two levels above this Makefile).
REPOROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../..)

# Absolute path to the crate dependency checker script (used by 'make check-deps').
CHECKDEPS := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))check-crate-deps.sh

# Git ref used for the snapshot release identifiers.  Defaults to HEAD.
# Override to a release tag when building a stable SRPM from a tag:
#   make rust-kurbu5-sys-srpm GIT_REF=v0.1.1
GIT_REF ?= HEAD

# Snapshot release identifiers derived from GIT_REF.
# SNAPDATE  — commit date+time of GIT_REF in YYYYMMDDhhmm format.
# SNAPCOMMIT — abbreviated commit hash of GIT_REF (7 hex digits).
# RELEASE   — full RPM Release field value (without %{?dist}).
SNAPDATE   := $(shell git -C "$(REPOROOT)" log -1 --format=%cd --date=format:%Y%m%d%H%M $(GIT_REF) 2>/dev/null)
SNAPCOMMIT := $(shell git -C "$(REPOROOT)" rev-parse --short $(GIT_REF) 2>/dev/null)
# IS_TAG is 'yes' when GIT_REF is a literal tag name (e.g. v0.1.1), 'no' otherwise.
IS_TAG     := $(shell git -C "$(REPOROOT)" tag -l "$(GIT_REF)" | grep -q . && echo yes || echo no)
RELEASE    := $(if $(filter yes,$(IS_TAG)),2,2.$(SNAPDATE).git$(SNAPCOMMIT))

# Mock chroot configuration for local test builds.  Override on the command line:
#   make mock MOCK_CONFIG=fedora-42-x86_64
MOCK_CONFIG ?= fedora-rawhide-x86_64

# ──────────────────────────────────────────────────────────────────────────────
# Crates.io base URL for individual crate tarballs
# ──────────────────────────────────────────────────────────────────────────────

CRATES_IO := https://static.crates.io/crates

# ──────────────────────────────────────────────────────────────────────────────
# Crate version — all crates share the workspace version from the root
# Cargo.toml (each crate uses version.workspace = true).
# ──────────────────────────────────────────────────────────────────────────────

CRATE_VERSION := $(shell awk -F '"' '/^version[[:space:]]*=/{print $$2; exit}' $(REPOROOT)/Cargo.toml)

# ──────────────────────────────────────────────────────────────────────────────

.PHONY: all help check-deps clean copr-chain-build \
	all-srpms \
	rust-kurbu5-sys-srpm \
	rust-kurbu5-derive-srpm \
	rust-kurbu5-rs-srpm \
	rust-kurbu5-kdb-sys-srpm \
	rust-kurbu5-kdb-derive-srpm \
	rust-kurbu5-kdb-rs-srpm \
	rust-kurbu5-kadm5-sys-srpm \
	rust-kurbu5-kadm5-derive-srpm \
	rust-kurbu5-kadm5-rs-srpm \
	regen-spec-kurbu5-sys regen-spec-kurbu5-derive regen-spec-kurbu5-rs \
	regen-spec-kurbu5-kdb-sys regen-spec-kurbu5-kdb-derive regen-spec-kurbu5-kdb-rs \
	regen-spec-kurbu5-kadm5-sys regen-spec-kurbu5-kadm5-derive regen-spec-kurbu5-kadm5-rs \
	regen-all-specs

all: all-srpms

help:
	@echo "SRPM build targets (crate $(CRATE_VERSION), all deps from crates.io):"
	@echo "  all-srpms                           build SRPMs for all 9 crates"
	@echo "  rust-kurbu5-sys-srpm                SRPM for rust-kurbu5-sys"
	@echo "  rust-kurbu5-derive-srpm             SRPM for rust-kurbu5-derive"
	@echo "  rust-kurbu5-rs-srpm                 SRPM for rust-kurbu5-rs"
	@echo "  rust-kurbu5-kdb-sys-srpm            SRPM for rust-kurbu5-kdb-sys"
	@echo "  rust-kurbu5-kdb-derive-srpm         SRPM for rust-kurbu5-kdb-derive"
	@echo "  rust-kurbu5-kdb-rs-srpm             SRPM for rust-kurbu5-kdb-rs"
	@echo "  rust-kurbu5-kadm5-sys-srpm          SRPM for rust-kurbu5-kadm5-sys"
	@echo "  rust-kurbu5-kadm5-derive-srpm       SRPM for rust-kurbu5-kadm5-derive"
	@echo "  rust-kurbu5-kadm5-rs-srpm           SRPM for rust-kurbu5-kadm5-rs"
	@echo ""
	@echo "  regen-all-specs             regenerate all individual-crate specs via rust2rpm"
	@echo "  regen-spec-<crate>          regenerate one spec (e.g. regen-spec-kurbu5-sys)"
	@echo "  check-deps                  check which Cargo.lock crates are available as system packages"
	@echo "  copr-chain-build COPR=project  submit all SRPMs to COPR in dep order"
	@echo "                              (override COPR_OPTS for extra flags)"
	@echo "  clean                       remove downloaded .crate files and built SRPMs"
	@echo ""
	@echo "Release:  $(RELEASE)  (GIT_REF=$(GIT_REF)  is-tag=$(IS_TAG))"

# ══════════════════════════════════════════════════════════════════════════════
# SRPM BUILD
# ══════════════════════════════════════════════════════════════════════════════
#
# Each SRPM is built directly from the rust2rpm-generated spec in the crate
# source directory.  Dependencies are resolved at binary-build time by COPR /
# Koji from crates.io and system packages; no offline vendor tarball is needed.
#
# The only source required locally for 'rpmbuild -bs' is the crate tarball
# (.crate file) so that rpmbuild can embed it in the SRPM.

# Helper: download a single crate tarball from crates.io (if not already present).
# Usage: $(call crate_download, CRATE_NAME, VERSION)
define crate_download
	@if [ ! -f "$(CURDIR)/$(1)-$(2).crate" ]; then \
	    echo "==> Downloading $(1)-$(2).crate"; \
	    curl -L --fail \
	        "$(CRATES_IO)/$(1)/$(1)-$(2).crate" \
	        -o "$(CURDIR)/$(1)-$(2).crate"; \
	else \
	    echo "==> $(1)-$(2).crate already present"; \
	fi
endef

# Helper macro: build an SRPM from a rust2rpm-generated spec.
#
# The spec lives in the crate source directory; this macro post-processes it
# with sed to inject:
#   • %global snapdate / %global snapcommit macros
#   • The correct Release field (clean for tag builds, snapshot otherwise)
#
# Usage: $(call crate_srpm, SPEC_PATH)
#   SPEC_PATH — full path to the rust2rpm-generated spec
#               e.g. $(REPOROOT)/kurbu5-sys/rust-kurbu5-sys.spec
define crate_srpm
	@echo "==> Building SRPM from $(1)"
	@SPEC_TMP="$(CURDIR)/$$(basename $(1))"; \
	sed \
	    -e "/^%global crate /a %global snapdate  $(SNAPDATE)" \
	    -e "/^%global crate /a %global snapcommit $(SNAPCOMMIT)" \
	    $(if $(filter yes,$(IS_TAG)), \
	        -e "s/^Release:[[:space:]].*/Release:        $(RELEASE)%{?dist}/", \
	        -e "s/^Release:[[:space:]].*/Release:        $(RELEASE)%{?dist}/") \
	    "$(1)" > "$$SPEC_TMP"; \
	rpmbuild -bs \
	    --define "_sourcedir $(CURDIR)" \
	    --define "_specdir   $(CURDIR)" \
	    --define "_srcrpmdir $(CURDIR)" \
	    "$$SPEC_TMP"; \
	rc=$$?; rm -f "$$SPEC_TMP"; exit $$rc
endef

# ══════════════════════════════════════════════════════════════════════════════
# SPEC REGENERATION VIA rust2rpm
# ══════════════════════════════════════════════════════════════════════════════
#
# Per Fedora Rust packaging guidelines, spec files should be generated (and
# re-generated on version bumps) using rust2rpm.  These targets download the
# .crate file from crates.io and regenerate the spec in the crate subdirectory.
#
# rust2rpm is run from inside the crate directory so that it picks up the
# rust2rpm.toml configuration file (which holds custom BuildRequires, summary,
# description, etc.) from the current working directory.
#
# Usage:
#   make regen-spec-kurbu5-sys      # regenerate one spec
#   make regen-all-specs            # regenerate all individual-crate specs
#
# Flags used:
#   --no-rpmautospec      do not emit %autorelease / %autochangelog
#   --no-existence-check  skip Fedora dist-git lookup (we are not in dist-git)
#   -O                    offline: use cached .crate file, skip crates.io queries

# Helper: ensure a crate is in rust2rpm's cache so -O works.
# Usage: $(call cache_crate, CRATE_NAME, VERSION)
define cache_crate
	@mkdir -p ~/.cache/rust2rpm
	@if [ ! -f "$(CURDIR)/$(1)-$(2).crate" ]; then \
	    echo "==> Downloading $(1)-$(2).crate for rust2rpm cache"; \
	    curl -L --fail "$(CRATES_IO)/$(1)/$(1)-$(2).crate" \
	        -o "$(CURDIR)/$(1)-$(2).crate"; \
	fi
	@cp "$(CURDIR)/$(1)-$(2).crate" ~/.cache/rust2rpm/
endef

# Helper: regenerate a spec via rust2rpm from inside the crate directory.
# Running from the crate directory ensures rust2rpm picks up rust2rpm.toml.
# Usage: $(call regen_spec, CRATE_NAME, VERSION, CRATE_DIR_RELPATH)
#   CRATE_DIR_RELPATH — path from REPOROOT to the crate directory
define regen_spec
	$(call cache_crate,$(1),$(2))
	cd "$(REPOROOT)/$(3)" && \
	rust2rpm --no-rpmautospec --no-existence-check -O $(1)@$(2)
endef

# ── individual regen-spec targets ─────────────────────────────────────────────

regen-spec-kurbu5-sys:
	$(call regen_spec,kurbu5-sys,$(CRATE_VERSION),kurbu5-sys)

regen-spec-kurbu5-derive:
	$(call regen_spec,kurbu5-derive,$(CRATE_VERSION),kurbu5-derive)

regen-spec-kurbu5-rs:
	$(call regen_spec,kurbu5-rs,$(CRATE_VERSION),kurbu5-rs)

regen-spec-kurbu5-kdb-sys:
	$(call regen_spec,kurbu5-kdb-sys,$(CRATE_VERSION),kurbu5-kdb/kurbu5-kdb-sys)

regen-spec-kurbu5-kdb-derive:
	$(call regen_spec,kurbu5-kdb-derive,$(CRATE_VERSION),kurbu5-kdb/kurbu5-kdb-derive)

regen-spec-kurbu5-kdb-rs:
	$(call regen_spec,kurbu5-kdb-rs,$(CRATE_VERSION),kurbu5-kdb/kurbu5-kdb-rs)

regen-spec-kurbu5-kadm5-sys:
	$(call regen_spec,kurbu5-kadm5-sys,$(CRATE_VERSION),kadm5/kurbu5-kadm5-sys)

regen-spec-kurbu5-kadm5-derive:
	$(call regen_spec,kurbu5-kadm5-derive,$(CRATE_VERSION),kadm5/kurbu5-kadm5-derive)

regen-spec-kurbu5-kadm5-rs:
	$(call regen_spec,kurbu5-kadm5-rs,$(CRATE_VERSION),kadm5/kurbu5-kadm5-rs)

regen-all-specs: \
	regen-spec-kurbu5-sys \
	regen-spec-kurbu5-derive \
	regen-spec-kurbu5-rs \
	regen-spec-kurbu5-kdb-sys \
	regen-spec-kurbu5-kdb-derive \
	regen-spec-kurbu5-kdb-rs \
	regen-spec-kurbu5-kadm5-sys \
	regen-spec-kurbu5-kadm5-derive \
	regen-spec-kurbu5-kadm5-rs

# ── all-srpms ─────────────────────────────────────────────────────────────────

all-srpms: \
	rust-kurbu5-sys-srpm \
	rust-kurbu5-derive-srpm \
	rust-kurbu5-rs-srpm \
	rust-kurbu5-kdb-sys-srpm \
	rust-kurbu5-kdb-derive-srpm \
	rust-kurbu5-kdb-rs-srpm \
	rust-kurbu5-kadm5-sys-srpm \
	rust-kurbu5-kadm5-derive-srpm \
	rust-kurbu5-kadm5-rs-srpm

# ── rust-kurbu5-sys ───────────────────────────────────────────────────────────

kurbu5-sys-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-sys,$(CRATE_VERSION))

rust-kurbu5-sys-srpm: kurbu5-sys-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kurbu5-sys/rust-kurbu5-sys.spec)

# ── rust-kurbu5-derive ────────────────────────────────────────────────────────

kurbu5-derive-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-derive,$(CRATE_VERSION))

rust-kurbu5-derive-srpm: kurbu5-derive-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kurbu5-derive/rust-kurbu5-derive.spec)

# ── rust-kurbu5-rs ────────────────────────────────────────────────────────────

kurbu5-rs-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-rs,$(CRATE_VERSION))

rust-kurbu5-rs-srpm: kurbu5-rs-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kurbu5-rs/rust-kurbu5-rs.spec)

# ── rust-kurbu5-kdb-sys ───────────────────────────────────────────────────────

kurbu5-kdb-sys-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-kdb-sys,$(CRATE_VERSION))

rust-kurbu5-kdb-sys-srpm: kurbu5-kdb-sys-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kurbu5-kdb/kurbu5-kdb-sys/rust-kurbu5-kdb-sys.spec)

# ── rust-kurbu5-kdb-derive ────────────────────────────────────────────────────

kurbu5-kdb-derive-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-kdb-derive,$(CRATE_VERSION))

rust-kurbu5-kdb-derive-srpm: kurbu5-kdb-derive-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kurbu5-kdb/kurbu5-kdb-derive/rust-kurbu5-kdb-derive.spec)

# ── rust-kurbu5-kdb-rs ────────────────────────────────────────────────────────

kurbu5-kdb-rs-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-kdb-rs,$(CRATE_VERSION))

rust-kurbu5-kdb-rs-srpm: kurbu5-kdb-rs-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kurbu5-kdb/kurbu5-kdb-rs/rust-kurbu5-kdb-rs.spec)

# ── rust-kurbu5-kadm5-sys ─────────────────────────────────────────────────────

kurbu5-kadm5-sys-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-kadm5-sys,$(CRATE_VERSION))

rust-kurbu5-kadm5-sys-srpm: kurbu5-kadm5-sys-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kadm5/kurbu5-kadm5-sys/rust-kurbu5-kadm5-sys.spec)

# ── rust-kurbu5-kadm5-derive ──────────────────────────────────────────────────

kurbu5-kadm5-derive-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-kadm5-derive,$(CRATE_VERSION))

rust-kurbu5-kadm5-derive-srpm: kurbu5-kadm5-derive-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kadm5/kurbu5-kadm5-derive/rust-kurbu5-kadm5-derive.spec)

# ── rust-kurbu5-kadm5-rs ──────────────────────────────────────────────────────

kurbu5-kadm5-rs-$(CRATE_VERSION).crate:
	$(call crate_download,kurbu5-kadm5-rs,$(CRATE_VERSION))

rust-kurbu5-kadm5-rs-srpm: kurbu5-kadm5-rs-$(CRATE_VERSION).crate
	$(call crate_srpm,$(REPOROOT)/kadm5/kurbu5-kadm5-rs/rust-kurbu5-kadm5-rs.spec)

# ── check-deps ────────────────────────────────────────────────────────────────

check-deps:
	@rc=0; bash $(dir $(abspath $(lastword $(MAKEFILE_LIST))))check-crate-deps.sh \
	    $(REPOROOT)/Cargo.lock || rc=$$?; exit $$((rc > 1 ? rc : 0))

# ── copr-chain-build ──────────────────────────────────────────────────────────
#
# Submit all SRPMs to a COPR project in dependency order using
# contrib/packages/copr-chain-build.sh.
#
# Usage:
#   make copr-chain-build COPR=@mygroup/kurbu5
#   make copr-chain-build COPR=myuser/kurbu5 COPR_OPTS="--chroot fedora-42-x86_64 --wait"
#
# COPR      — required: the COPR project (e.g. @mygroup/kurbu5)
# COPR_OPTS — optional: extra flags passed to copr-chain-build.sh

COPR      ?=
COPR_OPTS ?=

copr-chain-build:
	@test -n "$(COPR)" || \
	    { echo "ERROR: set COPR=<project>  e.g. make copr-chain-build COPR=@mygroup/kurbu5" >&2; exit 1; }
	bash $(CURDIR)/copr-chain-build.sh \
	    --srpm-dir $(CURDIR) \
	    $(COPR_OPTS) \
	    $(COPR)

# ── clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -f \
	    kurbu5-sys-$(CRATE_VERSION).crate \
	    kurbu5-derive-$(CRATE_VERSION).crate \
	    kurbu5-rs-$(CRATE_VERSION).crate \
	    kurbu5-kdb-sys-$(CRATE_VERSION).crate \
	    kurbu5-kdb-derive-$(CRATE_VERSION).crate \
	    kurbu5-kdb-rs-$(CRATE_VERSION).crate \
	    kurbu5-kadm5-sys-$(CRATE_VERSION).crate \
	    kurbu5-kadm5-derive-$(CRATE_VERSION).crate \
	    kurbu5-kadm5-rs-$(CRATE_VERSION).crate \
	    rust-kurbu5-*.src.rpm
