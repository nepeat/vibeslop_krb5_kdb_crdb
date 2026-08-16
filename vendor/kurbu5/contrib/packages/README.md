# Fedora packaging for kurbu5

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Files](#files)
- [Binary packages produced](#binary-packages-produced)
- [Prerequisites](#prerequisites)
- [Typical workflow](#typical-workflow)
  - [1. Prepare vendor tarballs (once per release)](#1-prepare-vendor-tarballs-once-per-release)
  - [2. Build an SRPM](#2-build-an-srpm)
  - [3. Test the build locally with mock](#3-test-the-build-locally-with-mock)
  - [4. Check which crates are already packaged as system RPMs (advisory)](#4-check-which-crates-are-already-packaged-as-system-rpms-advisory)
  - [5. Submit to COPR in dependency order](#5-submit-to-copr-in-dependency-order)
  - [Cleaning up](#cleaning-up)
- [Vendor tarball](#vendor-tarball)
- [Crate dependency build order](#crate-dependency-build-order)
- [Updating for a new release](#updating-for-a-new-release)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

This directory contains the files needed to build Fedora RPMs for the kurbu5
workspace — a collection of safe Rust crates for writing MIT Kerberos plugin
modules.

## Files

| File | Purpose |
|---|---|
| `Makefile` | Automates vendor tarball creation, SRPM builds, and spec regeneration |
| `check-crate-deps.sh` | Advisory script: reports which `Cargo.lock` crates are already available as system RPM packages |
| `copr-chain-build.sh` | Submits all nine SRPMs to a COPR project in the correct dependency order |
| `rust-kurbu5-sys.spec.in` | Spec template for the raw FFI bindings crate (Stage 1) |
| `rust-kurbu5-derive.spec.in` | Spec template for the non-KDB plugin derive macros (Stage 1) |
| `rust-kurbu5-rs.spec.in` | Spec template for the non-KDB safe plugin API (Stage 2) |
| `rust-kurbu5-kdb-sys.spec.in` | Spec template for the KDB sys re-export crate (Stage 2) |
| `rust-kurbu5-kdb-derive.spec.in` | Spec template for the KDB driver derive macro (Stage 1) |
| `rust-kurbu5-kdb-rs.spec.in` | Spec template for the KDB driver safe plugin API (Stage 3) |
| `rust-kurbu5-kadm5-sys.spec.in` | Spec template for the KADM5 sys bindings crate (Stage 2) |
| `rust-kurbu5-kadm5-derive.spec.in` | Spec template for the KADM5 plugin derive macros (Stage 1) |
| `rust-kurbu5-kadm5-rs.spec.in` | Spec template for the KADM5 safe plugin API (Stage 3) |

## Binary packages produced

| RPM | Contents |
|---|---|
| `rust-kurbu5-sys-devel` | Raw FFI bindings to libkrb5 and the KDB plugin API |
| `rust-kurbu5-derive-devel` | Derive macros for non-KDB Kerberos plugin interfaces |
| `rust-kurbu5-rs-devel` | Safe Rust API for non-KDB plugin modules |
| `rust-kurbu5-kdb-sys-devel` | KDB plugin API re-export with libkdb5 linkage |
| `rust-kurbu5-kdb-derive-devel` | Derive macro for KDB driver plugins |
| `rust-kurbu5-kdb-rs-devel` | Safe Rust API for KDB driver plugins |
| `rust-kurbu5-kadm5-sys-devel` | KADM5 plugin API bindings with libkadm5srv_mit linkage |
| `rust-kurbu5-kadm5-derive-devel` | Derive macros for KADM5_AUTH and KADM5_HOOK plugins |
| `rust-kurbu5-kadm5-rs-devel` | Safe Rust API for KADM5_AUTH and KADM5_HOOK plugin modules |

## Prerequisites

Install the required tools:

```
sudo dnf install git cargo rpmbuild rpmlint
```

For the `copr-chain-build` target, install the COPR CLI:

```
sudo dnf install copr-cli
```

For local mock builds, install mock and add your user to the `mock` group:

```
sudo dnf install mock
sudo usermod -aG mock $USER
```

Log out and back in for the group membership to take effect.

## Typical workflow

Run all commands from the `contrib/packages/` directory.

### 1. Prepare vendor tarballs (once per release)

```
make all-crate-vendors
```

This downloads each crate from crates.io, runs `cargo vendor` inside the
extracted crate directory, and archives the resulting `vendor/`,
`vendor-config.toml`, and `Cargo.lock` into a
`rust-<crate>-<version>-vendor.tar.gz` file.  The step requires internet
access; the Koji build system does not have network access, so these tarballs
must be prepared locally and uploaded alongside the source tarballs.

To vendor a single crate:

```
make rust-kurbu5-sys-vendor
```

### 2. Build an SRPM

```
make rust-kurbu5-sys-srpm
```

The Makefile substitutes the current `SNAPDATE` and `SNAPCOMMIT` values
(derived from `git log`) into the `Release:` field, copies all sources to a
temporary `.spec` file, and runs `rpmbuild -bs`.  The resulting `.src.rpm`
appears in the `contrib/packages/` directory.

To build SRPMs for all crates:

```
make rust-kurbu5-sys-srpm
make rust-kurbu5-derive-srpm
make rust-kurbu5-kdb-derive-srpm
make rust-kurbu5-kadm5-derive-srpm
make rust-kurbu5-rs-srpm
make rust-kurbu5-kdb-sys-srpm
make rust-kurbu5-kadm5-sys-srpm
make rust-kurbu5-kdb-rs-srpm
make rust-kurbu5-kadm5-rs-srpm
```

Build order matters for mock validation; see the dependency graph below.

### 3. Test the build locally with mock

```
mock -r fedora-rawhide-x86_64 --rebuild rust-kurbu5-sys-0.1.0-*.src.rpm
mock -r fedora-rawhide-x86_64 --install rust-kurbu5-sys-devel
mock -r fedora-rawhide-x86_64 --rebuild rust-kurbu5-derive-0.1.0-*.src.rpm
# ... continue in dependency order
```

Built RPMs are placed in `/var/lib/mock/<config>/result/`.

### 4. Check which crates are already packaged as system RPMs (advisory)

```
make check-deps
```

Compares `Cargo.lock` against the currently configured dnf repositories and
reports which crates already have Fedora system packages.  The output is
advisory only — all crates remain in the vendor tarball regardless.

### 5. Submit to COPR in dependency order

```
make copr-chain-build COPR=@mygroup/kurbu5
```

This calls `copr-chain-build.sh`, which submits all nine SRPMs in three
sequential stages using `copr-cli build --after-build-id` chaining.  COPR
runs each stage only after the previous one succeeds.

Pass extra flags via `COPR_OPTS`:

```
make copr-chain-build COPR=@mygroup/kurbu5 COPR_OPTS="--chroot fedora-42-x86_64 --wait"
```

### Cleaning up

```
make clean
```

Removes all `.crate` files and vendor tarballs from `contrib/packages/`.
Does not touch `~/rpmbuild` or any files outside this directory.

## Vendor tarball

The Fedora build system (Koji) runs without network access.  Cargo dependencies
must therefore be pre-downloaded and shipped as a second source tarball
(`rust-<crate>-<version>-vendor.tar.gz`).  Each spec's `%prep` section
unpacks this with `%cargo_prep -v vendor`, which writes a `.cargo/config.toml`
that redirects all crate lookups to the local `vendor/` directory.

`make <crate>-vendor` automates the preparation:

1. Downloads `<crate>-<version>.crate` from crates.io (or reuses a local copy).
2. Extracts it into a temporary directory.
3. Runs `cargo generate-lockfile` and `cargo vendor` to resolve and download
   all crate sources.
4. Archives `vendor/`, `vendor-config.toml`, and `Cargo.lock` together.

The vendor tarball must be regenerated whenever `Cargo.toml` changes in a way
that adds, removes, or updates a dependency.

## Crate dependency build order

The nine crates form a three-stage dependency graph:

**Stage 1** (can be built in parallel — no inter-kurbu5 deps):
- `rust-kurbu5-sys` — links libkrb5/libkdb5; runs bindgen at build time
- `rust-kurbu5-derive` — proc-macro; only syn/quote/proc-macro2
- `rust-kurbu5-kdb-derive` — proc-macro; only syn/quote/proc-macro2
- `rust-kurbu5-kadm5-derive` — proc-macro; only syn/quote/proc-macro2

**Stage 2** (after Stage 1; can be built in parallel):
- `rust-kurbu5-rs` — depends on kurbu5-sys and optionally kurbu5-derive
- `rust-kurbu5-kdb-sys` — depends on kurbu5-sys
- `rust-kurbu5-kadm5-sys` — depends on kurbu5-sys

**Stage 3** (after Stage 2; can be built in parallel):
- `rust-kurbu5-kdb-rs` — depends on kurbu5-sys, kurbu5-rs, kurbu5-kdb-sys, kurbu5-kdb-derive
- `rust-kurbu5-kadm5-rs` — depends on kurbu5-sys, kurbu5-rs, kurbu5-kadm5-sys, kurbu5-kadm5-derive

## Updating for a new release

1. Tag the release in git (`git tag v<NEW_VERSION>`).
2. Update `Version:` in each `*.spec.in` file.
3. Add a new `%changelog` entry in each `*.spec.in` file.
4. Run `make clean && make all-crate-vendors` to regenerate all vendor tarballs.
5. Build all SRPMs and verify the builds with mock in dependency order.
6. Upload the new sources and SRPMs to the package repository.
