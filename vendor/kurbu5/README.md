# kurbu5 — Safe Rust for MIT Kerberos Plugins

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Goals](#goals)
- [Workspace layout](#workspace-layout)
  - [Crate dependency graph](#crate-dependency-graph)
- [Plugin interfaces at a glance](#plugin-interfaces-at-a-glance)
  - [KDB — database driver plugins](#kdb-database-driver-plugins)
  - [Non-KDB plugins (kurbu5-rs)](#non-kdb-plugins-kurbu5-rs)
  - [KADM5 plugins and admin client (kurbu5-kadm5-rs)](#kadm5-plugins-and-admin-client-kurbu5-kadm5-rs)
- [Quick start](#quick-start)
  - [KDB plugin](#kdb-plugin)
  - [Non-KDB plugin (PWQUAL example)](#non-kdb-plugin-pwqual-example)
- [Building](#building)
- [Target](#target)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
  - [Near-term](#near-term)
  - [Longer-term](#longer-term)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

kurbu5 is a Rust workspace that makes it possible to write MIT Kerberos plugin
modules in safe, idiomatic Rust.  It covers three families of plugin interface:

* **KDB** (`kdb_vftabl`) — key distribution centre database drivers
* **Non-KDB** — nine supplementary plugin interfaces (PWQUAL, HOSTREALM,
  LOCALAUTH, CCSELECT, KDCPOLICY, CERTAUTH, KDCPREAUTH, CLPREAUTH, AUDIT)
* **KADM5** — two administration server plugin interfaces (KADM5_AUTH,
  KADM5_HOOK)

The name is a transliteration of "krb5" into Mesopotamian cuneiform phonology:
*Kurbu-ḫamšat-qaqqadī* — "The Blessed Five-Headed One".

---

## Goals

**Write Kerberos plugins without writing unsafe code.**

Every plugin family shares the same design principles:

1. **Single `unsafe` boundary.** All FFI plumbing lives in `glue.rs` files.
   Everything outside them is safe Rust.  A security reviewer only needs to
   audit those files.

2. **Zero-copy read access to C-owned data.** When the runtime passes a
   principal entry or request structure into a vtable function, the framework
   wraps it in a Rust reference with a lifetime tied to the call frame.  No
   heap allocation occurs on the read path.

3. **C-compatible owned allocation on the write path.** Where a module must
   return heap-allocated data (strings, realm lists, certificates, PA-DATA),
   the framework allocates using the same system allocator as libkrb5 so the
   runtime's free function works correctly.

4. **Static dispatch.** `make_<interface>_vtable::<M>()` monomorphises a
   complete vtable for a concrete module type at compile time.  No `dyn Trait`
   in the hot path.

5. **Declarative plugin export.**
   - KDB: `kdb_plugin!(name, Type)` exports static symbol `kdb_function_table`
   - Non-KDB / KADM5: `initvt_plugin!(prefix, ver, Type, make_fn)` exports
     `<prefix>_initvt` C function

6. **Idiomatic error handling.** Every trait method returns `Result<_, Error>`.
   The glue layer converts to/from `krb5_error_code` integers at the C boundary.

7. **Derive macros for delegation.** `#[derive(KdbModule)]`,
   `#[derive(PwqualModule)]`, etc. generate forwarding impls for overlay plugins
   that wrap another implementation, so you only override the methods you need.

---

## Workspace layout

```
crates/
  Cargo.toml                       # workspace root
  README.md                        # this file

  kurbu5-sys/                      # raw FFI bindings (all interfaces)
    Cargo.toml                     #   links = "krb5"; build-dep bindgen
    build.rs                       #   bindgen of krb5.h + kdb.h + 9 plugin
                                   #   headers + 2 kadm5 headers + profile.h
                                   #   + full admin.h function coverage
    src/lib.rs                     #   include! generated bindings

  kurbu5-rs/                       # non-KDB plugin interfaces
    Cargo.toml                     #   9 feature-gated interfaces + derive + profile
    README.md                      #   non-KDB plugin API reference
    src/
      lib.rs                       #   public API + initvt_plugin! macro
      error.rs                     #   Krb5Error enum
      context.rs                   #   PluginContext<'ctx> wrapper
      profile.rs                   #   Profile — RAII handle to krb5.conf / kdc.conf
      crypto.rs                    #   krb5 symmetric-key crypto wrappers
      tl_data.rs                   #   TlDataRef, TlDataIter, TlDataBuilder,
                                   #   OwnedTlDataList<P>, TlDataFreePolicy,
                                   #   GenericFree — shared across all plugin families
      pwqual.rs / pwqual/glue.rs   #   PWQUAL interface
      hostrealm.rs / .../glue.rs   #   HOSTREALM interface
      localauth.rs / .../glue.rs   #   LOCALAUTH interface
      ccselect.rs / .../glue.rs    #   CCSELECT interface
      kdcpolicy.rs / .../glue.rs   #   KDCPOLICY interface
      certauth.rs / .../glue.rs    #   CERTAUTH interface
      kdcpreauth.rs / .../glue.rs  #   KDCPREAUTH interface
      clpreauth.rs / .../glue.rs   #   CLPREAUTH interface
      audit.rs / .../glue.rs       #   AUDIT interface (private; KDC-only)
    examples/
      pwqual_example.rs            #   runnable PWQUAL example

  kurbu5-derive/                   # proc-macro derives for kurbu5-rs
    Cargo.toml                     #   proc-macro = true; 8 interface features
    src/lib.rs                     #   PwqualModule, HostrealmModule, … derives

  kurbu5-kdb/
    README.md                      # KDB API reference
    kurbu5-kdb-sys/                # KDB linkage layer
      Cargo.toml                   #   links = "kdb5"
      build.rs                     #   emits cargo:rustc-link-lib=dylib=kdb5
      src/lib.rs                   #   pub use kurbu5_sys::*

    kurbu5-kdb-rs/                 # safe, idiomatic KDB API
      Cargo.toml
      src/
        lib.rs                     #   KdbModule trait + kdb_plugin! macro
        error.rs                   #   KdbError enum + From impls
        types.rs                   #   OpenMode, LookupFlags, Timestamp, …
        principal.rs               #   PrincipalRef, PrincipalEntry, …
        tl_data.rs                 #   TlDataRef, TlDataIter, TlDataBuilder
        key_data.rs                #   KeyDataRef, KeyDataSlice, KeyDataBuilder
        policy.rs                  #   PolicyEntryRef, PolicyEntry
        context.rs                 #   KdbContext + utility wrappers
        module.rs                  #   KdbModule trait
        backing_db.rs              #   BackingDb for overlay plugins
        glue.rs                    #   ONLY unsafe file: C vtable <-> trait

    kurbu5-kdb-example/            # minimal example KDB plugin
      Cargo.toml                   #   crate-type = ["cdylib"]
      src/lib.rs

  kadm5/
    README.md                      # KADM5 plugin API reference
    kurbu5-kadm5-sys/              # KADM5 linkage layer
      Cargo.toml                   #   links = "kadm5srv_mit"
      build.rs                     #   emits cargo:rustc-link-lib=dylib=kadm5srv_mit
      src/lib.rs                   #   pub use kurbu5_sys::*

    kurbu5-kadm5-rs/               # safe, idiomatic KADM5 plugin API
      Cargo.toml                   #   kadm5_auth + kadm5_hook + admin features
      src/
        lib.rs                     #   public API + initvt_plugin! macro
        error.rs                   #   Krb5Error re-export
        context.rs                 #   PluginContext<'ctx> wrapper
        principal.rs               #   Kadm5PrincipalEntry<'a> view
        auth.rs / auth/glue.rs     #   KADM5_AUTH interface (24 methods)
        hook.rs / hook/glue.rs     #   KADM5_HOOK interface (8 methods)
        admin.rs                   #   AdminHandle — local-mode KADM5 admin client

    kurbu5-kadm5-derive/           # proc-macro derives for kadm5 interfaces
      Cargo.toml                   #   proc-macro = true
      src/lib.rs                   #   Kadm5AuthModule, Kadm5HookModule derives

  contrib/
    ci/
      local-ci.sh                  # local CI runner
      rust-valgrind.supp           # Valgrind suppressions
    toc/
      update-toc.py                # doctoc-compatible TOC checker
    validation/
      doc-rust-samples.py          # extract + compile Rust doc code blocks
      doc-rust-samples.sh          # shell driver
    analysis/
      analyze-deps.py              # workspace-agnostic Cargo dep analyser
```

### Crate dependency graph

```
kurbu5-sys  (links = "krb5")
  |
  +-- kurbu5-rs               (non-KDB plugin traits; 9 interfaces; shared TL-data types)
  |     +-- kurbu5-derive     (proc-macro derives for kurbu5-rs traits)
  |
  +-- kurbu5-kdb-sys          (links = "kdb5"; re-exports kurbu5-sys)
  |     +-- kurbu5-kdb-rs     (safe KDB API)  ────────────────────────────┐
  |           +-- kurbu5-kdb-example  (example cdylib)                    │ also depends
  |                                                                       │ on kurbu5-rs
  +-- kurbu5-kadm5-sys        (links = "kadm5srv_mit"; re-exports kurbu5-sys)
        +-- kurbu5-kadm5-rs   (safe KADM5 plugin + admin API)  ──────────-┘
              +-- kurbu5-kadm5-derive  (proc-macro derives for kadm5 traits)
```

`kurbu5-kdb-rs` and `kurbu5-kadm5-rs` both have a direct dependency on
`kurbu5-rs` for the shared `krb5_tl_data` types (`TlDataRef`, `TlDataIter`,
`TlDataBuilder`, `OwnedTlDataList`, `TlDataFreePolicy`, `GenericFree`) and for
the `Profile` API (`kurbu5_rs::profile::Profile`).  KDB-specific extensions
(`KdbFree`, `KdbTlDataList`) are defined in `kurbu5-kdb-rs` on top of the shared types.

---

## Plugin interfaces at a glance

### KDB — database driver plugins

| Trait | Vtable struct | C symbol exported |
|-------|---------------|-------------------|
| `KdbModule` | `kdb_vftabl` | `kdb_function_table` (static) |

See [`kurbu5-kdb/README.md`](kurbu5-kdb/README.md) for the full trait reference.

### Non-KDB plugins (kurbu5-rs)

| Feature | Trait | C header | Vtable struct |
|---------|-------|----------|---------------|
| `pwqual` | `PwqualModule` | `pwqual_plugin.h` | `krb5_pwqual_vtable_st` |
| `hostrealm` | `HostrealmModule` | `hostrealm_plugin.h` | `krb5_hostrealm_vtable_st` |
| `localauth` | `LocalauthModule` | `localauth_plugin.h` | `krb5_localauth_vtable_st` |
| `ccselect` | `CcselectModule` | `ccselect_plugin.h` | `krb5_ccselect_vtable_st` |
| `kdcpolicy` | `KdcpolicyModule` | `kdcpolicy_plugin.h` | `krb5_kdcpolicy_vtable` |
| `certauth` | `CertauthModule` | `certauth_plugin.h` | `krb5_certauth_vtable` |
| `kdcpreauth` | `KdcpreauthModule` | `kdcpreauth_plugin.h` | `krb5_kdcpreauth_vtable_st` |
| `clpreauth` | `ClpreauthModule` | `clpreauth_plugin.h` | `krb5_clpreauth_vtable_st` |
| `audit` | `AuditModule` | `audit_plugin.h` (private) | `krb5_audit_vtable_st` |

All nine share the same exported C function pattern: `<name>_initvt`.

See [`kurbu5-rs/README.md`](kurbu5-rs/README.md) for the full API reference.

### KADM5 plugins and admin client (kurbu5-kadm5-rs)

| Feature | Type | C header | Description |
|---------|------|----------|-------------|
| `kadm5_auth` | `Kadm5AuthModule` | `kadm5_auth_plugin.h` | 24-method auth plugin (all defaulted to allow) |
| `kadm5_hook` | `Kadm5HookModule` | `kadm5_hook_plugin.h` | 8-method hook plugin (all defaulted to no-op) |
| `admin` | `AdminHandle` | `kadm5/admin.h` | local-mode KDB-direct admin client |

See [`kadm5/README.md`](kadm5/README.md) for the full API reference.

---

## Quick start

### KDB plugin

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
kurbu5-kdb-rs = { git = "https://codeberg.org/abbra/kurbu5.git" }
```

```rust
use kurbu5_kdb_rs::{
    kdb_plugin, KdbContext, KdbError, KdbModule,
    LookupFlags, OpenMode, PrincipalEntry, PrincipalRef,
};

pub struct MyKdb { db_path: String }

impl KdbModule for MyKdb {
    fn open(
        _ctx: &KdbContext<'_>,
        conf_section: &str,
        _db_args: &[&str],
        _mode: OpenMode,
    ) -> Result<Self, KdbError> {
        Ok(MyKdb { db_path: format!("/var/lib/kerberos/{conf_section}.db") })
    }

    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        _flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        let _name = ctx.unparse_principal(search_for)?;
        Ok(None) // "not found"
    }
}

// Exports C symbol: kdb_function_table
kdb_plugin!(mykdb, MyKdb);
```

Only `open` and `get_principal` are mandatory.  All other vtable methods have
safe defaults.  Configure in `kdc.conf`:

```ini
[dbmodules]
    mykdb = { db_library = mykdb }
[realms]
    EXAMPLE.COM = { database_module = mykdb }
```

### Non-KDB plugin (PWQUAL example)

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
kurbu5-rs = { git = "https://codeberg.org/abbra/kurbu5.git", features = ["pwqual"] }
```

```rust
use std::ffi::CStr;
use kurbu5_rs::{initvt_plugin, PluginContext};
use kurbu5_rs::pwqual::{CheckRequest, PwqualError, PwqualModule};

pub struct MinLen;

impl PwqualModule for MinLen {
    const NAME: &'static CStr = c"min_len";

    fn open(_ctx: &PluginContext<'_>, _dict: Option<&str>) -> Result<Self, PwqualError> {
        Ok(MinLen)
    }

    fn check(&self, _ctx: &PluginContext<'_>, req: &CheckRequest<'_>) -> Result<(), PwqualError> {
        if req.password.chars().count() < 12 {
            Err(PwqualError::TooShort)
        } else {
            Ok(())
        }
    }
}

// Exports C function: pwqual_min_len_initvt
initvt_plugin!(pwqual_min_len, 1, MinLen, kurbu5_rs::pwqual::glue::make_pwqual_vtable);
```

Quick-start examples for the other seven interfaces and both KADM5 interfaces
are in the per-subsystem READMEs linked above.

---

## Building

Requirements:

* Rust 1.75 or later (edition 2021)
* MIT Kerberos development headers (`krb5-devel` / `libkrb5-dev`),
  version 1.22.1 or later (Fedora 43+ / Rawhide)
* `pkg-config` (used by `kurbu5-sys/build.rs` to locate headers)
* `clang-libs`, `clang-devel` (required by `bindgen`)
* `libkadm5srv_mit` headers (for the `kadm5/` crates)

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

To run only the non-KDB plugin tests with all interfaces enabled:

```sh
cargo test -p kurbu5-rs --features full
```

To run all KADM5 tests:

```sh
cargo test -p kurbu5-kadm5-rs --features full
```

The local CI script runs the full pipeline (build, fmt, clippy, doc, test):

```sh
contrib/ci/local-ci.sh
contrib/ci/local-ci.sh --valgrind   # route tests through Valgrind
```

---

## Target

* **KDB DAL major version 9** (`KRB5_KDB_DAL_MAJOR_VERSION = 9`), introduced
  in MIT Kerberos 1.21.
* **Non-KDB and KADM5 interfaces** as shipped in MIT Kerberos >= 1.22.1
  (Fedora 43+ / Rawhide).

Earlier versions are not supported.

---

## Known limitations

* **LOCATE** (`krb5_locate_plugin_vtable`) is not implemented; it is a legacy
  interface superseded by HOSTREALM.
* The **KDCPREAUTH** and **CLPREAUTH** async-callback pattern is bridged
  synchronously.  True `async`/`await` integration (tokio, async-std) is a
  future goal.
* `kurbu5-kadm5-sys` links against `libkadm5srv_mit`.  The exact library name
  is resolved at build time via `pkg-config` and may vary by platform.
* The framework is not a general-purpose krb5 Rust binding — it covers only
  the plugin surface areas listed above.
* The `krb5_context` is used from a single thread at a time per the existing
  krb5 threading contract.  The `Send` bound on module types allows moving
  them between threads between successive calls, not concurrent access.

---

## Roadmap

### Near-term

* `tracing` crate integration: auto-instrument every vtable entry point.

### Longer-term

* `async` support in `KdbModule`, KDCPREAUTH, and CLPREAUTH for plugins with
  network I/O (requires careful handling of the `krb5_context` threading model).
* PAC parsing utilities: safe wrappers around `krb5_pac_*` functions.
* Fuzzing harness for glue layers using `cargo-fuzz`.
* Windows support (conditional compilation; symbol export without prefix).

---

## License

This project is distributed under the same license as the MIT Kerberos 5
source tree — a BSD-style two-clause license.  See [`LICENSE`](LICENSE) for
the full text.
