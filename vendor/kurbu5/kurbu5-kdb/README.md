# Rust KDB Driver API

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Motivation](#motivation)
- [Design Principles](#design-principles)
  - [Zero-copy at the read boundary](#zero-copy-at-the-read-boundary)
  - [C-compatible owned allocation at the write boundary](#c-compatible-owned-allocation-at-the-write-boundary)
  - [Single unsafe boundary](#single-unsafe-boundary)
  - [Static dispatch via generics](#static-dispatch-via-generics)
  - [Idiomatic error handling](#idiomatic-error-handling)
- [Crate Layout](#crate-layout)
- [The `KdbModule` Trait](#the-kdbmodule-trait)
- [Plugin Export](#plugin-export)
- [Overlay Plugins (`#[derive(KdbModule)]`)](#overlay-plugins-derivekdbmodule)
  - [Required overrides](#required-overrides)
  - [Optional overrides](#optional-overrides)
  - [Full example](#full-example)
- [Zero-copy type summary](#zero-copy-type-summary)
- [TL-data ownership and free policies](#tl-data-ownership-and-free-policies)
- [`KdbContext` utilities](#kdbcontext-utilities)
- [Memory safety guarantees](#memory-safety-guarantees)
- [Compatibility](#compatibility)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

This directory contains a Rust framework for writing MIT Kerberos KDB (Key
Distribution Center Database) driver plugins.  The goal is to allow the
business logic of a KDB driver to be written in safe, idiomatic Rust while
keeping all FFI boundary details confined to a thin, well-audited glue layer.

## Motivation

The C KDB plugin API (`kdb_vftabl` in `src/include/kdb.h`) exposes a vtable of
function pointers that libkdb5 calls into.  Writing a driver directly in C
requires:

* Manual memory management of `krb5_db_entry`, `krb5_tl_data`, `krb5_key_data`,
  and `osa_policy_ent_rec` — each with its own allocation and ownership rules.
* Raw pointer casts to recover per-context state from
  `context->dal_handle->db_context`.
* Error-prone pattern of returning allocated `krb5_db_entry **` that libkdb5
  then owns and frees through `krb5_db_free_principal`.
* Callback-based iteration with raw `krb5_pointer` (void*) arguments.
* No type-level enforcement of which vtable slots are mandatory vs. optional.

The Rust layer provides:

* A `KdbModule` trait that maps the vtable to type-safe, `Result`-returning
  methods with sane defaults for optional operations.
* Zero-copy read views (`PrincipalEntryRef`, `TlDataRef`, `KeyDataSlice`) that
  borrow directly from C-owned memory without any allocation.
* An owned `PrincipalEntry` type that manages C-compatible allocations so
  libkdb5 can free them correctly.
* A `KdbContext` handle that provides safe wrappers around the krb5 utility
  functions modules commonly need.
* All `unsafe` code confined to `kurbu5-kdb-rs/src/glue.rs` — the single file a
  reviewer needs to audit for memory safety.
* A declarative `kdb_plugin!` macro that generates the C vtable and hides all
  FFI plumbing.

---

## Design Principles

### Zero-copy at the read boundary

When libkdb5 passes a `krb5_db_entry *` to the driver (e.g. in `put_principal`
or the `iterate` callback), the framework wraps it as a `PrincipalEntryRef<'a>`
— a Rust reference whose lifetime is tied to the C pointer's validity.  No heap
allocation occurs.  All fields are accessed via inline accessors that read
directly from the C struct.  The `tl_data` linked list is exposed as a
zero-allocation `TlDataIter<'a>` iterator.  The `key_data` array is exposed as
a `&'a [krb5_key_data]` slice.

### C-compatible owned allocation at the write boundary

When the driver creates a new entry to return from `get_principal`, it builds a
`PrincipalEntry` — a Rust struct that owns a heap-allocated `krb5_db_entry`
using the standard system allocator (which is the same malloc that libkdb5
uses on all POSIX platforms, per the note in `kdb.h`).  All embedded data
(tl_data nodes, key_data arrays, principal name) is similarly malloc-allocated
so that `krb5_db_free_principal` can free everything correctly.  The Rust code
transfers ownership to C via `PrincipalEntry::into_raw()` which returns the raw
pointer and prevents the Rust drop from running.

### Single unsafe boundary

Every `unsafe` block lives in `kurbu5-kdb-rs/src/glue.rs`.  The glue module:

1. Implements the bare `extern "C"` functions matching the `kdb_vftabl` slots.
2. Recovers the `Box<M>` module state from `db_context`.
3. Wraps raw C pointers into the zero-copy Rust types.
4. Calls the trait methods.
5. Translates `Result<_, KdbError>` back to `krb5_error_code`.

Nothing outside `glue.rs` touches raw pointers directly.

### Static dispatch via generics

The `make_vftabl::<M>()` const function monomorphises a complete `kdb_vftabl`
for any concrete module type `M: KdbModule`.  This gives zero-overhead dispatch
— the compiler sees the exact type at every call site and can inline freely.
There is no virtual dispatch (no `dyn Trait`) in the hot path.

### Idiomatic error handling

`KdbError` is a Rust enum covering the most common Kerberos error codes plus a
`Custom(krb5_error_code)` variant for pass-through of arbitrary codes.
`Result<T, KdbError>` is used everywhere in the public API.  The glue layer
converts back to the raw integer only at the C boundary.

---

## Crate Layout

```
crates/kurbu5-kdb/
  README.md             # this file

  kurbu5-kdb-sys/       # KDB linkage layer: re-exports kurbu5-sys + links libkdb5
    Cargo.toml
    build.rs            # emits cargo:rustc-link-lib=dylib=kdb5
    src/lib.rs          # pub use kurbu5_sys::*

  kurbu5-kdb-rs/               # safe, idiomatic KDB driver API
    Cargo.toml
    src/
      lib.rs            # public API surface; re-exports from sub-modules
      error.rs          # KdbError enum + From impls
      types.rs          # OpenMode, LockMode, LookupFlags, IterFlags,
                        # Timestamp, PrincipalAttributes,
                        # KdcOptions, TicketFlags, ...
      principal.rs      # PrincipalRef, PrincipalEntryRef, PrincipalEntry,
                        # OwnedPrincipal
      tl_data.rs        # re-exports TlDataRef, TlDataIter, TlDataBuilder,
                        # OwnedTlDataList, TlDataFreePolicy, GenericFree from
                        # kurbu5-rs; adds KdbFree + KdbTlDataList (KDB-layer
                        # drop policy)
      key_data.rs       # KeyDataRef, KeyDataSlice, KeyDataBuilder, KeyBlock,
                        # KeySalt
      policy.rs         # PolicyEntryRef, PolicyEntry
      context.rs        # KdbContext + utility method wrappers; Krb5Context RAII
      module.rs         # KdbModule trait (the main user-facing API)
      backing_db.rs     # BackingDb: owned context wrapping a loaded KDB module;
                        # implements KdbModule for use as a #[derive] delegate
      glue.rs           # unsafe: C vtable <-> trait dispatch (ONLY unsafe file)

  kurbu5-kdb-derive/           # proc-macro crate (enabled via derive feature)
    Cargo.toml
    src/lib.rs          # #[derive(KdbModule)], #[kdb_method], #[kdb_impl]

  kurbu5-kdb-example/          # minimal working example plugin
    Cargo.toml
    src/
      lib.rs            # ExampleKdb: uses kdb_plugin!; ExampleKdb: KdbModule
      tests.rs          # integration tests incl. OverlayKdb derive smoke-test
```

The workspace `Cargo.toml` lives at `crates/Cargo.toml` and lists all crates
under `crates/kurbu5-kdb/` (and any future plugin API namespaces).

---

## The `KdbModule` Trait

Below is the complete trait definition.  Methods with a default body are
optional; methods without one are mandatory.

```rust
pub trait KdbModule: Sized + Send + 'static {

    // -----------------------------------------------------------------------
    // Library lifecycle  (called once globally, not per-context)
    // -----------------------------------------------------------------------

    /// Called when the first database using this module is opened.
    fn init_library() -> Result<(), KdbError> { Ok(()) }

    /// Called when the last database using this module is closed.
    fn fini_library() -> Result<(), KdbError> { Ok(()) }

    // -----------------------------------------------------------------------
    // Context lifecycle
    // -----------------------------------------------------------------------

    /// Open (initialise) a database context.  Returns `Self` boxed into
    /// `db_context` by the glue layer.
    fn open(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
        mode: OpenMode,
    ) -> Result<Self, KdbError>;

    /// Close (finalise) this context.  Consumes `self`.
    fn close(self) -> Result<(), KdbError> { Ok(()) }

    // -----------------------------------------------------------------------
    // Database lifecycle  (optional; controlled by SUPPORTS_* constants)
    //
    // Each lifecycle method has a paired constant.  When the constant is
    // `false` (the default) the vtable slot is set to NULL and libkdb5
    // returns KRB5_PLUGIN_OP_NOTSUPP.  Set the constant to `true` *and*
    // provide a real implementation to expose the operation.
    //
    // If SUPPORTS_CREATE is true, create() is fully responsible for leaving
    // the krb5_context initialised (db_context set) so that subsequent KDB
    // calls work without a separate open() — call ctx.set_module() at the
    // end of create() to satisfy this contract.
    // -----------------------------------------------------------------------

    const SUPPORTS_CREATE: bool = false;
    const SUPPORTS_DESTROY: bool = false;
    const SUPPORTS_PROMOTE_DB: bool = false;

    fn create(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn destroy(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn promote_db(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // Locking  (optional)
    // -----------------------------------------------------------------------

    fn lock(&self, mode: LockMode) -> Result<(), KdbError> { Ok(()) }
    fn unlock(&self) -> Result<(), KdbError> { Ok(()) }

    // -----------------------------------------------------------------------
    // Principal CRUD  (get_principal mandatory; others optional)
    // -----------------------------------------------------------------------

    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError>;

    fn put_principal(
        &self,
        ctx: &KdbContext<'_>,
        entry: PrincipalEntryRef<'_>,
        db_args: &[&str],
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn delete_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn rename_principal(
        &self,
        ctx: &KdbContext<'_>,
        source: PrincipalRef<'_>,
        target: PrincipalRef<'_>,
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn iterate_principals(
        &self,
        ctx: &KdbContext<'_>,
        match_entry: Option<&str>,
        flags: IterFlags,
        callback: &mut dyn FnMut(PrincipalEntryRef<'_>) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // Password policy CRUD  (all optional)
    // -----------------------------------------------------------------------

    fn create_policy(&self, ctx: &KdbContext<'_>, policy: &PolicyEntry)
        -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn get_policy(&self, ctx: &KdbContext<'_>, name: &str)
        -> Result<Option<PolicyEntry>, KdbError> { Err(KdbError::NotSupported) }

    fn put_policy(&self, ctx: &KdbContext<'_>, policy: &PolicyEntry)
        -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn iter_policy(
        &self,
        ctx: &KdbContext<'_>,
        match_entry: Option<&str>,
        callback: &mut dyn FnMut(&PolicyEntry) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn delete_policy(&self, ctx: &KdbContext<'_>, name: &str)
        -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // Key encryption  (optional; controlled by SUPPORTS_* constants)
    //
    // When SUPPORTS_DECRYPT_KEY_DATA / SUPPORTS_ENCRYPT_KEY_DATA is false
    // (the default), the vtable slot is NULL and libkdb5 calls its built-in
    // krb5_dbe_def_decrypt_key_data / krb5_dbe_def_encrypt_key_data directly.
    // Most overlay drivers should leave these at false to avoid loading
    // per-call OpenSSL EVP cipher state in the plugin process.
    // -----------------------------------------------------------------------

    const SUPPORTS_DECRYPT_KEY_DATA: bool = false;
    const SUPPORTS_ENCRYPT_KEY_DATA: bool = false;

    fn decrypt_key_data(
        &self,
        ctx: &KdbContext<'_>,
        req: DecryptKeyRequest<'_>,
    ) -> Result<(KeyBlock, Option<KeySalt>), KdbError> { Err(KdbError::NotSupported) }

    fn encrypt_key_data(
        &self,
        ctx: &KdbContext<'_>,
        req: EncryptKeyRequest<'_>,
    ) -> Result<KeyDataOwned, KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // Master key operations  (optional)
    // -----------------------------------------------------------------------

    /// Retrieve the master keyblock from the stash file `db_args`.
    ///
    /// Returns `(key, kvno)`.  `NotSupported` → libkdb5 reads from the
    /// keytab or old-format stash file.
    fn fetch_master_key(
        &self,
        ctx: &KdbContext<'_>,
        mname: PrincipalRef<'_>,
        db_args: &str,
    ) -> Result<(KeyBlock, u32), KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // Key search  (optional)
    // -----------------------------------------------------------------------

    /// Search the key data of `entry` for a key matching the given criteria.
    ///
    /// `start` is an in-out parameter: on entry it is the position to start
    /// searching from; on success it is updated to point past the found key.
    /// Pass `ktype`, `stype`, or `kvno` as negative to match any value.
    ///
    /// `NotSupported` → libkdb5 uses its built-in default implementation.
    fn dbe_search_enctype<'entry>(
        &self,
        ctx: &KdbContext<'_>,
        entry: PrincipalEntryRef<'entry>,
        start: &mut i32,
        ktype: i32,
        stype: i32,
        kvno: i32,
    ) -> Result<Option<KeyDataRef<'entry>>, KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // KDC policy hooks  (optional; default is permissive / fall-through)
    // -----------------------------------------------------------------------

    /// Additional AS policy check.  Return `Ok(())` to permit.
    /// Return `Err(PolicyDenied { .. })` to deny.
    fn check_policy_as(
        &self,
        ctx: &KdbContext<'_>,
        req: AsPolicyRequest<'_>,
    ) -> Result<(), PolicyDenied> { Ok(()) }

    /// Additional TGS policy check.
    fn check_policy_tgs(
        &self,
        ctx: &KdbContext<'_>,
        req: TgsPolicyRequest<'_>,
    ) -> Result<(), PolicyDenied> { Ok(()) }

    /// Transited-realm check.  Return `Err(KdbError::NoHandle)` to fall
    /// through to the libkrb5 default implementation.
    fn check_transited_realms(
        &self,
        ctx: &KdbContext<'_>,
        tr_contents: &[u8],
        client_realm: &[u8],
        server_realm: &[u8],
    ) -> Result<(), KdbError> { Err(KdbError::NoHandle) }

    fn check_allowed_to_delegate(
        &self,
        ctx: &KdbContext<'_>,
        req: DelegationRequest<'_>,
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    fn allowed_to_delegate_from(
        &self,
        ctx: &KdbContext<'_>,
        req: ResourceDelegationRequest<'_>,
    ) -> Result<(), KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // Audit hooks  (optional, infallible)
    // -----------------------------------------------------------------------

    fn audit_as_req(&self, ctx: &KdbContext<'_>, event: AsAuditEvent<'_>) {}
    fn refresh_config(&self, ctx: &KdbContext<'_>) {}

    // -----------------------------------------------------------------------
    // S4U X.509 principal lookup  (optional)
    // -----------------------------------------------------------------------

    fn get_s4u_x509_principal(
        &self,
        ctx: &KdbContext<'_>,
        req: S4uX509Request<'_>,
    ) -> Result<Option<PrincipalEntry>, KdbError> { Err(KdbError::NotSupported) }

    // -----------------------------------------------------------------------
    // PAC issuance  (optional; Ok(()) = no additional buffers added)
    // -----------------------------------------------------------------------

    fn issue_pac(
        &self,
        ctx: &KdbContext<'_>,
        req: PacIssuanceRequest<'_>,
        output: &mut PacIssuanceOutput<'_>,
    ) -> Result<(), KdbError> { Ok(()) }

    // -----------------------------------------------------------------------
    // Memory management hook  (optional)
    // -----------------------------------------------------------------------

    /// Free the `e_data` pointer of a principal entry.  If not implemented,
    /// libkdb5 calls `free()` on the pointer directly.
    fn free_principal_e_data(&self, _e_data: *mut u8) {}
}
```

---

## Plugin Export

A KDB plugin is a shared library (`.so`) that exports the C symbol
`kdb_function_table`.  `libkdb5` selects the plugin by the filename derived
from `db_library` in `krb5.conf`, then calls `dlsym(handle, "kdb_function_table")`
to obtain the vtable.

There are two equivalent ways to generate the symbol export:

* **`kdb_plugin!` macro** — explicit, one-line call at the bottom of `lib.rs`.
* **`plugin = "name"` attribute** — absorbed into `#[derive(KdbModule)]` so
  overlay plugins need no separate macro call.

```rust
// Approach 1 — direct impl + kdb_plugin!  (Cargo.toml: crate-type = ["cdylib"])

use kurbu5_kdb_rs::{kdb_plugin, KdbModule, KdbContext, PrincipalRef, PrincipalEntry};
use kurbu5_kdb_rs::{KdbError, LookupFlags, OpenMode};

pub struct MyKdb {
    db_path: String,
    // ... your state
}

impl KdbModule for MyKdb {
    fn open(
        _ctx: &KdbContext<'_>,
        conf_section: &str,
        _db_args: &[&str],
        _mode: OpenMode,
    ) -> Result<Self, KdbError> {
        // read config, open connection, etc.  No unsafe code needed.
        Ok(MyKdb { db_path: format!("/var/kerberos/{}.db", conf_section) })
    }

    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError>
    {
        // Pure business logic: query your storage backend.
        // Use ctx.unparse_principal(search_for) for a string representation.
        // Build and return a PrincipalEntry using the builder API.
        Ok(None)  // not found
    }
}

// Generates and exports the C symbol kdb_function_table.
kdb_plugin!(mykdb, MyKdb);
```

See [Overlay Plugins](#overlay-plugins-derivekdbmodule) below for Approach 2
(`plugin = "name"` inside `#[kdb(...)]`).

---

## Overlay Plugins (`#[derive(KdbModule)]`)

An overlay plugin wraps another KDB module and intercepts only the operations
that differ from the backing store.  The `kurbu5-kdb-derive` crate (enabled via
`features = ["derive"]` on `kurbu5-kdb-rs`) provides three macros:

| Macro | Role |
|-------|------|
| `#[derive(KdbModule)]` | Generate `impl KdbModule` that delegates to a field |
| `#[kdb_method]` | Rename `fn foo` → `fn kdb_impl_foo` inside `#[kdb_impl]` blocks |
| `#[kdb_impl]` | Mark an inherent `impl` block containing override methods |

`BackingDb` implements `KdbModule`, so it can be the `delegate` field directly.
The generated delegation calls use fully-qualified syntax
`<BackingDb as KdbModule>::method(&self.backing, ctx, …)` to avoid any
ambiguity with `BackingDb`'s same-named inherent methods.

### Required overrides

`open` and `get_principal` have no defaults in `KdbModule`; the derive always
calls `Self::kdb_impl_open` and `self.kdb_impl_get_principal`.  Provide them
with `#[kdb_method]` inside `#[kdb_impl]`.

### Optional overrides

Optional methods with custom logic (e.g. `create`, `destroy`, `promote_db`)
must be listed in `overrides(…)` *and* marked `#[kdb_method]`.  Methods not
listed are auto-forwarded to the delegate field.

### Full example

```rust,ignore
// Cargo.toml:  kurbu5-kdb-rs = { …, features = ["derive"] }
//              crate-type = ["cdylib"]

use kurbu5_kdb_rs::{
    kdb_impl, kdb_method, AccessMode, BackingDb, KdbContext, KdbError, KdbModule,
    LookupFlags, OpenMode, PrincipalEntry, PrincipalRef, ServerType,
};

/// Overlay that augments klmdb with a custom get_principal fallback.
/// All other operations — put_principal, iterate_principals, policy
/// CRUD, check_policy_as, audit_as_req, … — are auto-delegated to
/// the backing BackingDb (which forwards them to klmdb).
#[derive(KdbModule)]
#[kdb(
    delegate = backing,
    supports_create,
    supports_destroy,
    supports_promote_db,
    overrides(create, destroy, promote_db),
    plugin = "my_overlay",            // exports kdb_function_table
)]
pub struct MyOverlay {
    disallow_aliases: bool,
    backing: BackingDb,
}

#[kdb_impl]
impl MyOverlay {
    // open and get_principal: required — always call kdb_impl_*.
    #[kdb_method]
    fn open(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
        mode: OpenMode,
    ) -> Result<Self, KdbError> {
        let disallow_aliases = ctx
            .db_module_string(conf_section, "disallow_aliases")
            .as_deref()
            .map(|v| v != "false")
            .unwrap_or(true);
        let backing = BackingDb::open(ctx, "klmdb", db_args, mode)?;
        Ok(MyOverlay { disallow_aliases, backing })
    }

    #[kdb_method]
    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        if let Some(entry) = self.backing.get_principal(search_for, flags)? {
            return Ok(Some(entry));
        }
        // … custom fallback logic …
        Ok(None)
    }

    // Optional overrides listed in overrides(create, destroy, promote_db).
    #[kdb_method]
    fn create(ctx: &KdbContext<'_>, conf_section: &str, db_args: &[&str])
        -> Result<(), KdbError>
    {
        BackingDb::create_db(ctx, "klmdb", db_args)?;
        let mode = OpenMode { access: AccessMode::ReadWrite, server: ServerType::Other };
        let backing = BackingDb::open(ctx, "klmdb", db_args, mode)?;
        ctx.set_module(MyOverlay { disallow_aliases: true, backing })
    }

    #[kdb_method]
    fn destroy(ctx: &KdbContext<'_>, _conf_section: &str, db_args: &[&str])
        -> Result<(), KdbError>
    {
        BackingDb::destroy_db(ctx, "klmdb", db_args)
    }

    #[kdb_method]
    fn promote_db(ctx: &KdbContext<'_>, _conf_section: &str, db_args: &[&str])
        -> Result<(), KdbError>
    {
        BackingDb::promote_db(ctx, "klmdb", db_args)
    }
}
// No kdb_plugin! needed — plugin = "my_overlay" above emits the symbol.
```

---

## Zero-copy type summary

| C type | Read (zero-copy Rust view) | Write (owned, C-freeable) |
|--------|---------------------------|--------------------------|
| `krb5_principal` | `PrincipalRef<'a>` | `OwnedPrincipal` |
| `krb5_db_entry *` | `PrincipalEntryRef<'a>` | `PrincipalEntry` |
| `krb5_tl_data *` (linked list) | `TlDataIter<'a>` → `TlDataRef<'a>` | `TlDataBuilder` → `TlDataList` / `KdbTlDataList` |
| `krb5_key_data[]` (array) | `KeyDataSlice<'a>` → `KeyDataRef<'a>` | `KeyDataBuilder` |
| `osa_policy_ent_t *` | `PolicyEntryRef<'a>` | `PolicyEntry` |
| `krb5_keyblock` | `KeyBlockRef<'a>` | `KeyBlock` |
| `krb5_kdc_req *` | `KdcRequestRef<'a>` | — |
| `krb5_ticket *` | `TicketRef<'a>` | — |
| `krb5_address *` | `AddressRef<'a>` | — |
| `krb5_pa_data **` (null-terminated) | `PaDataIter<'a>` (iterator of PA type codes) | — |
| `krb5_data` | `&'a [u8]` | `Vec<u8>` / `KrbData` |

`KdcRequestRef<'a>` accessors: `kdc_options() -> KdcOptions`, `requested_enctypes() -> &'a [i32]`,
`padata_types() -> PaDataIter<'a>`, `till() -> Timestamp`, `rtime() -> Timestamp`.

`KdcOptions` is a `bitflags!` type defined in `types.rs`.  Flag constants (all
prefixed `KdcOptions::`) include `FORWARDABLE`, `FORWARDED`, `PROXIABLE`, `PROXY`,
`ALLOW_POSTDATE`, `POSTDATED`, `RENEWABLE`, `CNAME_IN_ADDL_TKT`, `CANONICALIZE`,
`REQUEST_ANONYMOUS`, `DISABLE_TRANSITED_CHECK`, `RENEWABLE_OK`, `ENC_TKT_IN_SKEY`,
`RENEW`, and `VALIDATE`.

`TicketRef<'a>` accessors: `client() -> Option<PrincipalRef<'a>>` (from `enc_part2->client`),
`ticket_flags() -> TicketFlags`, `authtime() -> Timestamp`, `endtime() -> Timestamp`,
`renew_till() -> Timestamp`.

`TicketFlags` is a `bitflags!` type defined in `types.rs`.  Flag constants (all
prefixed `TicketFlags::`) include `FORWARDABLE`, `FORWARDED`, `PROXIABLE`, `PROXY`,
`MAY_POSTDATE`, `POSTDATED`, `INVALID`, `RENEWABLE`, `INITIAL`, `PRE_AUTH`,
`HW_AUTH`, `TRANSIT_POLICY_CHECKED`, `OK_AS_DELEGATE`, `ENC_PA_REP`, and `ANONYMOUS`.

`PaDataIter<'a>` is an `Iterator<Item = i32>` over PA-type codes from a
null-terminated `krb5_pa_data **` array.  Produced by `KdcRequestRef::padata_types()`.

`AddressRef<'a>` accessors: `addrtype() -> i32` (2 = IPv4, 24 = IPv6), `contents() -> &'a [u8]`,
`display() -> Option<String>` (formatted IPv4/IPv6 string).

---

## TL-data ownership and free policies

`krb5_tl_data` is a singly-linked list whose nodes are individually
malloc-allocated.  Freeing it correctly requires knowing which allocator
function to call.  This crate uses a **compile-time free policy** pattern
so that different contexts can use different cleanup strategies without
runtime overhead.

The core types live in `kurbu5-rs` and are re-exported here:

```rust
// Zero-cost marker trait — implement to control Drop behaviour.
pub unsafe trait TlDataFreePolicy: Send + 'static {
    unsafe fn free(head: *mut krb5_tl_data);
}

// Parameterised owned list — Drop calls P::free(self.head).
pub struct OwnedTlDataList<P: TlDataFreePolicy> { /* … */ }
impl<P: TlDataFreePolicy> OwnedTlDataList<P> {
    pub fn into_raw(self) -> (*mut krb5_tl_data, i16);  // transfers to C; skips Drop
    pub fn with_policy<Q: TlDataFreePolicy>(self) -> OwnedTlDataList<Q>;  // zero-copy convert
}
```

**Available policies:**

| Type | Defined in | Behaviour |
|------|------------|-----------|
| `GenericFree` | `kurbu5-rs` | Walks the list calling `libc::free` on each `tl_data_contents` buffer and each node.  Correct on POSIX/glibc (same allocator as libkrb5). |
| `KdbFree` | `kurbu5-kdb-rs` | Delegated to `GenericFree::free`.  `krb5_dbe_free_tl_data` is declared in `kdb.h` but not exported by `libkdb5.so` as of krb5 ≤ 1.22.x; the libc walk is functionally identical.  `KdbFree` is kept as a distinct marker for call-site clarity and forward compatibility. |

**Convenience aliases:**

```rust
pub type TlDataList    = OwnedTlDataList<GenericFree>;   // from kurbu5-rs
pub type KdbTlDataList = OwnedTlDataList<KdbFree>;       // from kurbu5-kdb-rs
```

`TlDataBuilder::build()` always produces a `TlDataList`.
`PrincipalEntry::set_tl_data` accepts any `OwnedTlDataList<P>`, so a
`TlDataList` returned from `build()` can be passed directly without an
explicit policy conversion.

**OOM handling:** `TlDataBuilder::build()` calls
`std::alloc::handle_alloc_error` (process abort) on allocation failure.
This prevents an OOM condition from being silently converted to `EINVAL` by
a `catch_unwind` boundary.

---

## `KdbContext` utilities

`KdbContext<'_>` is a zero-cost wrapper around `*mut krb5_context` that
provides safe wrappers for the krb5/libkdb5 utility functions that modules
commonly need:

```rust,ignore
impl<'ctx> KdbContext<'ctx> {
    /// Returns the default realm as an owned String.
    pub fn realm(&self) -> String;

    /// Read a string from `[dbmodules]/<conf_section>/<key>` in the KDC profile.
    ///
    /// Returns `None` if the key is absent or an error occurs.  Overlay
    /// plugins use this to read their own config keys (e.g. `database_name`,
    /// `disallow_name_aliases`) so they can forward them to the backing
    /// database as `db_args`.
    pub fn db_module_string(&self, conf_section: &str, key: &str) -> Option<String>;

    /// Unparse a principal to a string (e.g. `"user@REALM"`).
    pub fn unparse_principal(&self, princ: PrincipalRef<'_>)
        -> Result<String, KdbError>;

    /// Unparse a principal omitting the realm (e.g. `"user"` or
    /// `"host/server.example.com"`).
    pub fn unparse_principal_short(&self, princ: PrincipalRef<'_>)
        -> Result<String, KdbError>;

    /// Parse a principal from a string.
    pub fn parse_principal(&self, name: &str)
        -> Result<OwnedPrincipal, KdbError>;

    /// Store a module instance as the `db_context` for this context.
    ///
    /// Called by [`KdbModule::create`] implementations to satisfy the DAL
    /// contract that requires `db_context` to be initialised before
    /// `krb5_db_create` returns.  Only needed when `SUPPORTS_CREATE = true`.
    pub fn set_module<M: KdbModule>(&self, module: M) -> Result<(), KdbError>;

    // --- tl-data helpers -------------------------------------------------

    /// Look up a tagged-data record in an entry.
    pub fn lookup_tl_data<'e>(
        &self,
        entry: &PrincipalEntryRef<'e>,
        ty: TlDataType,
    ) -> Option<TlDataRef<'e>>;

    /// Insert or replace a tagged-data record.
    pub fn update_tl_data(
        &self,
        entry: &mut PrincipalEntry,
        ty: TlDataType,
        data: &[u8],
    ) -> Result<(), KdbError>;

    // --- string attribute helpers ----------------------------------------

    pub fn get_string_attr<'e>(
        &self,
        entry: &PrincipalEntryRef<'e>,
        key: &str,
    ) -> Result<Option<&'e str>, KdbError>;

    pub fn set_string_attr(
        &self,
        entry: &mut PrincipalEntry,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), KdbError>;

    // --- timestamp helpers -----------------------------------------------

    pub fn lookup_last_pwd_change(
        &self,
        entry: &PrincipalEntryRef<'_>,
    ) -> Result<Option<Timestamp>, KdbError>;

    pub fn update_last_pwd_change(
        &self,
        entry: &mut PrincipalEntry,
        stamp: Timestamp,
    ) -> Result<(), KdbError>;

    pub fn lookup_mod_princ(
        &self,
        entry: &PrincipalEntryRef<'_>,
    ) -> Result<Option<(Timestamp, OwnedPrincipal)>, KdbError>;

    pub fn update_mod_princ(
        &self,
        entry: &mut PrincipalEntry,
        stamp: Timestamp,
        mod_princ: PrincipalRef<'_>,
    ) -> Result<(), KdbError>;

    // --- PAC helpers -----------------------------------------------------

    /// Return the buffer type IDs present in a PAC.
    pub fn pac_get_buffer_types(&self, pac: &PacRef<'_>) -> Vec<u32>;

    /// Return the raw bytes of a specific PAC buffer, or `None` on error.
    pub fn pac_get_buffer(&self, pac: &PacRef<'_>, buf_type: u32)
        -> Option<Vec<u8>>;

    /// Add a buffer to a PAC under construction.
    pub fn pac_add_buffer(
        &self,
        pac: &mut PacBuilder<'_>,
        buf_type: u32,
        data: &[u8],
    ) -> Result<(), KdbError>;
}
```

---

## Memory safety guarantees

* No Rust code outside `glue.rs` holds a raw pointer.
* All `PrincipalEntryRef<'a>` lifetime bounds ensure the view cannot outlive
  the callback invocation that provided it.
* `PrincipalEntry::into_raw()` is the only path to hand ownership to C;
  it consumes the Rust value, preventing double-free.
* `Box::from_raw` in `fini_module` is the only place that reclaims module
  state stored by `open()`; it happens exactly once per context.
* `KdbContext::set_module` is the second (and only other) path to store module
  state; it is used exclusively from `create()` implementations that must
  initialise `db_context` before returning (DAL contract).
* `OwnedPrincipal` stores the `krb5_context` that allocated it.  `Drop` calls
  `krb5_free_principal(ctx, ptr)`, which releases the principal struct and all
  its embedded realm and component strings in one call.  When ownership is
  transferred to C via `into_raw`, `mem::forget` prevents the destructor from
  running.
* `PrincipalEntry::set_princ` takes a `&KdbContext<'_>` so it can call
  `krb5_free_principal` on the old principal before installing the new one.
  This prevents the old name from leaking when a driver replaces a stored
  principal (e.g. an overlay substituting `"userdb:<name>"` with the original
  search principal).
* `PrincipalEntry::set_tl_data` nulls out the stored `tl_data` pointer
  *before* freeing the old list.  If the `OwnedTlDataList::into_raw` call
  aborts due to OOM (via `handle_alloc_error`), the `Drop` impl sees a null
  pointer and does not double-free.  TL-data nodes are freed using
  `GenericFree::free` (libc walk), which is correct because both Rust and
  MIT Kerberos use the same glibc allocator on POSIX systems.
  `krb5_dbe_free_tl_data` is declared in `kdb.h` but is not exported by
  `libkdb5.so` in krb5 ≤ 1.22.x and therefore cannot be called at link time.
* `kurbu5-sys` is the only crate that includes the krb5/kdb headers;
  `kurbu5-kdb-sys` re-exports those bindings and adds libkdb5 linkage;
  `kurbu5-kdb-rs` depends on both `kurbu5-kdb-sys` (for the KDB vtable types
  and libkdb5 linkage) and `kurbu5-rs` (for the shared TL-data types).

---

## Compatibility

* The generated vtable sets `maj_ver = KRB5_KDB_DAL_MAJOR_VERSION` (9 as of
  krb5 1.21).
* Most optional vtable slots are set to `NULL` when not implemented, which
  libkdb5 treats as "use default implementation" or returns
  `KRB5_PLUGIN_OP_NOTSUPP`.
* The database lifecycle slots (`create`, `destroy`, `promote_db`) are
  controlled by the `SUPPORTS_CREATE`, `SUPPORTS_DESTROY`, and
  `SUPPORTS_PROMOTE_DB` associated constants on `KdbModule`.  When a constant
  is `false` (the default), the corresponding vtable slot is `NULL` and
  libkdb5 returns `KRB5_PLUGIN_OP_NOTSUPP` without invoking the driver.
  Overlay and read-only drivers that do not manage on-disk state should leave
  these constants at their defaults.
* The key en/decryption slots (`decrypt_key_data`, `encrypt_key_data`) are
  controlled by `SUPPORTS_DECRYPT_KEY_DATA` and `SUPPORTS_ENCRYPT_KEY_DATA`
  (both default `false`).  When `false`, the vtable slot is `NULL` and libkdb5
  calls `krb5_dbe_def_decrypt_key_data` / `krb5_dbe_def_encrypt_key_data`
  directly without entering the plugin.  Overlay drivers that do not provide
  custom key wrapping should leave these at their defaults; installing a
  no-op implementation via `SUPPORTS_DECRYPT_KEY_DATA = true` causes libkdb5
  to keep an OpenSSL EVP cipher context alive for the life of the process.
* `Err(KdbError::NotSupported)` → `KRB5_PLUGIN_OP_NOTSUPP`.
* `Err(KdbError::NoHandle)` → `KRB5_PLUGIN_NO_HANDLE`.
* `Err(KdbError::NoEntry)` → `KRB5_KDB_NOENTRY`.

**Minimum Rust edition:** 2021
**Minimum Supported Rust Version (MSRV):** 1.75

---

## License

Distributed under the same license as the MIT Kerberos 5 source tree — a
BSD-style two-clause license.  See [`LICENSE`](../LICENSE) for the full text.
