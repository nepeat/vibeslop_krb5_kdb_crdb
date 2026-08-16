# Changelog — kurbu5-kdb-rs

## [Unreleased]


## [0.1.3] — 2026-07-31

No functional changes; version bump for workspace consistency.

## [0.1.2] — 2026-04-29

No functional changes; version bump for workspace consistency.

## [0.1.1] — 2026-04-14

### Added

- `PrincipalEntry` setter methods now carry SAFETY documentation
- `OwnedPrincipal` and owning principal references now use `NonNull` pointers
- Fedora RPM packaging

### Fixed

- `get_string_attr` now returns an owned `String` instead of leaking memory
- `lookup_mod_princ` now returns `Ok(None)` for a missing TL-data entry rather than an error
- NULL client and server pointers in the KDB `audit_as_req` callback are handled gracefully
- Pedantic clippy warning fixes

## [0.1.0] — 2026-04-04

### Added

- `AddressRef` accessor methods
- `KdcRequestRef` and `TicketRef` accessor methods
- `KdcOptions` and `TicketFlags` bitflags
- `KdbContext::update_mod_princ_data()`
- `KRB5_KDB_V1_BASE_LENGTH` set in `PrincipalEntry::new()`; `set_len`/`len()` accessors added
- TL-data types migrated to kurbu5-rs; `KdbFree` policy added
- Bridge functions wrapped with `catch_unwind` to prevent panic UB
- `KdbModule` implementation for `BackingDb`
- `derive` feature re-exporting kurbu5-kdb-derive macros
- `Krb5Context` owned RAII wrapper and context integration tests
- `KdbContext::db_module_string` for reading `[dbmodules]` config
- `SUPPORTS_CREATE`/`SUPPORTS_DESTROY`/`SUPPORTS_PROMOTE_DB` constants set; context initialised in `create()`
- create/destroy/promote_db vtable slots gated behind `SUPPORTS_*` constants
- Only `krb5_*_def_*` functions exported from libkdb5.so are called
- `krb5_*_def_*` fallbacks wired for all optional-with-default vtable slots
- MIT krb5 license wired into all Cargo manifests
- Vtable glue, `BackingDb` overlay helper, and `kdb_plugin!` macro
- `KdbContext` — safe wrapper around `krb5_context`
- Key-data, TL-data, policy, and principal wrappers

### Fixed

- OOM handling and policy temp-copy free in glue layer
- `PolicyEntry::into_raw` now propagates OOM
- Memory leak in `KeyDataOwned::write_into`
- Memory management in `PrincipalEntry`
- Null-pointer panic in `issue_pac` for nullable C arguments
- Memory leaks in `OwnedPrincipal` and `PrincipalEntry::set_princ`
- create/destroy/promote_db for overlay plugins
- Plugin export symbol renamed to `kdb_function_table`
- Core types, error handling, and `KdbModule` trait
