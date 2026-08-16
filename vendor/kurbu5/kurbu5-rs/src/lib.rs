//! Safe, idiomatic Rust API for writing MIT Kerberos non-KDB plugin modules.
//!
//! # Overview
//!
//! MIT Kerberos exposes plugin interfaces beyond KDB.  Each interface is
//! loaded via an `initvt` C function that the loader calls after opening the
//! shared library.  This crate hides all of that registration plumbing behind
//! per-interface traits and the `initvt_plugin!` macro.
//!
//! Each interface is gated behind a Cargo feature:
//!
//! | Feature       | Interface            | Header                      |
//! |---------------|----------------------|-----------------------------|
//! | `pwqual`      | Password quality     | `krb5/pwqual_plugin.h`      |
//! | `hostrealm`   | Host-to-realm map    | `krb5/hostrealm_plugin.h`   |
//! | `localauth`   | Principal→account    | `krb5/localauth_plugin.h`   |
//! | `ccselect`    | Ccache selection     | `krb5/ccselect_plugin.h`    |
//! | `kdcpreauth`  | KDC preauth          | `krb5/kdcpreauth_plugin.h`  |
//! | `clpreauth`   | Client preauth       | `krb5/clpreauth_plugin.h`   |
//! | `kdcpolicy`   | KDC policy hooks     | `krb5/kdcpolicy_plugin.h`   |
//! | `certauth`    | PKINIT cert auth     | `krb5/certauth_plugin.h`    |
//! | `audit`       | KDC audit records    | `krb5/audit_plugin.h` (private) |
//!
//! Enable `full` to compile all interfaces at once.
//!
//! The following modules are available unconditionally (no feature flag):
//!
//! - [`profile`] — RAII handle to `krb5.conf` / `kdc.conf` via `profile_t`
//! - [`crypto`] — symmetric-key crypto helpers (`krb5_c_encrypt`, etc.)
//! - [`principal`] — parse/build Kerberos principals (`OwnedPrincipal`), and
//!   zero-copy accessors (`PrincipalRef`) over the `&krb5_principal_data`
//!   references plugin trait methods already receive
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::{initvt_plugin, PluginContext, Krb5Error};
//!
//! // (Trait implementation will be shown in the relevant iteration docs.)
//! ```
//!
//! # Safety model
//!
//! Unsafe code is confined to the per-interface `glue` sub-modules and to
//! `context.rs`, `principal.rs`, and `profile.rs`.  Every `unsafe` block carries a `// SAFETY:`
//! comment.  Plugin authors never need to write `unsafe` themselves.

pub mod context;
pub mod crypto;
pub mod error;
pub mod principal;
pub mod profile;
pub mod tl_data;

// The glue module is #[doc(hidden)] so it does not appear in rustdoc, but it
// must be `pub` so that the `initvt_plugin!` macro can reference it from the
// plugin crate's namespace.
#[doc(hidden)]
pub mod glue {}

// Re-export the raw sys types namespaced under `sys` for use in macro bodies.
#[doc(hidden)]
pub mod sys {
    pub use kurbu5_sys::*;
}

// ---------------------------------------------------------------------------
// Feature-gated interface modules
// (each module and its re-exports live here; implementations added later)
// ---------------------------------------------------------------------------

#[cfg(feature = "pwqual")]
pub mod pwqual;

#[cfg(feature = "hostrealm")]
pub mod hostrealm;

#[cfg(feature = "localauth")]
pub mod localauth;

#[cfg(feature = "ccselect")]
pub mod ccselect;

#[cfg(feature = "kdcpreauth")]
pub mod kdcpreauth;

#[cfg(feature = "clpreauth")]
pub mod clpreauth;

#[cfg(feature = "kdcpolicy")]
pub mod kdcpolicy;

#[cfg(feature = "certauth")]
pub mod certauth;

#[cfg(feature = "audit")]
pub mod audit;

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

pub use context::PluginContext;
pub use error::Krb5Error;
pub use principal::{OwnedPrincipal, PrincipalRef, PrincipalType};
pub use profile::Profile;
pub use tl_data::{
    GenericFree, OwnedTlDataList, TlDataBuilder, TlDataFreePolicy, TlDataIter,
    TlDataList, TlDataRef,
};

#[cfg(feature = "pwqual")]
pub use pwqual::{CheckRequest, PwqualError, PwqualModule};

#[cfg(feature = "hostrealm")]
pub use hostrealm::HostrealmModule;

#[cfg(feature = "localauth")]
pub use localauth::LocalauthModule;

#[cfg(feature = "ccselect")]
pub use ccselect::{CcacheHandle, CcselectModule};

#[cfg(feature = "kdcpolicy")]
pub use kdcpolicy::{AsRequest, KdcpolicyModule, PolicyError, TgsRequest};

#[cfg(feature = "certauth")]
pub use certauth::{CertRef, CertauthDecision, CertauthModule};

#[cfg(feature = "audit")]
pub use audit::{AuditModule, AuditStateRef};

#[cfg(feature = "kdcpreauth")]
pub use kdcpreauth::{
    KdcpreauthCallbacks, KdcpreauthModule, PA_HARDWARE, PA_PSEUDO,
    PA_REPLACES_KEY, PA_REQUIRED, PA_SUFFICIENT, PA_TYPED_E_DATA,
    ReturnPadataRequest, VerifyResponse,
};
// Note: kdcpreauth::PaData is intentionally not re-exported here to avoid a
// name conflict with clpreauth::PaData.  Use `kdcpreauth::PaData` directly.

#[cfg(feature = "clpreauth")]
pub use clpreauth::{
    ClpreauthCallbacks, ClpreauthModule, EtypeInfoRequest, KeyblockRef,
    PA_INFO, PA_REAL, PaData, ProcessRequest, Prompter, TryagainRequest,
};

// ---------------------------------------------------------------------------
// Derive macro re-exports (feature = "derive")
//
// When the `derive` feature is enabled, re-export the proc-macro derives from
// `kurbu5-derive` so plugin authors can write `use kurbu5_rs::PwqualModule`
// to get both the trait and its derive macro.
// ---------------------------------------------------------------------------

#[cfg(feature = "derive")]
pub use kurbu5_derive::*;

// ---------------------------------------------------------------------------
// `initvt_plugin!` macro
//
// This macro is the counterpart of `kdb_plugin!` in `kurbu5-kdb-rs`.
// Unlike `kdb_plugin!` which exports a static vtable symbol, non-KDB
// interfaces use a C function `<name>_initvt` that fills in a caller-
// allocated vtable after version negotiation.
//
// The macro signature:
//
//   initvt_plugin!(prefix, major_version, ModuleType, make_vtable_fn)
//
// where:
//   - `prefix`         — the C symbol prefix, e.g. `pwqual_myplugin`
//                        → exports `pwqual_myplugin_initvt`
//   - `major_version`  — the interface major version constant (e.g. `1`)
//   - `ModuleType`     — the Rust type implementing the module trait
//   - `make_vtable_fn` — a path to the `make_<interface>_vtable::<M>()` fn
//                        in the interface's glue module
//
// For iteration 0, no interface glue modules exist yet, so the macro body is
// a placeholder that performs version checking and returns an error for any
// unrecognised major version.  Full glue wiring is added per interface.
// ---------------------------------------------------------------------------

/// Register a non-KDB plugin and export the C `<name>_initvt` symbol.
///
/// The macro is the entry point for every plugin interface in `kurbu5-rs`.
/// It handles:
///
/// 1. Version negotiation: returns `KRB5_PLUGIN_VER_NOTSUPP` if `maj_ver`
///    does not equal `$major_ver`.
/// 2. Vtable initialisation: calls `$make_vtable_fn::<$module>()` and copies
///    the result into the caller-supplied vtable pointer.
///
/// # Example (PWQUAL, added in iteration 1)
///
/// ```rust,ignore
/// use kurbu5_rs::initvt_plugin;
/// use kurbu5_rs::pwqual::PwqualModule;
///
/// pub struct MyPlugin;
/// impl PwqualModule for MyPlugin { /* … */ }
///
/// initvt_plugin!(pwqual_myplugin, 1, MyPlugin, kurbu5_rs::pwqual::glue::make_pwqual_vtable);
/// // Exports C symbol: pwqual_myplugin_initvt
/// ```
///
/// The crate must be compiled as a `cdylib`:
/// ```toml
/// [lib]
/// crate-type = ["cdylib"]
/// ```
#[macro_export]
macro_rules! initvt_plugin {
    ($name:ident, $major_ver:expr, $module:ty, $make_vtable_fn:path) => {
        // SAFETY: This function is called by libkrb5 immediately after
        // dlopen().  The invariants are:
        //   - ctx is non-null and valid for the duration of the call.
        //   - vtable is non-null and points to a zeroed vtable struct of at
        //     least the size appropriate for maj_ver/min_ver.
        //   - maj_ver and min_ver are non-negative integers supplied by the
        //     libkrb5 plugin loader.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            _ctx: *mut $crate::sys::_krb5_context,
            maj_ver: ::libc::c_int,
            _min_ver: ::libc::c_int,
            vtable: *mut $crate::sys::krb5_plugin_vtable_st,
        ) -> $crate::sys::krb5_error_code {
            // Check the major version.  Minor version determines which fields
            // to fill in; we always fill through the highest known minor
            // version and leave extra slots at their zero-initialised value.
            if maj_ver != $major_ver {
                return $crate::sys::KRB5_PLUGIN_VER_NOTSUPP;
            }
            // SAFETY: vtable is non-null and points to a struct allocated by
            // the caller (libkrb5).  We cast to the concrete vtable type
            // expected by this interface and fill its fields.
            let vt = vtable as *mut _;
            // SAFETY: vt is non-null (derived from vtable which is non-null).
            // `use … as` aliases the path to a bare ident so that turbofish
            // compiles; Rust macro `path` fragments do not support `::< >`
            // in expression position when expanded from external crates.
            use $make_vtable_fn as _make_vt;
            *vt = _make_vt::<$module>();
            0
        }
    };
}
