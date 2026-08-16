//! Safe, idiomatic Rust API for MIT Kerberos KADM5 operations.
//!
//! # Overview
//!
//! This crate covers two distinct use cases:
//!
//! **1. KADM5 plugin interfaces** — `kadmind` exposes two plugin interfaces
//! for extending administration operations.  Each is loaded via an `initvt` C
//! function exported by a plugin shared library.  This crate hides all of that
//! registration plumbing behind per-interface traits and the `initvt_plugin!`
//! macro.
//!
//! | Feature       | Interface      | Header                              |
//! |---------------|----------------|-------------------------------------|
//! | `kadm5_auth`  | Authorization  | `krb5/kadm5_auth_plugin.h`          |
//! | `kadm5_hook`  | Operation hook | `krb5/kadm5_hook_plugin.h`          |
//!
//! **2. Local-mode KADM5 admin client** — `admin::AdminHandle` opens a
//! direct KDB connection (no network, no `kadmind`) and exposes the full
//! `kadm5/admin.h` API as safe Rust methods.  Enable with the `admin`
//! feature; see the `admin` module docs (only built with that feature) for
//! a quick-start example.
//!
//! Enable `full` to compile everything at once.
//!
//! # Quick start — plugin interfaces
//!
//! ```rust,no_run
//! use kurbu5_kadm5_rs::{initvt_plugin, PluginContext, Krb5Error};
//! use kurbu5_kadm5_rs::auth::Kadm5AuthModule;
//!
//! pub struct AllowAll;
//!
//! impl Kadm5AuthModule for AllowAll {
//!     const NAME: &'static std::ffi::CStr = c"allow_all";
//!     fn init_module(
//!         _ctx: &PluginContext<'_>,
//!         _acl_file: Option<&str>,
//!     ) -> Result<Self, Krb5Error> {
//!         Ok(AllowAll)
//!     }
//! }
//!
//! initvt_plugin!(kadm5_auth_allow_all, 1, AllowAll,
//!     kurbu5_kadm5_rs::auth::glue::make_kadm5_auth_vtable);
//! ```
//!
//! # Safety model
//!
//! Unsafe code is confined to the per-interface `glue` sub-modules and the
//! `admin` module.  Every `unsafe` block carries a `// SAFETY:` comment.
//! Plugin authors and admin-client callers never need to write `unsafe`
//! themselves.

// Re-export the raw sys types namespaced under `sys` for use in macro bodies.
#[doc(hidden)]
pub mod sys {
    pub use kurbu5_kadm5_sys::*;
}

// Re-export the proc-macro derive crate under the `derive` feature so users
// can write `use kurbu5_kadm5_rs::Kadm5AuthModule` alongside
// `#[derive(Kadm5AuthModule)]` without a separate dep declaration.
#[cfg(feature = "derive")]
pub use kurbu5_kadm5_derive::*;

// ---------------------------------------------------------------------------
// Feature-gated interface modules
// ---------------------------------------------------------------------------

#[cfg(feature = "kadm5_auth")]
pub mod auth;

#[cfg(feature = "kadm5_hook")]
pub mod hook;

#[cfg(feature = "admin")]
pub mod admin;

// ---------------------------------------------------------------------------
// Shared context wrapper
// ---------------------------------------------------------------------------

pub mod context;

// ---------------------------------------------------------------------------
// Shared error type
// ---------------------------------------------------------------------------

pub mod error;

// ---------------------------------------------------------------------------
// Shared view types
// ---------------------------------------------------------------------------

pub mod principal;

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

pub use context::PluginContext;
pub use error::Krb5Error;

#[cfg(feature = "kadm5_auth")]
pub use auth::{AddPrincRequest, Kadm5AuthModule, ModPrincRequest};

pub use principal::Kadm5PrincipalEntry;

#[cfg(feature = "kadm5_hook")]
pub use hook::{
    ChpassRequest, CreatePrincRequest, HookStage, Kadm5HookModule,
    ModifyPrincRequest,
};

// ---------------------------------------------------------------------------
// `initvt_plugin!` macro
//
// This macro is the counterpart of `kdb_plugin!` in `kurbu5-kdb-rs`.
// Unlike `kdb_plugin!` which exports a static vtable symbol, KADM5
// interfaces use a C function `<name>_initvt` that fills in a caller-
// allocated vtable after version negotiation.
//
// The macro signature:
//
//   initvt_plugin!(prefix, major_version, ModuleType, make_vtable_fn)
//
// where:
//   - `prefix`         — the C symbol prefix, e.g. `kadm5_auth_myplugin`
//                        → exports `kadm5_auth_myplugin_initvt`
//   - `major_version`  — the interface major version constant (1 for both
//                        KADM5_AUTH and KADM5_HOOK)
//   - `ModuleType`     — the Rust type implementing the module trait
//   - `make_vtable_fn` — a path to the `make_<interface>_vtable::<M>()` fn
// ---------------------------------------------------------------------------

/// Register a KADM5 plugin and export the C `<name>_initvt` symbol.
///
/// The macro handles version negotiation and vtable initialisation for both
/// the `KADM5_AUTH` and `KADM5_HOOK` interfaces.
///
/// # Example (`KADM5_AUTH`)
///
/// ```rust,no_run
/// use kurbu5_kadm5_rs::initvt_plugin;
/// use kurbu5_kadm5_rs::auth::Kadm5AuthModule;
///
/// pub struct MyAuth;
/// impl Kadm5AuthModule for MyAuth {
///     const NAME: &'static std::ffi::CStr = c"my_auth";
///     fn init_module(
///         _ctx: &kurbu5_kadm5_rs::PluginContext<'_>,
///         _acl_file: Option<&str>,
///     ) -> Result<Self, kurbu5_kadm5_rs::Krb5Error> {
///         Ok(MyAuth)
///     }
/// }
///
/// initvt_plugin!(
///     kadm5_auth_my_auth, 1, MyAuth,
///     kurbu5_kadm5_rs::auth::glue::make_kadm5_auth_vtable
/// );
/// // Exports C symbol: kadm5_auth_my_auth_initvt
/// ```
///
/// The crate must be compiled as a `cdylib`:
/// ```toml
/// [lib]
/// crate-type = ["cdylib"]
/// ```
#[macro_export]
macro_rules! initvt_plugin {
    ($name:ident, $major_ver:expr, $module:ty, $make_vtable_fn:path $(,)?) => {
        // SAFETY: This function is called by kadmind immediately after
        // dlopen().  The invariants are:
        //   - ctx is non-null and valid for the duration of the call.
        //   - vtable is non-null and points to a zeroed vtable struct of at
        //     least the size appropriate for maj_ver/min_ver.
        //   - maj_ver and min_ver are non-negative integers supplied by the
        //     kadmind plugin loader.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            _ctx: *mut $crate::sys::_krb5_context,
            maj_ver: ::libc::c_int,
            _min_ver: ::libc::c_int,
            vtable: *mut $crate::sys::krb5_plugin_vtable_st,
        ) -> $crate::sys::krb5_error_code {
            // Check the major version.
            if maj_ver != $major_ver {
                return $crate::sys::KRB5_PLUGIN_VER_NOTSUPP;
            }
            // SAFETY: vtable is non-null and points to a struct allocated by
            // the caller (kadmind).  We cast to the concrete vtable type
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
