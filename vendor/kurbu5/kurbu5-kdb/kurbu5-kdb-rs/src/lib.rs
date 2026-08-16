//! Safe, idiomatic Rust API for writing MIT Kerberos KDB driver plugins.
//!
//! # Overview
//!
//! A KDB plugin is a shared library loaded by `libkdb5` at runtime.  It must
//! export the C symbol `kdb_function_table` containing a filled-in
//! `kdb_vftabl` struct.  This crate hides all of that plumbing
//! behind a single trait and a macro.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_kdb_rs::{kdb_plugin, KdbModule, KdbContext, KdbError, LookupFlags, OpenMode};
//! use kurbu5_kdb_rs::{PrincipalRef, PrincipalEntry};
//!
//! pub struct MyKdb { path: String }
//!
//! impl KdbModule for MyKdb {
//!     fn open(
//!         _ctx: &KdbContext<'_>,
//!         conf_section: &str,
//!         _args: &[&str],
//!         _mode: OpenMode,
//!     ) -> Result<Self, KdbError> {
//!         Ok(MyKdb { path: format!("/var/kerberos/{}.db", conf_section) })
//!     }
//!
//!     fn get_principal(
//!         &self,
//!         _ctx: &KdbContext<'_>,
//!         _search_for: PrincipalRef<'_>,
//!         _flags: LookupFlags,
//!     ) -> Result<Option<PrincipalEntry>, KdbError>
//!     {
//!         Ok(None)  // not found
//!     }
//! }
//!
//! kdb_plugin!(mykdb, MyKdb);
//! // Exports C symbol: kdb_function_table (libkdb5 selects the .so by the
//! // name given in krb5.conf db_library, then dlsym's this fixed symbol)
//! ```
//!
//! # Safety model
//!
//! Unsafe code in this crate is confined to [`glue`], [`context`], and
//! [`backing_db`]; every unsafe block carries a `// SAFETY:` comment.
//! Plugin authors never need to write `unsafe` themselves.

pub mod backing_db;
pub mod context;
pub mod error;
pub mod key_data;
pub mod module;
pub mod policy;
pub mod principal;
pub mod tl_data;
pub mod types;

// The glue module is #[doc(hidden)] so it does not appear in rustdoc, but it
// must be `pub` so the `kdb_plugin!` macro can reference it from other crates.
#[doc(hidden)]
pub mod glue;

// Re-export the raw sys types namespaced under `sys`.
#[doc(hidden)]
pub mod sys {
    pub use kdb_sys::*;
}

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

pub use backing_db::BackingDb;
pub use context::{KdbContext, Krb5Context};
pub use error::{KdbError, PolicyDenied};
pub use key_data::{
    DecryptKeyRequest, EncryptKeyRequest, KeyBlock, KeyDataBuilder,
    KeyDataOwned, KeyDataRef, KeyDataSlice, KeySalt,
};
pub use module::{
    AddressRef, AsAuditEvent, AsPolicyRequest, AuthIndicators,
    DelegationRequest, KdbModule, KdcRequestRef, PaDataIter, PacBuilder,
    PacIssuanceOutput, PacIssuanceRequest, PacRef, ResourceDelegationRequest,
    S4uX509Request, TgsPolicyRequest, TicketRef,
};
pub use policy::{PolicyEntry, PolicyEntryRef};
pub use principal::{
    OwnedPrincipal, PrincipalEntry, PrincipalEntryRef, PrincipalRef,
};
pub use tl_data::{
    GenericFree, KdbFree, KdbTlDataList, OwnedTlDataList, TlDataBuilder,
    TlDataFreePolicy, TlDataIter, TlDataList, TlDataRef,
};
pub use types::{
    AccessMode, IterFlags, KdcOptions, LockMode, LookupFlags, OpenMode,
    PrincipalAttributes, ServerType, TicketFlags, Timestamp, TlDataType,
};

// ---------------------------------------------------------------------------
// Proc-macro re-exports (derive feature)
// ---------------------------------------------------------------------------

/// Rename a method for `#[derive(KdbModule)]` dispatch.
/// See `kurbu5_kdb_derive::kdb_method` for details.
#[cfg(feature = "derive")]
pub use kurbu5_kdb_derive::kdb_method;

/// Mark an inherent `impl` block containing KDB override methods.
/// See `kurbu5_kdb_derive::kdb_impl` for details.
#[cfg(feature = "derive")]
pub use kurbu5_kdb_derive::kdb_impl;

/// Derive `KdbModule` for overlay plugins via delegation to a backing field.
///
/// The derive macro and the [`KdbModule`] trait share the same name, exactly
/// as `serde::Serialize` covers both the derive and the trait.
/// See `kurbu5_kdb_derive::KdbModule` for full attribute documentation.
#[cfg(feature = "derive")]
pub use kurbu5_kdb_derive::KdbModule;

// ---------------------------------------------------------------------------
// Plugin export macro
// ---------------------------------------------------------------------------

/// Register a KDB plugin module and export the C vtable symbol.
///
/// Generates and exports the C symbol `kdb_function_table` that `libkdb5`
/// looks for when loading the plugin.  The plugin is selected by filename:
/// `db_library = mykdb` in `krb5.conf` causes `libkdb5` to load
/// `libmykdb.so` and then `dlsym` for `kdb_function_table`.
///
/// # Example
///
/// ```rust,ignore
/// kdb_plugin!(mykdb, MyKdb);
/// // Equivalent to:
/// // #[no_mangle]
/// // pub static kdb_function_table: kurbu5_kdb_rs::sys::kdb_vftabl =
/// //     kurbu5_kdb_rs::glue::make_vftabl::<MyKdb>();
/// ```
///
/// The crate must be compiled as a `cdylib`:
/// ```toml
/// [lib]
/// crate-type = ["cdylib"]
/// ```
#[macro_export]
macro_rules! kdb_plugin {
    ($name:ident, $module:ty) => {
        // SAFETY: kdb_vftabl is a C struct of function pointers.  All pointer
        // values are produced by make_vftabl<M>() which generates correct
        // extern "C" functions.  The static is placed in the .data section
        // and has the C ABI symbol name that libkdb5 dlsym's for.
        #[no_mangle]
        pub static kdb_function_table: $crate::sys::kdb_vftabl =
            $crate::glue::make_vftabl::<$module>();
    };
}
