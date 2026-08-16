//! CCSELECT — credential cache selection plugin interface.
//!
//! A CCSELECT plugin selects a credential cache when an application connects
//! to a service principal.  libkrb5 queries registered plugins in priority
//! order (authoritative before heuristic) until one returns a cache.
//!
//! # C interface
//!
//! Interface header: `krb5/ccselect_plugin.h`
//!
//! Major version: 1.  Minor version: 1 (all fields through `fini`).
//!
//! Vtable fields and their C signatures, in order:
//!
//! ```text
//! name     const char *
//! init     krb5_error_code (*)(krb5_context, krb5_ccselect_moddata *data_out,
//!                              int *priority_out)
//! choose   krb5_error_code (*)(krb5_context, krb5_ccselect_moddata data,
//!                              krb5_principal server,
//!                              krb5_ccache *cache_out,
//!                              krb5_principal *princ_out)
//! fini     void (*)(krb5_context, krb5_ccselect_moddata data)
//! ```
//!
//! # Rust mapping
//!
//! | C vtable field | Rust trait item |
//! |---|---|
//! | `name`   | `NAME` associated constant |
//! | `init`   | `init_module()` + `priority()` |
//! | `choose` | `ccache()` |
//! | `fini`   | `fini_module()` (default: no-op before drop) |
//!
//! The C `init` callback combines initialisation and priority reporting into
//! one call.  In Rust these are separated: `init_module` constructs the
//! module (called once by the glue layer when the initvt function fires),
//! and `priority()` is called immediately after to fill `*priority_out`.
//! This keeps each method focused on one concern.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::{initvt_plugin, PluginContext, Krb5Error};
//! use kurbu5_rs::ccselect::{CcacheHandle, CcselectModule};
//!
//! pub struct MyCcselect;
//!
//! impl CcselectModule for MyCcselect {
//!     const NAME: &'static std::ffi::CStr = c"myccselect";
//!
//!     fn init_module() -> Result<Self, Krb5Error> {
//!         Ok(MyCcselect)
//!     }
//!
//!     fn priority(&self) -> i32 {
//!         kurbu5_rs::sys::KRB5_CCSELECT_PRIORITY_HEURISTIC as i32
//!     }
//!
//!     fn ccache(
//!         &self,
//!         _ctx: &PluginContext<'_>,
//!         _server: &kurbu5_rs::sys::krb5_principal_data,
//!     ) -> Result<CcacheHandle, Krb5Error> {
//!         Err(Krb5Error::NoHandle)
//!     }
//! }
//!
//! initvt_plugin!(
//!     ccselect_myccselect,
//!     1,
//!     MyCcselect,
//!     kurbu5_rs::ccselect::glue::make_ccselect_vtable
//! );
//! // Exports C symbol: ccselect_myccselect_initvt
//! ```

use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// Glue sub-module (all unsafe lives here)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod glue;

// ---------------------------------------------------------------------------
// CcacheHandle — owned result of a ccache selection
// ---------------------------------------------------------------------------

/// An owned handle to the result of a CCSELECT plugin's cache selection.
///
/// `CcacheHandle` bundles the two output values that the C `choose` callback
/// writes into `*cache_out` and `*princ_out`:
///
/// - `cache`: the selected `krb5_ccache` (owned; libkrb5 must close it via
///   `krb5_cc_close` when done).
/// - `princ`: the default principal of the selected cache (owned; libkrb5
///   must free it via `krb5_free_principal` when done).
///
/// # Construction
///
/// Plugin authors construct a `CcacheHandle` via
/// [`CcacheHandle::new`], which requires both pointers.
///
/// # Ownership contract
///
/// `CcacheHandle` does **not** implement `Drop`.  Ownership of both raw
/// pointers is transferred to the C caller when the glue layer extracts them
/// via `into_raw_parts` and writes them into
/// the `*cache_out` and `*princ_out` output parameters.  Plugin code must not
/// close or free either pointer after returning `Ok(handle)` from
/// [`CcselectModule::ccache`].
///
/// # `KRB5_CC_NOTFOUND` semantics
///
/// When the client principal is authoritatively determined but no cache exists
/// for it, return `Err(Krb5Error::Custom(KRB5_CC_NOTFOUND))` instead of
/// constructing a `CcacheHandle`.  libkrb5 will stop querying further plugins
/// and report the specific error to the application.
pub struct CcacheHandle {
    /// The selected credential cache.
    ///
    /// Owned by this handle until the glue layer transfers it to libkrb5.
    cache: kurbu5_sys::krb5_ccache,

    /// The default principal of the selected cache.
    ///
    /// Owned by this handle until the glue layer transfers it to libkrb5.
    princ: kurbu5_sys::krb5_principal,

    // Prevent construction outside this module except via `CcacheHandle::new`.
    _phantom: PhantomData<*mut ()>,
}

impl CcacheHandle {
    /// Construct a `CcacheHandle` from raw C pointers.
    ///
    /// Plugin authors call this to build the return value of
    /// [`CcselectModule::ccache`].
    ///
    /// # Safety
    ///
    /// `cache` must be a valid `krb5_ccache` opened via a libkrb5 ccache API
    /// (e.g. `krb5_cc_default`) and not yet closed.  `princ` must be a valid
    /// `krb5_principal` allocated by libkrb5 and not yet freed.  Ownership of
    /// both transfers to the returned `CcacheHandle`.
    ///
    /// Do not close or free `cache` / `princ` after this call.
    pub unsafe fn new(
        cache: kurbu5_sys::krb5_ccache,
        princ: kurbu5_sys::krb5_principal,
    ) -> Self {
        debug_assert!(
            !cache.is_null(),
            "CcacheHandle::new: cache must be non-null"
        );
        debug_assert!(
            !princ.is_null(),
            "CcacheHandle::new: princ must be non-null"
        );
        CcacheHandle {
            cache,
            princ,
            _phantom: PhantomData,
        }
    }

    /// Consume the handle and return the raw `(krb5_ccache, krb5_principal)` pair.
    ///
    /// Used by the glue layer to write both pointers into the C output
    /// parameters of the `choose` vtable callback.  Ownership of both
    /// transfers to the caller.
    pub(crate) fn into_raw_parts(
        self,
    ) -> (kurbu5_sys::krb5_ccache, kurbu5_sys::krb5_principal) {
        (self.cache, self.princ)
    }
}

// ---------------------------------------------------------------------------
// CcselectModule trait
// ---------------------------------------------------------------------------

/// A CCSELECT plugin selects a credential cache for a given server principal.
///
/// Implement this trait and register the implementation with
/// `initvt_plugin!` to export a CCSELECT plugin.
///
/// # Vtable mapping
///
/// | Vtable field | Trait item |
/// |---|---|
/// | `name`   | `NAME` |
/// | `init`   | `init_module()` + `priority()` |
/// | `choose` | `ccache()` |
/// | `fini`   | `fini_module()` |
///
/// # Plugin priority
///
/// Return [`kurbu5_sys::KRB5_CCSELECT_PRIORITY_AUTHORITATIVE`] from
/// [`priority`](CcselectModule::priority) if the plugin can definitively
/// determine the correct cache.  Return
/// [`kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC`] for best-effort
/// selection.  Authoritative plugins are consulted before heuristic ones.
///
/// # Quick start
///
/// See the [module-level documentation](self) for a complete example.
pub trait CcselectModule: Sized + Send + 'static {
    /// The module name reported to libkrb5 (`vtable->name`).
    ///
    /// Must be a null-terminated C string literal (e.g. `c"myplugin"`).
    /// libkrb5 uses this only for logging and diagnostics; it does not need
    /// to match the initvt symbol prefix, but conventionally it does.
    ///
    /// The `c""` literal syntax (Rust 1.77+) produces a `&'static CStr`
    /// that is null-terminated, which is what the C vtable field requires.
    const NAME: &'static std::ffi::CStr;

    /// Initialise the module and return a new instance.
    ///
    /// Called once by the glue layer's `init` vtable bridge when libkrb5
    /// loads the plugin.  The module instance is stored on the heap and
    /// remains alive until [`fini_module`](CcselectModule::fini_module)
    /// is called.
    ///
    /// Returns `Err` to signal that the plugin cannot be loaded (libkrb5
    /// will log the error and skip this plugin).
    ///
    /// Corresponds to the `init` vtable field (`krb5_ccselect_init_fn`).
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` if the plugin cannot initialise.
    fn init_module() -> Result<Self, Krb5Error>;

    /// Return the selection priority of this plugin.
    ///
    /// The return value must be one of:
    /// - [`kurbu5_sys::KRB5_CCSELECT_PRIORITY_AUTHORITATIVE`] (`2`) — plugin
    ///   is consulted before heuristic plugins.
    /// - [`kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC`] (`1`) — plugin is
    ///   consulted after authoritative plugins.
    ///
    /// Called immediately after `init_module` by the glue layer to fill in
    /// `*priority_out` in the `init` vtable callback.
    ///
    /// Corresponds to the `priority_out` output of the `init` vtable field.
    fn priority(&self) -> i32;

    /// Select a credential cache for `server`.
    ///
    /// On success, return `Ok(handle)` with a [`CcacheHandle`] containing a
    /// valid `krb5_ccache` and its default principal.  The glue layer
    /// transfers ownership of both to libkrb5, which must close/free them.
    ///
    /// Return `Err(`[`Krb5Error::NoHandle`]`)` to pass control to the next
    /// plugin (`KRB5_PLUGIN_NO_HANDLE`).
    ///
    /// Return `Err(`[`Krb5Error::Custom`]`(KRB5_CC_NOTFOUND))` when the
    /// client principal is authoritatively known but no matching cache exists.
    /// libkrb5 will stop querying and report the error to the application.
    ///
    /// Return any other `Err` for unexpected failures.
    ///
    /// `server` is the service principal the application is connecting to.
    /// It is borrowed for the duration of this call only; do not store it.
    ///
    /// Corresponds to the `choose` vtable field (`krb5_ccselect_choose_fn`).
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn ccache(
        &self,
        ctx: &PluginContext<'_>,
        server: &kurbu5_sys::krb5_principal_data,
    ) -> Result<CcacheHandle, Krb5Error>;

    /// Release resources held by this module instance.
    ///
    /// Called once by the glue layer's `fini` vtable bridge immediately before
    /// dropping the module.  The default implementation is a no-op; the module
    /// is dropped by the glue layer after this method returns.
    ///
    /// Only override this if resources must be released in a specific order
    /// before the normal `Drop` runs (e.g. flushing a non-async I/O handle).
    ///
    /// Corresponds to the `fini` vtable field (`krb5_ccselect_fini_fn`).
    fn fini_module(self) {}
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal module used by trait-level tests — returns NoHandle always.
    // -----------------------------------------------------------------------

    struct NoopCcselect {
        priority: i32,
    }

    impl CcselectModule for NoopCcselect {
        const NAME: &'static std::ffi::CStr = c"noop";

        fn init_module() -> Result<Self, Krb5Error> {
            Ok(NoopCcselect {
                priority: kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC as i32,
            })
        }

        fn priority(&self) -> i32 {
            self.priority
        }

        fn ccache(
            &self,
            _ctx: &PluginContext<'_>,
            _server: &kurbu5_sys::krb5_principal_data,
        ) -> Result<CcacheHandle, Krb5Error> {
            Err(Krb5Error::NoHandle)
        }
    }

    // -----------------------------------------------------------------------
    // 4.4-a: init_module constructs the module without error.
    // -----------------------------------------------------------------------
    #[test]
    fn init_module_succeeds() {
        let m = NoopCcselect::init_module();
        assert!(m.is_ok());
    }

    // -----------------------------------------------------------------------
    // 4.4-b: priority returns the value set during construction.
    // -----------------------------------------------------------------------
    #[test]
    fn priority_heuristic() {
        let m = NoopCcselect::init_module().unwrap();
        assert_eq!(
            m.priority(),
            kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC as i32
        );
    }

    // -----------------------------------------------------------------------
    // 4.4-c: NAME constant is accessible and non-empty.
    // -----------------------------------------------------------------------
    #[test]
    fn name_constant_non_empty() {
        // CStr::to_bytes() excludes the null terminator; non-empty means at
        // least one byte before the null.
        assert!(!NoopCcselect::NAME.to_bytes().is_empty());
    }

    // -----------------------------------------------------------------------
    // 4.4-d: fini_module default implementation does not panic.
    // -----------------------------------------------------------------------
    #[test]
    fn fini_module_default_noop() {
        let m = NoopCcselect::init_module().unwrap();
        m.fini_module(); // must not panic
    }

    // -----------------------------------------------------------------------
    // 4.4-e: authoritative priority constant value matches C header.
    // -----------------------------------------------------------------------
    #[test]
    fn authoritative_priority_value() {
        assert_eq!(kurbu5_sys::KRB5_CCSELECT_PRIORITY_AUTHORITATIVE, 2u32);
    }

    // -----------------------------------------------------------------------
    // 4.4-f: heuristic priority constant value matches C header.
    // -----------------------------------------------------------------------
    #[test]
    fn heuristic_priority_value() {
        assert_eq!(kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC, 1u32);
    }

    // -----------------------------------------------------------------------
    // 4.4-g: CcacheHandle::new stores pointers; into_raw_parts round-trips.
    // -----------------------------------------------------------------------
    #[test]
    fn ccache_handle_round_trip() {
        // Use non-null sentinel pointers.  We never dereference them.
        let fake_cache: kurbu5_sys::krb5_ccache =
            0x1 as *mut kurbu5_sys::_krb5_ccache;
        let fake_princ: kurbu5_sys::krb5_principal =
            0x2 as *mut kurbu5_sys::krb5_principal_data;
        // SAFETY: Sentinel pointers; not dereferenced.
        let handle = unsafe { CcacheHandle::new(fake_cache, fake_princ) };
        let (cache, princ) = handle.into_raw_parts();
        assert_eq!(cache, fake_cache);
        assert_eq!(princ, fake_princ);
    }

    // -----------------------------------------------------------------------
    // 4.4-h: make_ccselect_vtable produces a non-null init pointer.
    // -----------------------------------------------------------------------
    #[test]
    fn vtable_init_field_is_set() {
        let vt = glue::make_ccselect_vtable::<NoopCcselect>();
        assert!(vt.init.is_some());
    }

    // -----------------------------------------------------------------------
    // 4.4-i: make_ccselect_vtable produces a non-null choose pointer.
    // -----------------------------------------------------------------------
    #[test]
    fn vtable_choose_field_is_set() {
        let vt = glue::make_ccselect_vtable::<NoopCcselect>();
        assert!(vt.choose.is_some());
    }

    // -----------------------------------------------------------------------
    // 4.4-j: make_ccselect_vtable produces a non-null fini pointer.
    // -----------------------------------------------------------------------
    #[test]
    fn vtable_fini_field_is_set() {
        let vt = glue::make_ccselect_vtable::<NoopCcselect>();
        assert!(vt.fini.is_some());
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers end-to-end.
    //
    // These tests drive init → priority verification → choose → fini through
    // the raw C vtable slots produced by make_ccselect_vtable.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::{CcacheHandle, CcselectModule, NoopCcselect, glue};
        use crate::context::PluginContext;
        use crate::error::Krb5Error;

        // A module with a fixed priority of 5, always returning NoHandle.
        struct FixedPriorityCcselect;

        impl CcselectModule for FixedPriorityCcselect {
            const NAME: &'static std::ffi::CStr = c"fixed_priority";

            fn init_module() -> Result<Self, Krb5Error> {
                Ok(FixedPriorityCcselect)
            }

            fn priority(&self) -> i32 {
                5
            }

            fn ccache(
                &self,
                _ctx: &PluginContext<'_>,
                _server: &kurbu5_sys::krb5_principal_data,
            ) -> Result<CcacheHandle, Krb5Error> {
                Err(Krb5Error::NoHandle)
            }
        }

        // Helper: create a real krb5_context.
        fn make_ctx() -> kurbu5_sys::krb5_context {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            // SAFETY: krb5_init_context writes a valid pointer on success.
            let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(code, 0, "krb5_init_context failed");
            ctx
        }

        /// init through vtable: verify the written priority value.
        #[test]
        fn vtable_priority() {
            let vt = glue::make_ccselect_vtable::<FixedPriorityCcselect>();
            let mut moddata: kurbu5_sys::krb5_ccselect_moddata =
                std::ptr::null_mut();
            let mut priority: libc::c_int = 0;

            let init_fn = vt.init.expect("init slot must be set");
            let code = unsafe {
                // SAFETY: ctx=null is not dereferenced by the bridge (_ctx param);
                // moddata and priority are stack out-pointers.
                init_fn(std::ptr::null_mut(), &mut moddata, &mut priority)
            };
            assert_eq!(code, 0, "init must succeed");
            assert_eq!(priority, 5, "priority must be 5");

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init; null ctx is ok (_ctx unused).
                fini_fn(std::ptr::null_mut(), moddata);
            }
        }

        /// choose through vtable with NoopCcselect → KRB5_PLUGIN_NO_HANDLE.
        #[test]
        fn vtable_ccache_no_handle() {
            let ctx = make_ctx();
            let vt = glue::make_ccselect_vtable::<NoopCcselect>();

            let mut moddata: kurbu5_sys::krb5_ccselect_moddata =
                std::ptr::null_mut();
            let mut priority: libc::c_int = 0;
            let init_fn = vt.init.expect("init slot must be set");
            unsafe {
                // SAFETY: ctx is valid; moddata and priority are stack pointers.
                init_fn(ctx, &mut moddata, &mut priority);
            }

            // Pass a zeroed server principal — NoopCcselect ignores it.
            let mut server_data = kurbu5_sys::krb5_principal_data::default();
            let server: kurbu5_sys::krb5_principal = &mut server_data;
            let mut cache_out: kurbu5_sys::krb5_ccache = std::ptr::null_mut();
            let mut princ_out: kurbu5_sys::krb5_principal =
                std::ptr::null_mut();

            let choose_fn = vt.choose.expect("choose slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; server is a non-null stack
                // reference; cache_out and princ_out are stack out-pointers.
                choose_fn(ctx, moddata, server, &mut cache_out, &mut princ_out)
            };
            assert_eq!(
                code,
                kurbu5_sys::KRB5_PLUGIN_NO_HANDLE,
                "choose must return KRB5_PLUGIN_NO_HANDLE for NoopCcselect"
            );
            // Output pointers must remain null on error.
            assert!(cache_out.is_null());
            assert!(princ_out.is_null());

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }
    }
}
