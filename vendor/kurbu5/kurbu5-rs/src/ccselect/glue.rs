//! Glue layer: C vtable function pointers → `CcselectModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the CCSELECT module that contains `unsafe` code.**
//!
//! All `unsafe` blocks in this file are annotated with a `// SAFETY:` comment
//! explaining the invariants that make them sound.  The overall invariants are:
//!
//! 1. `module_data` (`krb5_ccselect_moddata`) holds a `*mut M` placed there
//!    by the `init` bridge and removed (via `Box::from_raw`) by the `fini`
//!    bridge.  No other code touches it between those two calls.
//!
//! 2. All raw pointers received from libkrb5 (e.g. `krb5_principal`) are
//!    guaranteed non-null and valid for the duration of the call by the C API
//!    contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!
//! 4. All C strings passed to us are null-terminated.  We use `CStr::from_ptr`
//!    and propagate errors where conversion fails.
//!
//! # Memory ownership contracts
//!
//! | Value | Allocation | Deallocation |
//! |---|---|---|
//! | Module instance | `Box::into_raw(Box::new(M))` in `init` bridge | `Box::from_raw(data as *mut M)` in `fini` bridge |
//! | `krb5_ccache *cache_out` | allocated by the plugin (via libkrb5 API) | caller (libkrb5) closes via `krb5_cc_close` |
//! | `krb5_principal *princ_out` | allocated by the plugin (via libkrb5 API) | caller (libkrb5) frees via `krb5_free_principal` |

use crate::ccselect::CcselectModule;
use crate::context::PluginContext;

// ---------------------------------------------------------------------------
// vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `krb5_ccselect_vtable_st` for module type `M`.
///
/// Called from the `initvt_plugin!` macro expansion; produces a value that is
/// written into the caller-allocated vtable by the `initvt` C function.
/// All function pointers are monomorphised for `M` at compile time.
pub fn make_ccselect_vtable<M: CcselectModule>()
-> kurbu5_sys::krb5_ccselect_vtable_st {
    kurbu5_sys::krb5_ccselect_vtable_st {
        // SAFETY: M::NAME is a &'static CStr produced by a c"..." literal;
        // as_ptr() yields a null-terminated *const c_char valid for 'static.
        name: M::NAME.as_ptr(),
        init: Some(ccselect_init::<M>),
        choose: Some(ccselect_choose::<M>),
        fini: Some(ccselect_fini::<M>),
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Bridge for the `init` vtable field (`krb5_ccselect_init_fn`).
///
/// Calls `M::init_module()` to construct the module, then `M::priority()` to
/// fill `*priority_out`.  Stores the module as a `Box<M>` cast to
/// `krb5_ccselect_moddata` in `*data_out`.
///
/// # Memory contract
///
/// The `Box<M>` is created here and kept alive until `ccselect_fini` is
/// called.  `fini` reconstructs the box via `Box::from_raw` and drops it.
unsafe extern "C" fn ccselect_init<M: CcselectModule>(
    _ctx: kurbu5_sys::krb5_context,
    data_out: *mut kurbu5_sys::krb5_ccselect_moddata,
    priority_out: *mut libc::c_int,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // SAFETY: data_out is non-null: libkrb5 contract for the init callback.
        debug_assert!(!data_out.is_null());
        // SAFETY: priority_out is non-null: libkrb5 contract for the init callback.
        debug_assert!(!priority_out.is_null());

        let module = match M::init_module() {
            Ok(m) => m,
            Err(e) => return e.into_error_code(),
        };

        let prio = module.priority();
        let raw = Box::into_raw(Box::new(module));

        // SAFETY: data_out is non-null (asserted above); raw is a valid heap
        // pointer from Box::into_raw.  We cast *mut M to the opaque moddata type,
        // which is safe because krb5_ccselect_moddata is an opaque pointer type
        // used only as a void-pointer-equivalent by libkrb5.
        *data_out = raw as kurbu5_sys::krb5_ccselect_moddata;

        // SAFETY: priority_out is non-null (asserted above).
        *priority_out = prio;

        0
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge for the `choose` vtable field (`krb5_ccselect_choose_fn`).
///
/// Recovers the module from `data`, wraps `server` as a reference, and
/// calls `M::ccache()`.  On `Ok`, writes the cache and principal pointers
/// from the [`CcacheHandle`] into the output parameters.  Ownership of both
/// raw pointers transfers to libkrb5 at this point.
///
/// # Memory contract for output pointers
///
/// `*cache_out` and `*princ_out` receive raw pointers that libkrb5 owns and
/// must release via `krb5_cc_close` / `krb5_free_principal` respectively.
/// [`CcacheHandle::into_raw_parts`] is used to extract them without running
/// any destructor.
unsafe extern "C" fn ccselect_choose<M: CcselectModule>(
    ctx: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_ccselect_moddata,
    server: kurbu5_sys::krb5_principal,
    cache_out: *mut kurbu5_sys::krb5_ccache,
    princ_out: *mut kurbu5_sys::krb5_principal,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // SAFETY: server is non-null: libkrb5 contract — the server principal is
        // always provided to the choose callback.
        debug_assert!(!server.is_null());
        // SAFETY: cache_out is non-null: libkrb5 contract for the choose callback.
        debug_assert!(!cache_out.is_null());
        // SAFETY: princ_out is non-null: libkrb5 contract for the choose callback.
        debug_assert!(!princ_out.is_null());

        // SAFETY: ctx is non-null and valid for the duration of this call
        // (libkrb5 contract for all plugin callbacks).
        let plugin_ctx = PluginContext::from_raw(ctx);

        // SAFETY: server is non-null (asserted above) and valid for the duration
        // of this call; we create a Rust reference for the trait method only.
        let server_ref: &kurbu5_sys::krb5_principal_data = &*server;

        // SAFETY: data was written by ccselect_init as Box<M>::into_raw; it lives
        // until ccselect_fini calls Box::from_raw.
        let module = &*(data as *const M);

        match module.ccache(&plugin_ctx, server_ref) {
            Ok(handle) => {
                // SAFETY: cache_out and princ_out are non-null (asserted above).
                // into_raw_parts() yields the two raw pointers without running any
                // destructor.  Ownership transfers to libkrb5, which must close
                // the cache via krb5_cc_close and free the principal via
                // krb5_free_principal.
                let (cache, princ) = handle.into_raw_parts();
                *cache_out = cache;
                *princ_out = princ;
                0
            },
            Err(e) => {
                // On any error the C API specifies that *cache_out and *princ_out
                // are left at their pre-call values; libkrb5 initialises them to
                // NULL before calling choose.
                e.into_error_code()
            },
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge for the `fini` vtable field (`krb5_ccselect_fini_fn`).
///
/// Bridge for the `fini` vtable field (`krb5_ccselect_fini_fn`).
///
/// Reconstructs the `Box<M>` from `data`, unboxes it, and calls
/// `M::fini_module(self)` which consumes the value.
///
/// # Memory contract
///
/// The `Box<M>` created in `ccselect_init` is unboxed and passed by value to
/// `fini_module`; any `Drop` impl runs inside `fini_module`.  After this
/// function returns, `data` is a dangling pointer and must not be used.
unsafe extern "C" fn ccselect_fini<M: CcselectModule>(
    _ctx: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_ccselect_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            if data.is_null() {
                return;
            }
            // SAFETY: data was written by ccselect_init as Box<M>::into_raw cast to
            // krb5_ccselect_moddata.  We are the sole caller of fini (libkrb5
            // contract), so no other reference to the module exists at this point.
            // Unbox so that fini_module(self) can take ownership of the M value.
            let module: M = *Box::from_raw(data.cast::<M>());
            module.fini_module();
            // module is consumed by fini_module; no further drop needed.
        }));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccselect::{CcacheHandle, CcselectModule};
    use crate::error::Krb5Error;

    // Minimal module for glue-level tests — always returns NoHandle.
    struct AlwaysNoHandle;

    impl CcselectModule for AlwaysNoHandle {
        const NAME: &'static std::ffi::CStr = c"always_no_handle";

        fn init_module() -> Result<Self, Krb5Error> {
            Ok(AlwaysNoHandle)
        }

        fn priority(&self) -> i32 {
            kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC as i32
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
    // 4.4-k: make_ccselect_vtable name field points at the module NAME.
    // -----------------------------------------------------------------------
    #[test]
    fn vtable_name_field_matches_constant() {
        let vt = make_ccselect_vtable::<AlwaysNoHandle>();
        assert!(!vt.name.is_null());
        // SAFETY: vt.name was set to M::NAME.as_ptr() — a valid null-
        // terminated pointer derived from a &'static CStr.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, AlwaysNoHandle::NAME);
    }

    // -----------------------------------------------------------------------
    // 4.4-l: init bridge allocates a module and writes a valid data pointer.
    // -----------------------------------------------------------------------
    #[test]
    fn init_bridge_allocates_module() {
        let mut data: kurbu5_sys::krb5_ccselect_moddata = std::ptr::null_mut();
        let mut priority: libc::c_int = 0;

        // SAFETY: ctx=NULL is not dereferenced in our bridge (parameter is
        // _ctx); data and priority are stack-allocated and non-null.
        let code = unsafe {
            ccselect_init::<AlwaysNoHandle>(
                std::ptr::null_mut(),
                &mut data,
                &mut priority,
            )
        };

        assert_eq!(code, 0);
        assert!(!data.is_null());
        assert_eq!(
            priority,
            kurbu5_sys::KRB5_CCSELECT_PRIORITY_HEURISTIC as i32
        );

        // Clean up: run fini to free the box.
        // SAFETY: data was allocated by the init bridge; fini is the matching
        // deallocator.
        unsafe { ccselect_fini::<AlwaysNoHandle>(std::ptr::null_mut(), data) };
    }

    // -----------------------------------------------------------------------
    // 4.4-m: fini bridge with null data pointer is a no-op.
    // -----------------------------------------------------------------------
    #[test]
    fn fini_bridge_null_data_is_noop() {
        // SAFETY: null data is explicitly handled by the early-return guard.
        unsafe {
            ccselect_fini::<AlwaysNoHandle>(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // No panic — test passes.
    }

    // -----------------------------------------------------------------------
    // 4.4-n: choose bridge returns KRB5_PLUGIN_NO_HANDLE for AlwaysNoHandle.
    //
    // Uses a real krb5_context so that PluginContext::from_raw does not trip
    // the debug_assert in context.rs.
    // -----------------------------------------------------------------------
    #[test]
    fn choose_bridge_returns_no_handle() {
        // Initialise a real context; PluginContext::from_raw requires non-null.
        let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: krb5_init_context writes a valid pointer into ctx on success.
        let ctx_rc = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
        assert_eq!(ctx_rc, 0, "krb5_init_context failed");

        let mut data: kurbu5_sys::krb5_ccselect_moddata = std::ptr::null_mut();
        let mut priority: libc::c_int = 0;

        // SAFETY: ctx is valid; data and priority are stack-allocated.
        let init_code = unsafe {
            ccselect_init::<AlwaysNoHandle>(ctx, &mut data, &mut priority)
        };
        assert_eq!(init_code, 0);

        // A stack-allocated zeroed principal_data.  AlwaysNoHandle::ccache
        // ignores the server parameter entirely.
        let mut server_data = kurbu5_sys::krb5_principal_data::default();
        let server: kurbu5_sys::krb5_principal = &mut server_data;

        let mut cache_out: kurbu5_sys::krb5_ccache = std::ptr::null_mut();
        let mut princ_out: kurbu5_sys::krb5_principal = std::ptr::null_mut();

        // SAFETY: ctx is valid; data was allocated by init bridge; server is a
        // valid non-null stack reference; cache_out and princ_out are
        // stack-allocated (non-null addresses).
        let code = unsafe {
            ccselect_choose::<AlwaysNoHandle>(
                ctx,
                data,
                server,
                &mut cache_out,
                &mut princ_out,
            )
        };

        assert_eq!(code, kurbu5_sys::KRB5_PLUGIN_NO_HANDLE);
        assert!(cache_out.is_null());
        assert!(princ_out.is_null());

        // SAFETY: fini is the matching deallocator for data.
        unsafe { ccselect_fini::<AlwaysNoHandle>(ctx, data) };
        // SAFETY: ctx was allocated by krb5_init_context.
        unsafe { kurbu5_sys::krb5_free_context(ctx) };
    }
}
