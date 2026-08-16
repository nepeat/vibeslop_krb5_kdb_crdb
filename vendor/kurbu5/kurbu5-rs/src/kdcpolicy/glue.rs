//! Glue layer: C vtable function pointers → `KdcpolicyModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `kdcpolicy` module that contains `unsafe`
//! code.**
//!
//! All `unsafe` blocks are annotated with a `// SAFETY:` comment.  The
//! overall invariants this file relies on are:
//!
//! 1. `moddata` holds a `*mut M` placed by the `init` bridge function and
//!    reclaimed (via `Box::from_raw`) by the `fini` bridge function.  No
//!    other code touches the raw pointer between those two calls.
//!
//! 2. All raw pointers received from libkrb5 (`krb5_kdc_req *`, etc.) are
//!    guaranteed non-null and valid for the duration of the callback by the
//!    C API contract unless explicitly listed as nullable in the header.
//!
//! 3. The `status` output pointer is a `*mut *const c_char`.  We write the
//!    pointer from a `'static` `CStr` into it; libkrb5 reads and logs the
//!    string but does NOT free it.  This is consistent with the C header
//!    comment "set status to an appropriate string literal".  Because
//!    `PolicyError::status` is `&'static CStr`, the bytes are always
//!    null-terminated and the pointer is valid for the entire process
//!    lifetime.
//!
//! 4. The `lifetime_out` and `renew_lifetime_out` output pointers are valid
//!    when non-null; we only write to them, never read from them.
//!
//! 5. When `e_data` is `Some(Vec<u8>)` in a `PolicyError`, the KDCPOLICY
//!    vtable does not have a `free_data` slot and the C function signatures
//!    do not include a `krb5_data` output parameter.  The `Vec` is therefore
//!    dropped in place after each call.  The `e_data` field is reserved for
//!    future interface extensions.

use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::kdcpolicy::{AsRequest, KdcpolicyModule, PolicyError, TgsRequest};

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Bridge `init`: construct an `M` and store it as moddata.
///
/// Returns 0 on success, `KRB5_PLUGIN_NO_HANDLE` if `init_module` returns
/// `Err(Krb5Error::NoHandle)`, or the error code on any other failure.
pub(super) unsafe extern "C" fn init<M: KdcpolicyModule>(
    context: kurbu5_sys::krb5_context,
    data_out: *mut kurbu5_sys::krb5_kdcpolicy_moddata,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null (libkrb5 contract).
        debug_assert!(!context.is_null());
        // SAFETY: context is valid for the duration of init_module call.
        let ctx = unsafe { PluginContext::from_raw(context) };
        match M::init_module(&ctx) {
            Ok(module) => {
                // SAFETY: data_out is non-null (libkrb5 contract); we write a
                // Box<M> pointer cast to the opaque moddata type.
                let raw = Box::into_raw(Box::new(module))
                    as kurbu5_sys::krb5_kdcpolicy_moddata;
                unsafe { *data_out = raw };
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `fini`: recover `Box<M>` from moddata and drop it.
pub(super) unsafe extern "C" fn fini<M: KdcpolicyModule>(
    context: kurbu5_sys::krb5_context,
    moddata: kurbu5_sys::krb5_kdcpolicy_moddata,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null (libkrb5 contract).
        debug_assert!(!context.is_null());
        if moddata.is_null() {
            return 0;
        }
        // SAFETY: context is valid for the duration of fini_module call.
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: moddata was created by `init` as Box::into_raw(Box::new(M)).
        // We are the sole owner; no other reference exists after fini is called.
        let module = unsafe { *Box::from_raw(moddata.cast::<M>()) };
        match module.fini_module(&ctx) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Write a denial's outputs into the C output parameters.
///
/// - `status_ptr`: if non-null, set to the null-terminated status string
///   pointer (a `'static` `CStr`; never freed by libkrb5).
/// - `lifetime_out`: if non-null and `err.lifetime` is `Some`, set to the
///   lifetime value in seconds.
/// - `renew_lifetime_out`: if non-null and `err.renew_lifetime` is `Some`,
///   set to the renewable lifetime value in seconds.
///
/// Returns `KRB5KDC_ERR_POLICY` to propagate to libkrb5.
///
/// # Safety
///
/// All non-null pointer arguments must be writable for the duration of this
/// call.  The null case is explicitly handled for each parameter.
unsafe fn write_denial(
    err: PolicyError,
    status_ptr: *mut *const libc::c_char,
    lifetime_out: *mut kurbu5_sys::krb5_deltat,
    renew_lifetime_out: *mut kurbu5_sys::krb5_deltat,
) -> kurbu5_sys::krb5_error_code {
    // Write the null-terminated status string pointer.  `err.status` is a
    // `&'static CStr`, so `.as_ptr()` yields a pointer valid for the entire
    // process lifetime.  libkrb5 reads but does NOT free this pointer.
    if !status_ptr.is_null() {
        // SAFETY: err.status is 'static CStr (null-terminated); the pointer
        // outlives this call.  status_ptr is non-null and writable.
        unsafe { *status_ptr = err.status.as_ptr() };
    }

    // Write lifetime restriction if requested.
    if let (Some(lt), true) = (err.lifetime, !lifetime_out.is_null()) {
        // SAFETY: lifetime_out is non-null and writable (caller invariant).
        unsafe { *lifetime_out = lt };
    }

    // Write renewable lifetime restriction if requested.
    if let (Some(rlt), true) =
        (err.renew_lifetime, !renew_lifetime_out.is_null())
    {
        // SAFETY: renew_lifetime_out is non-null and writable (caller invariant).
        unsafe { *renew_lifetime_out = rlt };
    }

    // e_data handling: the KDCPOLICY vtable does not have a free_data slot,
    // and the check_as/check_tgs function signatures do not include a krb5_data
    // output parameter.  Drop the Vec<u8> here so it is not leaked.
    drop(err.e_data);

    // Return the standard KDC policy error code.
    kurbu5_sys::KRB5KDC_ERR_POLICY
}

/// Bridge `check_as`.
pub(super) unsafe extern "C" fn check_as<M: KdcpolicyModule>(
    context: kurbu5_sys::krb5_context,
    moddata: kurbu5_sys::krb5_kdcpolicy_moddata,
    request: *const kurbu5_sys::krb5_kdc_req,
    client: *const kurbu5_sys::_krb5_db_entry_new,
    server: *const kurbu5_sys::_krb5_db_entry_new,
    auth_indicators: *const *const libc::c_char,
    status: *mut *const libc::c_char,
    lifetime_out: *mut kurbu5_sys::krb5_deltat,
    renew_lifetime_out: *mut kurbu5_sys::krb5_deltat,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context and request are non-null (libkrb5 contract).
        debug_assert!(!context.is_null());
        debug_assert!(!request.is_null());
        // SAFETY: context is valid for the duration of this call.
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: moddata was created by `init` as Box<M>::into_raw; valid until fini.
        let module = unsafe { &*(moddata as *const M) };
        let req = AsRequest {
            request,
            client,
            server,
            auth_indicators,
            _phantom: PhantomData,
        };
        match module.check_as(&ctx, req) {
            Ok(()) => 0,
            Err(err) => {
                // SAFETY: status, lifetime_out, renew_lifetime_out are the C
                // output parameters forwarded verbatim from libkrb5; they satisfy
                // the write_denial invariants.
                unsafe {
                    write_denial(err, status, lifetime_out, renew_lifetime_out)
                }
            },
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `check_tgs`.
pub(super) unsafe extern "C" fn check_tgs<M: KdcpolicyModule>(
    context: kurbu5_sys::krb5_context,
    moddata: kurbu5_sys::krb5_kdcpolicy_moddata,
    request: *const kurbu5_sys::krb5_kdc_req,
    server: *const kurbu5_sys::_krb5_db_entry_new,
    ticket: *const kurbu5_sys::krb5_ticket,
    auth_indicators: *const *const libc::c_char,
    status: *mut *const libc::c_char,
    lifetime_out: *mut kurbu5_sys::krb5_deltat,
    renew_lifetime_out: *mut kurbu5_sys::krb5_deltat,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context, request, and ticket are non-null (libkrb5 contract).
        debug_assert!(!context.is_null());
        debug_assert!(!request.is_null());
        debug_assert!(!ticket.is_null());
        // SAFETY: context is valid for the duration of this call.
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: moddata was created by `init` as Box<M>::into_raw; valid until fini.
        let module = unsafe { &*(moddata as *const M) };
        let req = TgsRequest {
            request,
            server,
            ticket,
            auth_indicators,
            _phantom: PhantomData,
        };
        match module.check_tgs(&ctx, req) {
            Ok(()) => 0,
            Err(err) => {
                // SAFETY: status, lifetime_out, renew_lifetime_out are the C
                // output parameters forwarded verbatim from libkrb5.
                unsafe {
                    write_denial(err, status, lifetime_out, renew_lifetime_out)
                }
            },
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Vtable constructor (task 5.4)
// ---------------------------------------------------------------------------

/// Produce a `krb5_kdcpolicy_vtable_st` for module type `M`.
///
/// Called from `initvt_plugin!` to fill in the caller-allocated vtable.
/// All function pointers are monomorphised for `M` at compile time.
///
/// The `name` field is set from `M::NAME`.  The KDC uses this string in log
/// messages to identify the plugin; it is not the symbol prefix used by
/// `initvt_plugin!`.
pub fn make_kdcpolicy_vtable<M: KdcpolicyModule>()
-> kurbu5_sys::krb5_kdcpolicy_vtable_st {
    kurbu5_sys::krb5_kdcpolicy_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        init: Some(init::<M>),
        fini: Some(fini::<M>),
        check_as: Some(check_as::<M>),
        check_tgs: Some(check_tgs::<M>),
    }
}

// ---------------------------------------------------------------------------
// Unit tests (task 5.5 — glue round-trip)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Krb5Error;
    use crate::kdcpolicy::{KdcpolicyModule, PolicyError};

    // -----------------------------------------------------------------------
    // Minimal module for testing
    // -----------------------------------------------------------------------

    struct AllowAll;

    impl KdcpolicyModule for AllowAll {
        const NAME: &'static std::ffi::CStr = c"allow_all";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(AllowAll)
        }
        // check_as and check_tgs use defaults (Ok(()))
    }

    // -----------------------------------------------------------------------
    // Vtable construction
    // -----------------------------------------------------------------------

    #[test]
    fn vtable_fields_are_set() {
        let vt = make_kdcpolicy_vtable::<AllowAll>();
        assert!(vt.init.is_some());
        assert!(vt.fini.is_some());
        assert!(vt.check_as.is_some());
        assert!(vt.check_tgs.is_some());
        assert!(!vt.name.is_null());
    }

    #[test]
    fn vtable_name_matches_module_name() {
        let vt = make_kdcpolicy_vtable::<AllowAll>();
        // SAFETY: vt.name was set from AllowAll::NAME.as_ptr() — a valid
        // null-terminated *const c_char valid for 'static.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, AllowAll::NAME);
    }

    // -----------------------------------------------------------------------
    // write_denial helper
    // -----------------------------------------------------------------------

    #[test]
    fn write_denial_sets_status_pointer() {
        let err = PolicyError::deny(c"test status");
        let mut status_ptr: *const libc::c_char = std::ptr::null();
        let mut lifetime: kurbu5_sys::krb5_deltat = 0;
        let mut renew_lifetime: kurbu5_sys::krb5_deltat = 0;

        // SAFETY: all pointers are valid stack locals; we own them for this
        // call.
        let code = unsafe {
            write_denial(
                err,
                &mut status_ptr,
                &mut lifetime,
                &mut renew_lifetime,
            )
        };

        assert_ne!(code, 0);
        assert!(!status_ptr.is_null());
        // SAFETY: status_ptr points to the null-terminated bytes of c"test status".
        let s = unsafe { std::ffi::CStr::from_ptr(status_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(s, "test status");
        // No lifetime restriction was set.
        assert_eq!(lifetime, 0);
        assert_eq!(renew_lifetime, 0);
    }

    #[test]
    fn write_denial_sets_lifetime_restrictions() {
        let err = PolicyError {
            status: c"restricted",
            e_data: None,
            lifetime: Some(3600),
            renew_lifetime: Some(7200),
        };
        let mut status_ptr: *const libc::c_char = std::ptr::null();
        let mut lifetime: kurbu5_sys::krb5_deltat = 0;
        let mut renew_lifetime: kurbu5_sys::krb5_deltat = 0;

        // SAFETY: pointers are valid stack locals.
        unsafe {
            write_denial(
                err,
                &mut status_ptr,
                &mut lifetime,
                &mut renew_lifetime,
            )
        };

        assert_eq!(lifetime, 3600);
        assert_eq!(renew_lifetime, 7200);
    }

    #[test]
    fn write_denial_null_status_does_not_crash() {
        let err = PolicyError::deny(c"no crash");
        // SAFETY: null status pointer is explicitly handled in write_denial.
        unsafe {
            write_denial(
                err,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
    }

    #[test]
    fn write_denial_returns_policy_error_code() {
        let err = PolicyError::deny(c"test");
        // SAFETY: null pointers are handled.
        let code = unsafe {
            write_denial(
                err,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // KRB5KDC_ERR_POLICY is non-zero; the exact value is platform-defined.
        assert_ne!(code, 0);
        assert_eq!(code, kurbu5_sys::KRB5KDC_ERR_POLICY);
    }

    #[test]
    fn write_denial_drops_e_data() {
        // Verify that e_data is dropped (not leaked) when write_denial is called.
        let data = vec![1u8, 2, 3, 4];
        let err = PolicyError {
            status: c"test",
            e_data: Some(data),
            lifetime: None,
            renew_lifetime: None,
        };
        // SAFETY: null pointers are handled.
        unsafe {
            write_denial(
                err,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // If we reach here without asan/valgrind complaints, the Vec was dropped.
    }
}
