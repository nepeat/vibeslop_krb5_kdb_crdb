//! Glue layer: C vtable function pointers → `CertauthModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `certauth` module that contains `unsafe`
//! code.**
//!
//! All `unsafe` blocks are annotated with a `// SAFETY:` comment.
//! The overall invariants are:
//!
//! 1. `moddata` holds a `*mut M` placed there by `init_ex` (our bridge for
//!    both `init` and `init_ex`) and freed (via `Box::from_raw`) by `fini`.
//!    No other code touches the raw pointer.
//!
//! 2. All raw pointers received from libkrb5 (e.g. `cert`, `princ`) are
//!    guaranteed non-null and valid for the duration of the call by the C API
//!    contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!
//! 4. C strings passed to us are null-terminated.  We use `CStr::from_ptr`
//!    and propagate errors where they are not valid UTF-8.
//!
//! # Memory ownership contracts
//!
//! | What | Allocation | Deallocation |
//! |------|-----------|--------------|
//! | Module instance | `Box::into_raw(Box::new(M))` in `init_ex` | `Box::from_raw` in `fini` |
//! | Auth indicator list | `Vec<CString>` → `into_boxed_slice().into_raw()` in `authorize` | `free_ind` iterates and drops each `CString`, then the slice |
//! | Individual auth indicator | `CString::into_raw()` | `CString::from_raw()` in `free_ind` |

use std::ffi::{CStr, CString};

use kurbu5_sys as sys;

use crate::certauth::{CertRef, CertauthDecision, CertauthModule};
use crate::context::PluginContext;

// ---------------------------------------------------------------------------
// Helper: recover `&mut M` from the moddata opaque pointer
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helper: parse a null-terminated `const char *const *` realm list
// ---------------------------------------------------------------------------

/// Parse a `const char *const *` null-terminated realm list into `Vec<&str>`.
///
/// # Safety
///
/// `realmlist` must be null or point to a null-terminated array of
/// null-terminated C strings valid for `'a`.
unsafe fn cstr_realmlist<'a>(
    realmlist: *const *const libc::c_char,
) -> Vec<&'a str> {
    if realmlist.is_null() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut p = realmlist;
    while !(*p).is_null() {
        if let Ok(s) = CStr::from_ptr(*p).to_str() {
            out.push(s);
        }
        p = p.add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// vtable constructor (task 6.4)
// ---------------------------------------------------------------------------

/// Produce a `krb5_certauth_vtable_st` for module type `M`.
///
/// Called from `initvt_plugin!` via the `make_vtable_fn` argument.  All
/// function pointers are monomorphised for `M` at compile time.
///
/// The `init` field is left `None` because `init_ex` (minor v2) is a strict
/// superset: it receives the realm list in addition to the context.  When the
/// KDC supports only minor v1 it calls `init`; when it supports minor v2 it
/// calls `init_ex`.  We set `init` to a shim that calls `init_module` without
/// the realm list so that minor-v1 callers still work.
pub fn make_certauth_vtable<M: CertauthModule>() -> sys::krb5_certauth_vtable_st
{
    sys::krb5_certauth_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        init: Some(init::<M>),
        fini: Some(fini::<M>),
        authorize: Some(authorize::<M>),
        free_ind: Some(free_ind),
        init_ex: Some(init_ex::<M>),
    }
}

// ---------------------------------------------------------------------------
// Module lifecycle bridges
// ---------------------------------------------------------------------------

/// Bridge for the minor-v1 `init` vtable slot.
///
/// Allocates `Box<M>` via `M::init_module` and stores the raw pointer in
/// `*moddata_out` cast to `krb5_certauth_moddata`.
extern "C" fn init<M: CertauthModule>(
    context: sys::krb5_context,
    moddata_out: *mut sys::krb5_certauth_moddata,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null (libkrb5 contract for init callbacks).
        let ctx = unsafe { PluginContext::from_raw(context) };
        match M::init_module(&ctx) {
            Ok(module) => {
                // SAFETY: moddata_out is non-null and writable (libkrb5 contract).
                //         Box::into_raw transfers ownership; freed in fini.
                unsafe {
                    *moddata_out = Box::into_raw(Box::new(module))
                        .cast::<sys::krb5_certauth_moddata_st>();
                }
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge for the minor-v2 `init_ex` vtable slot.
///
/// Same as `init` but also passes the realm list to `init_module_ex`.
extern "C" fn init_ex<M: CertauthModule>(
    context: sys::krb5_context,
    realmlist: *const *const libc::c_char,
    moddata_out: *mut sys::krb5_certauth_moddata,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null (libkrb5 contract).
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: realmlist is null or a valid null-terminated array of C strings
        // for the duration of this call (libkrb5 contract).
        let realms = unsafe { cstr_realmlist(realmlist) };
        match M::init_module_ex(&ctx, &realms) {
            Ok(module) => {
                // SAFETY: moddata_out is non-null and writable (libkrb5 contract).
                //         Box::into_raw transfers ownership; freed in fini.
                unsafe {
                    *moddata_out = Box::into_raw(Box::new(module))
                        .cast::<sys::krb5_certauth_moddata_st>();
                }
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge for the `fini` vtable slot.
///
/// Reclaims the `Box<M>` stored as `moddata` and calls `fini_module`.
extern "C" fn fini<M: CertauthModule>(
    _context: sys::krb5_context,
    moddata: sys::krb5_certauth_moddata,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if moddata.is_null() {
            return;
        }
        // SAFETY: moddata was set by init/init_ex as Box<M>::into_raw cast to
        // *mut krb5_certauth_moddata_st.  This is the only place it is reclaimed.
        let module = unsafe { Box::from_raw(moddata.cast::<M>()) };
        module.fini_module();
    }));
}

// ---------------------------------------------------------------------------
// Authorization bridge
// ---------------------------------------------------------------------------

/// Bridge for the `authorize` vtable slot.
///
/// Converts the raw C parameters to safe Rust types, calls `M::authorize`,
/// and translates the `CertauthDecision` back to C return codes and
/// `authinds_out`.
///
/// # Memory contract for `authinds_out`
///
/// When `authorize` returns indicators (either `AuthorizedWithIndicators` or
/// `NoOpinionWithIndicators`), this function:
/// 1. Converts each `String` to a `CString` and calls `CString::into_raw()`.
/// 2. Appends a null sentinel pointer.
/// 3. Stores the `*mut *mut c_char` in `*authinds_out`.
///
/// The KDC later calls `free_ind` to release this memory.  `free_ind`
/// reconstructs each `CString` via `CString::from_raw` and drops the slice.
extern "C" fn authorize<M: CertauthModule>(
    context: sys::krb5_context,
    moddata: sys::krb5_certauth_moddata,
    cert: *const u8,
    cert_len: usize,
    princ: sys::krb5_const_principal,
    _opts: *const libc::c_void,
    _db_entry: *const sys::_krb5_db_entry_new,
    authinds_out: *mut *mut *mut libc::c_char,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: moddata was set by init/init_ex as Box<M>::into_raw; valid until fini.
        let module = unsafe { &*moddata.cast::<M>() };
        // SAFETY: context is non-null (libkrb5 contract).
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: cert is non-null and cert_len bytes are valid (libkrb5 contract).
        let cert_ref = unsafe { CertRef::from_raw(cert, cert_len) };
        // SAFETY: princ is a valid krb5_principal_data reference (libkrb5 contract).
        let princ_ref: &sys::krb5_principal_data = unsafe { &*princ };

        match module.authorize(&ctx, cert_ref, princ_ref) {
            Ok(CertauthDecision::Authorized) => 0,
            Ok(CertauthDecision::AuthorizedHwauth) => {
                sys::KRB5_CERTAUTH_HWAUTH
            },
            Ok(CertauthDecision::NoOpinion) => sys::KRB5_PLUGIN_NO_HANDLE,
            Ok(CertauthDecision::AuthorizedWithIndicators(indicators)) => {
                match write_indicators(indicators, authinds_out) {
                    Ok(()) => 0,
                    Err(code) => code,
                }
            },
            Ok(CertauthDecision::NoOpinionWithIndicators(indicators)) => {
                match write_indicators(indicators, authinds_out) {
                    Ok(()) => sys::KRB5_CERTAUTH_HWAUTH_PASS,
                    Err(code) => code,
                }
            },
            Ok(CertauthDecision::Rejected(code)) => code,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Convert a `Vec<String>` into a null-terminated `*mut *mut c_char` array
/// and write a pointer to it into `*out`.
///
/// Returns an error if any indicator contains an interior NUL byte.  Silently
/// dropping such an indicator would allow a plugin to return seemingly-complete
/// indicator sets that are actually truncated, bypassing indicator-based
/// authorization checks.
///
/// # Memory contract
///
/// - Each element `*ptr` was produced by `CString::into_raw()`; it must be
///   freed via `CString::from_raw(*ptr)`.
/// - The array pointer itself was produced by `Box::into_raw(slice.into_boxed_slice())`;
///   it must be freed by reconstructing a `Box<[*mut c_char]>`.
///
/// Called only from `authorize`; the `free_ind` bridge handles deallocation.
fn write_indicators(
    indicators: Vec<String>,
    out: *mut *mut *mut libc::c_char,
) -> Result<(), sys::krb5_error_code> {
    if out.is_null() {
        // The caller does not want indicators; just drop them.
        return Ok(());
    }
    // Convert all indicators to CStrings, failing fast if any contain interior
    // NUL bytes.  A NUL-containing indicator string cannot be represented as a
    // C string and must be treated as a programming error in the plugin.
    let cstrings: Result<Vec<CString>, _> = indicators
        .into_iter()
        .map(|s| {
            CString::new(s).map_err(|_| libc::EINVAL as sys::krb5_error_code)
        })
        .collect();
    let cstrings = cstrings?;

    // Build a null-terminated list of raw C string pointers.
    let mut ptrs: Vec<*mut libc::c_char> =
        cstrings.into_iter().map(CString::into_raw).collect();
    ptrs.push(std::ptr::null_mut()); // null sentinel

    let boxed: Box<[*mut libc::c_char]> = ptrs.into_boxed_slice();
    let raw: *mut *mut libc::c_char =
        Box::into_raw(boxed).cast::<*mut libc::c_char>();

    // SAFETY: out is non-null (checked above); *out receives ownership of the
    // array; the KDC must call free_ind to release it.
    unsafe { *out = raw };
    Ok(())
}

// ---------------------------------------------------------------------------
// Indicator deallocation bridge
// ---------------------------------------------------------------------------

/// Bridge for the `free_ind` vtable slot.
///
/// Frees the null-terminated `*mut *mut c_char` array allocated by `authorize`
/// when the plugin returned authentication indicators.
///
/// # Memory contract
///
/// For each non-null element `*p` in `authinds`:
/// - It was produced by `CString::into_raw()` in `write_indicators`.
/// - We reclaim it via `CString::from_raw(*p)` which drops the allocation.
///
/// The slice itself was produced by `Box::into_raw(boxed_slice)`:
/// - We reclaim it by counting elements up to the null sentinel and
///   reconstructing a `Box<[*mut c_char]>` via `Box::from_raw`.
extern "C" fn free_ind(
    _context: sys::krb5_context,
    _moddata: sys::krb5_certauth_moddata,
    authinds: *mut *mut libc::c_char,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if authinds.is_null() {
            return;
        }
        // Count elements and free each CString.
        let mut count = 0usize;
        // SAFETY: authinds points to a null-terminated array of C strings
        // allocated by write_indicators.  We walk until the null sentinel.
        unsafe {
            let mut p = authinds;
            while !(*p).is_null() {
                // SAFETY: *p was produced by CString::into_raw() in write_indicators.
                drop(CString::from_raw(*p));
                p = p.add(1);
                count += 1;
            }
            // include the null sentinel in the slice length
            count += 1;
            // SAFETY: authinds was produced by Box::into_raw(boxed_slice) where
            // the slice had `count` elements (strings + null sentinel).
            // Reconstruct and drop the box.
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                authinds, count,
            )));
        }
    }));
}
