//! Glue layer: C vtable function pointers → `LocalauthModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `localauth` module that contains `unsafe` code.**
//!
//! All `unsafe` blocks in this file are annotated with a `// SAFETY:` comment
//! explaining the invariants that make them sound.  The overall invariants are:
//!
//! 1. `krb5_localauth_moddata` holds a `*mut M` placed there by the bridge
//!    `init` function and removed (via `Box::from_raw`) by the bridge `fini`
//!    function.  No other code touches this pointer.
//!
//! 2. All raw pointers received from libkrb5 (e.g. `krb5_const_principal`)
//!    are guaranteed non-null and valid for the duration of the call by the
//!    C API contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!
//! 4. C strings passed to us are null-terminated.  We use `CStr::from_ptr`
//!    and propagate errors where they are not valid UTF-8.
//!
//! # String ownership for `an2ln`
//!
//! The `an2ln` bridge converts the `String` returned by the Rust trait method
//! into a `CString` via `CString::new(name)` followed by `into_raw()`.  The
//! resulting `*mut c_char` is written to `*lname_out`.  libkrb5 will later
//! call the vtable's `free_string` slot to release the memory.  The
//! `free_string` bridge calls `CString::from_raw` on the same pointer, which
//! drops it and returns the allocation to the Rust global allocator.
//!
//! Allocation site:   `an2ln` bridge — `CString::new(name)` + `into_raw()`.
//! Deallocation site: `free_string` bridge — `CString::from_raw(str_)` + drop.
//!
//! # Module data ownership
//!
//! Allocation site:   `init` bridge — `Box::into_raw(Box::new(module))`.
//! Deallocation site: `fini` bridge — `Box::from_raw(data as *mut M)` + drop.
//!
//! # Name and `an2ln_types` pointers
//!
//! The vtable's `name` field is set from `M::NAME` (a `'static CStr`); no
//! allocation occurs.  The `an2ln_types` field, when present, is built from
//! `M::AN2LN_TYPES` using `Box::leak` so that the allocation lives for the
//! process lifetime.  One allocation per plugin type per process load is
//! acceptable.
//!
//! Allocation site:   `make_localauth_vtable` — `Box::leak(CString::into_boxed_c_str())` for `an2ln_types`.
//! Deallocation site: none (intentional leak; lives for the process lifetime).

use std::ffi::{CStr, CString};

use kurbu5_sys as sys;

use crate::context::PluginContext;
use crate::error::Krb5Error;
use crate::localauth::LocalauthModule;

// ---------------------------------------------------------------------------
// Helper: parse a possibly-null *const c_char as an optional &str.
// ---------------------------------------------------------------------------

/// Parse a possibly-null `*const c_char` as an optional `&str`.
///
/// # Safety
///
/// `ptr` must either be null or point to a valid null-terminated C string
/// that is valid for at least lifetime `'a`.
unsafe fn optional_cstr<'a>(ptr: *const libc::c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is non-null and points to a valid null-terminated string
    // (caller guarantee).
    CStr::from_ptr(ptr).to_str().ok()
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Bridge: `krb5_localauth_init_fn` → `M::init_module`.
///
/// Called once by libkrb5 after loading the plugin.  Allocates `Box<M>` and
/// stores its raw pointer in `*data` as a `*mut krb5_localauth_moddata_st`.
pub(crate) unsafe extern "C" fn init<M: LocalauthModule>(
    context: sys::krb5_context,
    data: *mut sys::krb5_localauth_moddata,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null: libkrb5 contract.
        let ctx = unsafe { PluginContext::from_raw(context) };
        match M::init_module(&ctx) {
            Ok(module) => {
                // ALLOCATION: Box::into_raw transfers ownership to the C caller.
                // Deallocation: fini bridge calls Box::from_raw.
                let raw = Box::into_raw(Box::new(module))
                    .cast::<sys::krb5_localauth_moddata_st>();
                // SAFETY: data is non-null (libkrb5 contract); we write a valid
                // heap pointer produced by Box::into_raw.
                unsafe { *data = raw };
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge: `krb5_localauth_fini_fn` → `M::fini_module`.
///
/// Called once by libkrb5 when unloading the plugin.  Reclaims the `Box<M>`
/// stored in `data` and runs its destructor.
pub(crate) unsafe extern "C" fn fini<M: LocalauthModule>(
    context: sys::krb5_context,
    data: sys::krb5_localauth_moddata,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null: libkrb5 contract.
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: data was placed by `init` as Box<M>::into_raw cast to
        // *mut krb5_localauth_moddata_st.  It lives until this fini call.
        // DEALLOCATION: Box::from_raw reclaims the allocation made in init.
        let module = unsafe { Box::from_raw(data.cast::<M>()) };
        module.fini_module(&ctx);
        // `module` is dropped here, freeing the Box<M>.
    }));
}

/// Bridge: `krb5_localauth_userok_fn` → `M::userok`.
///
/// Returns 0 if authorised, the error code for explicit denial, or
/// `KRB5_PLUGIN_NO_HANDLE` if no opinion.
pub(crate) unsafe extern "C" fn userok<M: LocalauthModule>(
    context: sys::krb5_context,
    data: sys::krb5_localauth_moddata,
    aname: sys::krb5_const_principal,
    lname: *const libc::c_char,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null: libkrb5 contract.
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: data was placed by `init`; treated as a shared reference for
        // the duration of this call (no aliasing with fini, serialised by libkrb5).
        let module = unsafe { &*data.cast::<M>() };
        // SAFETY: aname is non-null and valid for the duration of this call:
        // libkrb5 contract for krb5_const_principal parameters.
        let principal = unsafe { &*aname };
        if lname.is_null() {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        }
        // SAFETY: lname is non-null (checked above) and null-terminated:
        // libkrb5 contract.
        let Ok(local_user) = (unsafe { CStr::from_ptr(lname).to_str() })
        else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };
        match module.userok(&ctx, principal, local_user) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge: `krb5_localauth_an2ln_fn` → `M::an2ln`.
///
/// On success (return 0), writes a `*mut c_char` into `*lname_out`.  The
/// string is a `CString` allocated by the Rust global allocator.  libkrb5
/// will later free it via the `free_string` slot.
///
/// # String ownership
///
/// Allocation: `CString::new(result_string)` + `into_raw()` in this bridge.
/// Deallocation: `free_string` bridge → `CString::from_raw(str_)` → drop.
pub(crate) unsafe extern "C" fn an2ln<M: LocalauthModule>(
    context: sys::krb5_context,
    data: sys::krb5_localauth_moddata,
    type_: *const libc::c_char,
    residual: *const libc::c_char,
    aname: sys::krb5_const_principal,
    lname_out: *mut *mut libc::c_char,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: context is non-null: libkrb5 contract.
        let ctx = unsafe { PluginContext::from_raw(context) };
        // SAFETY: data was placed by `init`.
        let module = unsafe { &*data.cast::<M>() };
        // SAFETY: aname is non-null and valid: libkrb5 contract.
        let principal = unsafe { &*aname };
        // SAFETY: type_ and residual are null or valid null-terminated strings:
        // libkrb5 contract for these optional parameters.
        let type_str = unsafe { optional_cstr(type_) };
        let residual_str = unsafe { optional_cstr(residual) };

        match module.an2ln(&ctx, type_str, residual_str, principal) {
            Ok(name) => {
                // Convert the Rust String to a CString for the C caller.
                // CString::new fails only if `name` contains interior NUL bytes,
                // which must not occur for a valid UNIX account name.  Return
                // ENOMEM (the mildest non-zero code) rather than crashing.
                let Ok(cname) = CString::new(name) else {
                    return Krb5Error::OutOfMemory.into_error_code();
                };
                // SAFETY: lname_out is non-null: libkrb5 contract.
                // ALLOCATION: CString::into_raw() transfers ownership to C caller.
                // Deallocation: free_string bridge → CString::from_raw(str_).
                unsafe { *lname_out = cname.into_raw() };
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge: `krb5_localauth_free_string_fn`.
///
/// Frees the `*mut c_char` produced by the `an2ln` bridge.
///
/// libkrb5 calls this for every `*lname_out` pointer that `an2ln` wrote on
/// success.  A null pointer is silently ignored.
///
/// This function is not generic over `M` because the deallocation contract
/// does not depend on the module type: every `an2ln` bridge allocates via
/// `CString::into_raw()`, and every `free_string` call uses `CString::from_raw`.
///
/// # Memory ownership
///
/// Deallocation: `CString::from_raw(str_)` reclaims the allocation made in
/// the `an2ln` bridge by `CString::into_raw()`.  The resulting `CString` is
/// then dropped, returning the memory to the Rust global allocator.
pub(crate) unsafe extern "C" fn free_string(
    _context: sys::krb5_context,
    _data: sys::krb5_localauth_moddata,
    str_: *mut libc::c_char,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if str_.is_null() {
            return;
        }
        // SAFETY: str_ is non-null and was produced by CString::into_raw() in
        // the an2ln bridge.  No other code holds a reference to this allocation.
        // CString::from_raw reclaims ownership and frees the allocation when the
        // CString is dropped at end of this block.
        drop(unsafe { CString::from_raw(str_) });
    }));
}

// ---------------------------------------------------------------------------
// Vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `krb5_localauth_vtable_st` for module type `M`.
///
/// Called from the `initvt_plugin!` macro (or a localauth-specific macro);
/// the result is written into the caller-supplied vtable pointer.
///
/// All function pointers are monomorphised for `M` at compile time.
///
/// The `name` field is set from `M::NAME` (a `'static CStr`).  The
/// `an2ln_types` field is built from `M::AN2LN_TYPES` if present, or set to
/// null.
///
/// # Leaks
///
/// `make_localauth_vtable` optionally leaks one `Box<[*const c_char]>` plus
/// one `CString` per type string (for `an2ln_types`) per plugin type per
/// process load.  This is intentional: the pointers must outlive the vtable,
/// which is valid for the process lifetime.
pub fn make_localauth_vtable<M: LocalauthModule>()
-> sys::krb5_localauth_vtable_st {
    // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
    // null-terminated *const c_char for the entire process lifetime.
    let name_ptr: *const libc::c_char = M::NAME.as_ptr();

    // Build the `an2ln_types` pointer array from M::AN2LN_TYPES.
    // The field type is *mut *const c_char (null-terminated array of C strings).
    let an2ln_types_ptr: *mut *const libc::c_char = match M::AN2LN_TYPES {
        None => std::ptr::null_mut(),
        Some(types) => {
            // Allocate a null-terminated array of *const c_char pointers.
            // Each type string is also leaked so it lives for the process lifetime.
            let mut ptrs: Vec<*const libc::c_char> = types
                .iter()
                .map(|&s| {
                    let cs = CString::new(s)
                        .expect("AN2LN_TYPES entry must not contain interior NUL bytes");
                    // SAFETY (leak): pointer must outlive the vtable.
                    Box::leak(cs.into_boxed_c_str()).as_ptr()
                })
                .collect();
            // Null sentinel required by C API.
            ptrs.push(std::ptr::null());
            // SAFETY (leak): the pointer array must outlive the vtable.
            // Cast *const to *mut: the C header declares this field as
            // `*mut *const char` even though the plugin populates it with a
            // static list that libkrb5 only reads.
            Box::leak(ptrs.into_boxed_slice()).as_mut_ptr()
        },
    };

    sys::krb5_localauth_vtable_st {
        name: name_ptr,
        an2ln_types: an2ln_types_ptr,
        init: Some(init::<M>),
        fini: Some(fini::<M>),
        userok: Some(userok::<M>),
        an2ln: Some(an2ln::<M>),
        free_string: Some(free_string),
    }
}
