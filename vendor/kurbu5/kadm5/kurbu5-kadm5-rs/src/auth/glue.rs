//! Glue layer: C vtable function pointers → `Kadm5AuthModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `auth` module that contains `unsafe` code.**
//!
//! All `unsafe` blocks are annotated with a `// SAFETY:` comment that names
//! the specific invariant being relied upon.  The overall invariants are:
//!
//! 1. `kadm5_auth_moddata` holds a `*mut M` placed there by `bridge_init`
//!    (as a `Box<M>` converted via `Box::into_raw`) and reclaimed (via
//!    `Box::from_raw`) by `bridge_fini`.  No other code touches this pointer
//!    concurrently.
//!
//! 2. All raw pointers received from kadmind (e.g. `krb5_context`,
//!    `krb5_const_principal`) are guaranteed non-null and valid for the
//!    duration of the call by the C API contract.  We document this per site.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!    All check methods take `&self` (not `&mut self`), matching the C API
//!    which does not promise single-threaded access to check methods.
//!
//! 4. All C strings (ACL file, key/value, policy names) are null-terminated.
//!    We use `CStr::from_ptr` and propagate errors where they are not valid
//!    UTF-8.
//!
//! # Memory ownership contracts
//!
//! | Pattern | Allocation | Deallocation |
//! |---------|-----------|--------------|
//! | Module instance | `Box::into_raw(Box::new(M))` in `bridge_init`, cast to `*mut c_void` | `bridge_fini` calls `Box::from_raw(data as *mut M)` |
//! | Restrictions out-param | `Box::into_raw(Box::new(rs))` cast to `*mut kadm5_auth_restrictions` in bridge functions that set `*rs_out` | `bridge_free_restrictions` calls `Box::from_raw(rs)` |

use std::ffi::CStr;
use std::marker::PhantomData;

use crate::auth::{AddPrincRequest, Kadm5AuthModule, ModPrincRequest};
use crate::context::PluginContext;
use crate::error::Krb5Error;
use crate::principal::Kadm5PrincipalEntry;

// ---------------------------------------------------------------------------
// Helper: parse a possibly-null `*const c_char` as an optional `&str`
// ---------------------------------------------------------------------------

/// Parse a possibly-null `*const c_char` as an optional `&str`.
///
/// # Safety
///
/// `ptr` must either be null or point to a valid null-terminated C string
/// that is valid for lifetime `'a`.
unsafe fn optional_cstr<'a>(ptr: *const libc::c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is non-null and points to a valid null-terminated C string
    // (caller guarantee).
    CStr::from_ptr(ptr).to_str().ok()
}

// ---------------------------------------------------------------------------
// Bridge functions — one per vtable slot
// ---------------------------------------------------------------------------

/// Bridge `kadm5_auth_init_fn`: construct the module.
///
/// The module is boxed and its raw pointer is stored in `*data_out`.
/// On error, `*data_out` is left unchanged (null) and the error code returned.
unsafe extern "C" fn bridge_init<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    acl_file: *const libc::c_char,
    data_out: *mut kurbu5_kadm5_sys::kadm5_auth_moddata,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "init: context is null");
        debug_assert!(!data_out.is_null(), "init: data_out is null");

        // SAFETY: context is non-null (kadmind invariant); valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: acl_file is either null or a valid C string (kadmind invariant).
        let acl = optional_cstr(acl_file);

        match M::init_module(&ctx, acl) {
            Ok(module) => {
                // SAFETY: Box::into_raw produces a valid heap pointer.  The cast
                // to kadm5_auth_moddata (which is *mut kadm5_auth_moddata_st) is
                // valid because we treat this as an opaque handle.  The raw
                // pointer outlives this frame; deallocation happens in bridge_fini.
                let raw = Box::into_raw(Box::new(module))
                    as kurbu5_kadm5_sys::kadm5_auth_moddata;
                // SAFETY: data_out is non-null (debug_assert above) and writable.
                *data_out = raw;
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_fini_fn`: reclaim the module.
unsafe extern "C" fn bridge_fini<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(!context.is_null(), "fini: context is null");
            if data.is_null() {
                return;
            }
            // SAFETY: context is non-null (kadmind invariant).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: data was placed by bridge_init as Box<M>::into_raw cast to
            // kadm5_auth_moddata.  We are the sole owner; this is the unique
            // reclamation point.  After Box::from_raw the pointer must not be used.
            let module = Box::from_raw(data.cast::<M>());
            module.fini_module(&ctx);
        }));
}

/// Bridge `kadm5_auth_addprinc_fn`: check add-principal authorization.
unsafe extern "C" fn bridge_addprinc<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
    ent: *const kurbu5_kadm5_sys::_kadm5_principal_ent_t,
    mask: libc::c_long,
    rs_out: *mut *mut kurbu5_kadm5_sys::kadm5_auth_restrictions,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "addprinc: context is null");
        debug_assert!(!data.is_null(), "addprinc: data is null");
        debug_assert!(!client.is_null(), "addprinc: client is null");
        debug_assert!(!target.is_null(), "addprinc: target is null");

        // SAFETY: context is non-null and valid (kadmind invariant).
        let ctx = PluginContext::from_raw(context);

        // SAFETY: client is non-null and points to a valid krb5_principal_data
        // (kadmind invariant); valid for the duration of this call.
        let client_ref = &*client;
        // SAFETY: target is non-null and valid (kadmind invariant).
        let target_ref = &*target;

        let entry = if ent.is_null() {
            None
        } else {
            Some(Kadm5PrincipalEntry {
                ptr: ent,
                _phantom: PhantomData,
            })
        };

        let req = AddPrincRequest {
            client: client_ref,
            target: target_ref,
            target_entry: entry,
            mask,
        };

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw; we borrow
        // it as &M for this call only.
        let module = &*(data as *const M);
        match module.check_add_principal(&ctx, &req) {
            Ok(None) => 0,
            Ok(Some(rs)) => {
                if rs_out.is_null() {
                    // kadmind did not allocate a slot for restrictions; returning 0
                    // here would silently discard them, authorising an operation
                    // that the plugin intended to restrict.  Signal a coding error.
                    return libc::EINVAL;
                }
                // Box the restrictions value so we can pass a raw pointer to
                // kadmind.  Ownership transfers to kadmind which calls
                // bridge_free_restrictions to reclaim it via Box::from_raw.
                // SAFETY: rs_out is non-null (checked above); write the raw pointer.
                *rs_out = Box::into_raw(Box::new(rs));
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_modprinc_fn`: check modify-principal authorization.
unsafe extern "C" fn bridge_modprinc<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
    ent: *const kurbu5_kadm5_sys::_kadm5_principal_ent_t,
    mask: libc::c_long,
    rs_out: *mut *mut kurbu5_kadm5_sys::kadm5_auth_restrictions,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "modprinc: context is null");
        debug_assert!(!data.is_null(), "modprinc: data is null");
        debug_assert!(!client.is_null(), "modprinc: client is null");
        debug_assert!(!target.is_null(), "modprinc: target is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        // SAFETY: client and target are non-null (kadmind invariant).
        let client_ref = &*client;
        let target_ref = &*target;

        let entry = if ent.is_null() {
            None
        } else {
            Some(Kadm5PrincipalEntry {
                ptr: ent,
                _phantom: PhantomData,
            })
        };

        let req = ModPrincRequest {
            client: client_ref,
            target: target_ref,
            target_entry: entry,
            mask,
        };

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_modify_principal(&ctx, &req) {
            Ok(None) => 0,
            Ok(Some(rs)) => {
                if rs_out.is_null() {
                    // Same reasoning as bridge_addprinc: silently discarding
                    // restrictions would authorise an operation that the plugin
                    // intended to restrict.
                    return libc::EINVAL;
                }
                // Box the value; ownership transfers to kadmind which calls
                // bridge_free_restrictions to reclaim it via Box::from_raw.
                // SAFETY: rs_out is non-null (checked above).
                *rs_out = Box::into_raw(Box::new(rs));
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_setstr_fn`: check set-string authorization.
unsafe extern "C" fn bridge_setstr<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
    key: *const libc::c_char,
    value: *const libc::c_char,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "setstr: context is null");
        debug_assert!(!data.is_null(), "setstr: data is null");
        debug_assert!(!client.is_null(), "setstr: client is null");
        debug_assert!(!target.is_null(), "setstr: target is null");
        debug_assert!(!key.is_null(), "setstr: key is null");

        // SAFETY: context, client, target are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: key is non-null and a valid C string.
        let Ok(key_str) = CStr::from_ptr(key).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };
        // SAFETY: value is either null or a valid C string.
        let value_str = optional_cstr(value);

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module
            .check_set_string(&ctx, client_ref, target_ref, key_str, value_str)
        {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_cpw_fn`: check change-password authorization.
unsafe extern "C" fn bridge_cpw<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "cpw: context is null");
        debug_assert!(!data.is_null(), "cpw: data is null");
        debug_assert!(!client.is_null(), "cpw: client is null");
        debug_assert!(!target.is_null(), "cpw: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_change_password(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_chrand_fn`: check randomize-keys authorization.
unsafe extern "C" fn bridge_chrand<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "chrand: context is null");
        debug_assert!(!data.is_null(), "chrand: data is null");
        debug_assert!(!client.is_null(), "chrand: client is null");
        debug_assert!(!target.is_null(), "chrand: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_randomize_keys(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_setkey_fn`: check set-key authorization.
unsafe extern "C" fn bridge_setkey<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "setkey: context is null");
        debug_assert!(!data.is_null(), "setkey: data is null");
        debug_assert!(!client.is_null(), "setkey: client is null");
        debug_assert!(!target.is_null(), "setkey: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_set_key(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_purgekeys_fn`: check purge-keys authorization.
unsafe extern "C" fn bridge_purgekeys<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "purgekeys: context is null");
        debug_assert!(!data.is_null(), "purgekeys: data is null");
        debug_assert!(!client.is_null(), "purgekeys: client is null");
        debug_assert!(!target.is_null(), "purgekeys: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_purge_keys(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_delprinc_fn`: check delete-principal authorization.
unsafe extern "C" fn bridge_delprinc<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "delprinc: context is null");
        debug_assert!(!data.is_null(), "delprinc: data is null");
        debug_assert!(!client.is_null(), "delprinc: client is null");
        debug_assert!(!target.is_null(), "delprinc: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_delete_principal(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_renprinc_fn`: check rename-principal authorization.
unsafe extern "C" fn bridge_renprinc<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    src: kurbu5_kadm5_sys::krb5_const_principal,
    dest: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "renprinc: context is null");
        debug_assert!(!data.is_null(), "renprinc: data is null");
        debug_assert!(!client.is_null(), "renprinc: client is null");
        debug_assert!(!src.is_null(), "renprinc: src is null");
        debug_assert!(!dest.is_null(), "renprinc: dest is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let src_ref = &*src;
        let dest_ref = &*dest;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module
            .check_rename_principal(&ctx, client_ref, src_ref, dest_ref)
        {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_getprinc_fn`: check get-principal authorization.
unsafe extern "C" fn bridge_getprinc<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "getprinc: context is null");
        debug_assert!(!data.is_null(), "getprinc: data is null");
        debug_assert!(!client.is_null(), "getprinc: client is null");
        debug_assert!(!target.is_null(), "getprinc: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_get_principal(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_getstrs_fn`: check get-strings authorization.
unsafe extern "C" fn bridge_getstrs<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "getstrs: context is null");
        debug_assert!(!data.is_null(), "getstrs: data is null");
        debug_assert!(!client.is_null(), "getstrs: client is null");
        debug_assert!(!target.is_null(), "getstrs: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_get_strings(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_extract_fn`: check extract-keys authorization.
unsafe extern "C" fn bridge_extract<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    target: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "extract: context is null");
        debug_assert!(!data.is_null(), "extract: data is null");
        debug_assert!(!client.is_null(), "extract: client is null");
        debug_assert!(!target.is_null(), "extract: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let target_ref = &*target;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_extract_keys(&ctx, client_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_listprincs_fn`: check list-principals authorization.
unsafe extern "C" fn bridge_listprincs<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "listprincs: context is null");
        debug_assert!(!data.is_null(), "listprincs: data is null");
        debug_assert!(!client.is_null(), "listprincs: client is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_list_principals(&ctx, client_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_addpol_fn`: check add-policy authorization.
///
/// The `ent` and `mask` parameters from the C signature carry the policy
/// entry details; we expose only the policy name since the policy struct
/// type is not yet wrapped.
unsafe extern "C" fn bridge_addpol<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    policy: *const libc::c_char,
    _ent: *const kurbu5_kadm5_sys::_kadm5_policy_ent_t,
    _mask: libc::c_long,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "addpol: context is null");
        debug_assert!(!data.is_null(), "addpol: data is null");
        debug_assert!(!client.is_null(), "addpol: client is null");
        debug_assert!(!policy.is_null(), "addpol: policy is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        // SAFETY: client is non-null and valid.
        let client_ref = &*client;
        // SAFETY: policy is non-null and a valid C string.
        let Ok(pol_str) = CStr::from_ptr(policy).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_add_policy(&ctx, client_ref, pol_str) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_modpol_fn`: check modify-policy authorization.
unsafe extern "C" fn bridge_modpol<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    policy: *const libc::c_char,
    _ent: *const kurbu5_kadm5_sys::_kadm5_policy_ent_t,
    _mask: libc::c_long,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "modpol: context is null");
        debug_assert!(!data.is_null(), "modpol: data is null");
        debug_assert!(!client.is_null(), "modpol: client is null");
        debug_assert!(!policy.is_null(), "modpol: policy is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        // SAFETY: policy is a valid C string.
        let Ok(pol_str) = CStr::from_ptr(policy).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_modify_policy(&ctx, client_ref, pol_str) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_delpol_fn`: check delete-policy authorization.
unsafe extern "C" fn bridge_delpol<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    policy: *const libc::c_char,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "delpol: context is null");
        debug_assert!(!data.is_null(), "delpol: data is null");
        debug_assert!(!client.is_null(), "delpol: client is null");
        debug_assert!(!policy.is_null(), "delpol: policy is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        // SAFETY: policy is a valid C string.
        let Ok(pol_str) = CStr::from_ptr(policy).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_delete_policy(&ctx, client_ref, pol_str) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_getpol_fn`: check get-policy authorization.
unsafe extern "C" fn bridge_getpol<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    policy: *const libc::c_char,
    client_policy: *const libc::c_char,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "getpol: context is null");
        debug_assert!(!data.is_null(), "getpol: data is null");
        debug_assert!(!client.is_null(), "getpol: client is null");
        debug_assert!(!policy.is_null(), "getpol: policy is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        // SAFETY: client is non-null and valid.
        let client_ref = &*client;
        // SAFETY: policy is a valid C string.
        let Ok(pol_str) = CStr::from_ptr(policy).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };
        // SAFETY: client_policy is either null or a valid C string.
        let client_pol = optional_cstr(client_policy);

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_get_policy(&ctx, client_ref, pol_str, client_pol) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_listpols_fn`: check list-policies authorization.
unsafe extern "C" fn bridge_listpols<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "listpols: context is null");
        debug_assert!(!data.is_null(), "listpols: data is null");
        debug_assert!(!client.is_null(), "listpols: client is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_list_policies(&ctx, client_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_iprop_fn`: check iprop authorization.
unsafe extern "C" fn bridge_iprop<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "iprop: context is null");
        debug_assert!(!data.is_null(), "iprop: data is null");
        debug_assert!(!client.is_null(), "iprop: client is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_iprop(&ctx, client_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kadm5_auth_end_fn`: end-of-operation notification.
unsafe extern "C" fn bridge_end<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(!context.is_null(), "end: context is null");
            if data.is_null() {
                return;
            }
            // SAFETY: context is non-null (kadmind invariant).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: data was placed by bridge_init as Box<M>::into_raw; we borrow
            // it as &M for this call only.
            let module = &*(data as *const M);
            module.end_operation(&ctx);
        }));
}

/// Bridge `kadm5_auth_free_restrictions_fn`: free a restrictions object.
///
/// The restrictions pointer was produced by `bridge_addprinc` or
/// `bridge_modprinc` via `Box::into_raw(Box::new(rs))`.  We reclaim it as a
/// `Box`, dereference it to get the value, and pass the value to
/// `M::free_restrictions` for any custom cleanup before dropping.
unsafe extern "C" fn bridge_free_restrictions<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    rs: *mut kurbu5_kadm5_sys::kadm5_auth_restrictions,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(
                !context.is_null(),
                "free_restrictions: context is null"
            );
            if rs.is_null() {
                return;
            }
            // SAFETY: context is non-null (kadmind invariant).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: rs was produced by Box::into_raw in bridge_addprinc/bridge_modprinc.
            // We are the unique deallocator; after Box::from_raw the pointer must not
            // be used again.  We dereference the Box to get the owned value.
            let rs_value = *Box::from_raw(rs);
            if data.is_null() {
                // Module data is gone (shouldn't happen, but be defensive).
                // rs_value is Copy; let binding silences the dropping_copy_types lint.
                let _ = rs_value;
                return;
            }
            // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
            let module = &*(data as *const M);
            module.free_restrictions(&ctx, rs_value);
        }));
}

/// Bridge `kadm5_auth_addalias_fn`: check add-alias authorization (`min_ver` 2).
unsafe extern "C" fn bridge_addalias<M: Kadm5AuthModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    data: kurbu5_kadm5_sys::kadm5_auth_moddata,
    client: kurbu5_kadm5_sys::krb5_const_principal,
    alias_princ: kurbu5_kadm5_sys::krb5_const_principal,
    target_princ: kurbu5_kadm5_sys::krb5_const_principal,
) -> kurbu5_kadm5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "addalias: context is null");
        debug_assert!(!data.is_null(), "addalias: data is null");
        debug_assert!(!client.is_null(), "addalias: client is null");
        debug_assert!(!alias_princ.is_null(), "addalias: alias_princ is null");
        debug_assert!(
            !target_princ.is_null(),
            "addalias: target_princ is null"
        );

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let client_ref = &*client;
        let alias_ref = &*alias_princ;
        let target_ref = &*target_princ;

        // SAFETY: data was placed by bridge_init as Box<M>::into_raw.
        let module = &*(data as *const M);
        match module.check_add_alias(&ctx, client_ref, alias_ref, target_ref) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `kadm5_auth_vtable_st` for module type `M`.
///
/// Called by the `initvt_plugin!` macro; the returned struct is written into
/// the caller-supplied vtable pointer after version negotiation succeeds.
/// All function pointers are monomorphised for `M` at compile time.
///
/// The `name` field is set from `M::NAME`.  The pointer is cast to
/// `*const c_char` and stored directly in the vtable.  libkadm5srv reads
/// this field for logging only and never frees it.  Since `M::NAME` is a
/// `'static CStr`, the pointer is valid for the entire process lifetime.
pub fn make_kadm5_auth_vtable<M: Kadm5AuthModule>()
-> kurbu5_kadm5_sys::kadm5_auth_vtable_st {
    kurbu5_kadm5_sys::kadm5_auth_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        init: Some(bridge_init::<M>),
        fini: Some(bridge_fini::<M>),
        addprinc: Some(bridge_addprinc::<M>),
        modprinc: Some(bridge_modprinc::<M>),
        setstr: Some(bridge_setstr::<M>),
        cpw: Some(bridge_cpw::<M>),
        chrand: Some(bridge_chrand::<M>),
        setkey: Some(bridge_setkey::<M>),
        purgekeys: Some(bridge_purgekeys::<M>),
        delprinc: Some(bridge_delprinc::<M>),
        renprinc: Some(bridge_renprinc::<M>),
        getprinc: Some(bridge_getprinc::<M>),
        getstrs: Some(bridge_getstrs::<M>),
        extract: Some(bridge_extract::<M>),
        listprincs: Some(bridge_listprincs::<M>),
        addpol: Some(bridge_addpol::<M>),
        modpol: Some(bridge_modpol::<M>),
        delpol: Some(bridge_delpol::<M>),
        getpol: Some(bridge_getpol::<M>),
        listpols: Some(bridge_listpols::<M>),
        iprop: Some(bridge_iprop::<M>),
        end: Some(bridge_end::<M>),
        free_restrictions: Some(bridge_free_restrictions::<M>),
        addalias: Some(bridge_addalias::<M>),
    }
}

// ---------------------------------------------------------------------------
// Unit tests (task 10.11)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Kadm5AuthModule;
    use crate::context::PluginContext;
    use crate::error::Krb5Error;

    /// Minimal module that authorizes everything — no state needed.
    struct AllowAll;

    impl Kadm5AuthModule for AllowAll {
        const NAME: &'static std::ffi::CStr = c"allow_all";

        fn init_module(
            _ctx: &PluginContext<'_>,
            _acl_file: Option<&str>,
        ) -> Result<Self, Krb5Error> {
            Ok(AllowAll)
        }
    }

    /// A module that explicitly denies delete-principal for all callers.
    struct DenyDelete;

    impl Kadm5AuthModule for DenyDelete {
        const NAME: &'static std::ffi::CStr = c"deny_delete";

        fn init_module(
            _ctx: &PluginContext<'_>,
            _acl_file: Option<&str>,
        ) -> Result<Self, Krb5Error> {
            Ok(DenyDelete)
        }

        fn check_delete_principal(
            &self,
            _ctx: &PluginContext<'_>,
            _client: &kurbu5_kadm5_sys::krb5_principal_data,
            _target: &kurbu5_kadm5_sys::krb5_principal_data,
        ) -> Result<(), Krb5Error> {
            Err(Krb5Error::Custom(libc::EPERM))
        }
    }

    fn make_test_context() -> kurbu5_kadm5_sys::krb5_context {
        let mut ctx: kurbu5_kadm5_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: krb5_init_context writes a valid pointer into ctx on success.
        let code = unsafe { kurbu5_kadm5_sys::krb5_init_context(&mut ctx) };
        assert_eq!(code, 0, "krb5_init_context failed with code {code}");
        ctx
    }

    unsafe fn free_test_context(ctx: kurbu5_kadm5_sys::krb5_context) {
        // SAFETY: ctx was created by krb5_init_context and is exclusively owned.
        kurbu5_kadm5_sys::krb5_free_context(ctx);
    }

    /// Verify `make_kadm5_auth_vtable` populates all mandatory slots.
    #[test]
    fn vtable_slots_populated() {
        let vt = make_kadm5_auth_vtable::<AllowAll>();
        assert!(vt.init.is_some(), "init slot must be populated");
        assert!(vt.fini.is_some(), "fini slot must be populated");
        assert!(vt.addprinc.is_some(), "addprinc slot must be populated");
        assert!(vt.delprinc.is_some(), "delprinc slot must be populated");
        assert!(vt.end.is_some(), "end slot must be populated");
        assert!(
            vt.free_restrictions.is_some(),
            "free_restrictions slot must be populated"
        );
        assert!(vt.addalias.is_some(), "addalias slot must be populated");
    }

    /// Verify the `name` pointer resolves to the expected string.
    #[test]
    fn vtable_name_matches_const() {
        let vt = make_kadm5_auth_vtable::<AllowAll>();
        assert!(!vt.name.is_null(), "name must be non-null");
        // SAFETY: vt.name was set from AllowAll::NAME.as_ptr() — a valid
        // null-terminated *const c_char valid for 'static.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, AllowAll::NAME);
    }

    /// Full init → check_delete_principal → fini round-trip for AllowAll.
    #[test]
    fn glue_round_trip_allow_all() {
        let ctx_ptr = make_test_context();
        let mut fake_princ = kurbu5_kadm5_sys::krb5_principal_data::default();

        // --- init ---
        let mut moddata: kurbu5_kadm5_sys::kadm5_auth_moddata =
            std::ptr::null_mut();
        let init_code = unsafe {
            // SAFETY: ctx_ptr is a valid context; acl_file=null is accepted;
            // &mut moddata is a valid stack out-pointer.
            bridge_init::<AllowAll>(ctx_ptr, std::ptr::null(), &mut moddata)
        };
        assert_eq!(init_code, 0, "init should succeed");
        assert!(!moddata.is_null(), "moddata must be set after init");

        // --- check_delete_principal (default Ok(())) ---
        let del_code = unsafe {
            // SAFETY: ctx_ptr and moddata are valid; fake_princ is a valid
            // zeroed krb5_principal_data on the stack — AllowAll never reads
            // any fields.
            bridge_delprinc::<AllowAll>(
                ctx_ptr,
                moddata,
                &mut fake_princ,
                &mut fake_princ,
            )
        };
        assert_eq!(del_code, 0, "AllowAll should authorize delete");

        // --- fini ---
        unsafe {
            // SAFETY: moddata was set by bridge_init; not accessed after this.
            bridge_fini::<AllowAll>(ctx_ptr, moddata);
            free_test_context(ctx_ptr);
        }
    }

    /// Full init → check_delete_principal → fini round-trip for DenyDelete.
    #[test]
    fn glue_round_trip_deny_delete() {
        let ctx_ptr = make_test_context();
        let mut fake_princ = kurbu5_kadm5_sys::krb5_principal_data::default();

        // --- init ---
        let mut moddata: kurbu5_kadm5_sys::kadm5_auth_moddata =
            std::ptr::null_mut();
        let init_code = unsafe {
            // SAFETY: ctx_ptr is valid; acl_file=null is accepted.
            bridge_init::<DenyDelete>(ctx_ptr, std::ptr::null(), &mut moddata)
        };
        assert_eq!(init_code, 0, "init should succeed");

        // --- check_delete_principal → must be denied ---
        let del_code = unsafe {
            // SAFETY: ctx_ptr and moddata are valid.
            bridge_delprinc::<DenyDelete>(
                ctx_ptr,
                moddata,
                &mut fake_princ,
                &mut fake_princ,
            )
        };
        assert_eq!(
            del_code,
            Krb5Error::Custom(libc::EPERM).into_error_code(),
            "DenyDelete should deny with EPERM"
        );

        // --- fini ---
        unsafe {
            // SAFETY: moddata was set by bridge_init.
            bridge_fini::<DenyDelete>(ctx_ptr, moddata);
            free_test_context(ctx_ptr);
        }
    }

    /// Verify that `bridge_fini` with a null `data` pointer is a safe no-op.
    #[test]
    fn fini_null_data_is_noop() {
        let ctx_ptr = make_test_context();
        unsafe {
            // SAFETY: null data is guarded by bridge_fini before any
            // dereference.  ctx_ptr is a valid context.
            bridge_fini::<AllowAll>(ctx_ptr, std::ptr::null_mut());
            free_test_context(ctx_ptr);
        }
    }

    /// Verify error-code round-trip through the deny_delete bridge.
    #[test]
    fn check_error_code_round_trip() {
        let ctx_ptr = make_test_context();
        let mut fake_princ = kurbu5_kadm5_sys::krb5_principal_data::default();
        let mut moddata: kurbu5_kadm5_sys::kadm5_auth_moddata =
            std::ptr::null_mut();

        unsafe {
            // SAFETY: ctx_ptr is valid; acl_file=null is accepted.
            bridge_init::<DenyDelete>(ctx_ptr, std::ptr::null(), &mut moddata);
        }

        let code = unsafe {
            // SAFETY: ctx_ptr and moddata are valid.
            bridge_delprinc::<DenyDelete>(
                ctx_ptr,
                moddata,
                &mut fake_princ,
                &mut fake_princ,
            )
        };
        assert_eq!(code, libc::EPERM, "EPERM should be the raw error code");

        unsafe {
            // SAFETY: moddata was set by bridge_init.
            bridge_fini::<DenyDelete>(ctx_ptr, moddata);
            free_test_context(ctx_ptr);
        }
    }
}
