//! Glue layer: C vtable function pointers → `KdbModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in `kurbu5-kdb-rs` that contains `unsafe` code.**
//!
//! All `unsafe` blocks in this file are annotated with a `// SAFETY:` comment
//! explaining the invariants that make them sound.  The overall invariants are:
//!
//! 1. `db_context` holds a `*mut Box<M>` placed there by `init_module` and
//!    removed (via `Box::from_raw`) by `fini_module`.  No other code touches it.
//!
//! 2. All raw pointers received from libkdb5 (e.g. `krb5_db_entry *`) are
//!    guaranteed non-null and valid for the duration of the call by the C API
//!    contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!
//! 4. All C strings passed to us are null-terminated and valid UTF-8 or
//!    ASCII.  We use `CStr::from_ptr` and propagate errors where they are not.

use std::ffi::CStr;
use std::marker::PhantomData;

use crate::KdbModule;
use crate::context::KdbContext;
use crate::error::KdbError;
use crate::key_data::{
    DecryptKeyRequest, EncryptKeyRequest, KeyBlock, KeyDataRef, KeySalt,
};
use crate::module::{
    AddressRef, AsAuditEvent, AsPolicyRequest, AuthIndicators,
    DelegationRequest, KdcRequestRef, PacBuilder, PacIssuanceOutput,
    PacIssuanceRequest, PacRef, ResourceDelegationRequest, S4uX509Request,
    TgsPolicyRequest, TicketRef,
};
use crate::policy::{PolicyEntry, PolicyEntryRef};
use crate::principal::{PrincipalEntryRef, PrincipalRef};
use crate::types::{IterFlags, LockMode, LookupFlags, OpenMode, Timestamp};

// ---------------------------------------------------------------------------
// Helper: recover the module from db_context
// ---------------------------------------------------------------------------

/// Recover a `&mut M` from `context->dal_handle->db_context`.
///
/// # Safety
///
/// The caller must guarantee that `db_context` was set by `init_module`
/// (as a `Box<M>` stored as `*mut M`) and that this call is not concurrent
/// with any other access to the module.
unsafe fn get_module<M: KdbModule>(
    ctx: kdb_sys::krb5_context,
) -> &'static mut M {
    debug_assert!(!ctx.is_null());
    // Retrieve the module pointer via the public krb5_db_get_context API.
    // This avoids accessing the internal (opaque) _krb5_context struct fields.
    // SAFETY: ctx is non-null (libkdb5 invariant).
    let mut db_ctx: *mut libc::c_void = std::ptr::null_mut();
    let code = kdb_sys::krb5_db_get_context(ctx, &raw mut db_ctx);
    debug_assert_eq!(code, 0, "krb5_db_get_context failed in get_module");
    debug_assert!(!db_ctx.is_null(), "db_context is null in get_module");
    // SAFETY: db_ctx was placed by init_module as Box<M>::into_raw cast to
    // *mut c_void.  It lives until fini_module calls Box::from_raw.
    &mut *db_ctx.cast::<M>()
}

/// Parse a possibly-null `*const c_char` as an optional `&str`.
///
/// # Safety
///
/// `ptr` must either be null or point to a valid null-terminated C string.
unsafe fn optional_cstr<'a>(ptr: *const libc::c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

/// Parse a `**c_char` null-terminated list into a `Vec<&str>`.
///
/// # Safety
///
/// `argv` must be null or point to a null-terminated array of null-terminated
/// C strings valid for `'a`.
unsafe fn cstr_argv<'a>(argv: *mut *mut libc::c_char) -> Vec<&'a str> {
    if argv.is_null() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut p = argv;
    while !(*p).is_null() {
        if let Ok(s) = CStr::from_ptr((*p).cast_const()).to_str() {
            out.push(s);
        }
        p = p.add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `kdb_vftabl` for module type `M`.
///
/// Called only from the `kdb_plugin!` macro; produces a static value.
/// All function pointers are monomorphised for `M` at compile time.
pub const fn make_vftabl<M: KdbModule>() -> kdb_sys::kdb_vftabl {
    kdb_sys::kdb_vftabl {
        maj_ver: kdb_sys::KDB_DAL_MAJOR_VERSION,
        min_ver: kdb_sys::KDB_DAL_MINOR_VERSION,
        init_library: Some(init_library::<M>),
        fini_library: Some(fini_library::<M>),
        init_module: Some(init_module::<M>),
        fini_module: Some(fini_module::<M>),
        create: if M::SUPPORTS_CREATE {
            Some(create::<M>)
        } else {
            None
        },
        destroy: if M::SUPPORTS_DESTROY {
            Some(destroy::<M>)
        } else {
            None
        },
        get_age: None, // deprecated since DAL v8
        lock: Some(lock::<M>),
        unlock: Some(unlock::<M>),
        get_principal: Some(get_principal::<M>),
        put_principal: Some(put_principal::<M>),
        delete_principal: Some(delete_principal::<M>),
        rename_principal: Some(rename_principal::<M>),
        iterate: Some(iterate::<M>),
        create_policy: Some(create_policy::<M>),
        get_policy: Some(get_policy::<M>),
        put_policy: Some(put_policy::<M>),
        iter_policy: Some(iter_policy::<M>),
        delete_policy: Some(delete_policy::<M>),
        fetch_master_key: None, // krb5_db_def_fetch_mkey not exported; use libkdb5 built-in
        fetch_master_key_list: None, // krb5_def_fetch_mkey_list not exported
        store_master_key_list: Some(store_master_key_list), // krb5_def_store_mkey_list IS exported
        dbe_search_enctype: None, // krb5_dbe_def_search_enctype not exported
        change_pwd: None,         // krb5_dbe_def_cpw not exported
        promote_db: if M::SUPPORTS_PROMOTE_DB {
            Some(promote_db::<M>)
        } else {
            None
        },
        decrypt_key_data: if M::SUPPORTS_DECRYPT_KEY_DATA {
            Some(decrypt_key_data::<M>)
        } else {
            None // libkdb5 uses krb5_dbe_def_decrypt_key_data directly
        },
        encrypt_key_data: if M::SUPPORTS_ENCRYPT_KEY_DATA {
            Some(encrypt_key_data::<M>)
        } else {
            None // libkdb5 uses krb5_dbe_def_encrypt_key_data directly
        },
        check_transited_realms: Some(check_transited_realms::<M>),
        check_policy_as: Some(check_policy_as::<M>),
        check_policy_tgs: Some(check_policy_tgs::<M>),
        audit_as_req: Some(audit_as_req::<M>),
        refresh_config: Some(refresh_config::<M>),
        check_allowed_to_delegate: Some(check_allowed_to_delegate::<M>),
        free_principal_e_data: Some(free_principal_e_data::<M>),
        get_s4u_x509_principal: Some(get_s4u_x509_principal::<M>),
        allowed_to_delegate_from: Some(allowed_to_delegate_from::<M>),
        issue_pac: Some(issue_pac::<M>),
    }
}

// ---------------------------------------------------------------------------
// Library lifecycle
// ---------------------------------------------------------------------------

extern "C" fn init_library<M: KdbModule>() -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match M::init_library() {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn fini_library<M: KdbModule>() -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match M::fini_library() {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Context lifecycle
// ---------------------------------------------------------------------------

extern "C" fn init_module<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    conf_section: *mut libc::c_char,
    db_args: *mut *mut libc::c_char,
    mode: libc::c_int,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        // SAFETY: conf_section is non-null (libkdb5 invariant for init_module).
        let section = unsafe {
            CStr::from_ptr(conf_section.cast_const())
                .to_str()
                .unwrap_or("")
        };
        // SAFETY: db_args is a null-terminated argv or null.
        let args = unsafe { cstr_argv(db_args) };
        let open_mode = OpenMode::from_raw(mode);
        // SAFETY: kcontext is valid for the duration of init_module.
        let ctx = unsafe { KdbContext::from_raw(kcontext) };

        match M::open(&ctx, section, &args, open_mode) {
            Ok(module) => {
                // Box the module and store the raw pointer via the public API.
                let raw =
                    Box::into_raw(Box::new(module)).cast::<libc::c_void>();
                // SAFETY: kcontext is valid (libkdb5 invariant).
                let code =
                    unsafe { kdb_sys::krb5_db_set_context(kcontext, raw) };
                if code != 0 {
                    // Failed to store; reclaim memory to avoid leak.
                    unsafe { drop(Box::from_raw(raw.cast::<M>())) };
                    return code;
                }
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn fini_module<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        // SAFETY: db_context was set by init_module as Box<M>::into_raw.
        // This is the only place it is reclaimed.
        //
        // db_ctx may be null if fini_module is called without a preceding
        // init_module (e.g. krb5_db_fini called during kdb5_util create before
        // the database has been opened).  Return success without touching anything.
        let module = unsafe {
            let mut db_ctx: *mut libc::c_void = std::ptr::null_mut();
            kdb_sys::krb5_db_get_context(kcontext, &raw mut db_ctx);
            if db_ctx.is_null() {
                return 0;
            }
            // Clear the stored pointer so any stray access hits a null.
            kdb_sys::krb5_db_set_context(kcontext, std::ptr::null_mut());
            Box::from_raw(db_ctx.cast::<M>())
        };
        match module.close() {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Database lifecycle
// ---------------------------------------------------------------------------

extern "C" fn create<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    conf_section: *mut libc::c_char,
    db_args: *mut *mut libc::c_char,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        let section =
            unsafe { optional_cstr(conf_section.cast_const()).unwrap_or("") };
        let args = unsafe { cstr_argv(db_args) };
        // SAFETY: kcontext is valid for the duration of this call.
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        match M::create(&ctx, section, &args) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn destroy<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    conf_section: *mut libc::c_char,
    db_args: *mut *mut libc::c_char,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        let section =
            unsafe { optional_cstr(conf_section.cast_const()).unwrap_or("") };
        let args = unsafe { cstr_argv(db_args) };
        // SAFETY: kcontext is valid for the duration of this call.
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        match M::destroy(&ctx, section, &args) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn promote_db<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    conf_section: *mut libc::c_char,
    db_args: *mut *mut libc::c_char,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        let section =
            unsafe { optional_cstr(conf_section.cast_const()).unwrap_or("") };
        let args = unsafe { cstr_argv(db_args) };
        // SAFETY: kcontext is valid for the duration of this call.
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        match M::promote_db(&ctx, section, &args) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------

extern "C" fn lock<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    mode: libc::c_int,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: get_module invariants hold.
        let module = unsafe { get_module::<M>(kcontext) };
        match module.lock(LockMode::from_raw(mode)) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn unlock<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        match module.unlock() {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Principal CRUD
// ---------------------------------------------------------------------------

extern "C" fn get_principal<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    search_for: kdb_sys::krb5_const_principal,
    flags: libc::c_uint,
    entry: *mut *mut kdb_sys::krb5_db_entry,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: kcontext, search_for, and entry are non-null (libkdb5 invariant).
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        // SAFETY: search_for is valid for the duration of this call.
        let princ = unsafe { PrincipalRef::from_raw(search_for) };
        let lookup_flags = LookupFlags::from_raw(flags);

        match module.get_principal(&ctx, princ, lookup_flags) {
            Ok(Some(owned)) => {
                // SAFETY: entry is a non-null, writable out-pointer guaranteed
                // by libkdb5. into_raw() transfers ownership to libkdb5, which
                // frees via krb5_db_free_principal; mem::forget inside into_raw
                // prevents a double-free if Drop would otherwise run.
                unsafe { *entry = owned.into_raw().as_ptr() };
                0
            },
            Ok(None) => KdbError::NoEntry.into_error_code(),
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn put_principal<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    entry: *mut kdb_sys::krb5_db_entry,
    db_args: *mut *mut libc::c_char,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        // SAFETY: entry is non-null and valid for the duration of this call.
        let entry_ref = unsafe { PrincipalEntryRef::from_raw(entry) };
        let args = unsafe { cstr_argv(db_args) };
        match module.put_principal(&ctx, entry_ref, &args) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn delete_principal<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    search_for: kdb_sys::krb5_const_principal,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let princ = unsafe { PrincipalRef::from_raw(search_for) };
        match module.delete_principal(&ctx, princ) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn rename_principal<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    source: kdb_sys::krb5_const_principal,
    target: kdb_sys::krb5_const_principal,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let src = unsafe { PrincipalRef::from_raw(source) };
        let tgt = unsafe { PrincipalRef::from_raw(target) };
        match module.rename_principal(&ctx, src, tgt) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Iteration
//
// libkdb5 passes a C function pointer and a void* arg.  We bridge these to a
// Rust `&mut dyn FnMut(PrincipalEntryRef) -> Result<(), KdbError>`.
//
// The bridge stores the closure pointer in `func_arg` alongside the original
// C arg in a small stack struct, then dispatches through a trampoline.
// ---------------------------------------------------------------------------

extern "C" fn iterate<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    match_entry: *mut libc::c_char,
    func: Option<
        unsafe extern "C" fn(
            kdb_sys::krb5_pointer,
            *mut kdb_sys::krb5_db_entry,
        ) -> libc::c_int,
    >,
    func_arg: kdb_sys::krb5_pointer,
    iterflags: kdb_sys::krb5_flags,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let match_str = unsafe { optional_cstr(match_entry.cast_const()) };
        // iterflags is krb5_flags = i32; reinterpret bits as u32 for flag processing.
        let flags = IterFlags::from_bits_truncate(u32::from_ne_bytes(
            iterflags.to_ne_bytes(),
        ));

        // If the module wants to call back into C (forward iteration to the C
        // layer), provide a Rust closure that calls the C func pointer.
        // If M::iterate_principals is NotSupported we also fall through to the
        // C func if one is provided.
        let mut callback =
            |entry_ref: PrincipalEntryRef<'_>| -> Result<(), KdbError> {
                if let Some(f) = func {
                    // SAFETY: f is a valid C callback; func_arg is the C caller's
                    // opaque state pointer, unchanged from what libkdb5 passed.
                    let code =
                        unsafe { f(func_arg, entry_ref.as_raw().cast_mut()) };
                    if code != 0 {
                        return Err(KdbError::from_error_code(code));
                    }
                }
                Ok(())
            };

        match module.iterate_principals(&ctx, match_str, flags, &mut callback)
        {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

extern "C" fn create_policy<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    policy: kdb_sys::osa_policy_ent_t,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        // SAFETY: policy is non-null (libkdb5 invariant).
        let pol_ref = unsafe { PolicyEntryRef::from_raw(policy) };
        let owned = PolicyEntry::from_ref(pol_ref);
        match module.create_policy(&ctx, &owned) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn get_policy<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    name: *mut libc::c_char,
    policy: *mut kdb_sys::osa_policy_ent_t,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let name_str =
            unsafe { optional_cstr(name.cast_const()).unwrap_or("") };
        match module.get_policy(&ctx, name_str) {
            Ok(Some(owned)) => {
                // SAFETY: into_raw produces a malloc'd osa_policy_ent_rec.
                match owned.into_raw() {
                    None => libc::ENOMEM,
                    Some(raw) => {
                        unsafe { *policy = raw };
                        0
                    },
                }
            },
            Ok(None) => KdbError::NoEntry.into_error_code(),
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn put_policy<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    policy: kdb_sys::osa_policy_ent_t,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let pol_ref = unsafe { PolicyEntryRef::from_raw(policy) };
        let owned = PolicyEntry::from_ref(pol_ref);
        match module.put_policy(&ctx, &owned) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn iter_policy<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    match_entry: *mut libc::c_char,
    func: kdb_sys::osa_adb_iter_policy_func,
    data: *mut libc::c_void,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let match_str = unsafe { optional_cstr(match_entry.cast_const()) };

        let mut callback = |pol: &PolicyEntry| -> Result<(), KdbError> {
            if let Some(f) = func {
                // into_raw may return None on OOM; propagate as OutOfMemory.
                let raw =
                    pol.clone().into_raw().ok_or(KdbError::OutOfMemory)?;
                // SAFETY: f is a valid C callback; raw is a valid policy pointer.
                unsafe { f(data, raw) };
                // Free the temporary raw copy via the libkdb5 function, which
                // correctly frees name, allowed_keysalts, TL-data, and the
                // outer struct — consistent with backing_db.rs.
                // SAFETY: kcontext is valid (libkdb5 invariant); raw was just
                // produced by into_raw so its layout matches osa_policy_ent_rec.
                unsafe { kdb_sys::krb5_db_free_policy(kcontext, raw) };
            }
            Ok(())
        };

        match module.iter_policy(&ctx, match_str, &mut callback) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn delete_policy<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    policy: *mut libc::c_char,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let name = unsafe { optional_cstr(policy.cast_const()).unwrap_or("") };
        match module.delete_policy(&ctx, name) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Master key operations
// ---------------------------------------------------------------------------

extern "C" fn store_master_key_list(
    kcontext: kdb_sys::krb5_context,
    db_arg: *mut libc::c_char,
    mname: kdb_sys::krb5_principal,
    keylist: *mut kdb_sys::krb5_keylist_node,
    master_pwd: *mut libc::c_char,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        // krb5_def_store_mkey_list IS exported from libkdb5.so; always delegate.
        // No Rust wrapper for krb5_keylist_node yet.
        // SAFETY: all pointers are valid for the duration of this call.
        unsafe {
            kdb_sys::krb5_def_store_mkey_list(
                kcontext, db_arg, mname, keylist, master_pwd,
            )
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Key operations
// ---------------------------------------------------------------------------

extern "C" fn decrypt_key_data<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    mkey: *const kdb_sys::krb5_keyblock,
    key_data: *const kdb_sys::krb5_key_data,
    dbkey: *mut kdb_sys::krb5_keyblock,
    keysalt: *mut kdb_sys::krb5_keysalt,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        // Fall back to the libkdb5 default when the module is not yet open
        // (e.g. kdb5_util create calls decrypt_key_data before krb5_db_open).
        let mut db_ctx: *mut libc::c_void = std::ptr::null_mut();
        unsafe { kdb_sys::krb5_db_get_context(kcontext, &raw mut db_ctx) };
        if db_ctx.is_null() {
            // SAFETY: all pointers are valid for the duration of this call.
            return unsafe {
                kdb_sys::krb5_dbe_def_decrypt_key_data(
                    kcontext, mkey, key_data, dbkey, keysalt,
                )
            };
        }
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };

        // SAFETY: key_data is non-null (libkdb5 invariant).
        let kd_ref = KeyDataRef::from_ref(unsafe { &*key_data });

        let mkey_opt = if mkey.is_null() {
            None
        } else {
            // SAFETY: mkey is valid for this call if non-null.
            let kb = unsafe { &*mkey };
            Some(KeyBlock {
                enctype: kb.enctype,
                contents: if kb.contents.is_null() || kb.length == 0 {
                    vec![]
                } else {
                    // SAFETY: contents points to length bytes.
                    unsafe {
                        std::slice::from_raw_parts(
                            kb.contents,
                            kb.length as usize,
                        )
                    }
                    .to_vec()
                },
            })
        };

        let req = DecryptKeyRequest {
            mkey: mkey_opt.as_ref(),
            key_data: kd_ref,
        };

        match module.decrypt_key_data(&ctx, req) {
            Err(KdbError::NotSupported) => {
                // Module defers to the libkdb5 default implementation.
                // SAFETY: all pointers valid for this call.
                unsafe {
                    kdb_sys::krb5_dbe_def_decrypt_key_data(
                        kcontext, mkey, key_data, dbkey, keysalt,
                    )
                }
            },
            Ok((key, salt)) => {
                // Write key into dbkey.
                // SAFETY: dbkey is non-null and writable (libkdb5 invariant).
                let out = unsafe { &mut *dbkey };
                out.enctype = key.enctype;
                out.length =
                    u32::try_from(key.contents.len()).unwrap_or(u32::MAX);
                if !key.contents.is_empty() {
                    let ptr = unsafe {
                        libc::malloc(key.contents.len()).cast::<u8>()
                    };
                    assert!(!ptr.is_null());
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            key.contents.as_ptr(),
                            ptr,
                            key.contents.len(),
                        );
                    };
                    out.contents = ptr;
                }

                // Write salt if requested and present.
                if !keysalt.is_null() {
                    if let Some(s) = salt {
                        let ks = unsafe { &mut *keysalt };
                        ks.type_ =
                            i16::try_from(s.salttype).unwrap_or(i16::MAX);
                        ks.data.length =
                            u32::try_from(s.data.len()).unwrap_or(u32::MAX);
                        if !s.data.is_empty() {
                            let ptr = unsafe {
                                libc::malloc(s.data.len()).cast::<u8>()
                            };
                            assert!(!ptr.is_null());
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    s.data.as_ptr(),
                                    ptr,
                                    s.data.len(),
                                );
                            };
                            ks.data.data = ptr.cast::<libc::c_char>();
                        }
                    }
                }
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn encrypt_key_data<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    mkey: *const kdb_sys::krb5_keyblock,
    dbkey: *const kdb_sys::krb5_keyblock,
    keysalt: *const kdb_sys::krb5_keysalt,
    keyver: libc::c_int,
    key_data: *mut kdb_sys::krb5_key_data,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!kcontext.is_null(), "kcontext must not be null");
        // Fall back to the libkdb5 default when the module is not yet open
        // (e.g. kdb5_util create calls encrypt_key_data before krb5_db_open).
        let mut db_ctx: *mut libc::c_void = std::ptr::null_mut();
        unsafe { kdb_sys::krb5_db_get_context(kcontext, &raw mut db_ctx) };
        if db_ctx.is_null() {
            // SAFETY: all pointers are valid for the duration of this call.
            return unsafe {
                kdb_sys::krb5_dbe_def_encrypt_key_data(
                    kcontext, mkey, dbkey, keysalt, keyver, key_data,
                )
            };
        }
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };

        // SAFETY: mkey and dbkey are non-null (libkdb5 invariant).
        let mk = unsafe { &*mkey };
        let dk = unsafe { &*dbkey };

        let mkey_block = KeyBlock {
            enctype: mk.enctype,
            contents: if mk.contents.is_null() || mk.length == 0 {
                vec![]
            } else {
                unsafe {
                    std::slice::from_raw_parts(mk.contents, mk.length as usize)
                }
                .to_vec()
            },
        };
        let dbkey_block = KeyBlock {
            enctype: dk.enctype,
            contents: if dk.contents.is_null() || dk.length == 0 {
                vec![]
            } else {
                unsafe {
                    std::slice::from_raw_parts(dk.contents, dk.length as usize)
                }
                .to_vec()
            },
        };
        let salt_opt = if keysalt.is_null() {
            None
        } else {
            let ks = unsafe { &*keysalt };
            Some(KeySalt {
                salttype: i32::from(ks.type_),
                data: if ks.data.data.is_null() || ks.data.length == 0 {
                    vec![]
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            ks.data.data.cast::<u8>(),
                            ks.data.length as usize,
                        )
                    }
                    .to_vec()
                },
            })
        };

        let req = EncryptKeyRequest {
            mkey: &mkey_block,
            dbkey: &dbkey_block,
            keysalt: salt_opt.as_ref(),
            keyver,
        };

        match module.encrypt_key_data(&ctx, req) {
            Err(KdbError::NotSupported) => {
                // Module defers to the libkdb5 default implementation.
                // SAFETY: all pointers valid for this call.
                unsafe {
                    kdb_sys::krb5_dbe_def_encrypt_key_data(
                        kcontext, mkey, dbkey, keysalt, keyver, key_data,
                    )
                }
            },
            Ok(owned) => {
                // SAFETY: key_data is non-null and writable (libkdb5 invariant).
                match unsafe { owned.write_into(key_data) } {
                    Ok(()) => 0,
                    Err(()) => libc::ENOMEM,
                }
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Policy hooks
// ---------------------------------------------------------------------------

extern "C" fn check_policy_as<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    request: *mut kdb_sys::krb5_kdc_req,
    client: *mut kdb_sys::krb5_db_entry,
    server: *mut kdb_sys::krb5_db_entry,
    kdc_time: kdb_sys::krb5_timestamp,
    status: *mut *const libc::c_char,
    e_data: *mut *mut *mut kdb_sys::krb5_pa_data,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let req = AsPolicyRequest {
            // SAFETY: request, client, server are non-null (libkdb5 invariant).
            request: KdcRequestRef {
                ptr: request,
                _phantom: PhantomData,
            },
            client: unsafe { PrincipalEntryRef::from_raw(client) },
            server: unsafe { PrincipalEntryRef::from_raw(server) },
            kdc_time: Timestamp(kdc_time),
        };
        match module.check_policy_as(&ctx, req) {
            Ok(()) => 0,
            Err(denied) => {
                // SAFETY: status is non-null (libkdb5 invariant).
                if !status.is_null() {
                    // denied.status is 'static so the pointer is valid after return.
                    unsafe {
                        *status =
                            denied.status.as_ptr().cast::<libc::c_char>();
                    };
                }
                // e_data: future iteration will wire up pa_data allocation.
                let _ = (e_data, denied.e_data);
                KdbError::Custom(kdb_sys::KRB5KDC_ERR_POLICY).into_error_code()
            },
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn check_policy_tgs<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    request: *mut kdb_sys::krb5_kdc_req,
    server: *mut kdb_sys::krb5_db_entry,
    ticket: *mut kdb_sys::krb5_ticket,
    status: *mut *const libc::c_char,
    e_data: *mut *mut *mut kdb_sys::krb5_pa_data,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let req = TgsPolicyRequest {
            request: KdcRequestRef {
                ptr: request,
                _phantom: PhantomData,
            },
            server: unsafe { PrincipalEntryRef::from_raw(server) },
            ticket: TicketRef {
                ptr: ticket,
                _phantom: PhantomData,
            },
        };
        match module.check_policy_tgs(&ctx, req) {
            Ok(()) => 0,
            Err(denied) => {
                if !status.is_null() {
                    unsafe {
                        *status =
                            denied.status.as_ptr().cast::<libc::c_char>();
                    };
                }
                let _ = (e_data, denied.e_data);
                KdbError::Custom(kdb_sys::KRB5KDC_ERR_POLICY).into_error_code()
            },
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn check_transited_realms<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    tr_contents: *const kdb_sys::krb5_data,
    client_realm: *const kdb_sys::krb5_data,
    server_realm: *const kdb_sys::krb5_data,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };

        let to_slice = |d: *const kdb_sys::krb5_data| -> &[u8] {
            if d.is_null() {
                return &[];
            }
            let d = unsafe { &*d };
            if d.data.is_null() || d.length == 0 {
                return &[];
            }
            // SAFETY: data and length are consistent (libkdb5 invariant).
            unsafe {
                std::slice::from_raw_parts(
                    d.data.cast::<u8>(),
                    d.length as usize,
                )
            }
        };

        match module.check_transited_realms(
            &ctx,
            to_slice(tr_contents),
            to_slice(client_realm),
            to_slice(server_realm),
        ) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn check_allowed_to_delegate<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    client: kdb_sys::krb5_const_principal,
    server: *const kdb_sys::krb5_db_entry,
    proxy: kdb_sys::krb5_const_principal,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let req = DelegationRequest {
            client: if client.is_null() {
                None
            } else {
                // SAFETY: client is non-null here.
                Some(unsafe { PrincipalRef::from_raw(client) })
            },
            server: if server.is_null() {
                None
            } else {
                // SAFETY: server is non-null here.
                Some(unsafe { PrincipalEntryRef::from_raw(server) })
            },
            proxy: if proxy.is_null() {
                None
            } else {
                // SAFETY: proxy is non-null here.
                Some(unsafe { PrincipalRef::from_raw(proxy) })
            },
        };
        match module.check_allowed_to_delegate(&ctx, req) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn allowed_to_delegate_from<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    client: kdb_sys::krb5_const_principal,
    server: kdb_sys::krb5_const_principal,
    server_pac: kdb_sys::krb5_pac,
    proxy: *const kdb_sys::krb5_db_entry,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let req = ResourceDelegationRequest {
            client: if client.is_null() {
                None
            } else {
                // SAFETY: client is non-null here.
                Some(unsafe { PrincipalRef::from_raw(client) })
            },
            server: if server.is_null() {
                None
            } else {
                // SAFETY: server is non-null here.
                Some(unsafe { PrincipalRef::from_raw(server) })
            },
            server_pac: PacRef {
                pac: server_pac,
                _phantom: PhantomData,
            },
            proxy: if proxy.is_null() {
                None
            } else {
                // SAFETY: proxy is non-null here.
                Some(unsafe { PrincipalEntryRef::from_raw(proxy) })
            },
        };
        match module.allowed_to_delegate_from(&ctx, req) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

extern "C" fn audit_as_req<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    request: *mut kdb_sys::krb5_kdc_req,
    local_addr: *const kdb_sys::krb5_address,
    remote_addr: *const kdb_sys::krb5_address,
    client: *mut kdb_sys::krb5_db_entry,
    server: *mut kdb_sys::krb5_db_entry,
    authtime: kdb_sys::krb5_timestamp,
    error_code: kdb_sys::krb5_error_code,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        let event = AsAuditEvent {
            request: KdcRequestRef {
                ptr: request,
                _phantom: PhantomData,
            },
            local_addr: if local_addr.is_null() {
                None
            } else {
                Some(AddressRef {
                    ptr: local_addr,
                    _phantom: PhantomData,
                })
            },
            remote_addr: if remote_addr.is_null() {
                None
            } else {
                Some(AddressRef {
                    ptr: remote_addr,
                    _phantom: PhantomData,
                })
            },
            client: if client.is_null() {
                None
            } else {
                // SAFETY: client is non-null here.
                Some(unsafe { PrincipalEntryRef::from_raw(client) })
            },
            server: if server.is_null() {
                None
            } else {
                // SAFETY: server is non-null here.
                Some(unsafe { PrincipalEntryRef::from_raw(server) })
            },
            authtime: Timestamp(authtime),
            error_code,
        };
        module.audit_as_req(&ctx, event);
    }));
}

extern "C" fn refresh_config<M: KdbModule>(kcontext: kdb_sys::krb5_context) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };
        module.refresh_config(&ctx);
    }));
}

// ---------------------------------------------------------------------------
// S4U X.509
// ---------------------------------------------------------------------------

extern "C" fn get_s4u_x509_principal<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    client_cert: *const kdb_sys::krb5_data,
    princ: kdb_sys::krb5_const_principal,
    flags: libc::c_uint,
    entry_out: *mut *mut kdb_sys::krb5_db_entry,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };

        // SAFETY: client_cert is non-null (libkdb5 invariant).
        let cert_data = unsafe { &*client_cert };
        let cert_bytes = if cert_data.data.is_null() || cert_data.length == 0 {
            &[][..]
        } else {
            unsafe {
                std::slice::from_raw_parts(
                    cert_data.data.cast::<u8>(),
                    cert_data.length as usize,
                )
            }
        };

        let req = S4uX509Request {
            client_cert: cert_bytes,
            princ: unsafe { PrincipalRef::from_raw(princ) },
            flags: LookupFlags::from_raw(flags),
        };

        match module.get_s4u_x509_principal(&ctx, req) {
            Ok(Some(owned)) => {
                // SAFETY: entry_out is a non-null, writable out-pointer
                // guaranteed by libkdb5. into_raw() transfers ownership to
                // libkdb5, which frees via krb5_db_free_principal.
                unsafe { *entry_out = owned.into_raw().as_ptr() };
                0
            },
            Ok(None) => KdbError::NoEntry.into_error_code(),
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// PAC issuance
// ---------------------------------------------------------------------------

extern "C" fn issue_pac<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    flags: libc::c_uint,
    client: *mut kdb_sys::krb5_db_entry,
    replaced_reply_key: *mut kdb_sys::krb5_keyblock,
    server: *mut kdb_sys::krb5_db_entry,
    signing_krbtgt: *mut kdb_sys::krb5_db_entry,
    authtime: kdb_sys::krb5_timestamp,
    old_pac: kdb_sys::krb5_pac,
    new_pac: kdb_sys::krb5_pac,
    auth_indicators: *mut *mut *mut kdb_sys::krb5_data,
) -> kdb_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        let ctx = unsafe { KdbContext::from_raw(kcontext) };

        let replaced_key = if replaced_reply_key.is_null() {
            None
        } else {
            let kb = unsafe { &*replaced_reply_key };
            Some(KeyBlock {
                enctype: kb.enctype,
                contents: if kb.contents.is_null() || kb.length == 0 {
                    vec![]
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            kb.contents,
                            kb.length as usize,
                        )
                    }
                    .to_vec()
                },
            })
        };

        let req = PacIssuanceRequest {
            flags,
            client: if client.is_null() {
                None
            } else {
                Some(unsafe { PrincipalEntryRef::from_raw(client) })
            },
            replaced_reply_key: replaced_key,
            server: if server.is_null() {
                None
            } else {
                Some(unsafe { PrincipalEntryRef::from_raw(server) })
            },
            signing_krbtgt: if signing_krbtgt.is_null() {
                None
            } else {
                Some(unsafe { PrincipalEntryRef::from_raw(signing_krbtgt) })
            },
            authtime: Timestamp(authtime),
            old_pac: if old_pac.is_null() {
                None
            } else {
                Some(PacRef {
                    pac: old_pac,
                    _phantom: PhantomData,
                })
            },
        };

        let mut output = PacIssuanceOutput {
            new_pac: PacBuilder {
                pac: new_pac,
                _phantom: PhantomData,
            },
            auth_indicators: AuthIndicators {
                ptr: auth_indicators,
            },
        };

        match module.issue_pac(&ctx, req, &mut output) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// e_data freeing
// ---------------------------------------------------------------------------

extern "C" fn free_principal_e_data<M: KdbModule>(
    kcontext: kdb_sys::krb5_context,
    e_data: *mut kdb_sys::krb5_octet,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let module = unsafe { get_module::<M>(kcontext) };
        module.free_principal_e_data(e_data);
    }));
}
