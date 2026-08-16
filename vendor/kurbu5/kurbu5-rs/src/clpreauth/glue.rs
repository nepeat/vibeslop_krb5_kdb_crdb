//! Glue layer: C vtable function pointers → `ClpreauthModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `clpreauth` module that contains `unsafe`
//! code.**
//!
//! All `unsafe` blocks in this file are annotated with a `// SAFETY:` comment.
//! The overall invariants this file relies on are:
//!
//! 1. `moddata` holds a `*mut M` placed by `clpreauth_init` and removed (via
//!    `Box::from_raw`) by `clpreauth_fini`.  No other code touches it.
//!
//! 2. All raw pointers received from libkrb5 (e.g. `krb5_context`,
//!    `krb5_clpreauth_callbacks`, `krb5_clpreauth_rock`) are guaranteed
//!    non-null and valid for the duration of the call by the C API contract.
//!    We `debug_assert!` this at each call site.
//!
//! 3. We never alias `&mut M` with any other reference to the same memory.
//!
//! 4. PA-DATA output arrays are allocated as `Box<[*mut krb5_pa_data]>` with
//!    a null sentinel, then released via `into_raw()`.  The corresponding C
//!    free function in the vtable is not present for clpreauth — libkrb5 frees
//!    the returned `krb5_pa_data **` with its own allocator.  Therefore we
//!    must allocate each `krb5_pa_data` element and its `contents` buffer
//!    with the C allocator (`libc::malloc`) so that libkrb5 can `free()` them.
//!
//! # Memory ownership for PA-DATA output
//!
//! `process` and `tryagain` must write a `krb5_pa_data **` out-parameter.
//! Ownership semantics per `src/lib/krb5/krb5/init_creds_ctx.h`:
//!
//! - The caller (libkrb5) frees the returned array and every element inside
//!   it using `krb5_free_pa_data`.
//! - `krb5_free_pa_data` calls `free()` on each `krb5_pa_data *` and on
//!   its `contents` field.
//! - Therefore we must use `libc::malloc`/`calloc` for these allocations.
//!
//! # Module data pointer
//!
//! The module data pointer flows through `krb5_clpreauth_moddata`, which is
//! an opaque pointer type (`*mut krb5_clpreauth_moddata_st`).  The glue layer
//! stores `Box<M>` as `*mut M` cast to `krb5_clpreauth_moddata`.
//!
//! Per-request data flows through `krb5_clpreauth_modreq` similarly; the
//! glue stores a unit value there since `ClpreauthModule` does not expose
//! per-request state (advanced users use `Arc<Mutex<T>>`).

use std::marker::PhantomData;

use kurbu5_sys as sys;

use crate::clpreauth::{
    ClpreauthCallbacks, ClpreauthModule, EtypeInfoRequest, PaData,
    ProcessRequest, Prompter, TryagainRequest,
};
use crate::context::PluginContext;

// ---------------------------------------------------------------------------
// Helper: recover the module from moddata
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helper: convert a raw krb5_data to an optional &[u8]
// ---------------------------------------------------------------------------

/// Convert a nullable `*mut krb5_data` to an `Option<&[u8]>`.
///
/// # Safety
///
/// `ptr` must be null or point to a valid `krb5_data` whose `data` field is
/// valid for `length` bytes for the lifetime of the returned slice.
unsafe fn optional_data<'a>(ptr: *mut sys::krb5_data) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    let d = &*ptr;
    if d.data.is_null() || d.length == 0 {
        Some(&[])
    } else {
        Some(std::slice::from_raw_parts(
            d.data as *const u8,
            d.length as usize,
        ))
    }
}

// ---------------------------------------------------------------------------
// Helper: allocate a krb5_pa_data with the C allocator
// ---------------------------------------------------------------------------

/// Allocate a `krb5_pa_data` struct in C memory for libkrb5 to free.
///
/// Both the struct and the `contents` buffer are allocated with `libc::malloc`
/// so that `krb5_free_pa_data` (which calls `free()`) can reclaim them.
///
/// Returns `None` on allocation failure.
///
/// # Safety
///
/// The returned pointer must be freed (transitively) by `krb5_free_pa_data`
/// or equivalent; do not use `Box::from_raw` on it.
unsafe fn alloc_c_pa_data(pa: &PaData) -> Option<*mut sys::krb5_pa_data> {
    // SAFETY: calloc with size > 0 is well-defined; returns null on OOM.
    let ptr = libc::calloc(1, std::mem::size_of::<sys::krb5_pa_data>())
        .cast::<sys::krb5_pa_data>();
    if ptr.is_null() {
        return None;
    }
    (*ptr).pa_type = pa.pa_type;
    if pa.contents.is_empty() {
        (*ptr).length = 0;
        (*ptr).contents = std::ptr::null_mut();
    } else {
        // SAFETY: malloc with size > 0 is well-defined.
        let contents = libc::malloc(pa.contents.len()).cast::<u8>();
        if contents.is_null() {
            libc::free(ptr.cast::<libc::c_void>());
            return None;
        }
        // SAFETY: contents points to at least pa.contents.len() bytes of
        // malloc'd memory; pa.contents is a valid Rust slice.
        std::ptr::copy_nonoverlapping(
            pa.contents.as_ptr(),
            contents,
            pa.contents.len(),
        );
        // SAFETY: pa.contents.len() is the exact byte count; krb5_pa_data.length
        // is u32 and padata in practice never exceeds a few KiB.
        #[allow(clippy::cast_possible_truncation)]
        let length = pa.contents.len() as libc::c_uint;
        (*ptr).length = length;
        (*ptr).contents = contents;
    }
    Some(ptr)
}

// ---------------------------------------------------------------------------
// Helper: convert Vec<PaData> to a C null-terminated krb5_pa_data ** array
// ---------------------------------------------------------------------------

/// Convert a `Vec<PaData>` into a C-allocated null-terminated `krb5_pa_data**`
/// array and write its address to `*pa_data_out`.
///
/// Ownership: both the array and each element are allocated with `libc::malloc`
/// (via `alloc_c_pa_data`).  Libkrb5 frees them with `krb5_free_pa_data`.
///
/// Returns `0` on success, `ENOMEM` on allocation failure.
///
/// # Safety
///
/// `pa_data_out` must be non-null.
unsafe fn write_pa_data_out(
    pa_list: &[PaData],
    pa_data_out: *mut *mut *mut sys::krb5_pa_data,
) -> sys::krb5_error_code {
    debug_assert!(!pa_data_out.is_null());

    if pa_list.is_empty() {
        // Write a null pointer to signal no output data.
        *pa_data_out = std::ptr::null_mut();
        return 0;
    }

    // Allocate array of n+1 pointers (n elements + null sentinel).
    let count = pa_list.len();
    // SAFETY: count+1 > 0 always.
    let arr =
        libc::calloc(count + 1, std::mem::size_of::<*mut sys::krb5_pa_data>())
            .cast::<*mut sys::krb5_pa_data>();
    if arr.is_null() {
        return libc::ENOMEM;
    }

    for (i, pa) in pa_list.iter().enumerate() {
        if let Some(ptr) = alloc_c_pa_data(pa) {
            *arr.add(i) = ptr;
        } else {
            // Free already-allocated elements then the array itself.
            for j in 0..i {
                let elem = *arr.add(j);
                if !(*elem).contents.is_null() {
                    libc::free((*elem).contents.cast::<libc::c_void>());
                }
                libc::free(elem.cast::<libc::c_void>());
            }
            libc::free(arr.cast::<libc::c_void>());
            return libc::ENOMEM;
        }
    }
    // Null sentinel is already zeroed by calloc.
    *pa_data_out = arr;
    0
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// `init` bridge: call `ClpreauthModule::init_module`, store `Box<M>` in
/// `*moddata_out`.
///
/// # Safety
///
/// `context` and `moddata_out` are non-null (libkrb5 contract).
pub(crate) extern "C" fn clpreauth_init<M: ClpreauthModule>(
    context: sys::krb5_context,
    moddata_out: *mut sys::krb5_clpreauth_moddata,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null());
        debug_assert!(!moddata_out.is_null());

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        match M::init_module(&ctx) {
            Ok(module) => {
                // SAFETY: Box::into_raw gives a valid non-null pointer.
                *moddata_out = Box::into_raw(Box::new(module))
                    as sys::krb5_clpreauth_moddata;
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `fini` bridge: recover `Box<M>` from `moddata` and drop it.
///
/// # Safety
///
/// `moddata` was stored by `clpreauth_init` as `Box<M>::into_raw()`.
pub(crate) extern "C" fn clpreauth_fini<M: ClpreauthModule>(
    _context: sys::krb5_context,
    moddata: sys::krb5_clpreauth_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            if moddata.is_null() {
                return;
            }
            // SAFETY: moddata was set by clpreauth_init via Box::into_raw; we are
            // the sole owner and this is the designated drop point.
            let module = Box::from_raw(moddata.cast::<M>());
            module.fini_module();
        }));
}

/// `flags` bridge: call `ClpreauthModule::flags`.
///
/// # Safety
///
/// `context` is non-null (libkrb5 contract).
pub(crate) extern "C" fn clpreauth_flags<M: ClpreauthModule>(
    context: sys::krb5_context,
    pa_type: sys::krb5_preauthtype,
) -> libc::c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null());
        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        M::flags(&ctx, pa_type) as libc::c_int
    }))
    .unwrap_or(libc::EINVAL)
}

/// `request_init` bridge: allocate a unit `modreq` placeholder.
///
/// The glue uses a `Box<()>` so that `request_fini` has a valid pointer to
/// free.  Modules that need per-request state use `Arc<Mutex<T>>` stored in
/// the module itself.
///
/// # Safety
///
/// `modreq_out` is non-null (libkrb5 contract).
pub(crate) extern "C" fn clpreauth_request_init(
    _context: sys::krb5_context,
    _moddata: sys::krb5_clpreauth_moddata,
    modreq_out: *mut sys::krb5_clpreauth_modreq,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(!modreq_out.is_null());
            // SAFETY: Box::into_raw gives a valid non-null pointer.
            *modreq_out =
                Box::into_raw(Box::new(())) as sys::krb5_clpreauth_modreq;
        }));
}

/// `request_fini` bridge: free the unit `modreq` placeholder and call
/// `ClpreauthModule::free_modreq`.
///
/// # Safety
///
/// `modreq` was set by `clpreauth_request_init` as `Box<()>::into_raw()`.
pub(crate) extern "C" fn clpreauth_request_fini<M: ClpreauthModule>(
    _context: sys::krb5_context,
    moddata: sys::krb5_clpreauth_moddata,
    modreq: sys::krb5_clpreauth_modreq,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            if !modreq.is_null() {
                // SAFETY: modreq was set by clpreauth_request_init via Box::into_raw.
                drop(Box::from_raw(modreq.cast::<()>()));
            }
            if moddata.is_null() {
                return;
            }
            // SAFETY: moddata was set by clpreauth_init as Box<M>::into_raw; valid until fini.
            let module = &mut *moddata.cast::<M>();
            module.free_modreq();
        }));
}

/// `prep_questions` bridge: call `ClpreauthModule::init_etype_info`.
///
/// # Safety
///
/// All pointer arguments are non-null unless the C spec allows null (only
/// `encoded_request_body` and `encoded_previous_request` may be null).
pub(crate) extern "C" fn clpreauth_prep_questions<M: ClpreauthModule>(
    context: sys::krb5_context,
    moddata: sys::krb5_clpreauth_moddata,
    _modreq: sys::krb5_clpreauth_modreq,
    opt: *mut sys::krb5_get_init_creds_opt,
    cb: sys::krb5_clpreauth_callbacks,
    rock: sys::krb5_clpreauth_rock,
    request: *mut sys::krb5_kdc_req,
    encoded_request_body: *mut sys::krb5_data,
    encoded_previous_request: *mut sys::krb5_data,
    pa_data: *mut sys::krb5_pa_data,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null());
        debug_assert!(!moddata.is_null());
        debug_assert!(!cb.is_null());
        debug_assert!(!rock.is_null());
        debug_assert!(!pa_data.is_null());

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: moddata was set by clpreauth_init as Box<M>::into_raw; valid until fini.
        let module = &mut *moddata.cast::<M>();
        let mut callbacks = ClpreauthCallbacks {
            cb,
            rock,
            ctx: context,
            _phantom: PhantomData,
        };
        // SAFETY: encoded_request_body and encoded_previous_request may be null
        // (first round trip); optional_data handles null correctly.
        let enc_req_body = optional_data(encoded_request_body);
        let enc_prev_req = optional_data(encoded_previous_request);
        // SAFETY: pa_data is non-null (libkrb5 contract).
        let pa = &*pa_data;

        let req = EtypeInfoRequest {
            opt,
            request: request.cast_const(),
            encoded_request_body: enc_req_body,
            encoded_previous_request: enc_prev_req,
            pa_data: pa,
        };

        match module.init_etype_info(&ctx, &mut callbacks, &req) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `process` bridge: call `ClpreauthModule::process`.
///
/// # Safety
///
/// All pointer arguments are non-null per libkrb5 contract unless the C spec
/// allows null (`encoded_request_body`, `encoded_previous_request`, and
/// `prompter`/`prompter_data` may be null).
pub(crate) extern "C" fn clpreauth_process<M: ClpreauthModule>(
    context: sys::krb5_context,
    moddata: sys::krb5_clpreauth_moddata,
    _modreq: sys::krb5_clpreauth_modreq,
    opt: *mut sys::krb5_get_init_creds_opt,
    cb: sys::krb5_clpreauth_callbacks,
    rock: sys::krb5_clpreauth_rock,
    request: *mut sys::krb5_kdc_req,
    encoded_request_body: *mut sys::krb5_data,
    encoded_previous_request: *mut sys::krb5_data,
    pa_data: *mut sys::krb5_pa_data,
    prompter: sys::krb5_prompter_fct,
    prompter_data: *mut libc::c_void,
    pa_data_out: *mut *mut *mut sys::krb5_pa_data,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null());
        debug_assert!(!moddata.is_null());
        debug_assert!(!cb.is_null());
        debug_assert!(!rock.is_null());
        debug_assert!(!pa_data.is_null());
        debug_assert!(!pa_data_out.is_null());

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: moddata was set by clpreauth_init as Box<M>::into_raw; valid until fini.
        let module = &mut *moddata.cast::<M>();
        let mut callbacks = ClpreauthCallbacks {
            cb,
            rock,
            ctx: context,
            _phantom: PhantomData,
        };
        // SAFETY: encoded_request_body and encoded_previous_request may be null.
        let enc_req_body = optional_data(encoded_request_body);
        let enc_prev_req = optional_data(encoded_previous_request);
        // SAFETY: pa_data is non-null.
        let pa = &*pa_data;

        let req = ProcessRequest {
            opt,
            request: request.cast_const(),
            encoded_request_body: enc_req_body,
            encoded_previous_request: enc_prev_req,
            pa_data: pa,
            // prompter may be None (null function pointer); record availability only.
            prompter: Prompter {
                available: prompter.is_some(),
                _phantom: PhantomData,
            },
        };
        // Keep prompter and prompter_data accessible in case future extensions
        // need to invoke the C function from within the bridge.
        let _ = (prompter, prompter_data);

        match module.process(&ctx, &mut callbacks, &req) {
            Ok(pa_list) => write_pa_data_out(&pa_list, pa_data_out),
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `tryagain` bridge: call `ClpreauthModule::tryagain`.
///
/// # Safety
///
/// All pointer arguments are non-null per libkrb5 contract except
/// `encoded_request_body`, `encoded_previous_request`, `prompter`, and
/// `prompter_data`.
pub(crate) extern "C" fn clpreauth_tryagain<M: ClpreauthModule>(
    context: sys::krb5_context,
    moddata: sys::krb5_clpreauth_moddata,
    _modreq: sys::krb5_clpreauth_modreq,
    opt: *mut sys::krb5_get_init_creds_opt,
    cb: sys::krb5_clpreauth_callbacks,
    rock: sys::krb5_clpreauth_rock,
    request: *mut sys::krb5_kdc_req,
    encoded_request_body: *mut sys::krb5_data,
    encoded_previous_request: *mut sys::krb5_data,
    pa_type: sys::krb5_preauthtype,
    error: *mut sys::krb5_error,
    error_padata: *mut *mut sys::krb5_pa_data,
    prompter: sys::krb5_prompter_fct,
    prompter_data: *mut libc::c_void,
    pa_data_out: *mut *mut *mut sys::krb5_pa_data,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null());
        debug_assert!(!moddata.is_null());
        debug_assert!(!cb.is_null());
        debug_assert!(!rock.is_null());
        debug_assert!(!error.is_null());
        debug_assert!(!pa_data_out.is_null());

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: moddata was set by clpreauth_init as Box<M>::into_raw; valid until fini.
        let module = &mut *moddata.cast::<M>();
        let mut callbacks = ClpreauthCallbacks {
            cb,
            rock,
            ctx: context,
            _phantom: PhantomData,
        };
        // SAFETY: encoded_request_body and encoded_previous_request may be null.
        let enc_req_body = optional_data(encoded_request_body);
        let enc_prev_req = optional_data(encoded_previous_request);
        // SAFETY: error is non-null.
        let err_ref = &*error;

        let req = TryagainRequest {
            opt,
            request: request.cast_const(),
            encoded_request_body: enc_req_body,
            encoded_previous_request: enc_prev_req,
            pa_type,
            error: err_ref,
            error_padata,
            // prompter may be None; record availability only.
            prompter: Prompter {
                available: prompter.is_some(),
                _phantom: PhantomData,
            },
        };
        // Keep prompter and prompter_data accessible in case future extensions
        // need to invoke the C function from within the bridge.
        let _ = (prompter, prompter_data);

        match module.tryagain(&ctx, &mut callbacks, &req) {
            Ok(pa_list) => write_pa_data_out(&pa_list, pa_data_out),
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `gic_opts` bridge: call `ClpreauthModule::supply_gic_opts`.
///
/// # Safety
///
/// `context`, `moddata`, `attr`, and `value` are non-null (libkrb5 contract).
pub(crate) extern "C" fn clpreauth_supply_gic_opts<M: ClpreauthModule>(
    context: sys::krb5_context,
    moddata: sys::krb5_clpreauth_moddata,
    opt: *mut sys::krb5_get_init_creds_opt,
    attr: *const std::os::raw::c_char,
    value: *const std::os::raw::c_char,
) -> sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null());
        debug_assert!(!moddata.is_null());
        debug_assert!(!attr.is_null());
        debug_assert!(!value.is_null());

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: moddata was set by clpreauth_init as Box<M>::into_raw; valid until fini.
        let module = &mut *moddata.cast::<M>();
        // SAFETY: attr and value are non-null C strings from libkrb5.
        let attr_str = std::ffi::CStr::from_ptr(attr).to_str().unwrap_or("");
        let value_str = std::ffi::CStr::from_ptr(value).to_str().unwrap_or("");

        match module.supply_gic_opts(&ctx, opt, attr_str, value_str) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// vtable constructor (task 8.4)
// ---------------------------------------------------------------------------

/// Produce a `krb5_clpreauth_vtable_st` for module type `M`.
///
/// Called by the `initvt_plugin!` macro.  All function pointers are
/// monomorphised for `M` at compile time.
///
/// The `pa_type_list` and `name` fields point to `'static` data owned by
/// the module's `impl ClpreauthModule`.  They are valid for the entire
/// lifetime of the shared library.
///
/// `enctype_list` is left null when `M::enctype_list()` returns `None`.
pub fn make_clpreauth_vtable<M: ClpreauthModule>()
-> sys::krb5_clpreauth_vtable_st {
    sys::krb5_clpreauth_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the shared library's lifetime.
        name: M::NAME.as_ptr(),

        // SAFETY: pa_type_list() returns a 'static slice; its pointer is
        // valid for the shared library's lifetime.  The C API requires a
        // null-terminated list; our pa_type_list helpers always end with 0
        // (enforced by the macro / convention).  Note: callers MUST ensure
        // the slice is 0-terminated.
        pa_type_list: M::pa_type_list().as_ptr().cast_mut(),

        enctype_list: match M::enctype_list() {
            Some(list) => list.as_ptr().cast_mut(),
            None => std::ptr::null_mut(),
        },

        init: Some(clpreauth_init::<M>),
        fini: Some(clpreauth_fini::<M>),
        flags: Some(clpreauth_flags::<M>),
        request_init: Some(clpreauth_request_init),
        request_fini: Some(clpreauth_request_fini::<M>),
        process: Some(clpreauth_process::<M>),
        tryagain: Some(clpreauth_tryagain::<M>),
        gic_opts: Some(clpreauth_supply_gic_opts::<M>),
        prep_questions: Some(clpreauth_prep_questions::<M>),
    }
}
