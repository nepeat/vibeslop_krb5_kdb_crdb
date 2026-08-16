//! Glue layer: C vtable function pointers → `KdcpreauthModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `kdcpreauth` module that contains `unsafe`
//! code.**
//!
//! Overall invariants that all `unsafe` blocks in this file rely on:
//!
//! 1. `moddata` holds a `*mut M` placed by `init` and removed by `fini` via
//!    `Box::from_raw`.  The cast is sound: `init` cast `Box<M>::into_raw()` to
//!    `krb5_kdcpreauth_moddata`; `fini` and callers cast back to `*mut M`.
//!
//! 2. `modreq` holds a `*mut Box<dyn Any + Send + 'static>` placed by the
//!    `verify` respond closure and removed by `free_modreq` via `Box::from_raw`.
//!    The double-box is required because `Box<dyn Any>` is a fat pointer (two
//!    words) and cannot be cast directly to/from the thin opaque modreq pointer.
//!
//! 3. All raw pointers received from the KDC are guaranteed non-null and valid
//!    for the duration of the call by the C API contract; documented per-site.
//!
//! 4. The async-callback pattern for `edata` and `verify`: the Rust bridge
//!    calls the Rust `respond` closure exactly once before returning.  The KDC
//!    must not call the C respond pointer after the bridge function returns.
//!
//! 5. `pa_type_list()` must return a slice whose last element is `0` (the C
//!    null-terminator).  The vtable stores the raw pointer directly without
//!    copying; the slice must be `'static`.

use std::any::Any;
use std::ffi::CStr;
use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::error::Krb5Error;
use crate::kdcpreauth::{
    KdcpreauthCallbacks, KdcpreauthModule, PaData, ReturnPadataRequest,
    VerifyResponse,
};

// ---------------------------------------------------------------------------
// Helper: parse a null-terminated realm name list
// ---------------------------------------------------------------------------

/// Parse a null-terminated `*mut *const c_char` argv into `Vec<&str>`.
///
/// # Safety
///
/// `argv` must be null or point to a null-terminated array of null-terminated
/// C strings valid for `'a`.
unsafe fn realm_argv<'a>(argv: *mut *const libc::c_char) -> Vec<&'a str> {
    if argv.is_null() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut p = argv;
    while !(*p).is_null() {
        if let Ok(s) = CStr::from_ptr(*p).to_str() {
            out.push(s);
        }
        p = p.add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// Helper: recover the module from moddata
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PaData ↔ C conversion helpers
// ---------------------------------------------------------------------------

/// Allocate a `krb5_pa_data` struct in C memory for the KDC to free.
///
/// Both the struct and the `contents` buffer are allocated with
/// `libc::calloc`/`libc::malloc` so that the KDC can `free()` them via
/// `krb5_free_pa_data`.  Returns `None` on allocation failure.
///
/// # Safety
///
/// The returned pointer must be freed by the KDC via `krb5_free_pa_data` (or
/// equivalent); do not use `Box::from_raw` on it.
unsafe fn pa_data_to_c(pa: &PaData) -> Option<*mut kurbu5_sys::krb5_pa_data> {
    // SAFETY: calloc with size > 0 is well-defined; returns null on OOM.
    let ptr = libc::calloc(1, std::mem::size_of::<kurbu5_sys::krb5_pa_data>())
        .cast::<kurbu5_sys::krb5_pa_data>();
    if ptr.is_null() {
        return None;
    }
    (*ptr).magic = kurbu5_sys::KV5M_PA_DATA;
    (*ptr).pa_type = pa.pa_type as kurbu5_sys::krb5_preauthtype;
    if pa.contents.is_empty() {
        (*ptr).length = 0;
        (*ptr).contents = std::ptr::null_mut();
    } else {
        // SAFETY: malloc with size > 0 is well-defined.
        let contents = libc::malloc(pa.contents.len()).cast::<libc::c_uchar>();
        if contents.is_null() {
            libc::free(ptr.cast::<libc::c_void>());
            return None;
        }
        // SAFETY: contents points to pa.contents.len() bytes of malloc'd memory;
        // pa.contents is a valid Rust slice.
        std::ptr::copy_nonoverlapping(
            pa.contents.as_ptr(),
            contents,
            pa.contents.len(),
        );
        // SAFETY: pa.contents.len() is the exact byte count placed in contents;
        // krb5_pa_data.length is u32 and on 64-bit platforms usize > u32 is
        // possible, but KRB5 padata in practice never exceeds a few KiB.
        #[allow(clippy::cast_possible_truncation)]
        let length = pa.contents.len() as libc::c_uint;
        (*ptr).length = length;
        (*ptr).contents = contents;
    }
    Some(ptr)
}

/// Convert a non-empty `Vec<PaData>` into a C-allocated null-terminated
/// `*mut *mut krb5_pa_data`.
///
/// # Memory ownership contract
///
/// Both the array and each element are allocated with `libc::calloc`/
/// `libc::malloc` (via `pa_data_to_c`).  The KDC frees them with
/// `krb5_free_pa_data`.  Returns `None` on OOM; all partially-allocated
/// memory is freed before returning.
///
/// # Safety
///
/// `list` must be non-empty.  On `Some`, the returned pointer must be freed
/// exactly once by the KDC.
unsafe fn pa_data_list_to_c(
    list: &[PaData],
) -> Option<*mut *mut kurbu5_sys::krb5_pa_data> {
    let count = list.len();
    // SAFETY: calloc with count+1 > 0 is well-defined; null sentinel zeroed.
    let arr = libc::calloc(
        count + 1,
        std::mem::size_of::<*mut kurbu5_sys::krb5_pa_data>(),
    )
    .cast::<*mut kurbu5_sys::krb5_pa_data>();
    if arr.is_null() {
        return None;
    }
    for (i, pa) in list.iter().enumerate() {
        match pa_data_to_c(pa) {
            None => {
                // Free already-allocated elements then the array itself.
                for j in 0..i {
                    let elem = *arr.add(j);
                    if !(*elem).contents.is_null() {
                        libc::free((*elem).contents.cast::<libc::c_void>());
                    }
                    libc::free(elem.cast::<libc::c_void>());
                }
                libc::free(arr.cast::<libc::c_void>());
                return None;
            },
            Some(pa_ptr) => *arr.add(i) = pa_ptr,
        }
    }
    // Null sentinel is already zeroed by calloc.
    Some(arr)
}

// ---------------------------------------------------------------------------
// Vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `krb5_kdcpreauth_vtable_st` for module type `M`.
///
/// Called only from the `initvt_plugin!` macro.  All function pointers are
/// monomorphised for `M` at compile time.
///
/// # Contract: `NAME` and `pa_type_list`
///
/// - `M::NAME` is a `'static CStr`; `as_ptr()` yields a valid null-terminated C string.
/// - `M::pa_type_list()` must end with a `0` sentinel (C zero-terminated list).
///
/// Both are `'static` slices; their pointers are stored directly in the vtable
/// without copying.
pub fn make_kdcpreauth_vtable<M: KdcpreauthModule>()
-> kurbu5_sys::krb5_kdcpreauth_vtable_st {
    kurbu5_sys::krb5_kdcpreauth_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        // SAFETY: pa_type_list() returns a 'static slice with a trailing 0 sentinel.
        // The pointer is valid for the lifetime of the process.
        pa_type_list: M::pa_type_list().as_ptr().cast_mut(),
        init: Some(init::<M>),
        fini: Some(fini::<M>),
        flags: Some(flags::<M>),
        edata: Some(edata::<M>),
        verify: Some(verify::<M>),
        return_padata: Some(return_padata::<M>),
        free_modreq: Some(free_modreq_fn),
        loop_: None, // verto event loop hook; not exposed
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

extern "C" fn init<M: KdcpreauthModule>(
    context: kurbu5_sys::krb5_context,
    moddata_out: *mut kurbu5_sys::krb5_kdcpreauth_moddata,
    realmnames: *mut *const libc::c_char,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // SAFETY: context is non-null (KDC contract for init).
        let ctx = PluginContext::from_raw(context);
        // SAFETY: realmnames is a null-terminated argv or null.
        let realms = realm_argv(realmnames);
        match M::init_module(&ctx, &realms) {
            Ok(module) => {
                // SAFETY: moddata_out is non-null (KDC contract for init).
                // We cast Box<M> to the opaque moddata pointer.  The cast is sound
                // because krb5_kdcpreauth_moddata_st is an opaque marker type;
                // the only invariant is that the pointer is retrievable and non-null.
                *moddata_out = Box::into_raw(Box::new(module))
                    as kurbu5_sys::krb5_kdcpreauth_moddata;
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn fini<M: KdcpreauthModule>(
    _context: kurbu5_sys::krb5_context,
    moddata: kurbu5_sys::krb5_kdcpreauth_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            if moddata.is_null() {
                return;
            }
            // SAFETY: moddata was placed by init as Box<M>::into_raw() cast to moddata.
            // This is the only place it is reclaimed.
            let module = Box::from_raw(moddata.cast::<M>());
            module.fini_module();
        }));
}

extern "C" fn flags<M: KdcpreauthModule>(
    context: kurbu5_sys::krb5_context,
    pa_type: kurbu5_sys::krb5_preauthtype,
) -> libc::c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // The C krb5_kdcpreauth_flags_fn receives (context, pa_type) with no moddata;
        // it may be called before init.  We call the associated function flags_for_type.
        // SAFETY: context is non-null (KDC contract).
        let ctx = PluginContext::from_raw(context);
        M::flags_for_type(&ctx, pa_type)
    }))
    .unwrap_or(libc::EINVAL)
}

extern "C" fn edata<M: KdcpreauthModule>(
    context: kurbu5_sys::krb5_context,
    _request: *mut kurbu5_sys::krb5_kdc_req,
    cb: kurbu5_sys::krb5_kdcpreauth_callbacks,
    rock: kurbu5_sys::krb5_kdcpreauth_rock,
    moddata: kurbu5_sys::krb5_kdcpreauth_moddata,
    pa_type: kurbu5_sys::krb5_preauthtype,
    respond: kurbu5_sys::krb5_kdcpreauth_edata_respond_fn,
    arg: *mut libc::c_void,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            // SAFETY: context is non-null (KDC invariant for edata).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: moddata was placed by init as Box<M>::into_raw; valid until fini.
            let module = &*moddata.cast::<M>();
            // SAFETY: cb is non-null and valid for this call; rock is an opaque handle.
            let callbacks = KdcpreauthCallbacks {
                ctx: context,
                cb,
                rock,
                _phantom: PhantomData,
            };

            // Build the Rust respond closure.  The closure is called exactly once (before
            // this function returns in the synchronous case).
            //
            // PANIC NOTE: if the closure panics *after* the C respond callback has
            // been invoked, the KDC has already received the response and the panic
            // cannot be recovered from.  `catch_unwind` above will catch it (UB
            // prevention), but the KDC state may be inconsistent.  Plugin authors
            // must not panic inside respond closures once the C callback is called.
            let respond_fn: Box<
                dyn FnOnce(Result<Option<PaData>, Krb5Error>),
            > = Box::new(move |result: Result<Option<PaData>, Krb5Error>| {
                // SAFETY: respond is non-null (KDC contract for edata).
                let f = respond
                    .expect("edata respond fn is non-null per KDC contract");
                match result {
                    Err(e) => {
                        // SAFETY: arg is the opaque argument provided by the KDC;
                        // the null pa tells the KDC not to include this type.
                        f(arg, e.into_error_code(), std::ptr::null_mut());
                    },
                    Ok(None) => {
                        // Include this padata type with an empty value (null pa, code 0).
                        // SAFETY: arg is valid; null pa indicates empty value.
                        f(arg, 0, std::ptr::null_mut());
                    },
                    Ok(Some(ref pa)) => {
                        // SAFETY: pa_data_to_c uses the C allocator; KDC frees.
                        match pa_data_to_c(pa) {
                            None => f(arg, libc::ENOMEM, std::ptr::null_mut()),
                            Some(c_pa) => {
                                // SAFETY: arg and c_pa are both valid.
                                f(arg, 0, c_pa);
                            },
                        }
                    },
                }
            });

            module.get_edata(&ctx, pa_type, &callbacks, respond_fn);
        }));
}

extern "C" fn verify<M: KdcpreauthModule>(
    context: kurbu5_sys::krb5_context,
    _req_pkt: *mut kurbu5_sys::krb5_data,
    _request: *mut kurbu5_sys::krb5_kdc_req,
    enc_tkt_reply: *mut kurbu5_sys::krb5_enc_tkt_part,
    data: *mut kurbu5_sys::krb5_pa_data,
    cb: kurbu5_sys::krb5_kdcpreauth_callbacks,
    rock: kurbu5_sys::krb5_kdcpreauth_rock,
    moddata: kurbu5_sys::krb5_kdcpreauth_moddata,
    respond: kurbu5_sys::krb5_kdcpreauth_verify_respond_fn,
    arg: *mut libc::c_void,
) {
    // TKT_FLG_PRE_AUTH from krb5.h — the KDC framework does not set this
    // automatically; each preauth module must set it on enc_tkt_reply when
    // verification succeeds (see MIT's encrypted_timestamp, encrypted_challenge,
    // and OTP modules for precedent).
    const TKT_FLG_PRE_AUTH: kurbu5_sys::krb5_flags = 0x0020_0000;

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || unsafe {
            // SAFETY: context is non-null (KDC invariant for verify).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: moddata was placed by init as Box<M>::into_raw; valid until fini.
            let module = &*moddata.cast::<M>();
            // SAFETY: cb is non-null; rock is an opaque handle.
            let callbacks = KdcpreauthCallbacks {
                ctx: context,
                cb,
                rock,
                _phantom: PhantomData,
            };

            // Convert the raw pa_data pointer to an owned PaData.  data may be null
            // in unusual flows (e.g. re-authentication hints).
            let pa_data_owned: PaData = if data.is_null() {
                PaData::new(0, vec![])
            } else {
                // SAFETY: data is non-null and valid for the duration of this call.
                let raw = &*data;
                let contents = if raw.contents.is_null() || raw.length == 0 {
                    vec![]
                } else {
                    // SAFETY: raw.contents points to raw.length bytes owned by the KDC.
                    std::slice::from_raw_parts(
                        raw.contents,
                        raw.length as usize,
                    )
                    .to_vec()
                };
                PaData::new(raw.pa_type, contents)
            };

            let respond_fn: Box<dyn FnOnce(VerifyResponse)> = Box::new(
                move |vr: VerifyResponse| {
                    // Convert the optional modreq to an opaque C handle.
                    let modreq_raw: kurbu5_sys::krb5_kdcpreauth_modreq =
                        match vr.modreq {
                            None => std::ptr::null_mut(),
                            Some(mr) => {
                                // SAFETY: We box the fat pointer (Box<dyn Any>) into an outer Box
                                // to obtain a thin pointer.  The inner box carries the concrete
                                // type.  free_modreq is the only place this is reclaimed.
                                Box::into_raw(Box::new(mr))
                                    as kurbu5_sys::krb5_kdcpreauth_modreq
                            },
                        };

                    // On successful verification, set TKT_FLG_PRE_AUTH on the ticket.
                    // The KDC's missing_required_preauth() check requires this flag
                    // when the client principal has +requires_preauth.
                    if vr.code == 0 && !enc_tkt_reply.is_null() {
                        // SAFETY: enc_tkt_reply is non-null and valid for this call
                        // (KDC contract for verify).
                        (*enc_tkt_reply).flags |= TKT_FLG_PRE_AUTH;
                    }

                    // Convert e_data to a C-allocated null-terminated array, or null if empty.
                    let e_data_raw: *mut *mut kurbu5_sys::krb5_pa_data = if vr
                        .e_data
                        .is_empty()
                    {
                        std::ptr::null_mut()
                    } else {
                        // SAFETY: pa_data_list_to_c uses the C allocator; KDC frees.
                        match pa_data_list_to_c(&vr.e_data) {
                            None => {
                                // OOM: report failure; modreq_raw ownership passes to KDC.
                                let f = respond.expect("verify respond fn is non-null per KDC contract");
                                f(
                                    arg,
                                    libc::ENOMEM,
                                    modreq_raw,
                                    std::ptr::null_mut(),
                                    std::ptr::null_mut(),
                                );
                                return;
                            },
                            Some(arr) => arr,
                        }
                    };

                    // SAFETY: respond is non-null (KDC contract); arg is the opaque handle
                    // provided by the KDC.  authz_data is null: KDCPREAUTH plugins that need
                    // to add authdata use the PAC mechanism, not direct authdata injection.
                    let f = respond.expect(
                        "verify respond fn is non-null per KDC contract",
                    );
                    f(
                        arg,
                        vr.code,
                        modreq_raw,
                        e_data_raw,
                        std::ptr::null_mut(),
                    );
                },
            );

            module.verify(&ctx, &pa_data_owned, &callbacks, respond_fn);
        },
    ));
}

extern "C" fn return_padata<M: KdcpreauthModule>(
    context: kurbu5_sys::krb5_context,
    padata: *mut kurbu5_sys::krb5_pa_data,
    req_pkt: *mut kurbu5_sys::krb5_data,
    request: *mut kurbu5_sys::krb5_kdc_req,
    reply: *mut kurbu5_sys::krb5_kdc_rep,
    encrypting_key: *mut kurbu5_sys::krb5_keyblock,
    send_pa_out: *mut *mut kurbu5_sys::krb5_pa_data,
    cb: kurbu5_sys::krb5_kdcpreauth_callbacks,
    rock: kurbu5_sys::krb5_kdcpreauth_rock,
    moddata: kurbu5_sys::krb5_kdcpreauth_moddata,
    modreq: kurbu5_sys::krb5_kdcpreauth_modreq,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // SAFETY: context is non-null (KDC invariant for return_padata).
        let ctx = PluginContext::from_raw(context);
        // SAFETY: moddata was placed by init as Box<M>::into_raw; valid until fini.
        let module = &*moddata.cast::<M>();
        // SAFETY: cb and rock are valid for this call.
        let callbacks = KdcpreauthCallbacks {
            ctx: context,
            cb,
            rock,
            _phantom: PhantomData,
        };

        // Convert the input padata into an owned PaData if non-null.
        let pa_owned: Option<PaData> = if padata.is_null() {
            None
        } else {
            // SAFETY: padata is non-null and valid for this call.
            let raw = &*padata;
            let contents = if raw.contents.is_null() || raw.length == 0 {
                vec![]
            } else {
                // SAFETY: raw.contents points to raw.length bytes owned by the KDC.
                std::slice::from_raw_parts(raw.contents, raw.length as usize)
                    .to_vec()
            };
            Some(PaData::new(raw.pa_type, contents))
        };

        // Convert req_pkt to a byte slice for the request packet.
        let req_pkt_slice: &[u8] = if req_pkt.is_null() {
            &[]
        } else {
            let rp = &*req_pkt;
            if rp.data.is_null() || rp.length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(
                    rp.data as *const u8,
                    rp.length as usize,
                )
            }
        };

        // Borrow the modreq without consuming it; free_modreq will reclaim it later.
        let modreq_ref: Option<&dyn Any> = if modreq.is_null() {
            None
        } else {
            // SAFETY: modreq was placed by verify's respond closure as
            // Box<Box<dyn Any + Send + 'static>>::into_raw().
            // We borrow the outer Box without consuming it.
            let boxed: &Box<dyn Any + Send + 'static> =
                &*modreq.cast::<Box<dyn Any + Send + 'static>>();
            Some(boxed.as_ref())
        };

        let req = ReturnPadataRequest {
            padata: pa_owned.as_ref(),
            modreq: modreq_ref,
            encrypting_key,
            reply,
            request_packet: req_pkt_slice,
            request: request.cast_const(),
        };

        match module.return_padata(&ctx, req, &callbacks) {
            Err(e) => e.into_error_code(),
            Ok(None) => {
                // SAFETY: send_pa_out is non-null (KDC contract).
                *send_pa_out = std::ptr::null_mut();
                0
            },
            Ok(Some(ref pa)) => {
                // SAFETY: pa_data_to_c uses the C allocator; KDC frees.
                match pa_data_to_c(pa) {
                    None => libc::ENOMEM,
                    Some(c_pa) => {
                        *send_pa_out = c_pa;
                        0
                    },
                }
            },
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Free a per-request module state object.
///
/// Not generic over `M` because the modreq type is always
/// `Box<Box<dyn Any + Send + 'static>>` regardless of the module type.
/// The vtable references this via `Some(free_modreq_fn)`.
///
/// # Panic safety
///
/// The user's modreq destructor may panic.  The `catch_unwind` wrapper
/// prevents the panic from crossing the `extern "C"` boundary (UB).
/// If the destructor panics, the modreq allocation is leaked; this is
/// preferable to undefined behaviour.
extern "C" fn free_modreq_fn(
    _context: kurbu5_sys::krb5_context,
    _moddata: kurbu5_sys::krb5_kdcpreauth_moddata,
    modreq: kurbu5_sys::krb5_kdcpreauth_modreq,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            if modreq.is_null() {
                return;
            }
            // SAFETY: modreq was placed by verify's respond closure as
            // Box<Box<dyn Any + Send + 'static>>::into_raw().  This is the only place
            // it is reclaimed.  Dropping the outer Box drops the inner fat pointer,
            // which drops the concrete modreq value via its own destructor.
            drop(Box::from_raw(
                modreq.cast::<Box<dyn Any + Send + 'static>>(),
            ));
        }));
}
