//! Glue layer: C vtable function pointers → `HostrealmModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `hostrealm` module that contains `unsafe`
//! code.**
//!
//! All `unsafe` blocks in this file are annotated with a `// SAFETY:` comment
//! explaining the invariants that make them sound.  The overall invariants are:
//!
//! 1. The `moddata` opaque pointer passed between `init` and `fini` / query
//!    methods holds a `*mut M` placed there by the `init` bridge function and
//!    reclaimed (via `Box::from_raw`) by the `fini` bridge.  No other code
//!    touches this pointer.
//!
//! 2. All raw pointers received from libkrb5 (`context`, `host`, `realms_out`)
//!    are non-null and valid for the duration of the call by the C API
//!    contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!
//! 4. C string parameters (`host`) are null-terminated and valid ASCII/UTF-8.
//!    We use `CStr::from_ptr` and bail early on conversion failure.
//!
//! # Realm-list memory ownership contract
//!
//! The three query bridge functions (`host_realm`, `fallback_realm`,
//! `default_realm`) convert the Rust `Vec<String>` returned by the trait
//! into a `*mut *mut c_char` null-terminated array that libkrb5 takes
//! ownership of via the `*realms_out` out-parameter.
//!
//! Allocation (bridge functions):
//!   1. Each `String` in the `Vec` is converted to a `CString` and its raw
//!      pointer is stored as `*mut c_char`.
//!   2. A null sentinel is appended.
//!   3. The `Vec<*mut c_char>` is converted to a `Box<[*mut c_char]>` via
//!      `into_boxed_slice()`, then to a raw pointer via `Box::into_raw()`.
//!      The raw pointer to the first element is written to `*realms_out`.
//!
//! Deallocation (`free_list` bridge):
//!   1. The `*mut *mut c_char` pointer is recovered as a `Box<[*mut c_char]>`
//!      via `Box::from_raw(slice_ptr)` where `slice_ptr` uses the pre-computed
//!      length stored alongside the allocation.  Because the length cannot be
//!      recovered from a raw pointer alone, we store the boxed slice's pointer
//!      as a `*mut *mut c_char` (pointing to the first element) and recompute
//!      the length by scanning for the null sentinel.
//!   2. Each non-null element is reclaimed as a `CString` via
//!      `CString::from_raw(ptr)` which drops it.
//!   3. The array itself is freed by reconstructing the `Box<[*mut c_char]>`
//!      with the element count (including the null sentinel) and dropping it.

use std::ffi::{CStr, CString};

use crate::context::PluginContext;
use crate::error::Krb5Error;
use crate::hostrealm::HostrealmModule;

// ---------------------------------------------------------------------------
// Helper: build a C null-terminated realm list from Vec<String>
// ---------------------------------------------------------------------------

/// Convert a `Vec<String>` to a heap-allocated `*mut *mut c_char` null-terminated
/// array that libkrb5 can take ownership of.
///
/// Returns `None` if any realm string contains an interior null byte (which
/// would make a valid C string impossible to form).
///
/// # Allocation contract
///
/// - Each element is converted to `CString` and extracted via `into_raw()`.
/// - The array (including null sentinel) is heap-allocated as a
///   `Box<[*mut c_char]>` and unwrapped via `into_raw()`.
/// - Deallocation is performed by `free_realm_list_ptr` defined below.
unsafe fn build_realm_list(
    realms: Vec<String>,
) -> Option<*mut *mut libc::c_char> {
    let mut ptrs: Vec<*mut libc::c_char> =
        Vec::with_capacity(realms.len() + 1);
    for r in realms {
        if let Ok(cs) = CString::new(r) {
            ptrs.push(cs.into_raw());
        } else {
            // Interior null byte — free what we've allocated so far and bail.
            for p in ptrs {
                // SAFETY: p was produced by CString::into_raw just above.
                drop(CString::from_raw(p));
            }
            return None;
        }
    }
    // Null sentinel
    ptrs.push(std::ptr::null_mut());

    // Move the Vec into a Box<[_]> and extract the raw pointer to the first
    // element.  The boxed slice owns the allocation; we are now responsible
    // for freeing it with the matching procedure in free_realm_list_ptr.
    let boxed: Box<[*mut libc::c_char]> = ptrs.into_boxed_slice();
    Some(Box::into_raw(boxed).cast::<*mut libc::c_char>())
}

/// Free a realm-list pointer that was produced by `build_realm_list`.
///
/// Scans for the null sentinel to determine element count, reclaims each
/// `CString`, then frees the array itself.
///
/// # Safety
///
/// `list` must have been produced by `build_realm_list` and must not have
/// been freed before.
unsafe fn free_realm_list_ptr(list: *mut *mut libc::c_char) {
    if list.is_null() {
        return;
    }
    // Count elements (not counting the null sentinel) to compute the total
    // boxed-slice length (elements + 1 for sentinel).
    let mut len = 0usize;
    let mut p = list;
    while !(*p).is_null() {
        // SAFETY: Each element was produced by CString::into_raw in build_realm_list.
        drop(CString::from_raw(*p));
        len += 1;
        p = p.add(1);
    }
    // len + 1 accounts for the null sentinel slot in the boxed slice.
    let total = len + 1;
    // SAFETY: list was produced by Box::into_raw(boxed_slice) in build_realm_list.
    // Reconstruct the fat pointer (ptr + length) and drop the Box.
    // slice_from_raw_parts_mut produces a *mut [T] without creating a reference,
    // avoiding the cast_slice_from_raw_parts lint triggered by from_raw_parts_mut.
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
        list, total,
    )));
}

// ---------------------------------------------------------------------------
// Bridge functions — extern "C" adapters from libkrb5 into Rust trait calls
// ---------------------------------------------------------------------------

/// `init` bridge: allocate `Box<M>` and store as opaque `moddata`.
///
/// # Safety
///
/// `context` is non-null (libkrb5 contract).
/// `data` is non-null and points to a caller-zeroed `krb5_hostrealm_moddata`.
unsafe extern "C" fn init_bridge<M: HostrealmModule>(
    context: kurbu5_sys::krb5_context,
    data: *mut kurbu5_sys::krb5_hostrealm_moddata,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "init_bridge: context is null");
        debug_assert!(!data.is_null(), "init_bridge: data is null");
        // SAFETY: context is non-null; valid for the duration of this call.
        let ctx = PluginContext::from_raw(context);
        match M::init_module(&ctx) {
            Ok(module) => {
                // SAFETY: Box::into_raw produces a valid non-null pointer.
                // Cast to *mut krb5_hostrealm_moddata_st satisfies the C API's
                // opaque pointer type; cast back at each call site.
                *data = Box::into_raw(Box::new(module))
                    as kurbu5_sys::krb5_hostrealm_moddata;
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `fini` bridge: reclaim `Box<M>` from `moddata` and drop it.
///
/// # Safety
///
/// `data` is the pointer stored by `init_bridge`; it is non-null and not
/// aliased by any other live reference.
unsafe extern "C" fn fini_bridge<M: HostrealmModule>(
    _context: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_hostrealm_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(!data.is_null(), "fini_bridge: data is null");
            // SAFETY: data was placed by init_bridge as Box<M>::into_raw; we are the
            // sole owner at this point and may reclaim it.
            let module = Box::from_raw(data.cast::<M>());
            module.fini_module();
        }));
}

/// `host_realm` bridge.
///
/// # Safety
///
/// `context`, `data`, and `realms_out` are non-null (libkrb5 contract).
/// `host` is non-null and points to a valid null-terminated C string.
unsafe extern "C" fn host_realm_bridge<M: HostrealmModule>(
    context: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_hostrealm_moddata,
    host: *const libc::c_char,
    realms_out: *mut *mut *mut libc::c_char,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(
            !context.is_null(),
            "host_realm_bridge: context is null"
        );
        debug_assert!(!data.is_null(), "host_realm_bridge: data is null");
        debug_assert!(!host.is_null(), "host_realm_bridge: host is null");
        debug_assert!(
            !realms_out.is_null(),
            "host_realm_bridge: realms_out is null"
        );

        // SAFETY: host is a valid null-terminated C string (libkrb5 contract).
        let Ok(host_str) = CStr::from_ptr(host).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: data was set by init_bridge as Box<M>::into_raw; valid until fini_bridge.
        let module = &*data.cast::<M>();

        match module.host_realm(&ctx, host_str) {
            Ok(realms) => {
                // SAFETY: build_realm_list allocates with CString::into_raw; the
                // pointer is valid for libkrb5 to read and will be freed by
                // free_list_bridge.
                match build_realm_list(realms) {
                    Some(ptr) => {
                        *realms_out = ptr;
                        0
                    },
                    None => Krb5Error::OutOfMemory.into_error_code(),
                }
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `fallback_realm` bridge.
///
/// # Safety
///
/// Same invariants as `host_realm_bridge`.
unsafe extern "C" fn fallback_realm_bridge<M: HostrealmModule>(
    context: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_hostrealm_moddata,
    host: *const libc::c_char,
    realms_out: *mut *mut *mut libc::c_char,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(
            !context.is_null(),
            "fallback_realm_bridge: context is null"
        );
        debug_assert!(!data.is_null(), "fallback_realm_bridge: data is null");
        debug_assert!(!host.is_null(), "fallback_realm_bridge: host is null");
        debug_assert!(
            !realms_out.is_null(),
            "fallback_realm_bridge: realms_out is null"
        );

        // SAFETY: host is a valid null-terminated C string.
        let Ok(host_str) = CStr::from_ptr(host).to_str() else {
            return Krb5Error::Custom(libc::EINVAL).into_error_code();
        };

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: data was set by init_bridge as Box<M>::into_raw; valid until fini_bridge.
        let module = &*data.cast::<M>();

        match module.fallback_realm(&ctx, host_str) {
            Ok(realms) => {
                // SAFETY: build_realm_list allocates with CString::into_raw; freed
                // by free_list_bridge.
                match build_realm_list(realms) {
                    Some(ptr) => {
                        *realms_out = ptr;
                        0
                    },
                    None => Krb5Error::OutOfMemory.into_error_code(),
                }
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `default_realm` bridge.
///
/// # Safety
///
/// `context`, `data`, and `realms_out` are non-null (libkrb5 contract).
unsafe extern "C" fn default_realm_bridge<M: HostrealmModule>(
    context: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_hostrealm_moddata,
    realms_out: *mut *mut *mut libc::c_char,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(
            !context.is_null(),
            "default_realm_bridge: context is null"
        );
        debug_assert!(!data.is_null(), "default_realm_bridge: data is null");
        debug_assert!(
            !realms_out.is_null(),
            "default_realm_bridge: realms_out is null"
        );

        // SAFETY: context is non-null and valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: data was set by init_bridge as Box<M>::into_raw; valid until fini_bridge.
        let module = &*data.cast::<M>();

        match module.default_realm(&ctx) {
            Ok(realms) => {
                // SAFETY: build_realm_list allocates with CString::into_raw; freed
                // by free_list_bridge.
                match build_realm_list(realms) {
                    Some(ptr) => {
                        *realms_out = ptr;
                        0
                    },
                    None => Krb5Error::OutOfMemory.into_error_code(),
                }
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// `free_list` bridge: reclaim a realm list allocated by any query bridge.
///
/// This bridge is not type-parameterised because `free_realm_list_ptr` does
/// not need to know the module type — it follows the allocation protocol
/// established by `build_realm_list` regardless of which module produced the
/// list.  A single concrete function pointer is shared across all vtable
/// instances.
///
/// # Safety
///
/// `list` must be a pointer produced by `build_realm_list` (via one of the
/// query bridges), or null.  libkrb5 guarantees it does not call `free_list`
/// with a null pointer, but we guard for correctness anyway.
unsafe extern "C" fn free_list_bridge(
    _context: kurbu5_sys::krb5_context,
    _data: kurbu5_sys::krb5_hostrealm_moddata,
    list: *mut *mut libc::c_char,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            // SAFETY: list was produced by build_realm_list in one of the query
            // bridges.  free_realm_list_ptr reclaims each CString and the array Box.
            free_realm_list_ptr(list);
        }));
}

// ---------------------------------------------------------------------------
// vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `krb5_hostrealm_vtable_st` for module type `M`.
///
/// Called from the `initvt_plugin!` macro.  All function pointers are
/// monomorphised for `M` at compile time.
///
/// The `name` field is left as a null pointer; the C ABI uses it only for
/// diagnostic messages and the loader does not require it to be set.  Plugin
/// authors who need a name should set it in their own `initvt` function after
/// calling this.
pub fn make_hostrealm_vtable<M: HostrealmModule>()
-> kurbu5_sys::krb5_hostrealm_vtable_st {
    kurbu5_sys::krb5_hostrealm_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        init: Some(init_bridge::<M>),
        fini: Some(fini_bridge::<M>),
        host_realm: Some(host_realm_bridge::<M>),
        fallback_realm: Some(fallback_realm_bridge::<M>),
        default_realm: Some(default_realm_bridge::<M>),
        // free_list_bridge is not type-parameterised; one concrete function
        // pointer serves all module types because free_realm_list_ptr follows
        // the build_realm_list protocol regardless of module type M.
        free_list: Some(free_list_bridge),
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the glue layer (task 2.4)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Krb5Error;

    // ---------------------------------------------------------------------------
    // build_realm_list / free_realm_list_ptr round-trip tests
    // ---------------------------------------------------------------------------

    #[test]
    fn realm_list_round_trip_single() {
        let realms = vec!["EXAMPLE.COM".to_owned()];
        // SAFETY: build_realm_list and free_realm_list_ptr are used together
        // in the correct order; no other reference to the allocation exists.
        unsafe {
            let ptr = build_realm_list(realms)
                .expect("build_realm_list returned None");
            assert!(!ptr.is_null());
            // First element is EXAMPLE.COM
            let first = CStr::from_ptr(*ptr).to_str().unwrap();
            assert_eq!(first, "EXAMPLE.COM");
            // Second element is the null sentinel
            assert!((*ptr.add(1)).is_null());
            free_realm_list_ptr(ptr);
        }
    }

    #[test]
    fn realm_list_round_trip_multiple() {
        let realms = vec!["REALM1.ORG".to_owned(), "REALM2.ORG".to_owned()];
        // SAFETY: paired allocation and deallocation; no aliasing.
        unsafe {
            let ptr = build_realm_list(realms)
                .expect("build_realm_list returned None");
            assert!(!ptr.is_null());
            let r0 = CStr::from_ptr(*ptr).to_str().unwrap();
            let r1 = CStr::from_ptr(*ptr.add(1)).to_str().unwrap();
            assert_eq!(r0, "REALM1.ORG");
            assert_eq!(r1, "REALM2.ORG");
            assert!((*ptr.add(2)).is_null());
            free_realm_list_ptr(ptr);
        }
    }

    #[test]
    fn realm_list_empty_vec_produces_sentinel_only() {
        let realms: Vec<String> = vec![];
        // SAFETY: paired allocation and deallocation; no aliasing.
        unsafe {
            let ptr = build_realm_list(realms)
                .expect("build_realm_list returned None");
            assert!(!ptr.is_null());
            // Only element is the null sentinel.
            assert!((*ptr).is_null());
            free_realm_list_ptr(ptr);
        }
    }

    #[test]
    fn free_realm_list_ptr_null_is_noop() {
        // SAFETY: free_realm_list_ptr explicitly guards against null input.
        unsafe { free_realm_list_ptr(std::ptr::null_mut()) };
    }

    // ---------------------------------------------------------------------------
    // make_hostrealm_vtable sanity check — all function pointers are set
    // ---------------------------------------------------------------------------

    struct DummyModule;

    impl HostrealmModule for DummyModule {
        const NAME: &'static std::ffi::CStr = c"dummy";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(DummyModule)
        }
    }

    #[test]
    fn vtable_all_fields_set() {
        let vt = make_hostrealm_vtable::<DummyModule>();
        assert!(vt.init.is_some());
        assert!(vt.fini.is_some());
        assert!(vt.host_realm.is_some());
        assert!(vt.fallback_realm.is_some());
        assert!(vt.default_realm.is_some());
        assert!(vt.free_list.is_some());
    }
}
