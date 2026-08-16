//! Glue layer: C vtable function pointers → `AuditModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `audit` module that contains `unsafe`
//! code.**
//!
//! All `unsafe` blocks are annotated with a `// SAFETY:` comment.  The
//! overall invariants this file relies on are:
//!
//! 1. After `open` succeeds, `moddata` holds a `*mut M` created by
//!    `Box::into_raw(Box::new(M::open()?))` cast to `krb5_audit_moddata`.
//!    `close` reclaims it via `Box::from_raw(moddata as *mut M)`.  No other
//!    code touches the raw pointer between those two calls.
//!
//! 2. The audit interface does **not** pass a `krb5_context` to any callback.
//!    The only Kerberos state available inside a callback is what `M` itself
//!    stored during `open`.
//!
//! 3. `krb5_audit_moddata` is `typedef struct krb5_audit_moddata_st
//!    *krb5_audit_moddata` — a pointer to an opaque struct.  We store a
//!    `*mut M` in that slot; the pointer size and alignment are compatible on
//!    all supported platforms because we cast through `*mut c_void`.
//!
//! 4. The `open` vtable function signature is
//!    `krb5_error_code (*)(krb5_audit_moddata *auctx)` — a pointer-to-pointer
//!    out-parameter.  We write the `Box<M>` raw pointer into `*auctx`.
//!
//! 5. All `krb5_audit_state *` parameters received by event callbacks are
//!    guaranteed non-null and valid for the duration of the callback by the
//!    C API contract.
//!
//! 6. `krb5_boolean` is `u32` in the MIT Kerberos ABI; the bridge functions
//!    compare against 0 to obtain a Rust `bool`.

use std::marker::PhantomData;

use crate::audit::{AuditModule, AuditStateRef};

// ---------------------------------------------------------------------------
// Memory ownership contract for moddata
//
// Allocation site:   `open` bridge — Box::into_raw(Box::new(M::open()?))
//                    cast to krb5_audit_moddata.
//
// Deallocation site: `close` bridge — Box::from_raw(moddata as *mut M).
//
// No intermediate function creates, copies, or frees moddata.
// ---------------------------------------------------------------------------

/// Bridge `open`: construct an `M` and write its raw pointer as moddata.
///
/// The `auctx` parameter is the out-pointer for the moddata handle.  On
/// success the caller (libkrb5 plugin loader) stores the handle and passes it
/// to every subsequent callback.  On failure `*auctx` is left null (or
/// unchanged) and no cleanup is needed.
pub(super) unsafe extern "C" fn open<M: AuditModule>(
    auctx: *mut kurbu5_sys::krb5_audit_moddata,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: auctx is non-null (libkrb5 contract: the loader provides a
        // valid out-pointer for the moddata handle).
        debug_assert!(!auctx.is_null());
        match M::open() {
            Ok(module) => {
                // SAFETY: Box::into_raw produces a non-null, heap-allocated
                // pointer owned exclusively by this code until close is called.
                // We cast to the opaque krb5_audit_moddata_st pointer type.
                let raw = Box::into_raw(Box::new(module))
                    .cast::<kurbu5_sys::krb5_audit_moddata_st>();
                // SAFETY: auctx is non-null and writable (caller invariant).
                unsafe { *auctx = raw };
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `close`: recover `Box<M>` from moddata and drop it.
///
/// After this call, `moddata` must not be used again.  The C API guarantees
/// that `close` is called exactly once per successful `open`.
pub(super) unsafe extern "C" fn close<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if moddata.is_null() {
            return 0;
        }
        // SAFETY: moddata was created by `open` as Box::into_raw(Box::new(M))
        // cast to krb5_audit_moddata.  We are the sole owner; recovering via
        // Box::from_raw is sound because no other reference to the data exists.
        let module = unsafe { *Box::from_raw(moddata.cast::<M>()) };
        match module.close() {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kdc_start`.
pub(super) unsafe extern "C" fn kdc_start<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!moddata.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw; valid
        // until `close` is called.
        let module = unsafe { &*moddata.cast::<M>() };
        match module.kdc_start(ev_success != 0) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `kdc_stop`.
pub(super) unsafe extern "C" fn kdc_stop<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!moddata.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw.
        let module = unsafe { &*moddata.cast::<M>() };
        match module.kdc_stop(ev_success != 0) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `as_req`.
pub(super) unsafe extern "C" fn as_req<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
    state: *mut kurbu5_sys::krb5_audit_state,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: moddata and state are non-null (libkrb5 contract for
        // mandatory-presence parameters in the C API header).
        debug_assert!(!moddata.is_null());
        debug_assert!(!state.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw.
        let module = unsafe { &*moddata.cast::<M>() };
        let audit_state = AuditStateRef {
            // SAFETY: state is non-null and valid for the duration of this
            // callback (libkrb5 AS callback contract).
            ptr: state.cast_const(),
            _phantom: PhantomData,
        };
        match module.as_req(ev_success != 0, audit_state) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `tgs_req`.
pub(super) unsafe extern "C" fn tgs_req<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
    state: *mut kurbu5_sys::krb5_audit_state,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: state is non-null (libkrb5 TGS callback contract).
        debug_assert!(!moddata.is_null());
        debug_assert!(!state.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw.
        let module = unsafe { &*moddata.cast::<M>() };
        let audit_state = AuditStateRef {
            // SAFETY: state is non-null and valid for the callback duration.
            ptr: state.cast_const(),
            _phantom: PhantomData,
        };
        match module.tgs_req(ev_success != 0, audit_state) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `tgs_s4u2self`.
pub(super) unsafe extern "C" fn tgs_s4u2self<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
    state: *mut kurbu5_sys::krb5_audit_state,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!moddata.is_null());
        debug_assert!(!state.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw.
        let module = unsafe { &*moddata.cast::<M>() };
        let audit_state = AuditStateRef {
            // SAFETY: state is non-null and valid for the callback duration.
            ptr: state.cast_const(),
            _phantom: PhantomData,
        };
        match module.tgs_s4u2self(ev_success != 0, audit_state) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `tgs_s4u2proxy`.
pub(super) unsafe extern "C" fn tgs_s4u2proxy<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
    state: *mut kurbu5_sys::krb5_audit_state,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!moddata.is_null());
        debug_assert!(!state.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw.
        let module = unsafe { &*moddata.cast::<M>() };
        let audit_state = AuditStateRef {
            // SAFETY: state is non-null and valid for the callback duration.
            ptr: state.cast_const(),
            _phantom: PhantomData,
        };
        match module.tgs_s4u2proxy(ev_success != 0, audit_state) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `tgs_u2u`.
pub(super) unsafe extern "C" fn tgs_u2u<M: AuditModule>(
    moddata: kurbu5_sys::krb5_audit_moddata,
    ev_success: kurbu5_sys::krb5_boolean,
    state: *mut kurbu5_sys::krb5_audit_state,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug_assert!(!moddata.is_null());
        debug_assert!(!state.is_null());
        // SAFETY: moddata was created by `open` as Box<M>::into_raw.
        let module = unsafe { &*moddata.cast::<M>() };
        let audit_state = AuditStateRef {
            // SAFETY: state is non-null and valid for the callback duration.
            ptr: state.cast_const(),
            _phantom: PhantomData,
        };
        match module.tgs_u2u(ev_success != 0, audit_state) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

// ---------------------------------------------------------------------------
// Vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `krb5_audit_vtable_st` for module type `M`.
///
/// Called from `initvt_plugin!` to fill in the caller-allocated vtable.  All
/// function pointer fields are set; the audit interface has no optional-NULL
/// vtable slots (the C API says "Optional" per method, but the libkrb5 plugin
/// machinery checks each slot independently).
///
/// The `name` field is set from `M::NAME`.  The KDC uses this string in log
/// messages to identify the plugin.
///
/// # Note on the typedef
///
/// In the C header, `krb5_audit_vtable` is a *pointer* typedef:
/// `typedef struct krb5_audit_vtable_st { ... } *krb5_audit_vtable`.
/// The `initvt_plugin!` macro casts the incoming `*mut krb5_plugin_vtable_st`
/// to `*mut krb5_audit_vtable_st` and writes the struct directly — not the
/// pointer.  This matches the pattern used by the MIT KDC itself when it
/// allocates the vtable and passes its address to `initvt`.
pub fn make_audit_vtable<M: AuditModule>() -> kurbu5_sys::krb5_audit_vtable_st
{
    kurbu5_sys::krb5_audit_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        open: Some(open::<M>),
        close: Some(close::<M>),
        kdc_start: Some(kdc_start::<M>),
        kdc_stop: Some(kdc_stop::<M>),
        as_req: Some(as_req::<M>),
        tgs_req: Some(tgs_req::<M>),
        tgs_s4u2self: Some(tgs_s4u2self::<M>),
        tgs_s4u2proxy: Some(tgs_s4u2proxy::<M>),
        tgs_u2u: Some(tgs_u2u::<M>),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditModule;
    use crate::error::Krb5Error;

    // -----------------------------------------------------------------------
    // Minimal module for vtable construction tests
    // -----------------------------------------------------------------------

    struct AllNoop;

    impl AuditModule for AllNoop {
        const NAME: &'static std::ffi::CStr = c"all_noop";
        fn open() -> Result<Self, Krb5Error> {
            Ok(AllNoop)
        }
    }

    // -----------------------------------------------------------------------
    // Vtable construction
    // -----------------------------------------------------------------------

    #[test]
    fn vtable_all_fields_set() {
        let vt = make_audit_vtable::<AllNoop>();
        assert!(vt.open.is_some(), "open");
        assert!(vt.close.is_some(), "close");
        assert!(vt.kdc_start.is_some(), "kdc_start");
        assert!(vt.kdc_stop.is_some(), "kdc_stop");
        assert!(vt.as_req.is_some(), "as_req");
        assert!(vt.tgs_req.is_some(), "tgs_req");
        assert!(vt.tgs_s4u2self.is_some(), "tgs_s4u2self");
        assert!(vt.tgs_s4u2proxy.is_some(), "tgs_s4u2proxy");
        assert!(vt.tgs_u2u.is_some(), "tgs_u2u");
        assert!(!vt.name.is_null(), "name");
    }

    #[test]
    fn vtable_name_matches_module_name() {
        let vt = make_audit_vtable::<AllNoop>();
        // SAFETY: vt.name is set from AllNoop::NAME.as_ptr() — a valid
        // null-terminated *const c_char with 'static lifetime.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, AllNoop::NAME);
    }

    // -----------------------------------------------------------------------
    // moddata round-trip: open then close without a live krb5_context
    // -----------------------------------------------------------------------

    #[test]
    fn moddata_round_trip_open_close() {
        let vt = make_audit_vtable::<AllNoop>();

        let mut moddata: kurbu5_sys::krb5_audit_moddata = std::ptr::null_mut();
        // SAFETY: moddata is a stack out-pointer.
        let open_code = unsafe { vt.open.unwrap()(&mut moddata) };
        assert_eq!(open_code, 0, "open must return 0");
        assert!(!moddata.is_null(), "moddata must be non-null after open");

        // SAFETY: moddata was set by open.
        let close_code = unsafe { vt.close.unwrap()(moddata) };
        assert_eq!(close_code, 0, "close must return 0");
        // After close, moddata is freed; do not dereference it.
    }

    #[test]
    fn moddata_close_null_is_noop() {
        // Calling close with a null moddata must not crash or return an error.
        // SAFETY: null moddata is explicitly handled in the close bridge.
        let code = unsafe { close::<AllNoop>(std::ptr::null_mut()) };
        assert_eq!(code, 0);
    }

    // -----------------------------------------------------------------------
    // kdc_start / kdc_stop round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn kdc_start_and_stop_round_trip() {
        let vt = make_audit_vtable::<AllNoop>();
        let mut moddata: kurbu5_sys::krb5_audit_moddata = std::ptr::null_mut();
        // SAFETY: moddata is a stack out-pointer.
        unsafe { vt.open.unwrap()(&mut moddata) };

        // SAFETY: moddata is valid; ev_success is 1 (true).
        let start_code = unsafe { vt.kdc_start.unwrap()(moddata, 1) };
        assert_eq!(start_code, 0, "kdc_start must succeed");

        // SAFETY: moddata is valid; ev_success is 0 (false).
        let stop_code = unsafe { vt.kdc_stop.unwrap()(moddata, 0) };
        assert_eq!(stop_code, 0, "kdc_stop must succeed");

        // SAFETY: moddata was set by open.
        unsafe { vt.close.unwrap()(moddata) };
    }

    // -----------------------------------------------------------------------
    // Event bridge round-trips with a zeroed audit state
    // -----------------------------------------------------------------------

    fn event_round_trip<M: AuditModule>(
        bridge: unsafe extern "C" fn(
            kurbu5_sys::krb5_audit_moddata,
            kurbu5_sys::krb5_boolean,
            *mut kurbu5_sys::krb5_audit_state,
        ) -> kurbu5_sys::krb5_error_code,
    ) {
        let mut moddata: kurbu5_sys::krb5_audit_moddata = std::ptr::null_mut();
        // SAFETY: moddata is a stack out-pointer.
        unsafe { open::<M>(&mut moddata) };
        let raw_state: kurbu5_sys::_krb5_audit_state =
            unsafe { std::mem::zeroed() };
        // SAFETY: moddata is valid; raw_state is a valid stack struct.
        let code = unsafe {
            bridge(
                moddata,
                1,
                &raw_state as *const kurbu5_sys::krb5_audit_state
                    as *mut kurbu5_sys::krb5_audit_state,
            )
        };
        assert_eq!(code, 0);
        // SAFETY: moddata was set by open.
        unsafe { close::<M>(moddata) };
    }

    #[test]
    fn as_req_bridge_round_trip() {
        event_round_trip::<AllNoop>(as_req::<AllNoop>);
    }

    #[test]
    fn tgs_req_bridge_round_trip() {
        event_round_trip::<AllNoop>(tgs_req::<AllNoop>);
    }

    #[test]
    fn tgs_s4u2self_bridge_round_trip() {
        event_round_trip::<AllNoop>(tgs_s4u2self::<AllNoop>);
    }

    #[test]
    fn tgs_s4u2proxy_bridge_round_trip() {
        event_round_trip::<AllNoop>(tgs_s4u2proxy::<AllNoop>);
    }

    #[test]
    fn tgs_u2u_bridge_round_trip() {
        event_round_trip::<AllNoop>(tgs_u2u::<AllNoop>);
    }
}
