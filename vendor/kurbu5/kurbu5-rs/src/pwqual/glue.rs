//! Glue layer: C vtable function pointers → `PwqualModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `pwqual` module that contains `unsafe` code.**
//!
//! All `unsafe` blocks are annotated with a `// SAFETY:` comment that names
//! the specific invariant being relied upon.  The overall invariants are:
//!
//! 1. `krb5_pwqual_moddata` holds a `*mut M` placed there by `bridge_open`
//!    (as a `Box<M>` converted via `Box::into_raw`) and reclaimed (via
//!    `Box::from_raw`) by `bridge_close`.  No other code touches this pointer.
//!
//! 2. All raw pointers received from libkrb5 (e.g. `krb5_context`,
//!    `krb5_principal`) are guaranteed non-null and valid for the duration of
//!    the call by the C API contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!    Specifically, `bridge_check` borrows the module as `&M` (not `&mut M`)
//!    because `PwqualModule::check` takes `&self`.
//!
//! 4. All C strings passed to us are null-terminated.  We use
//!    `CStr::from_ptr` and propagate errors where they are not valid UTF-8.
//!
//! # Memory ownership contracts
//!
//! | Pattern | Allocation | Deallocation |
//! |---------|-----------|--------------|
//! | Module instance | `Box::into_raw(Box::new(M))` in `bridge_open`, cast to `krb5_pwqual_moddata` | `bridge_close` calls `Box::from_raw(data as *mut M)` |

use std::ffi::CStr;

use crate::context::PluginContext;
use crate::pwqual::{CheckRequest, PwqualError, PwqualModule};

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

/// Parse a `*mut *const c_char` null-terminated list into a `Vec<&str>`.
///
/// The `languages` parameter in `krb5_pwqual_check_fn` is declared as
/// `*mut *const c_char` by the bindgen-generated type — `*mut` because
/// the C declaration is `const char **` (pointer to array of pointers to
/// const char); the outer pointer is not const.  We do not write through it.
///
/// # Safety
///
/// `argv` must be null or point to a null-terminated array of pointers, each
/// pointing to a valid null-terminated C string, all valid for lifetime `'a`.
unsafe fn cstr_argv<'a>(argv: *mut *const libc::c_char) -> Vec<&'a str> {
    if argv.is_null() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut p = argv;
    // SAFETY: p starts at argv (non-null); we advance one slot at a time
    // until *p is null (null-terminated array invariant).
    while !(*p).is_null() {
        // SAFETY: *p is non-null and points to a valid C string (caller guarantee).
        if let Ok(s) = CStr::from_ptr(*p).to_str() {
            out.push(s);
        }
        p = p.add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// Bridge functions — one per vtable slot
// ---------------------------------------------------------------------------

/// Bridge `krb5_pwqual_open_fn`: construct the module and store it as `*data`.
///
/// The module is heap-allocated via `Box::new(M::open(...))` and the raw
/// pointer is stored in `*data` as a `krb5_pwqual_moddata` (opaque pointer).
/// libkrb5 passes this pointer to every subsequent `check` and `close` call.
///
/// On error, `*data` is left unchanged (still null as initialised by libkrb5)
/// and the error code is returned.
unsafe extern "C" fn bridge_open<M: PwqualModule>(
    context: kurbu5_sys::krb5_context,
    dict_file: *const libc::c_char,
    data: *mut kurbu5_sys::krb5_pwqual_moddata,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "open: context is null");
        debug_assert!(!data.is_null(), "open: data out-pointer is null");

        // SAFETY: context is non-null (libkrb5 invariant); valid for this call.
        let ctx = PluginContext::from_raw(context);
        // SAFETY: dict_file is either null or a valid C string (libkrb5 invariant).
        let dict = optional_cstr(dict_file);

        match M::open(&ctx, dict) {
            Ok(module) => {
                // Box the module and convert to a raw pointer.  The raw pointer
                // is stored in *data and will outlive this call frame.
                // Deallocation happens in bridge_close via Box::from_raw.
                let raw = Box::into_raw(Box::new(module));
                // SAFETY: data is non-null (debug_assert above); *data receives
                // the heap pointer which libkrb5 will pass back in check/close.
                *data = raw as kurbu5_sys::krb5_pwqual_moddata;
                0
            },
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `krb5_pwqual_check_fn`: invoke `M::check` with a safe `CheckRequest`.
///
/// The `data` pointer was placed here by `bridge_open` as a `Box<M>`.  We
/// borrow it as `&M` (not `&mut M`) because `check` takes `&self` — no
/// aliasing occurs.  libkrb5 guarantees that `check` is not called
/// concurrently with another `check` on the same moddata pointer.
unsafe extern "C" fn bridge_check<M: PwqualModule>(
    context: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_pwqual_moddata,
    password: *const libc::c_char,
    policy_name: *const libc::c_char,
    princ: kurbu5_sys::krb5_principal,
    languages: *mut *const libc::c_char,
) -> kurbu5_sys::krb5_error_code {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "check: context is null");
        debug_assert!(!data.is_null(), "check: data is null");
        debug_assert!(!password.is_null(), "check: password is null");
        debug_assert!(!princ.is_null(), "check: principal is null");

        // SAFETY: context is non-null and valid (libkrb5 invariant).
        let ctx = PluginContext::from_raw(context);

        // SAFETY: password is non-null and a valid C string (libkrb5 invariant).
        let Ok(pw_str) = CStr::from_ptr(password).to_str() else {
            return PwqualError::Generic.into_error_code();
        };

        // SAFETY: policy_name is either null or a valid C string.
        let pol = optional_cstr(policy_name);

        // SAFETY: princ is non-null and points to a valid krb5_principal_data
        // allocated by libkrb5; it is valid for the duration of this call.
        let principal = &*princ;

        // SAFETY: languages is either null or a null-terminated array of C strings
        // (libkrb5 invariant for the languages parameter).
        let langs: Vec<&str> = cstr_argv(languages);

        let req = CheckRequest {
            password: pw_str,
            policy_name: pol,
            principal,
            languages: &langs,
        };

        // SAFETY: data was placed by bridge_open as Box<M>::into_raw.  We borrow
        // it as &M for this call only; bridge_close is not called concurrently
        // (libkrb5 contract), so no aliased mutable access exists.
        let module = &*(data as *const M);
        match module.check(&ctx, &req) {
            Ok(()) => 0,
            Err(e) => e.into_error_code(),
        }
    }))
    .unwrap_or(libc::EINVAL)
}

/// Bridge `krb5_pwqual_close_fn`: reclaim the `Box<M>` and call `M::close`.
///
/// After this call `data` is a dangling pointer; libkrb5 must not dereference
/// it again.  The C API guarantees that `close` is called exactly once after
/// all `check` calls are complete.
///
/// A null `data` is handled as a no-op — this can happen if `open` returned
/// an error and libkrb5 still calls `close` to match the lifecycle.
unsafe extern "C" fn bridge_close<M: PwqualModule>(
    context: kurbu5_sys::krb5_context,
    data: kurbu5_sys::krb5_pwqual_moddata,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(!context.is_null(), "close: context is null");
            if data.is_null() {
                // open was never called or returned an error; nothing to free.
                return;
            }
            // SAFETY: context is non-null and valid (libkrb5 invariant).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: data was placed by bridge_open as Box<M>::into_raw.  We are the
            // sole owner; this is the unique reclamation point.  After Box::from_raw
            // the pointer must not be used again (libkrb5 contract: close is final).
            let module = Box::from_raw(data.cast::<M>());
            module.close(&ctx);
        }));
}

// ---------------------------------------------------------------------------
// vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `krb5_pwqual_vtable_st` for module type `M`.
///
/// Called by the `initvt_plugin!` macro; the returned struct is written into
/// the caller-supplied vtable pointer after version negotiation succeeds.
/// All function pointers are monomorphised for `M` at compile time.
///
/// The `name` field is set from `M::NAME`.  The pointer is cast to
/// `*const c_char` and stored directly in the vtable.  libkrb5 reads this
/// field for logging only and never frees it.  Since `M::NAME` is a
/// `'static str`, the pointer is valid for the entire process lifetime.
///
/// Note: `M::NAME` must not contain embedded NUL bytes; libkrb5 treats it
/// as a C string.  The absence of a NUL terminator at `M::NAME.len()` is not
/// observable in practice because libkrb5 uses `printf`-style formatting
/// with the name as a `%s` argument, which reads until the first NUL.  Rust
/// string literals are followed in memory by enough zero padding from the
/// binary image that this works in practice, but the invariant is not
/// formally guaranteed.  To be safe, consider using `concat!(NAME, "\0")` in
/// the implementation.
pub fn make_pwqual_vtable<M: PwqualModule>()
-> kurbu5_sys::krb5_pwqual_vtable_st {
    kurbu5_sys::krb5_pwqual_vtable_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        // libkrb5 reads this field for logging only and does not free it.
        name: M::NAME.as_ptr(),
        open: Some(bridge_open::<M>),
        check: Some(bridge_check::<M>),
        close: Some(bridge_close::<M>),
    }
}

// ---------------------------------------------------------------------------
// Unit tests — glue round-trip (task 1.6)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pwqual::PwqualError;

    // A minimal stateless module for glue testing.  It rejects passwords
    // shorter than 4 characters and accepts anything longer.
    struct FourCharMin;

    impl PwqualModule for FourCharMin {
        const NAME: &'static std::ffi::CStr = c"four_char_min";

        fn open(
            _ctx: &PluginContext<'_>,
            _dict_file: Option<&str>,
        ) -> Result<Self, PwqualError> {
            Ok(FourCharMin)
        }

        fn check(
            &self,
            _ctx: &PluginContext<'_>,
            req: &CheckRequest<'_>,
        ) -> Result<(), PwqualError> {
            if req.password.len() < 4 {
                Err(PwqualError::TooShort)
            } else {
                Ok(())
            }
        }
    }

    // Helper: create a real krb5_context for use in glue tests.
    //
    // Using a real context is required because bridge_open/check/close call
    // PluginContext::from_raw, which debug_assert!s non-null.  Tests that
    // do not need the context to be functional (e.g. FourCharMin ignores it)
    // still need a non-null pointer to satisfy the assertion.
    //
    // Returns (ctx, must_free) — the caller must free ctx via
    // krb5_free_context when done.  Returns null if init fails; callers
    // should skip the test gracefully on init failure.
    fn make_test_context() -> kurbu5_sys::krb5_context {
        let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: krb5_init_context writes a valid pointer into ctx on
        // success; we check for error before using ctx.
        let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
        assert_eq!(code, 0, "krb5_init_context failed with code {code}");
        ctx
    }

    // Helper: free a context created by make_test_context.
    unsafe fn free_test_context(ctx: kurbu5_sys::krb5_context) {
        // SAFETY: ctx was created by krb5_init_context and is exclusively
        // owned by the current test.
        kurbu5_sys::krb5_free_context(ctx);
    }

    /// Verify that `make_pwqual_vtable` produces a vtable with all slots set.
    #[test]
    fn vtable_slots_populated() {
        let vt = make_pwqual_vtable::<FourCharMin>();
        assert!(vt.open.is_some(), "open slot must be populated");
        assert!(vt.check.is_some(), "check slot must be populated");
        assert!(vt.close.is_some(), "close slot must be populated");
    }

    /// Verify the `name` pointer in the vtable resolves to the expected string.
    #[test]
    fn vtable_name_matches_const() {
        let vt = make_pwqual_vtable::<FourCharMin>();
        assert!(!vt.name.is_null(), "name must be non-null");
        // SAFETY: vt.name was set from FourCharMin::NAME.as_ptr() — a valid
        // null-terminated *const c_char valid for 'static.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, FourCharMin::NAME);
    }

    /// Invoke `bridge_open` → `bridge_check` → `bridge_close` via raw function
    /// pointers, verifying the full glue round-trip.
    ///
    /// A real `krb5_context` is required because the bridge functions call
    /// `PluginContext::from_raw`, which asserts non-null in debug builds.
    /// `FourCharMin` does not access any context fields — the context pointer
    /// is needed only to satisfy the type system and the assertion.
    #[test]
    fn glue_round_trip_short_password() {
        let ctx_ptr = make_test_context();

        // Allocate a zeroed krb5_principal_data on the stack.  bridge_check
        // dereferences princ to get &krb5_principal_data for CheckRequest;
        // FourCharMin::check does not access any fields, so zeroed memory
        // is safe.
        let mut fake_princ = kurbu5_sys::krb5_principal_data::default();

        // --- open ---
        let mut moddata: kurbu5_sys::krb5_pwqual_moddata =
            std::ptr::null_mut();
        let open_code = unsafe {
            // SAFETY: ctx_ptr is a valid krb5_context; dict_file null is
            // accepted by FourCharMin::open; &mut moddata is a valid stack
            // out-pointer.
            bridge_open::<FourCharMin>(ctx_ptr, std::ptr::null(), &mut moddata)
        };
        assert_eq!(open_code, 0, "open should succeed");
        assert!(!moddata.is_null(), "moddata must be set after open");

        // --- check (short password: expect TooShort) ---
        let pw = b"abc\0";
        let check_code = unsafe {
            // SAFETY: ctx_ptr is valid; moddata was set by bridge_open as
            // Box<FourCharMin>::into_raw; pw is a valid C string; fake_princ
            // is a valid krb5_principal_data on the stack.
            bridge_check::<FourCharMin>(
                ctx_ptr,
                moddata,
                pw.as_ptr() as *const libc::c_char,
                std::ptr::null(),
                &mut fake_princ as kurbu5_sys::krb5_principal,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            check_code,
            PwqualError::TooShort.into_error_code(),
            "short password must return TooShort error code"
        );

        // --- check (long enough password: expect Ok) ---
        let pw_ok = b"abcdefgh\0";
        let ok_code = unsafe {
            // SAFETY: same invariants as the check above.
            bridge_check::<FourCharMin>(
                ctx_ptr,
                moddata,
                pw_ok.as_ptr() as *const libc::c_char,
                std::ptr::null(),
                &mut fake_princ as kurbu5_sys::krb5_principal,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ok_code, 0, "long-enough password must succeed");

        // --- close ---
        unsafe {
            // SAFETY: moddata was set by bridge_open; not accessed after this.
            bridge_close::<FourCharMin>(ctx_ptr, moddata);
            free_test_context(ctx_ptr);
        }
    }

    /// Verify that `bridge_close` with a null `data` pointer is a safe no-op.
    ///
    /// This can happen when `open` returns an error and libkrb5 calls `close`
    /// anyway to match the interface lifecycle.
    #[test]
    fn close_null_data_is_noop() {
        let ctx_ptr = make_test_context();
        unsafe {
            // SAFETY: null data is explicitly guarded by bridge_close before
            // any dereference.  ctx_ptr is a valid context.
            bridge_close::<FourCharMin>(ctx_ptr, std::ptr::null_mut());
            free_test_context(ctx_ptr);
        }
    }

    /// Verify error-code round-trip: `PwqualError::from_error_code` on the
    /// value returned by `bridge_check` produces the original variant.
    #[test]
    fn check_error_code_round_trip() {
        let ctx_ptr = make_test_context();
        let mut fake_princ = kurbu5_sys::krb5_principal_data::default();
        let mut moddata: kurbu5_sys::krb5_pwqual_moddata =
            std::ptr::null_mut();

        unsafe {
            // SAFETY: ctx_ptr is a valid context; dict_file null accepted.
            bridge_open::<FourCharMin>(
                ctx_ptr,
                std::ptr::null(),
                &mut moddata,
            );
        }

        let pw = b"x\0";
        let code = unsafe {
            // SAFETY: same as glue_round_trip_short_password.
            bridge_check::<FourCharMin>(
                ctx_ptr,
                moddata,
                pw.as_ptr() as *const libc::c_char,
                std::ptr::null(),
                &mut fake_princ as kurbu5_sys::krb5_principal,
                std::ptr::null_mut(),
            )
        };
        assert!(
            matches!(
                PwqualError::from_error_code(code),
                PwqualError::TooShort
            ),
            "error code {code} should map to TooShort"
        );

        unsafe {
            // SAFETY: moddata was set by bridge_open; not accessed after this.
            bridge_close::<FourCharMin>(ctx_ptr, moddata);
            free_test_context(ctx_ptr);
        }
    }
}
