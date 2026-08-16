//! PWQUAL — password quality plugin interface.
//!
//! A PWQUAL plugin checks candidate passwords against site-defined quality
//! rules before kadmind accepts a password change.  Multiple plugins may be
//! registered; libkrb5 calls each in turn and rejects the password if any
//! plugin returns an error.
//!
//! # Interface contract (from `krb5/pwqual_plugin.h`)
//!
//! Major version 1, minor version 1.  The vtable contains four fields:
//!
//! | C field | Role | Required by Rust |
//! |---------|------|-----------------|
//! | `name`  | Module name string | Yes (associated constant) |
//! | `open`  | Initialise module data | Yes (creates `Self`) |
//! | `check` | Check a password | Yes |
//! | `close` | Release module data | No (default drops `self`) |
//!
//! Both `open` and `close` are always set in the vtable (never NULL) because
//! the module instance IS the `krb5_pwqual_moddata` opaque pointer; there is
//! no alternative storage location.  Plugins that need no initialisation
//! simply return `Ok(Self)` immediately from `open`.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::pwqual::{PwqualModule, CheckRequest, PwqualError};
//! use kurbu5_rs::{PluginContext, initvt_plugin};
//!
//! pub struct MinLenCheck;
//!
//! impl PwqualModule for MinLenCheck {
//!     const NAME: &'static str = "min_len";
//!
//!     fn open(
//!         _ctx: &PluginContext<'_>,
//!         _dict_file: Option<&str>,
//!     ) -> Result<Self, PwqualError> {
//!         Ok(MinLenCheck)
//!     }
//!
//!     fn check(
//!         &self,
//!         _ctx: &PluginContext<'_>,
//!         req: &CheckRequest<'_>,
//!     ) -> Result<(), PwqualError> {
//!         if req.password.len() < 12 {
//!             Err(PwqualError::TooShort)
//!         } else {
//!             Ok(())
//!         }
//!     }
//! }
//!
//! initvt_plugin!(
//!     pwqual_min_len, 1, MinLenCheck,
//!     kurbu5_rs::pwqual::glue::make_pwqual_vtable
//! );
//! ```
//!
//! # Safety model
//!
//! All unsafe code is confined to [`glue`].  Plugin authors never write
//! `unsafe` themselves.

use crate::context::PluginContext;

// ---------------------------------------------------------------------------
// Sub-module: glue layer (all unsafe confined here)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod glue;

// ---------------------------------------------------------------------------
// PwqualError
// ---------------------------------------------------------------------------

/// Errors that a PWQUAL plugin method can return.
///
/// The named variants correspond directly to the `KADM5_PASS_Q_*` error codes
/// documented in `krb5/pwqual_plugin.h`.  These codes are passed back to
/// kadmind, which uses them to format the rejection message displayed to the
/// end user.
///
/// Use [`PwqualError::Generic`] for any quality failure that does not fit a
/// more specific category, or [`PwqualError::Custom`] to return an arbitrary
/// Kerberos error code.
#[derive(Debug)]
#[non_exhaustive]
pub enum PwqualError {
    /// Password is too short (`KADM5_PASS_Q_TOOSHORT` = 43787542).
    TooShort,

    /// Password does not meet character-class requirements
    /// (`KADM5_PASS_Q_CLASS` = 43787543).
    ///
    /// For example, a policy might require at least one digit and one
    /// uppercase letter.
    InsufficientClass,

    /// Password appears in a dictionary (`KADM5_PASS_Q_DICT` = 43787544).
    Dict,

    /// Unspecified quality failure (`KADM5_PASS_Q_GENERIC` = 43787577).
    ///
    /// Use this when the reason does not fit `TooShort`, `InsufficientClass`,
    /// or `Dict`.
    Generic,

    /// This plugin has no opinion; libkrb5 should try the next plugin
    /// (`KRB5_PLUGIN_NO_HANDLE`).
    ///
    /// Return this from `open` when the plugin wants to be skipped entirely
    /// for this invocation (e.g. an optional dictionary file is not installed
    /// and the plugin requires it).
    NoHandle,

    /// Memory allocation failure (`ENOMEM`).
    OutOfMemory,

    /// Pass through any other `krb5_error_code` integer directly.
    Custom(i32),
}

// KADM5_PASS_Q_* constants are defined in <kadm5/kadm_err.h> as plain C macros
// and are not captured by the kurbu5-sys bindgen allowlist.  They are
// reproduced here as literal i32 values so this crate does not need to depend
// on a kadm5-sys crate.
//
// Values sourced from /usr/include/kadm5/kadm_err.h:
//   KADM5_PASS_Q_TOOSHORT = 43787542
//   KADM5_PASS_Q_CLASS    = 43787543
//   KADM5_PASS_Q_DICT     = 43787544
//   KADM5_PASS_Q_GENERIC  = 43787577
pub(crate) const KADM5_PASS_Q_TOOSHORT: i32 = 43_787_542_i32;
pub(crate) const KADM5_PASS_Q_CLASS: i32 = 43_787_543_i32;
pub(crate) const KADM5_PASS_Q_DICT: i32 = 43_787_544_i32;
pub(crate) const KADM5_PASS_Q_GENERIC: i32 = 43_787_577_i32;

impl PwqualError {
    /// Convert to the raw `krb5_error_code` integer expected by libkrb5.
    #[must_use]
    pub fn into_error_code(self) -> i32 {
        match self {
            PwqualError::TooShort => KADM5_PASS_Q_TOOSHORT,
            PwqualError::InsufficientClass => KADM5_PASS_Q_CLASS,
            PwqualError::Dict => KADM5_PASS_Q_DICT,
            PwqualError::Generic => KADM5_PASS_Q_GENERIC,
            PwqualError::NoHandle => kurbu5_sys::KRB5_PLUGIN_NO_HANDLE,
            PwqualError::OutOfMemory => libc::ENOMEM,
            PwqualError::Custom(code) => code,
        }
    }

    /// Construct a `PwqualError` from a raw error code.
    #[must_use]
    pub fn from_error_code(code: i32) -> Self {
        match code {
            c if c == KADM5_PASS_Q_TOOSHORT => PwqualError::TooShort,
            c if c == KADM5_PASS_Q_CLASS => PwqualError::InsufficientClass,
            c if c == KADM5_PASS_Q_DICT => PwqualError::Dict,
            c if c == KADM5_PASS_Q_GENERIC => PwqualError::Generic,
            c if c == kurbu5_sys::KRB5_PLUGIN_NO_HANDLE => {
                PwqualError::NoHandle
            },
            c if c == libc::ENOMEM => PwqualError::OutOfMemory,
            other => PwqualError::Custom(other),
        }
    }
}

impl From<PwqualError> for i32 {
    fn from(e: PwqualError) -> i32 {
        e.into_error_code()
    }
}

impl From<i32> for PwqualError {
    fn from(code: i32) -> PwqualError {
        PwqualError::from_error_code(code)
    }
}

impl std::fmt::Display for PwqualError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PwqualError::TooShort => write!(f, "password is too short"),
            PwqualError::InsufficientClass => {
                write!(
                    f,
                    "password does not meet character-class requirements"
                )
            },
            PwqualError::Dict => write!(f, "password appears in a dictionary"),
            PwqualError::Generic => {
                write!(f, "password does not meet quality requirements")
            },
            PwqualError::NoHandle => {
                write!(f, "no plugin handles this request")
            },
            PwqualError::OutOfMemory => write!(f, "out of memory"),
            PwqualError::Custom(code) => {
                write!(f, "password quality error code {code}")
            },
        }
    }
}

impl std::error::Error for PwqualError {}

// ---------------------------------------------------------------------------
// Input record type
// ---------------------------------------------------------------------------

/// All inputs to a `PwqualModule::check` call.
///
/// Grouping the parameters into a struct allows future extension without a
/// breaking API change, and documents the role of each argument.
pub struct CheckRequest<'a> {
    /// The candidate password to evaluate.
    pub password: &'a str,

    /// The password policy name associated with `principal`, or `None` if the
    /// principal has no associated policy.  The plugin may use this to look up
    /// policy-specific minimum-length rules or character-class requirements.
    pub policy_name: Option<&'a str>,

    /// The principal whose password is being changed.  May be used to reject
    /// passwords that contain the principal name as a substring.
    ///
    /// This is a borrowed reference into libkrb5-owned memory; it is valid
    /// for the duration of the `check` call only.
    pub principal: &'a kurbu5_sys::krb5_principal_data,

    /// Client-specified language tags (RFC 5646), or an empty slice when the
    /// client did not advertise a language preference.  The plugin may use
    /// these to return a localised rejection message via
    /// `krb5_set_error_message`.
    pub languages: &'a [&'a str],
}

// ---------------------------------------------------------------------------
// PwqualModule trait
// ---------------------------------------------------------------------------

/// Implement this trait to create a PWQUAL (password quality) plugin.
///
/// Use [`initvt_plugin!`](crate::initvt_plugin) to export the C `initvt`
/// symbol.  libkrb5 calls each registered plugin's `check` method in turn;
/// if any returns an error the password change is rejected.
///
/// # Required methods
///
/// [`open`](PwqualModule::open) and [`check`](PwqualModule::check) are
/// mandatory.  [`close`](PwqualModule::close) has a default implementation
/// that simply drops `self`.
///
/// # Lifetime contract
///
/// `PwqualModule: Sized + Send + 'static` for the same reasons as `KdbModule`
/// in `kurbu5-kdb-rs`:
/// - `Sized` allows storing in `Box<M>` and recovering via `Box::from_raw`.
/// - `Send` allows the `Box` to be moved between threads (kadmind may service
///   password-change requests from multiple threads).
/// - `'static` prevents holding references into caller stacks.
///
/// # Quick start
///
/// See the [module-level documentation](self) for an example.
pub trait PwqualModule: Sized + Send + 'static {
    /// The module name string exposed in the vtable.
    ///
    /// libkrb5 uses this for logging and for the `[plugins]` section of
    /// `krb5.conf` to identify which module to enable or disable.
    ///
    /// The string must be ASCII and must not contain embedded NUL bytes.
    ///
    /// (Corresponds to `krb5_pwqual_vtable_st::name`.)
    const NAME: &'static std::ffi::CStr;

    /// Initialise the module and return an owned instance.
    ///
    /// `dict_file` is the realm's configured dictionary filename from
    /// `krb5.conf`, or `None` if no dictionary was configured.  Plugins that
    /// require a dictionary file should return `Err(PwqualError::NoHandle)`
    /// when `dict_file` is `None` so that libkrb5 skips this plugin cleanly.
    ///
    /// libkrb5 stores the returned module as `krb5_pwqual_moddata` and passes
    /// the same pointer to every subsequent `check` and `close` call.
    ///
    /// # Errors
    ///
    /// Return `Err(PwqualError::NoHandle)` when the plugin cannot initialize
    /// (e.g. dictionary file missing), or any other `PwqualError` on failure.
    ///
    /// (Corresponds to `krb5_pwqual_vtable_st::open`.)
    fn open(
        ctx: &PluginContext<'_>,
        dict_file: Option<&str>,
    ) -> Result<Self, PwqualError>;

    /// Check `req.password` against the plugin's quality rules.
    ///
    /// Return `Ok(())` to accept the password.  Return an appropriate
    /// [`PwqualError`] variant to reject it; libkrb5 will propagate the error
    /// code back to kadmind, which passes it to the client.
    ///
    /// The plugin may call `krb5_set_error_message()` (future API on
    /// `PluginContext`) to provide a human-readable reason that kadmind
    /// includes in its log.
    ///
    /// # Errors
    ///
    /// Return a [`PwqualError`] variant to reject the password.
    ///
    /// (Corresponds to `krb5_pwqual_vtable_st::check`.)
    fn check(
        &self,
        ctx: &PluginContext<'_>,
        req: &CheckRequest<'_>,
    ) -> Result<(), PwqualError>;

    /// Release any resources allocated by [`open`](PwqualModule::open).
    ///
    /// Called by libkrb5 once when the plugin is being unloaded.  The default
    /// implementation drops `self`, which is correct for most plugins.  Only
    /// override this if cleanup beyond `Drop` is needed (e.g. flushing logs or
    /// joining background threads).
    ///
    /// (Corresponds to `krb5_pwqual_vtable_st::close`.)
    fn close(self, _ctx: &PluginContext<'_>) {
        drop(self);
    }
}

// ---------------------------------------------------------------------------
// Derive macro integration tests
//
// These tests verify that #[derive(PwqualModule)] generates a correct
// delegation impl.  They are gated on the `derive` feature so that the
// default build (feature = "pwqual" only) does not pull in kurbu5-derive.
//
// The test pattern mirrors the KDB derive tests in kurbu5-kdb-example/src/tests.rs:
// a wrapper struct with a backing field exercises delegation and override.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "derive"))]
mod derive_tests {
    use super::{CheckRequest, PwqualError, PwqualModule};
    use crate::PluginContext;

    // -------------------------------------------------------------------
    // Helper: allocate a real krb5_context for tests.
    //
    // SAFETY: krb5_init_context initialises a new context;
    // krb5_free_context releases it.  Both are called only within
    // the scope of each test — the context does not escape.
    // -------------------------------------------------------------------
    struct TestCtx(kurbu5_sys::krb5_context);

    impl TestCtx {
        fn new() -> Self {
            let mut ctx = std::ptr::null_mut();
            // SAFETY: krb5_init_context requires a valid &mut pointer to
            // receive the new context; the pointer is valid for the
            // duration of the call and is initialised on return.
            let rc = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(rc, 0, "krb5_init_context failed");
            TestCtx(ctx)
        }

        fn as_plugin_ctx(&self) -> PluginContext<'_> {
            // SAFETY: self.0 is non-null (checked by TestCtx::new) and
            // remains valid for the lifetime `'_` tied to &self.
            unsafe { PluginContext::from_raw(self.0) }
        }
    }

    impl Drop for TestCtx {
        fn drop(&mut self) {
            // SAFETY: self.0 was returned by krb5_init_context and has not
            // been freed; this is the unique Drop call for this TestCtx.
            unsafe { kurbu5_sys::krb5_free_context(self.0) }
        }
    }

    // -------------------------------------------------------------------
    // Backing implementation used as the delegate target.
    // -------------------------------------------------------------------

    /// Minimal module that rejects passwords shorter than 8 characters.
    struct MinLen {
        min: usize,
    }

    impl PwqualModule for MinLen {
        const NAME: &'static std::ffi::CStr = c"min_len";

        fn open(
            _ctx: &PluginContext<'_>,
            _dict_file: Option<&str>,
        ) -> Result<Self, PwqualError> {
            Ok(MinLen { min: 8 })
        }

        fn check(
            &self,
            _ctx: &PluginContext<'_>,
            req: &CheckRequest<'_>,
        ) -> Result<(), PwqualError> {
            if req.password.len() < self.min {
                Err(PwqualError::TooShort)
            } else {
                Ok(())
            }
        }
    }

    // -------------------------------------------------------------------
    // Test 1: full delegation.
    //
    // #[derive(PwqualModule)] generates `impl PwqualModule for Wrapper`
    // that forwards `open`, `check`, and `close` to `self.inner`.
    // `NAME` is delegated: `<MinLen as PwqualModule>::NAME`.
    // -------------------------------------------------------------------

    #[derive(crate::PwqualModule)]
    #[plugin(delegate = inner, crate = crate)]
    struct Wrapper {
        inner: MinLen,
    }

    #[test]
    fn derive_delegation_name_inherited() {
        // The generated NAME constant delegates to the backing type.
        assert_eq!(
            <Wrapper as PwqualModule>::NAME,
            c"min_len",
            "derived NAME should match backing type's NAME"
        );
    }

    #[test]
    fn derive_delegation_accepts_long_password() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let w = <Wrapper as PwqualModule>::open(&ctx, None).unwrap();

        // Build a minimal CheckRequest.  `principal` is a zeroed C struct;
        // MinLen::check does not inspect it.
        let princ: kurbu5_sys::krb5_principal_data =
            unsafe { std::mem::zeroed() };
        let req = CheckRequest {
            password: "longpassword",
            policy_name: None,
            principal: &princ,
            languages: &[],
        };

        assert!(
            w.check(&ctx, &req).is_ok(),
            "delegation should accept a password of length >= 8"
        );
    }

    #[test]
    fn derive_delegation_rejects_short_password() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let w = <Wrapper as PwqualModule>::open(&ctx, None).unwrap();
        let princ: kurbu5_sys::krb5_principal_data =
            unsafe { std::mem::zeroed() };
        let req = CheckRequest {
            password: "short",
            policy_name: None,
            principal: &princ,
            languages: &[],
        };
        assert!(
            matches!(w.check(&ctx, &req), Err(PwqualError::TooShort)),
            "delegation should propagate TooShort from backing"
        );
    }

    // -------------------------------------------------------------------
    // Test 2: selective override.
    //
    // OverrideCheck overrides `check` via `plugin_impl_check`; `open` and
    // `close` are still delegated.
    // -------------------------------------------------------------------

    #[derive(crate::PwqualModule)]
    #[plugin(delegate = inner, overrides(check), crate = crate)]
    struct OverrideCheck {
        inner: MinLen,
    }

    impl OverrideCheck {
        /// The override always accepts any password (permissive policy).
        fn plugin_impl_check(
            &self,
            _ctx: &PluginContext<'_>,
            _req: &CheckRequest<'_>,
        ) -> Result<(), PwqualError> {
            Ok(())
        }
    }

    #[test]
    fn derive_override_accepts_short_password() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        // open is still delegated to MinLen::open.
        let o = <OverrideCheck as PwqualModule>::open(&ctx, None).unwrap();
        let princ: kurbu5_sys::krb5_principal_data =
            unsafe { std::mem::zeroed() };
        let req = CheckRequest {
            password: "x",
            policy_name: None,
            principal: &princ,
            languages: &[],
        };
        // The overridden check always returns Ok — short password is accepted.
        assert!(
            o.check(&ctx, &req).is_ok(),
            "overridden check should accept short password"
        );
    }
}

// ---------------------------------------------------------------------------
// Unit tests for PwqualError round-trips
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Integration tests: exercise the vtable function pointers end-to-end.
    //
    // These tests call open → check → close through the raw C function pointer
    // slots returned by make_pwqual_vtable.  They catch memory ownership bugs
    // in the glue layer that trait-level tests miss because trait-level tests
    // never invoke Box::into_raw / Box::from_raw.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::super::{CheckRequest, PwqualError, PwqualModule};
        use crate::context::PluginContext;
        use crate::pwqual::glue::make_pwqual_vtable;

        // A test plugin: rejects passwords shorter than 8 characters.
        struct TestPwqual {
            min_len: usize,
        }

        impl PwqualModule for TestPwqual {
            const NAME: &'static std::ffi::CStr = c"test_pwqual";

            fn open(
                _ctx: &PluginContext<'_>,
                _dict_file: Option<&str>,
            ) -> Result<Self, PwqualError> {
                Ok(TestPwqual { min_len: 8 })
            }

            fn check(
                &self,
                _ctx: &PluginContext<'_>,
                req: &CheckRequest<'_>,
            ) -> Result<(), PwqualError> {
                if req.password.len() < self.min_len {
                    Err(PwqualError::TooShort)
                } else {
                    Ok(())
                }
            }
        }

        // Helper: initialise a real krb5_context for the bridge functions.
        // Returns the raw context pointer; caller must free it via
        // krb5_free_context when done.
        fn make_ctx() -> kurbu5_sys::krb5_context {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            // SAFETY: krb5_init_context writes a valid pointer on success.
            let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(code, 0, "krb5_init_context failed");
            ctx
        }

        // Helper: free a context produced by make_ctx.
        unsafe fn free_ctx(ctx: kurbu5_sys::krb5_context) {
            // SAFETY: ctx was produced by krb5_init_context and is exclusively
            // owned by the current test.
            kurbu5_sys::krb5_free_context(ctx);
        }

        /// Exercise open → check (short password → TooShort) → check (long password → 0)
        /// → close through the raw vtable function pointers.
        #[test]
        fn vtable_open_check_close_roundtrip() {
            let vt = make_pwqual_vtable::<TestPwqual>();
            let ctx = make_ctx();

            // A zeroed principal_data: TestPwqual::check does not inspect it.
            let mut fake_princ = kurbu5_sys::krb5_principal_data::default();

            // --- open ---
            let mut moddata: kurbu5_sys::krb5_pwqual_moddata =
                std::ptr::null_mut();
            let open_fn = vt.open.expect("open vtable slot must be set");
            let open_code = unsafe {
                // SAFETY: ctx is a valid krb5_context; dict_file null is
                // accepted by TestPwqual::open; moddata is a stack out-pointer.
                open_fn(ctx, std::ptr::null(), &mut moddata)
            };
            assert_eq!(open_code, 0, "open must succeed");
            assert!(!moddata.is_null(), "moddata must be set after open");

            // --- check: short password → TooShort ---
            let short_pw = b"short\0";
            let check_fn = vt.check.expect("check vtable slot must be set");
            let short_code = unsafe {
                // SAFETY: ctx and moddata are valid; short_pw is a null-terminated
                // C string; fake_princ is a valid stack-allocated principal_data.
                check_fn(
                    ctx,
                    moddata,
                    short_pw.as_ptr() as *const libc::c_char,
                    std::ptr::null(), // no policy
                    &mut fake_princ as kurbu5_sys::krb5_principal,
                    std::ptr::null_mut(), // no languages
                )
            };
            assert_eq!(
                short_code,
                PwqualError::TooShort.into_error_code(),
                "short password must return TooShort"
            );

            // --- check: long password → 0 ---
            let long_pw = b"longpassword\0";
            let ok_code = unsafe {
                // SAFETY: same invariants as the short-password check above.
                check_fn(
                    ctx,
                    moddata,
                    long_pw.as_ptr() as *const libc::c_char,
                    std::ptr::null(),
                    &mut fake_princ as kurbu5_sys::krb5_principal,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(ok_code, 0, "long password must succeed");

            // --- close ---
            let close_fn = vt.close.expect("close vtable slot must be set");
            unsafe {
                // SAFETY: moddata was set by open; this is the single reclamation.
                close_fn(ctx, moddata);
                free_ctx(ctx);
            }
        }

        /// Verify that the error code returned by the check function pointer
        /// round-trips through PwqualError::from_error_code.
        #[test]
        fn vtable_check_propagates_error_code() {
            let vt = make_pwqual_vtable::<TestPwqual>();
            let ctx = make_ctx();
            let mut fake_princ = kurbu5_sys::krb5_principal_data::default();
            let mut moddata: kurbu5_sys::krb5_pwqual_moddata =
                std::ptr::null_mut();

            let open_fn = vt.open.expect("open must be set");
            unsafe {
                // SAFETY: ctx is valid; dict_file null accepted; moddata is stack.
                open_fn(ctx, std::ptr::null(), &mut moddata);
            }

            let pw = b"x\0"; // one char — shorter than min_len=8
            let check_fn = vt.check.expect("check must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; pw is a null-terminated string.
                check_fn(
                    ctx,
                    moddata,
                    pw.as_ptr() as *const libc::c_char,
                    std::ptr::null(),
                    &mut fake_princ as kurbu5_sys::krb5_principal,
                    std::ptr::null_mut(),
                )
            };

            // The returned i32 must round-trip to TooShort.
            assert!(
                matches!(
                    PwqualError::from_error_code(code),
                    PwqualError::TooShort
                ),
                "error code {code} must map to TooShort"
            );
            assert_eq!(
                code,
                PwqualError::TooShort.into_error_code(),
                "code must equal TooShort.into_error_code()"
            );

            let close_fn = vt.close.expect("close must be set");
            unsafe {
                // SAFETY: moddata was set by open; not accessed after this point.
                close_fn(ctx, moddata);
                free_ctx(ctx);
            }
        }
    }

    #[test]
    fn round_trip_too_short() {
        let code: i32 = PwqualError::TooShort.into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::TooShort
        ));
    }

    #[test]
    fn round_trip_insufficient_class() {
        let code: i32 = PwqualError::InsufficientClass.into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::InsufficientClass
        ));
    }

    #[test]
    fn round_trip_dict() {
        let code: i32 = PwqualError::Dict.into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::Dict
        ));
    }

    #[test]
    fn round_trip_generic() {
        let code: i32 = PwqualError::Generic.into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::Generic
        ));
    }

    #[test]
    fn round_trip_no_handle() {
        let code: i32 = PwqualError::NoHandle.into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::NoHandle
        ));
    }

    #[test]
    fn round_trip_out_of_memory() {
        let code: i32 = PwqualError::OutOfMemory.into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::OutOfMemory
        ));
    }

    #[test]
    fn round_trip_custom() {
        let code: i32 = PwqualError::Custom(12345).into_error_code();
        assert!(matches!(
            PwqualError::from_error_code(code),
            PwqualError::Custom(12345)
        ));
    }

    #[test]
    fn from_into_symmetry() {
        let code: i32 = 12345;
        let err: PwqualError = PwqualError::from(code);
        let back: i32 = i32::from(err);
        assert_eq!(back, code);
    }

    /// Verify that all KADM5_PASS_Q_* codes are distinct and match the header.
    #[test]
    fn kadm5_pass_q_constants_distinct() {
        let codes = [
            KADM5_PASS_Q_TOOSHORT,
            KADM5_PASS_Q_CLASS,
            KADM5_PASS_Q_DICT,
            KADM5_PASS_Q_GENERIC,
        ];
        // All values must be unique.
        for (i, &a) in codes.iter().enumerate() {
            for (j, &b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a, b,
                        "KADM5_PASS_Q_* constant collision at indices {i}/{j}"
                    );
                }
            }
        }
        // Spot-check against values from kadm_err.h.
        assert_eq!(KADM5_PASS_Q_TOOSHORT, 43787542_i32);
        assert_eq!(KADM5_PASS_Q_CLASS, 43787543_i32);
        assert_eq!(KADM5_PASS_Q_DICT, 43787544_i32);
        assert_eq!(KADM5_PASS_Q_GENERIC, 43787577_i32);
    }
}
