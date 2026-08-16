//! CERTAUTH — PKINIT certificate authorization plugin interface.
//!
//! This module provides a safe Rust API for the `krb5_certauth_vtable_st`
//! interface.  A CERTAUTH plugin is called by the KDC during PKINIT
//! authentication to decide whether a client certificate is authorized to
//! authenticate as a given principal.
//!
//! The C interface is defined in `<krb5/certauth_plugin.h>`.  The major
//! version is 1; minor version 2 adds `init_ex` (realm-aware init).
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::certauth::{CertauthModule, CertauthDecision, CertRef};
//! use kurbu5_rs::{initvt_plugin, PluginContext, Krb5Error};
//!
//! pub struct MyCertauth;
//!
//! impl CertauthModule for MyCertauth {
//!     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
//!         Ok(MyCertauth)
//!     }
//!
//!     fn authorize(
//!         &self,
//!         _ctx: &PluginContext<'_>,
//!         cert: CertRef<'_>,
//!         _princ: &kurbu5_rs::sys::krb5_principal_data,
//!     ) -> Result<CertauthDecision, Krb5Error> {
//!         // Inspect cert.as_der() and return a decision.
//!         let _ = cert.as_der();
//!         Ok(CertauthDecision::NoOpinion)
//!     }
//! }
//!
//! initvt_plugin!(
//!     certauth_myplugin,
//!     1,
//!     MyCertauth,
//!     kurbu5_rs::certauth::glue::make_certauth_vtable
//! );
//! // Exports C symbol: certauth_myplugin_initvt
//! ```

use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// CertRef<'a> — zero-copy view over DER-encoded certificate bytes (task 6.3)
// ---------------------------------------------------------------------------

/// A zero-copy view over the raw ASN.1 DER bytes of an X.509 certificate.
///
/// The KDC passes the certificate as a `(const uint8_t *cert, size_t cert_len)`
/// pair.  `CertRef` binds those two fields together so that trait methods
/// receive a single typed argument rather than a raw slice.
///
/// The lifetime `'a` binds the view to the buffer owned by the KDC; no copy
/// occurs when constructing a `CertRef`.
///
/// `CertRef` is intentionally non-`Clone`.  Cloning would suggest ownership;
/// use `as_der()` to borrow the bytes if you need them beyond the call scope.
pub struct CertRef<'a> {
    ptr: *const u8,
    len: usize,
    _phantom: PhantomData<&'a [u8]>,
}

impl<'a> CertRef<'a> {
    /// Construct a `CertRef` from a raw pointer and length.
    ///
    /// # Safety (caller — glue module only)
    ///
    /// `ptr` must be non-null and `ptr..ptr+len` must be valid for reads for
    /// the lifetime `'a`.  The C API guarantees this when called from the
    /// `authorize` bridge function.
    pub(crate) unsafe fn from_raw(ptr: *const u8, len: usize) -> Self {
        debug_assert!(!ptr.is_null() || len == 0);
        CertRef {
            ptr,
            len,
            _phantom: PhantomData,
        }
    }

    /// The raw DER bytes of the certificate.
    ///
    /// The slice is valid for `'a`; the data is owned by the KDC and must not
    /// be retained beyond the enclosing `authorize` call.
    #[must_use]
    pub fn as_der(&self) -> &'a [u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: ptr and len were validated by from_raw; the lifetime 'a
        // guarantees the buffer remains valid for the slice's lifetime.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

// ---------------------------------------------------------------------------
// CertauthDecision — result of an authorize call (task 6.2)
// ---------------------------------------------------------------------------

/// The authorization decision returned by [`CertauthModule::authorize`].
///
/// The C API encodes the decision in the return code and an out-parameter
/// (`char ***authinds_out`).  The glue layer converts a `CertauthDecision`
/// to the appropriate C representation.
///
/// # Variant semantics
///
/// | Variant | Return code | `authinds_out` |
/// |---------|-------------|----------------|
/// | `Authorized` | `0` | empty or `NULL` |
/// | `AuthorizedWithIndicators` | `0` | null-terminated array of indicator strings |
/// | `AuthorizedHwauth` | `KRB5_CERTAUTH_HWAUTH` | empty or `NULL` |
/// | `AuthorizedHwauth` with indicators would require a separate variant — use `AuthorizedWithIndicators` and rely on the hw-authent flag being set by PKINIT itself |
/// | `NoOpinion` | `KRB5_PLUGIN_NO_HANDLE` | empty or `NULL` |
/// | `NoOpinionWithIndicators` | `KRB5_CERTAUTH_HWAUTH_PASS` | null-terminated array of indicator strings |
/// | `Rejected(code)` | the given error code | `NULL` |
#[derive(Debug)]
#[non_exhaustive]
pub enum CertauthDecision {
    /// The certificate is authorized.  The KDC issues the ticket normally.
    /// Maps to return code `0`.
    Authorized,

    /// The certificate is authorized and the plugin contributes authentication
    /// indicator strings.  Maps to return code `0` with `authinds_out` set.
    ///
    /// Each string becomes an authentication indicator attached to the issued
    /// ticket (used for conditional access policy in later authorization).
    AuthorizedWithIndicators(Vec<String>),

    /// The certificate is authorized and the plugin requests that the
    /// `hw-authent` flag be set in the issued ticket.
    /// Maps to `KRB5_CERTAUTH_HWAUTH`.  Added in MIT krb5 1.19.
    AuthorizedHwauth,

    /// The plugin has no opinion on this certificate; the KDC should consult
    /// the next registered CERTAUTH plugin.  Maps to `KRB5_PLUGIN_NO_HANDLE`.
    ///
    /// This is the correct default for plugins that only handle a specific
    /// certificate policy: return `NoOpinion` when the certificate is outside
    /// your scope, and the built-in module makes the final call.
    NoOpinion,

    /// The plugin has no opinion, but requests that `hw-authent` be set if
    /// another plugin authorizes the certificate.
    /// Maps to `KRB5_CERTAUTH_HWAUTH_PASS`.  Added in MIT krb5 1.20.
    NoOpinionWithIndicators(Vec<String>),

    /// The certificate is rejected.  `code` must be one of:
    ///
    /// - `KRB5KDC_ERR_CLIENT_NAME_MISMATCH` — incorrect SAN value
    /// - `KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE` — incorrect EKU
    /// - `KRB5KDC_ERR_CERTIFICATE_MISMATCH` — other extension error
    ///
    /// Using a different error code is allowed but may produce confusing
    /// client-side error messages.
    Rejected(i32),
}

// ---------------------------------------------------------------------------
// CertauthModule trait (task 6.1)
// ---------------------------------------------------------------------------

/// Implement this trait to create a CERTAUTH plugin.
///
/// CERTAUTH plugins are called by the KDC during PKINIT authentication to
/// decide whether a client certificate is permitted to authenticate as a given
/// principal.  Multiple plugins may be registered; the KDC consults them in
/// order until one authorizes or rejects the certificate.
///
/// Use [`initvt_plugin!`](crate::initvt_plugin) to export the plugin's
/// `initvt` entry point.
///
/// # Lifetime contract
///
/// `CertauthModule: Sized + Send + 'static` for the same reasons as
/// `KdbModule` in `kurbu5-kdb-rs`:
/// - `Sized` allows storing in `Box<M>` and recovering via `Box::from_raw`.
/// - `Send` allows the `Box` to be moved between threads.
/// - `'static` prevents the module from holding stack references.
///
/// # Quick start
///
/// ```rust,ignore
/// use kurbu5_rs::certauth::{CertauthModule, CertauthDecision, CertRef};
/// use kurbu5_rs::{initvt_plugin, PluginContext, Krb5Error};
///
/// pub struct MyCertauth;
///
/// impl CertauthModule for MyCertauth {
///     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
///         Ok(MyCertauth)
///     }
///
///     fn authorize(
///         &self,
///         _ctx: &PluginContext<'_>,
///         cert: CertRef<'_>,
///         _princ: &kurbu5_rs::sys::krb5_principal_data,
///     ) -> Result<CertauthDecision, Krb5Error> {
///         let _ = cert.as_der();
///         Ok(CertauthDecision::NoOpinion)
///     }
/// }
///
/// initvt_plugin!(
///     certauth_myplugin,
///     1,
///     MyCertauth,
///     kurbu5_rs::certauth::glue::make_certauth_vtable
/// );
/// ```
pub trait CertauthModule: Sized + Send + 'static {
    /// The module name written into `krb5_certauth_vtable::name`.
    ///
    /// Used by the KDC for logging and plugin selection in `krb5.conf`.
    const NAME: &'static std::ffi::CStr;

    // -----------------------------------------------------------------------
    // Module lifecycle
    //
    // The C vtable has both `init` (minor v1) and `init_ex` (minor v2).
    // The glue layer always sets `init_ex` and leaves `init` null, since
    // `init_ex` is a strict superset: it receives the realm list in addition
    // to the context.  When the plugin does not need the realm list, the
    // default `init_module_ex` delegates to `init_module`.
    // -----------------------------------------------------------------------

    /// Initialise the plugin module.
    ///
    /// Called once by the KDC when the plugin is loaded.  Returns an owned
    /// module instance that is boxed and stored as the `moddata` opaque
    /// pointer for the lifetime of the KDC process (until `fini_module`).
    ///
    /// Return `Err(Krb5Error::OutOfMemory)` if initialisation fails due to
    /// resource exhaustion, or `Err(Krb5Error::Custom(code))` for other
    /// errors.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the module cannot be initialised.
    ///
    /// C vtable field: `init` (minor v1) / superseded by `init_ex` (minor v2).
    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;

    /// Initialise the plugin with the realm list (minor version 2).
    ///
    /// Called instead of `init_module` when the KDC supports minor version 2.
    /// `realms` is the null-terminated list of realms served by this KDC.
    ///
    /// The default delegates to `init_module`, ignoring the realm list.
    /// Override only if your plugin needs to read realm-specific configuration
    /// at init time.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the module cannot be initialised.
    ///
    /// C vtable field: `init_ex`.
    fn init_module_ex(
        ctx: &PluginContext<'_>,
        _realms: &[&str],
    ) -> Result<Self, Krb5Error> {
        Self::init_module(ctx)
    }

    /// Finalise and free the module.  Consumes `self`.
    ///
    /// Called once when the KDC unloads the plugin.  The default is a no-op
    /// (the `Box<M>` drop handles cleanup for most plugins).
    ///
    /// C vtable field: `fini`.
    fn fini_module(self) {}

    // -----------------------------------------------------------------------
    // Authorization
    // -----------------------------------------------------------------------

    /// Determine whether `cert` is authorized to authenticate as `princ`.
    ///
    /// This is the sole mandatory operation.  The KDC calls it for every
    /// PKINIT AS-REQ after decoding the client certificate.
    ///
    /// # Parameters
    ///
    /// - `ctx`   — the Kerberos context; use for logging or krb5 utilities.
    /// - `cert`  — zero-copy view of the ASN.1 DER-encoded client certificate.
    /// - `princ` — the requested client principal from the AS-REQ.
    ///
    /// # Return value
    ///
    /// - `Ok(CertauthDecision::Authorized)` — the certificate is accepted.
    /// - `Ok(CertauthDecision::AuthorizedWithIndicators(v))` — accepted; `v`
    ///   is attached to the ticket as authentication indicators.
    /// - `Ok(CertauthDecision::AuthorizedHwauth)` — accepted; set hw-authent.
    /// - `Ok(CertauthDecision::NoOpinion)` — pass to the next plugin.
    /// - `Ok(CertauthDecision::NoOpinionWithIndicators(v))` — pass, but
    ///   contribute indicators if another module authorizes.
    /// - `Err(Krb5Error::Custom(KRB5KDC_ERR_CLIENT_NAME_MISMATCH))` — the
    ///   SAN does not match `princ`.
    /// - `Err(Krb5Error::Custom(KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE))` —
    ///   the EKU does not permit client authentication.
    /// - `Err(Krb5Error::Custom(KRB5KDC_ERR_CERTIFICATE_MISMATCH))` — other
    ///   certificate extension mismatch.
    ///
    /// The `opts` and `db_entry` C parameters are internal to built-in
    /// modules and are not exposed here.  Third-party plugins must ignore them
    /// (per the `certauth_plugin.h` comment).
    ///
    /// # Errors
    ///
    /// Returns `Err` to reject the certificate with the given error code.
    ///
    /// C vtable field: `authorize`.
    fn authorize(
        &self,
        ctx: &PluginContext<'_>,
        cert: CertRef<'_>,
        princ: &kurbu5_sys::krb5_principal_data,
    ) -> Result<CertauthDecision, Krb5Error>;

    // -----------------------------------------------------------------------
    // Optional hooks
    // -----------------------------------------------------------------------

    /// Notification that PKINIT pre-authentication failed for `princ`.
    ///
    /// Called after all plugins have been consulted and none authorized the
    /// certificate.  Useful for audit logging or account lockout.
    ///
    /// The default is a no-op.  The method is infallible: errors are logged
    /// internally but not propagated.
    ///
    /// Note: this field does not exist in `krb5_certauth_vtable_st` as a
    /// named slot — the C API expresses "no opinion / pass through" semantics
    /// via `KRB5_PLUGIN_NO_HANDLE` from `authorize`.  This method is a
    /// higher-level convenience: the glue sets it to `None` (NULL) so the KDC
    /// does not call it.  Override `authorize` and return `NoOpinion` for the
    /// same effect.
    ///
    /// C vtable field: not a separate slot; expressed via `authorize` return.
    fn notify_pkinit_failure(
        &self,
        _ctx: &PluginContext<'_>,
        _princ: &kurbu5_sys::krb5_principal_data,
    ) {
    }

    /// Free per-request state allocated during `authorize`.
    ///
    /// The default is a no-op.  Override if `authorize` allocates per-request
    /// state that must be freed after the AS-REQ is complete.
    ///
    /// Note: CERTAUTH does not have a separate `free_modreq` vtable slot —
    /// per-module state is managed via `moddata` (the module instance itself).
    /// This method is provided for API symmetry with other interfaces but the
    /// glue does not wire it to a vtable slot.
    fn free_modreq(&self) {}
}

// ---------------------------------------------------------------------------
// Glue sub-module
// ---------------------------------------------------------------------------

/// Vtable construction and C bridge functions for the CERTAUTH interface.
///
/// All unsafe code for this interface lives here.
pub mod glue;

// ---------------------------------------------------------------------------
// Unit tests (task 6.5)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CertRef tests
    // -----------------------------------------------------------------------

    #[test]
    fn cert_ref_empty_slice() {
        // When len == 0, as_der() must return an empty slice regardless of ptr.
        let cert = unsafe { CertRef::from_raw(std::ptr::null(), 0) };
        assert!(cert.as_der().is_empty());
    }

    #[test]
    fn cert_ref_round_trip_bytes() {
        let der: &[u8] = &[0x30, 0x82, 0x01, 0x00];
        let cert = unsafe { CertRef::from_raw(der.as_ptr(), der.len()) };
        assert_eq!(cert.as_der(), der);
    }

    // -----------------------------------------------------------------------
    // CertauthDecision tests (task 6.2)
    // -----------------------------------------------------------------------

    #[test]
    fn decision_authorized_is_debug() {
        let d = CertauthDecision::Authorized;
        let s = format!("{d:?}");
        assert!(s.contains("Authorized"));
    }

    #[test]
    fn decision_authorized_with_indicators() {
        let indicators = vec!["pkinit".to_string(), "hwauth".to_string()];
        let d = CertauthDecision::AuthorizedWithIndicators(indicators);
        if let CertauthDecision::AuthorizedWithIndicators(v) = d {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], "pkinit");
        } else {
            panic!("expected AuthorizedWithIndicators");
        }
    }

    #[test]
    fn decision_no_opinion_with_indicators() {
        let d = CertauthDecision::NoOpinionWithIndicators(vec![
            "test".to_string(),
        ]);
        if let CertauthDecision::NoOpinionWithIndicators(v) = d {
            assert_eq!(v[0], "test");
        } else {
            panic!("expected NoOpinionWithIndicators");
        }
    }

    #[test]
    fn decision_rejected_stores_code() {
        // KRB5KDC_ERR_CLIENT_NAME_MISMATCH = -1765328309
        let code: i32 = -1_765_328_309;
        let d = CertauthDecision::Rejected(code);
        if let CertauthDecision::Rejected(c) = d {
            assert_eq!(c, code);
        } else {
            panic!("expected Rejected");
        }
    }

    // -----------------------------------------------------------------------
    // Minimal CertauthModule smoke test
    // -----------------------------------------------------------------------

    struct AlwaysNoOpinion;

    impl CertauthModule for AlwaysNoOpinion {
        const NAME: &'static std::ffi::CStr = c"always_no_opinion";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(AlwaysNoOpinion)
        }

        fn authorize(
            &self,
            _ctx: &PluginContext<'_>,
            _cert: CertRef<'_>,
            _princ: &kurbu5_sys::krb5_principal_data,
        ) -> Result<CertauthDecision, Krb5Error> {
            Ok(CertauthDecision::NoOpinion)
        }
    }

    #[test]
    fn always_no_opinion_is_send_and_static() {
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<AlwaysNoOpinion>();
    }

    #[test]
    fn default_free_modreq_is_noop() {
        // Constructing without a context is fine for this test — we only call
        // the default method, which does nothing.
        let m = AlwaysNoOpinion;
        m.free_modreq(); // must not panic
    }

    #[test]
    fn default_fini_module_is_noop() {
        let m = AlwaysNoOpinion;
        m.fini_module(); // must not panic
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers end-to-end.
    //
    // These tests drive init_ex → authorize (Authorized) and init_ex →
    // authorize (AuthorizedWithIndicators) → free_ind through the raw C vtable
    // slots produced by make_certauth_vtable.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::{CertRef, CertauthDecision, CertauthModule};
        use crate::certauth::glue::make_certauth_vtable;
        use crate::context::PluginContext;
        use crate::error::Krb5Error;
        use std::ffi::CStr;

        // Plugin that always returns Authorized.
        struct AuthorizeAll;

        impl CertauthModule for AuthorizeAll {
            const NAME: &'static std::ffi::CStr = c"authorize_all";
            fn init_module(
                _ctx: &PluginContext<'_>,
            ) -> Result<Self, Krb5Error> {
                Ok(AuthorizeAll)
            }

            fn authorize(
                &self,
                _ctx: &PluginContext<'_>,
                _cert: CertRef<'_>,
                _princ: &kurbu5_sys::krb5_principal_data,
            ) -> Result<CertauthDecision, Krb5Error> {
                Ok(CertauthDecision::Authorized)
            }
        }

        // Plugin that returns AuthorizedWithIndicators(["pkinit"]).
        struct WithIndicators;

        impl CertauthModule for WithIndicators {
            const NAME: &'static std::ffi::CStr = c"with_indicators";
            fn init_module(
                _ctx: &PluginContext<'_>,
            ) -> Result<Self, Krb5Error> {
                Ok(WithIndicators)
            }

            fn authorize(
                &self,
                _ctx: &PluginContext<'_>,
                _cert: CertRef<'_>,
                _princ: &kurbu5_sys::krb5_principal_data,
            ) -> Result<CertauthDecision, Krb5Error> {
                Ok(CertauthDecision::AuthorizedWithIndicators(vec![
                    "pkinit".to_string(),
                ]))
            }
        }

        // Helper: create a real krb5_context.
        fn make_ctx() -> kurbu5_sys::krb5_context {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            // SAFETY: krb5_init_context writes a valid pointer on success.
            let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(code, 0, "krb5_init_context failed");
            ctx
        }

        // Helper: init via the init_ex vtable slot; returns moddata.
        unsafe fn vtable_init_ex<M: CertauthModule>(
            ctx: kurbu5_sys::krb5_context,
        ) -> kurbu5_sys::krb5_certauth_moddata {
            let vt = make_certauth_vtable::<M>();
            let init_ex_fn = vt.init_ex.expect("init_ex slot must be set");
            let mut moddata: kurbu5_sys::krb5_certauth_moddata =
                std::ptr::null_mut();
            // SAFETY: ctx is valid; realmlist null accepted (no realms);
            // moddata is a stack out-pointer.
            let code = init_ex_fn(ctx, std::ptr::null(), &mut moddata);
            assert_eq!(code, 0, "init_ex must succeed");
            assert!(!moddata.is_null());
            moddata
        }

        /// AuthorizeAll: init_ex → authorize → 0 (no indicators).
        #[test]
        fn vtable_authorize_ok() {
            let ctx = make_ctx();
            let vt = make_certauth_vtable::<AuthorizeAll>();

            // SAFETY: ctx is valid.
            let moddata = unsafe { vtable_init_ex::<AuthorizeAll>(ctx) };

            // A zeroed principal — AuthorizeAll does not inspect it.
            let princ: kurbu5_sys::krb5_principal_data =
                unsafe { std::mem::zeroed() };
            let der: &[u8] = &[0x30, 0x00]; // minimal DER
            let mut authinds_out: *mut *mut libc::c_char =
                std::ptr::null_mut();

            let auth_fn = vt.authorize.expect("authorize slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; cert points to a stack slice
                // of len 2; princ is a stack pointer; opts and db_entry null
                // accepted (AuthorizeAll ignores them); authinds_out is stack.
                auth_fn(
                    ctx,
                    moddata,
                    der.as_ptr(),
                    der.len(),
                    &princ as *const kurbu5_sys::krb5_principal_data,
                    std::ptr::null(), // opts — null accepted
                    std::ptr::null(), // db_entry — null accepted
                    &mut authinds_out,
                )
            };
            assert_eq!(code, 0, "AuthorizeAll::authorize must return 0");
            // No indicators — authinds_out should be null.
            assert!(authinds_out.is_null());

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init_ex.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }

        /// WithIndicators: init_ex → authorize → authinds_out == ["pkinit"] → free_ind.
        #[test]
        fn vtable_authorize_with_indicators_alloc_free() {
            let ctx = make_ctx();
            let vt = make_certauth_vtable::<WithIndicators>();

            // SAFETY: ctx is valid.
            let moddata = unsafe { vtable_init_ex::<WithIndicators>(ctx) };

            let princ: kurbu5_sys::krb5_principal_data =
                unsafe { std::mem::zeroed() };
            let der: &[u8] = &[0x30, 0x00];
            let mut authinds_out: *mut *mut libc::c_char =
                std::ptr::null_mut();

            let auth_fn = vt.authorize.expect("authorize slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata valid; cert is a stack slice; princ
                // is stack; opts/db_entry null accepted; authinds_out is stack.
                auth_fn(
                    ctx,
                    moddata,
                    der.as_ptr(),
                    der.len(),
                    &princ as *const kurbu5_sys::krb5_principal_data,
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut authinds_out,
                )
            };
            assert_eq!(code, 0, "WithIndicators::authorize must return 0");
            assert!(!authinds_out.is_null(), "authinds_out must be set");

            // Verify the first indicator is "pkinit".
            let first_ptr = unsafe { *authinds_out };
            assert!(!first_ptr.is_null(), "first indicator must not be null");
            let indicator = unsafe {
                // SAFETY: first_ptr was produced by CString::into_raw in
                // write_indicators; it is a valid null-terminated string.
                CStr::from_ptr(first_ptr)
                    .to_str()
                    .expect("indicator is valid UTF-8")
            };
            assert_eq!(indicator, "pkinit");

            // Verify null sentinel after the first entry.
            let sentinel = unsafe { *authinds_out.add(1) };
            assert!(
                sentinel.is_null(),
                "indicator array must be null-terminated"
            );

            // free_ind: release the array allocated by write_indicators.
            let free_fn = vt.free_ind.expect("free_ind slot must be set");
            unsafe {
                // SAFETY: authinds_out was produced by write_indicators via
                // Box::into_raw(boxed_slice) and CString::into_raw for each
                // element.  free_ind is the matching deallocator.
                free_fn(ctx, moddata, authinds_out);
            }

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init_ex.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }
    }
}
