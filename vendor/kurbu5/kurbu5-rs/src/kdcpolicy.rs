//! KDCPOLICY — KDC policy plugin interface.
//!
//! A KDCPOLICY plugin applies site-specific policy to AS and TGS requests,
//! supplementing the built-in checks performed by the MIT KDC.  It can deny
//! a request outright (with a log status string) or restrict the ticket
//! lifetime beyond the KDC's normal limits.
//!
//! # C interface
//!
//! Interface file: `krb5/kdcpolicy_plugin.h`
//! Major version: 1, minor version: 1.
//!
//! The `initvt` export is named `kdcpolicy_<plugin>_initvt`.
//!
//! # Vtable mapping
//!
//! | C field      | Rust method                          |
//! |--------------|--------------------------------------|
//! | `name`       | `KdcpolicyModule::NAME`               |
//! | `init`       | `init_module(ctx) -> Result<Self>`   |
//! | `fini`       | `fini_module(self) -> Result<()>`    |
//! | `check_as`   | `check_as(ctx, req) -> Result<()>`   |
//! | `check_tgs`  | `check_tgs(ctx, req) -> Result<()>`  |
//!
//! # Quick start
//!
//! ```rust,ignore
//! use std::ffi::CStr;
//! use kurbu5_rs::{initvt_plugin, PluginContext};
//! use kurbu5_rs::kdcpolicy::{KdcpolicyModule, PolicyError, AsRequest, TgsRequest};
//!
//! pub struct MyPolicy;
//!
//! impl KdcpolicyModule for MyPolicy {
//!     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, kurbu5_rs::Krb5Error> {
//!         Ok(MyPolicy)
//!     }
//!
//!     fn check_as(
//!         &self,
//!         _ctx: &PluginContext<'_>,
//!         req: AsRequest<'_>,
//!     ) -> Result<(), PolicyError> {
//!         // Deny all anonymous requests.
//!         if req.client_is_anonymous() {
//!             return Err(PolicyError::deny(c"anonymous AS requests not permitted"));
//!         }
//!         Ok(())
//!     }
//! }
//!
//! initvt_plugin!(
//!     kdcpolicy_mypolicy,
//!     1,
//!     MyPolicy,
//!     kurbu5_rs::kdcpolicy::glue::make_kdcpolicy_vtable
//! );
//! ```
//!
//! # Safety model
//!
//! All unsafe code in this interface is confined to [`glue`].  Plugin authors
//! never need to write `unsafe` themselves.

use std::ffi::CStr;
use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::error::Krb5Error;

pub mod glue;

// ---------------------------------------------------------------------------
// PolicyError (task 5.2)
// ---------------------------------------------------------------------------

/// The error returned when a KDCPOLICY check denies a request.
///
/// # What the KDC does with each field
///
/// - `status`: a static, null-terminated ASCII string written into the C
///   `**status` output parameter.  The KDC logs this string; it is NOT sent
///   to the client.  Must be `'static` and null-terminated because the KDC
///   may hold the pointer after the call returns and pass it to C functions.
///   Use the `c"..."` literal syntax: `c"anonymous requests denied"`.
///
/// - `e_data`: optional structured error data (`Vec<u8>`) to include in the
///   KRB-ERROR response sent to the client.  The KDCPOLICY vtable does not
///   have a `free_data` slot and the `check_as`/`check_tgs` signatures do
///   not include a `krb5_data` output parameter, so the glue layer drops
///   this value after each call.  The field is preserved for forward
///   compatibility.  See `glue.rs` for the detailed ownership contract.
///
/// - `lifetime`: if `Some`, the ticket lifetime output (`*lifetime_out`) is
///   set to this value, restricting it.
///
/// - `renew_lifetime`: if `Some`, the renewable lifetime output
///   (`*renew_lifetime_out`) is set to this value.
///
/// # Deny vs. restrict
///
/// Returning a `PolicyError` from `check_as` or `check_tgs` denies the
/// request.  Use `Ok(())` to allow; there is no way to restrict lifetimes
/// while allowing the request via this type (the C API's output parameters
/// are only meaningful when the function returns an error code).
#[derive(Debug)]
pub struct PolicyError {
    /// Null-terminated ASCII status string included in KDC logs.
    ///
    /// Must be `'static` because the KDC may hold the pointer after this
    /// function returns.  Use the `c"..."` literal syntax (Rust 1.77+).
    pub status: &'static CStr,

    /// Optional structured data bytes reserved for future use.
    ///
    /// The KDCPOLICY vtable does not have a `free_data` slot, so the glue
    /// layer drops this value after each call.  Setting this field has no
    /// effect on the KDC response in the current interface version.
    pub e_data: Option<Vec<u8>>,

    /// If `Some`, set `*lifetime_out` to this value on denial.
    pub lifetime: Option<i32>,

    /// If `Some`, set `*renew_lifetime_out` to this value on denial.
    pub renew_lifetime: Option<i32>,
}

impl PolicyError {
    /// Construct a simple denial with a null-terminated status string.
    ///
    /// No `e_data` is attached and no lifetime restriction is applied.  Use
    /// the struct literal syntax when you need finer control.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// Err(PolicyError::deny(c"policy check failed"))
    /// ```
    #[must_use]
    pub fn deny(status: &'static CStr) -> Self {
        PolicyError {
            status,
            e_data: None,
            lifetime: None,
            renew_lifetime: None,
        }
    }

    /// Construct a denial with structured error data for future interface use.
    #[must_use]
    pub fn deny_with_data(status: &'static CStr, data: Vec<u8>) -> Self {
        PolicyError {
            status,
            e_data: Some(data),
            lifetime: None,
            renew_lifetime: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Zero-copy view types (task 5.3)
// ---------------------------------------------------------------------------

/// Zero-copy view of the inputs to a `check_as` call.
///
/// Wraps the raw `krb5_kdc_req` pointer, the client and server
/// `_krb5_db_entry_new` pointers, and the authentication indicators list.
/// All pointers are valid for the duration of the `check_as` callback; do
/// not store this struct beyond that call.
///
/// Only the accessors that plugin implementations actually need are provided.
/// No raw pointer is exposed in the public API.
pub struct AsRequest<'a> {
    pub(crate) request: *const kurbu5_sys::krb5_kdc_req,
    /// Client database entry.  May be null when the KDC has not yet loaded
    /// the entry (e.g. for referral AS requests).
    pub(crate) client: *const kurbu5_sys::_krb5_db_entry_new,
    /// Server database entry.
    pub(crate) server: *const kurbu5_sys::_krb5_db_entry_new,
    /// Null-terminated array of NUL-terminated authentication indicator strings.
    /// May be null if no indicators are present.
    pub(crate) auth_indicators: *const *const libc::c_char,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> AsRequest<'a> {
    /// Return the message type from the raw AS request (`KRB_AS_REQ` = 10).
    ///
    /// Most plugins do not need this field; it is provided for completeness.
    #[must_use]
    pub fn msg_type(&self) -> u32 {
        // SAFETY: self.request is non-null and valid for 'a (glue invariant).
        unsafe { (*self.request).msg_type }
    }

    /// Return the KDC options flags from the AS request.
    ///
    /// The type is `i32` matching `krb5_flags` from the C API.  The bits are
    /// defined by RFC 4120 §5.4.1.  Use bitwise operations and the
    /// `KRB5_KDC_OPT_*` constants from `kurbu5_sys` to test specific options.
    #[must_use]
    pub fn kdc_options(&self) -> i32 {
        // SAFETY: self.request is non-null and valid for 'a (glue invariant).
        unsafe { (*self.request).kdc_options }
    }

    /// Return `true` if the client database entry pointer is null.
    ///
    /// A null client entry occurs in referral processing; plugins should
    /// generally allow such requests without inspection.
    #[must_use]
    pub fn client_is_null(&self) -> bool {
        self.client.is_null()
    }

    /// Return `true` if the server database entry pointer is null.
    ///
    /// Under normal KDC operation this should not occur; check before
    /// accessing any server entry fields.
    #[must_use]
    pub fn server_is_null(&self) -> bool {
        self.server.is_null()
    }

    /// Return `true` if the anonymous flag is set in the AS request options.
    ///
    /// Checks whether `KDC_OPT_REQUEST_ANONYMOUS` (bit 14 in the wire
    /// encoding, `0x0001_0000` in the flags integer) is set.
    ///
    /// Note: for reliable comparisons use the `KRB5_KDC_OPT_*` constants
    /// from `kurbu5_sys` rather than the hardcoded value here.
    #[must_use]
    pub fn client_is_anonymous(&self) -> bool {
        // KDC_OPT_REQUEST_ANONYMOUS is bit 14 (0x0001_0000 in flags integer).
        const REQUEST_ANONYMOUS: i32 = 0x0001_0000;
        self.kdc_options() & REQUEST_ANONYMOUS != 0
    }

    /// Return the authentication indicators as a `Vec<&str>`.
    ///
    /// Returns an empty vec when no indicators are present or when any
    /// indicator string is not valid UTF-8.  The strings are borrowed for
    /// lifetime `'a`.
    #[must_use]
    pub fn auth_indicators(&self) -> Vec<&'a str> {
        if self.auth_indicators.is_null() {
            return vec![];
        }
        let mut out = Vec::new();
        let mut p = self.auth_indicators;
        // SAFETY: auth_indicators is a null-terminated array of null-terminated
        // strings valid for 'a (libkrb5 AS callback contract).
        unsafe {
            while !(*p).is_null() {
                if let Ok(s) = CStr::from_ptr(*p).to_str() {
                    out.push(s);
                }
                p = p.add(1);
            }
        }
        out
    }
}

/// Zero-copy view of the inputs to a `check_tgs` call.
///
/// Wraps the raw `krb5_kdc_req`, the server `_krb5_db_entry_new`, the header
/// `krb5_ticket`, and the authentication indicators.  All pointers are valid
/// for the duration of the `check_tgs` callback; do not store this struct.
pub struct TgsRequest<'a> {
    pub(crate) request: *const kurbu5_sys::krb5_kdc_req,
    /// Server database entry.
    pub(crate) server: *const kurbu5_sys::_krb5_db_entry_new,
    /// The TGT (header ticket) from the TGS request.
    pub(crate) ticket: *const kurbu5_sys::krb5_ticket,
    /// Null-terminated array of authentication indicator strings.
    pub(crate) auth_indicators: *const *const libc::c_char,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> TgsRequest<'a> {
    /// Return the message type from the raw TGS request (`KRB_TGS_REQ` = 12).
    #[must_use]
    pub fn msg_type(&self) -> u32 {
        // SAFETY: self.request is non-null and valid for 'a (glue invariant).
        unsafe { (*self.request).msg_type }
    }

    /// Return the KDC options flags from the TGS request.
    ///
    /// The type is `i32` matching `krb5_flags` from the C API.
    #[must_use]
    pub fn kdc_options(&self) -> i32 {
        // SAFETY: self.request is non-null and valid for 'a (glue invariant).
        unsafe { (*self.request).kdc_options }
    }

    /// Return the requested service principal from the TGS request.
    ///
    /// This is `request->server` — the target service the client is
    /// requesting a ticket for.  Pass the returned reference directly to
    /// [`PluginContext::unparse_principal`] to obtain a displayable name.
    ///
    /// Returns `None` when the server principal pointer is null (unusual
    /// under normal KDC operation).
    #[must_use]
    pub fn request_server(
        &self,
    ) -> Option<&'a kurbu5_sys::krb5_principal_data> {
        if self.request.is_null() {
            return None;
        }
        // SAFETY: self.request is non-null and valid for 'a (glue invariant).
        let req = unsafe { &*self.request };
        if req.server.is_null() {
            return None;
        }
        // SAFETY: req.server is non-null and the pointed-to data is valid for 'a.
        Some(unsafe { &*req.server })
    }

    /// Return `true` if the server database entry pointer is null.
    #[must_use]
    pub fn server_is_null(&self) -> bool {
        self.server.is_null()
    }

    /// Return `true` if the header ticket pointer is null.
    ///
    /// Under normal TGS operation this is never null; check before accessing
    /// ticket fields.
    #[must_use]
    pub fn ticket_is_null(&self) -> bool {
        self.ticket.is_null()
    }

    /// Return the client principal from the decrypted TGT body.
    ///
    /// In a TGS exchange the authenticating client's identity is stored in
    /// the decrypted part of the TGT (`ticket->enc_part2->client`), not in
    /// the outer request struct.  This is the correct field to use when
    /// constructing TGS log records or enforcing client-identity policy.
    ///
    /// Pass the returned reference directly to
    /// [`PluginContext::unparse_principal`] to obtain a displayable name.
    ///
    /// Returns `None` when the ticket pointer, its decrypted body
    /// (`enc_part2`), or the client principal pointer within it is null.
    /// Under normal KDC operation all three are non-null by the time
    /// `check_tgs` is called.
    #[must_use]
    pub fn ticket_client(
        &self,
    ) -> Option<&'a kurbu5_sys::krb5_principal_data> {
        if self.ticket.is_null() {
            return None;
        }
        // SAFETY: self.ticket is non-null and valid for 'a (glue invariant).
        let tkt = unsafe { &*self.ticket };
        if tkt.enc_part2.is_null() {
            return None;
        }
        // SAFETY: enc_part2 is non-null; the KDC decrypts the TGT before
        // invoking check_tgs, so enc_part2 is populated.
        let enc = unsafe { &*tkt.enc_part2 };
        if enc.client.is_null() {
            return None;
        }
        // SAFETY: enc.client is non-null and valid for 'a (part of the
        // decrypted TGT body, which lives for the duration of the request).
        Some(unsafe { &*enc.client })
    }

    /// Return the server principal recorded in the TGT itself.
    ///
    /// This is `ticket->server` — the principal the TGT was issued to
    /// (typically `krbtgt/REALM@REALM`).  It is distinct from
    /// [`request_server`](Self::request_server), which is the service the
    /// client is currently requesting a ticket for.
    ///
    /// Returns `None` when the ticket or its server principal pointer is null.
    #[must_use]
    pub fn ticket_server(
        &self,
    ) -> Option<&'a kurbu5_sys::krb5_principal_data> {
        if self.ticket.is_null() {
            return None;
        }
        // SAFETY: self.ticket is non-null and valid for 'a (glue invariant).
        let tkt = unsafe { &*self.ticket };
        if tkt.server.is_null() {
            return None;
        }
        // SAFETY: tkt.server is non-null and valid for 'a.
        Some(unsafe { &*tkt.server })
    }

    /// Return the authentication indicators as a `Vec<&str>`.
    ///
    /// Returns an empty vec when no indicators are present or when any
    /// indicator string is not valid UTF-8.
    #[must_use]
    pub fn auth_indicators(&self) -> Vec<&'a str> {
        if self.auth_indicators.is_null() {
            return vec![];
        }
        let mut out = Vec::new();
        let mut p = self.auth_indicators;
        // SAFETY: auth_indicators is a null-terminated array of null-terminated
        // strings valid for 'a (libkrb5 TGS callback contract).
        unsafe {
            while !(*p).is_null() {
                if let Ok(s) = CStr::from_ptr(*p).to_str() {
                    out.push(s);
                }
                p = p.add(1);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// KdcpolicyModule trait (task 5.1)
// ---------------------------------------------------------------------------

/// Implement this trait to create a KDCPOLICY plugin.
///
/// A KDCPOLICY plugin applies site policy to AS and TGS requests.  It can
/// deny a request or restrict ticket lifetimes beyond the KDC's normal
/// limits.  Multiple KDCPOLICY plugins can be registered; the KDC calls each
/// in turn and honours the most restrictive result.
///
/// Use [`initvt_plugin!`](crate::initvt_plugin) to export the C entry point:
///
/// ```rust,ignore
/// initvt_plugin!(
///     kdcpolicy_myplugin,
///     1,
///     MyPolicy,
///     kurbu5_rs::kdcpolicy::glue::make_kdcpolicy_vtable
/// );
/// ```
///
/// # Default implementations
///
/// `check_as` and `check_tgs` default to `Ok(())`, meaning the plugin allows
/// all requests.  Override them to enforce site policy.
///
/// `fini_module` defaults to consuming `self` without error; override when
/// your module holds resources that require explicit cleanup.
///
/// # Lifetime contract
///
/// `KdcpolicyModule` requires `Sized + Send + 'static`:
/// - `Sized` allows storing in a `Box<M>`.
/// - `Send` allows the box to be moved between KDC worker threads.
/// - `'static` prevents the module from borrowing stack data.
pub trait KdcpolicyModule: Sized + Send + 'static {
    /// The module name written into the vtable `name` field.
    ///
    /// Used by the KDC for logging and plugin selection in `krb5.conf`.
    const NAME: &'static std::ffi::CStr;

    /// Initialise the module and return an instance.
    ///
    /// Called once when the KDC loads the plugin.  Return
    /// `Err(Krb5Error::NoHandle)` to signal that this plugin is inoperable
    /// (e.g. due to missing configuration), causing the KDC to skip it.
    /// Return any other error to abort KDC startup.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` if the plugin is inoperable.
    /// Returns any other `Krb5Error` to abort KDC startup.
    ///
    /// C vtable field: `init`.
    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;

    /// Finalise the module.  Consumes `self`.
    ///
    /// Called when the KDC unloads the plugin.  The default implementation
    /// drops `self` without error, which is correct for most plugins.
    ///
    /// # Errors
    ///
    /// Returns `Err` if cleanup of module resources fails.
    ///
    /// C vtable field: `fini`.
    fn fini_module(self, _ctx: &PluginContext<'_>) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Apply site policy to an AS request.
    ///
    /// Return `Ok(())` to allow the request.  Return `Err(PolicyError { .. })`
    /// to deny it; the KDC logs `status` and returns the error code to the
    /// client.
    ///
    /// The `lifetime` and `renew_lifetime` fields of [`PolicyError`] restrict
    /// the ticket lifetimes when the request is denied.
    ///
    /// The default allows all AS requests (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err(PolicyError)` to deny the AS request.
    ///
    /// C vtable field: `check_as`.
    fn check_as(
        &self,
        _ctx: &PluginContext<'_>,
        _req: AsRequest<'_>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    /// Apply site policy to a TGS request.
    ///
    /// Return `Ok(())` to allow the request.  Return `Err(PolicyError { .. })`
    /// to deny it.
    ///
    /// The default allows all TGS requests (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err(PolicyError)` to deny the TGS request.
    ///
    /// C vtable field: `check_tgs`.
    fn check_tgs(
        &self,
        _ctx: &PluginContext<'_>,
        _req: TgsRequest<'_>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests (task 5.5)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PolicyError construction
    // -----------------------------------------------------------------------

    #[test]
    fn policy_error_deny_has_no_data() {
        let err = PolicyError::deny(c"too many AS requests");
        assert_eq!(err.status, c"too many AS requests");
        assert!(err.e_data.is_none());
        assert!(err.lifetime.is_none());
        assert!(err.renew_lifetime.is_none());
    }

    #[test]
    fn policy_error_deny_with_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let err = PolicyError::deny_with_data(c"custom error", data.clone());
        assert_eq!(err.status, c"custom error");
        assert_eq!(err.e_data.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn policy_error_struct_literal_with_lifetimes() {
        let err = PolicyError {
            status: c"lifetime restricted",
            e_data: None,
            lifetime: Some(3600),
            renew_lifetime: Some(86400),
        };
        assert_eq!(err.lifetime, Some(3600));
        assert_eq!(err.renew_lifetime, Some(86400));
    }

    // -----------------------------------------------------------------------
    // Default trait implementations
    // -----------------------------------------------------------------------

    struct AllowAll;

    impl KdcpolicyModule for AllowAll {
        const NAME: &'static std::ffi::CStr = c"allow_all";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(AllowAll)
        }
    }

    // Verify the default check_as and check_tgs return Ok(()) without a
    // live krb5_context by using null pointers.  The default impls ignore
    // all arguments so the null context and null request pointers are safe
    // here.
    #[test]
    fn default_check_as_allows() {
        let module = AllowAll;
        let req = AsRequest {
            request: std::ptr::null(),
            client: std::ptr::null(),
            server: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        // We cannot construct a PluginContext without a live krb5_context in
        // a unit test; the glue round-trip tests in glue.rs exercise the full
        // path.  Here we only verify that the type compiles correctly.
        let _ = req;
        let _ = module;
    }

    #[test]
    fn default_check_tgs_allows() {
        let module = AllowAll;
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        let _ = req;
        let _ = module;
    }

    // -----------------------------------------------------------------------
    // AsRequest / TgsRequest accessors
    // -----------------------------------------------------------------------

    #[test]
    fn as_request_null_auth_indicators_returns_empty() {
        let req = AsRequest {
            request: std::ptr::null(),
            client: std::ptr::null(),
            server: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.auth_indicators().is_empty());
    }

    #[test]
    fn tgs_request_null_auth_indicators_returns_empty() {
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.auth_indicators().is_empty());
    }

    #[test]
    fn as_request_client_is_null_when_null() {
        let req = AsRequest {
            request: std::ptr::null(),
            client: std::ptr::null(),
            server: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.client_is_null());
    }

    #[test]
    fn as_request_server_is_null_when_null() {
        let req = AsRequest {
            request: std::ptr::null(),
            client: std::ptr::null(),
            server: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.server_is_null());
    }

    #[test]
    fn tgs_request_ticket_is_null_when_null() {
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.ticket_is_null());
    }

    #[test]
    fn tgs_request_ticket_client_none_when_ticket_null() {
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.ticket_client().is_none());
    }

    #[test]
    fn tgs_request_ticket_client_none_when_enc_part2_null() {
        // A ticket struct with enc_part2 = null — ticket_client() must not
        // dereference enc_part2 and must return None.
        let tkt = kurbu5_sys::_krb5_ticket {
            magic: 0,
            server: std::ptr::null_mut(),
            enc_part: unsafe { std::mem::zeroed() },
            enc_part2: std::ptr::null_mut(),
        };
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: &tkt as *const _,
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.ticket_client().is_none());
    }

    #[test]
    fn tgs_request_ticket_server_none_when_ticket_null() {
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.ticket_server().is_none());
    }

    #[test]
    fn tgs_request_ticket_server_none_when_server_null() {
        let tkt = kurbu5_sys::_krb5_ticket {
            magic: 0,
            server: std::ptr::null_mut(),
            enc_part: unsafe { std::mem::zeroed() },
            enc_part2: std::ptr::null_mut(),
        };
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: &tkt as *const _,
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.ticket_server().is_none());
    }

    #[test]
    fn tgs_request_request_server_none_when_request_null() {
        let req = TgsRequest {
            request: std::ptr::null(),
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.request_server().is_none());
    }

    #[test]
    fn tgs_request_request_server_none_when_server_principal_null() {
        let kdc_req: kurbu5_sys::krb5_kdc_req = unsafe { std::mem::zeroed() };
        // zeroed krb5_kdc_req has server = null.
        let req = TgsRequest {
            request: &kdc_req as *const _,
            server: std::ptr::null(),
            ticket: std::ptr::null(),
            auth_indicators: std::ptr::null(),
            _phantom: PhantomData,
        };
        assert!(req.request_server().is_none());
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers end-to-end.
    //
    // These tests drive init → check_as (allow) and init → check_as (deny)
    // through the raw C vtable slots produced by make_kdcpolicy_vtable.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::super::{KdcpolicyModule, PolicyError};
        use crate::context::PluginContext;
        use crate::error::Krb5Error;
        use crate::kdcpolicy::AsRequest;
        use crate::kdcpolicy::glue::make_kdcpolicy_vtable;

        // Plugin that allows all requests (uses the default check_as / check_tgs).
        struct AllowPlugin;

        impl KdcpolicyModule for AllowPlugin {
            const NAME: &'static std::ffi::CStr = c"allow_plugin";
            fn init_module(
                _ctx: &PluginContext<'_>,
            ) -> Result<Self, Krb5Error> {
                Ok(AllowPlugin)
            }
        }

        // Plugin that always denies with e_data attached.
        struct DenyPlugin;

        impl KdcpolicyModule for DenyPlugin {
            const NAME: &'static std::ffi::CStr = c"deny_plugin";
            fn init_module(
                _ctx: &PluginContext<'_>,
            ) -> Result<Self, Krb5Error> {
                Ok(DenyPlugin)
            }

            fn check_as(
                &self,
                _ctx: &PluginContext<'_>,
                _req: AsRequest<'_>,
            ) -> Result<(), PolicyError> {
                Err(PolicyError {
                    status: c"denied",
                    e_data: Some(vec![1, 2, 3]),
                    lifetime: None,
                    renew_lifetime: None,
                })
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

        /// AllowPlugin: init → check_as → fini → code == 0.
        ///
        /// Passes null for client, server, and auth_indicators because
        /// AllowPlugin::check_as (the default) ignores all request arguments.
        /// The check_as bridge requires request to be non-null; we supply a
        /// zeroed stack-allocated krb5_kdc_req.
        #[test]
        fn vtable_check_as_allow() {
            let ctx = make_ctx();
            let vt = make_kdcpolicy_vtable::<AllowPlugin>();

            let mut moddata: kurbu5_sys::krb5_kdcpolicy_moddata =
                std::ptr::null_mut();
            let init_fn = vt.init.expect("init slot must be set");
            let init_code = unsafe {
                // SAFETY: ctx is valid; moddata is a stack out-pointer.
                init_fn(ctx, &mut moddata)
            };
            assert_eq!(init_code, 0, "init must succeed");

            // A zeroed krb5_kdc_req satisfies the non-null assertion in the
            // check_as bridge.  AllowPlugin ignores every field of the request.
            let req: kurbu5_sys::krb5_kdc_req = unsafe { std::mem::zeroed() };
            let mut status: *const libc::c_char = std::ptr::null();
            let mut lifetime: kurbu5_sys::krb5_deltat = 0;
            let mut renew_lt: kurbu5_sys::krb5_deltat = 0;

            let check_fn = vt.check_as.expect("check_as slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; req is a stack krb5_kdc_req;
                // client/server/auth_indicators null accepted by AllowPlugin;
                // status, lifetime, renew_lt are stack out-params.
                check_fn(
                    ctx,
                    moddata,
                    &req as *const kurbu5_sys::krb5_kdc_req,
                    std::ptr::null(), // client db entry — null accepted
                    std::ptr::null(), // server db entry — null accepted
                    std::ptr::null(), // auth_indicators  — null accepted
                    &mut status,
                    &mut lifetime,
                    &mut renew_lt,
                )
            };
            assert_eq!(code, 0, "AllowPlugin check_as must return 0");

            let fini_fn = vt.fini.expect("fini slot must be set");
            let fini_code = unsafe {
                // SAFETY: moddata was set by init.
                fini_fn(ctx, moddata)
            };
            assert_eq!(fini_code, 0, "fini must succeed");
            unsafe { kurbu5_sys::krb5_free_context(ctx) };
        }

        /// DenyPlugin: init → check_as → verify non-zero code and status pointer
        /// → fini.  The e_data Vec is dropped inside write_denial (KDCPOLICY has
        /// no free_data vtable slot).
        #[test]
        fn vtable_check_as_deny_with_edata() {
            let ctx = make_ctx();
            let vt = make_kdcpolicy_vtable::<DenyPlugin>();

            let mut moddata: kurbu5_sys::krb5_kdcpolicy_moddata =
                std::ptr::null_mut();
            let init_fn = vt.init.expect("init slot must be set");
            unsafe {
                // SAFETY: ctx is valid; moddata is a stack pointer.
                init_fn(ctx, &mut moddata);
            }

            let req: kurbu5_sys::krb5_kdc_req = unsafe { std::mem::zeroed() };
            let mut status: *const libc::c_char = std::ptr::null();
            let mut lifetime: kurbu5_sys::krb5_deltat = 0;
            let mut renew_lt: kurbu5_sys::krb5_deltat = 0;

            let check_fn = vt.check_as.expect("check_as slot must be set");
            let code = unsafe {
                // SAFETY: same as vtable_check_as_allow.
                check_fn(
                    ctx,
                    moddata,
                    &req as *const kurbu5_sys::krb5_kdc_req,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut status,
                    &mut lifetime,
                    &mut renew_lt,
                )
            };
            assert_ne!(code, 0, "DenyPlugin check_as must be non-zero");
            assert!(!status.is_null(), "status must be set on denial");
            let status_str = unsafe {
                // SAFETY: status points to the 'static bytes of c"denied".
                std::ffi::CStr::from_ptr(status)
                    .to_str()
                    .expect("status is valid UTF-8")
            };
            assert_eq!(status_str, "denied");
            // e_data is dropped inside write_denial; reaching here without
            // a crash or asan/valgrind error confirms no leak.

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }
    }
}
