//! AUDIT — KDC audit plugin interface.
//!
//! An AUDIT plugin allows the MIT KDC to produce log output or audit records
//! in any desired form.  Multiple AUDIT plugins can be registered; the KDC
//! calls each in turn for every auditable event.
//!
//! # Stability warning
//!
//! **This is a private MIT Kerberos interface and may change incompatibly
//! between versions.**  The upstream header comment in `audit_plugin.h` states:
//! "NOTE: This is a private interface and may change incompatibly between
//! versions."  This crate vendors the header at the version in use when the
//! crate was built; shipping a plugin based on this interface against a
//! different MIT Kerberos minor release may require a rebuild.
//!
//! # C interface
//!
//! Interface file: `krb5/audit_plugin.h` (private; vendored under
//! `kurbu5-sys/include/krb5/audit_plugin.h`)
//! Major version: 1, minor version: 1.
//!
//! The `initvt` export is named `audit_<plugin>_initvt`.
//!
//! Unlike most other plugin interfaces, audit callbacks do **not** receive a
//! `krb5_context`.  Each callback receives only the opaque module data pointer
//! (`krb5_audit_moddata`) that was set up by `open`.
//!
//! # Vtable mapping
//!
//! | C field         | Rust method                                                           |
//! |-----------------|-----------------------------------------------------------------------|
//! | `name`          | `AuditModule::NAME`                                                   |
//! | `open`          | `open() -> Result<Self, Krb5Error>`                                   |
//! | `close`         | `close(self) -> Result<(), Krb5Error>`                                |
//! | `kdc_start`     | `kdc_start(success: bool) -> Result<(), Krb5Error>`                   |
//! | `kdc_stop`      | `kdc_stop(success: bool) -> Result<(), Krb5Error>`                    |
//! | `as_req`        | `as_req(success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error>`        |
//! | `tgs_req`       | `tgs_req(success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error>`       |
//! | `tgs_s4u2self`  | `tgs_s4u2self(success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error>`  |
//! | `tgs_s4u2proxy` | `tgs_s4u2proxy(success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error>` |
//! | `tgs_u2u`       | `tgs_u2u(success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error>`       |
//!
//! # Quick start
//!
//! ```rust,ignore
//! use std::ffi::CStr;
//! use kurbu5_rs::{initvt_plugin, Krb5Error};
//! use kurbu5_rs::audit::{AuditModule, AuditStateRef};
//!
//! pub struct MyAudit;
//!
//! impl AuditModule for MyAudit {
//!     const NAME: &'static CStr = c"myaudit";
//!
//!     fn open() -> Result<Self, Krb5Error> {
//!         Ok(MyAudit)
//!     }
//!
//!     fn tgs_req(
//!         &self,
//!         success: bool,
//!         state: AuditStateRef<'_>,
//!     ) -> Result<(), Krb5Error> {
//!         eprintln!("tgs_req: success={} req_id={}", success, state.req_id());
//!         Ok(())
//!     }
//! }
//!
//! initvt_plugin!(
//!     audit_myaudit,
//!     1,
//!     MyAudit,
//!     kurbu5_rs::audit::glue::make_audit_vtable
//! );
//! ```
//!
//! # Safety model
//!
//! All unsafe code in this interface is confined to [`glue`].  Plugin authors
//! never need to write `unsafe` themselves.

use std::ffi::CStr;
use std::marker::PhantomData;

use crate::error::Krb5Error;

pub mod glue;

// ---------------------------------------------------------------------------
// AuditStateRef — zero-copy view of krb5_audit_state
// ---------------------------------------------------------------------------

/// Zero-copy view of the KDC audit state structure.
///
/// Wraps a `*const krb5_audit_state` (the `_krb5_audit_state` struct from
/// bindgen).  All pointers inside the state are valid for the duration of the
/// callback that passes this value; do not store `AuditStateRef` beyond the
/// call.
///
/// Accessors for the simple scalar and string fields are provided as safe
/// methods.  Raw pointer fields for complex structures (`request`, `reply`,
/// `cl_addr`, `cl_realm`, `s4u2self_user`) are exposed as `*_raw` methods
/// returning the C pointer; callers must handle their lifetimes carefully.
///
/// # Lifetime `'a`
///
/// `'a` binds `AuditStateRef` to the lifetime of the data pointed to by the
/// C pointer.  The KDC guarantees all state fields are valid for the duration
/// of the callback invocation.
pub struct AuditStateRef<'a> {
    pub(crate) ptr: *const kurbu5_sys::_krb5_audit_state,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> AuditStateRef<'a> {
    /// The current KDC processing stage.
    ///
    /// The value is one of the constants from `kurbu5_sys`:
    /// - `AUTHN_REQ_CL` (1): authenticate request and client.
    /// - `SRVC_PRINC` (2): determine service principal.
    /// - `VALIDATE_POL` (3): validate local and protocol policies.
    /// - `ISSUE_TKT` (4): issue ticket.
    /// - `ENCR_REP` (5): encrypt reply.
    ///
    /// C field: `stage`.
    #[must_use]
    pub fn stage(&self) -> i32 {
        // SAFETY: self.ptr is non-null and valid for 'a (glue invariant).
        unsafe { (*self.ptr).stage }
    }

    /// The KDC status message, if available.
    ///
    /// Returns `None` if the `status` pointer is null (not yet set, or not
    /// applicable for this event) or if the string is not valid UTF-8.
    /// The string describes the outcome of the KDC processing step (e.g.
    /// `"NEEDED_PREAUTH"`, `"ISSUE"`, `"CLIENT_NOT_FOUND"`).
    ///
    /// C field: `status`.
    #[must_use]
    pub fn status(&self) -> Option<&'a str> {
        // SAFETY: self.ptr is non-null and valid for 'a (glue invariant).
        let p = unsafe { (*self.ptr).status };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a non-null null-terminated C string valid for 'a.
        unsafe { CStr::from_ptr(p).to_str().ok() }
    }

    /// The alphanumeric request identifier (up to `REQID_LEN` = 32 chars).
    ///
    /// This is a fixed-size `char[REQID_LEN]` array embedded in the state
    /// struct (not a pointer).  The KDC assigns a unique request ID to each
    /// request; plugins use it to correlate log entries for the same request
    /// across multiple audit events.  Returns `""` if the array contains
    /// bytes that are not valid UTF-8.
    ///
    /// C field: `req_id`.
    #[must_use]
    pub fn req_id(&self) -> &'a str {
        // SAFETY: self.ptr is non-null and valid for 'a.  req_id is a
        // null-terminated fixed array of REQID_LEN (32) chars embedded in
        // the state struct; reading it is always safe.
        let arr: &'a [libc::c_char; 32] = unsafe { &(*self.ptr).req_id };
        // Find the null terminator.
        let len = arr.iter().take_while(|&&c| c != 0).count();
        // SAFETY: arr.as_ptr() is non-null and valid for 'a.  `len` bytes
        // were all non-null (< 128 for ASCII) so the slice is valid UTF-8
        // if the bytes are ASCII.  If not, fall back to "".
        let bytes = unsafe {
            std::slice::from_raw_parts(arr.as_ptr().cast::<u8>(), len)
        };
        std::str::from_utf8(bytes).unwrap_or("")
    }

    /// The client port number.
    ///
    /// Recorded as a 32-bit unsigned integer (`krb5_ui_4`).  Set to 0 when
    /// unavailable (e.g. UNIX socket connections).
    ///
    /// C field: `cl_port`.
    #[must_use]
    pub fn cl_port(&self) -> u32 {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).cl_port }
    }

    /// The policy violation type, if any.
    ///
    /// Returns 0 when no violation was recorded.  Non-zero values are:
    /// - `PROT_CONSTRAINT` (1): a Kerberos protocol constraint violation.
    /// - `LOCAL_POLICY` (2): a local policy violation.
    ///
    /// Both constants are available in `kurbu5_sys`.
    ///
    /// C field: `violation`.
    #[must_use]
    pub fn violation(&self) -> i32 {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).violation }
    }

    /// The primary (TGT) ticket ID string, if set.
    ///
    /// Returns `None` if the `tkt_in_id` pointer is null or the string is not
    /// valid UTF-8.  The ticket ID is a malloc'd C string; its data is valid
    /// for lifetime `'a`.
    ///
    /// C field: `tkt_in_id`.
    #[must_use]
    pub fn tkt_in_id(&self) -> Option<&'a str> {
        // SAFETY: self.ptr is non-null and valid for 'a.
        let p = unsafe { (*self.ptr).tkt_in_id };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a non-null null-terminated C string valid for 'a.
        unsafe { CStr::from_ptr(p).to_str().ok() }
    }

    /// The derived (service or referral TGT) ticket ID string, if set.
    ///
    /// Returns `None` if the `tkt_out_id` pointer is null or the string is not
    /// valid UTF-8.
    ///
    /// C field: `tkt_out_id`.
    #[must_use]
    pub fn tkt_out_id(&self) -> Option<&'a str> {
        // SAFETY: self.ptr is non-null and valid for 'a.
        let p = unsafe { (*self.ptr).tkt_out_id };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a non-null null-terminated C string valid for 'a.
        unsafe { CStr::from_ptr(p).to_str().ok() }
    }

    /// The evidence ticket ID (S4U2PROXY) or second ticket ID (U2U), if set.
    ///
    /// Returns `None` if the `evid_tkt_id` pointer is null or the string is
    /// not valid UTF-8.
    ///
    /// C field: `evid_tkt_id`.
    #[must_use]
    pub fn evid_tkt_id(&self) -> Option<&'a str> {
        // SAFETY: self.ptr is non-null and valid for 'a.
        let p = unsafe { (*self.ptr).evid_tkt_id };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a non-null null-terminated C string valid for 'a.
        unsafe { CStr::from_ptr(p).to_str().ok() }
    }

    /// The raw pointer to the KDC request struct (`krb5_kdc_req`).
    ///
    /// May be null.  When non-null, the pointed-to data is valid for lifetime
    /// `'a`.  Plugins that need to inspect the full request must check for
    /// null and use `unsafe` to dereference.
    ///
    /// C field: `request`.
    #[must_use]
    pub fn request_raw(&self) -> *const kurbu5_sys::krb5_kdc_req {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).request }
    }

    /// The raw pointer to the KDC reply struct (`krb5_kdc_rep`).
    ///
    /// Null before the reply has been constructed (i.e. before the `ENCR_REP`
    /// stage).  When non-null, valid for lifetime `'a`.
    ///
    /// C field: `reply`.
    #[must_use]
    pub fn reply_raw(&self) -> *const kurbu5_sys::krb5_kdc_rep {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).reply }
    }

    /// The raw pointer to the client address struct (`krb5_address`).
    ///
    /// May be null (e.g. UNIX domain socket connections).  When non-null,
    /// valid for lifetime `'a`.
    ///
    /// C field: `cl_addr`.
    #[must_use]
    pub fn cl_addr_raw(&self) -> *const kurbu5_sys::krb5_address {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).cl_addr }
    }

    /// The raw pointer to the client realm data (`krb5_data`), for referrals.
    ///
    /// Only set during referral processing (remote client's realm); null for
    /// non-referral requests.  When non-null, valid for lifetime `'a`.
    ///
    /// C field: `cl_realm`.
    #[must_use]
    pub fn cl_realm_raw(&self) -> *const kurbu5_sys::krb5_data {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).cl_realm }
    }

    /// The raw `krb5_principal` for the impersonated user (S4U2SELF).
    ///
    /// Only set for S4U2SELF events; null for other event types.  When
    /// non-null, valid for lifetime `'a`.
    ///
    /// C field: `s4u2self_user`.
    #[must_use]
    pub fn s4u2self_user_raw(&self) -> kurbu5_sys::krb5_principal {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).s4u2self_user }
    }
}

// ---------------------------------------------------------------------------
// AuditModule trait
// ---------------------------------------------------------------------------

/// Implement this trait to create an AUDIT plugin.
///
/// An AUDIT plugin receives callbacks for every auditable KDC event.  It is
/// responsible for opening a connection to the audit subsystem in [`open`] and
/// closing it in [`close`].  All other methods are optional and default to a
/// no-op returning `Ok(())`.
///
/// Unlike most other plugin interfaces, audit callbacks do **not** receive a
/// `krb5_context`.  The only Kerberos state available to callbacks is what
/// the plugin stored in `Self` during [`open`].
///
/// Use [`initvt_plugin!`](crate::initvt_plugin) to export the C entry point.
/// The symbol prefix for audit plugins is `audit_<name>`, so:
///
/// ```rust,ignore
/// initvt_plugin!(
///     audit_myplugin,
///     1,
///     MyAudit,
///     kurbu5_rs::audit::glue::make_audit_vtable
/// );
/// // Exports C symbol: audit_myplugin_initvt
/// ```
///
/// # Default implementations
///
/// All methods except [`open`] have default implementations.  [`close`]
/// defaults to consuming `self` without error, which is correct for plugins
/// with no explicit teardown.  All event notification methods (`kdc_start`,
/// `kdc_stop`, `as_req`, `tgs_req`, `tgs_s4u2self`, `tgs_s4u2proxy`,
/// `tgs_u2u`) default to `Ok(())` — a silent no-op.
///
/// # Lifetime contract
///
/// `AuditModule` requires `Sized + Send + 'static`:
/// - `Sized` allows storing in a `Box<M>`.
/// - `Send` allows the box to be moved between KDC worker threads.
/// - `'static` prevents the module from borrowing stack data.
///
/// [`open`]: AuditModule::open
/// [`close`]: AuditModule::close
pub trait AuditModule: Sized + Send + 'static {
    /// The module name written into the vtable `name` field.
    ///
    /// The KDC uses this string for logging and plugin selection in
    /// `krb5.conf`.  Must be a null-terminated `CStr` literal; use the
    /// `c"..."` syntax (Rust 1.77+).
    ///
    /// C vtable field: `name`.
    const NAME: &'static CStr;

    /// Open a connection to the audit subsystem and initialise the module.
    ///
    /// Called once when the KDC loads the plugin.  If this returns `Err`,
    /// the KDC will not invoke any other callbacks on this module instance.
    /// Return `Err(Krb5Error::NoHandle)` to signal that this plugin is
    /// inoperable but other registered plugins should still be tried.
    ///
    /// The C header states: "If the underlying (OS or third party) audit
    /// facility fails to open, no auditable KDC events should be recorded."
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` if this plugin is inoperable.
    /// Returns any other `Err` if opening the audit facility fails.
    ///
    /// C vtable field: `open`.
    fn open() -> Result<Self, Krb5Error>;

    /// Close the connection to the audit subsystem.  Consumes `self`.
    ///
    /// Called when the KDC unloads the plugin.  The default implementation
    /// drops `self` without error, which is correct for most plugins.
    ///
    /// # Errors
    ///
    /// Returns `Err` if closing the audit facility fails.
    ///
    /// C vtable field: `close`.
    fn close(self) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log a KDC-start event.
    ///
    /// Called when the KDC process starts up.  `success` is `true` when
    /// startup completed successfully, `false` if the KDC is about to abort.
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the KDC-start event fails.
    ///
    /// C vtable field: `kdc_start`.
    fn kdc_start(&self, _success: bool) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log a KDC-stop event.
    ///
    /// Called when the KDC process shuts down.  `success` is `true` for a
    /// clean shutdown, `false` when the KDC is terminating abnormally.
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the KDC-stop event fails.
    ///
    /// C vtable field: `kdc_stop`.
    fn kdc_stop(&self, _success: bool) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log an AS exchange event.
    ///
    /// Called after each AS request is processed.  `success` is `true` when
    /// a ticket was issued.
    ///
    /// `state` provides: the request, assigned request ID, client address and
    /// port, processing stage, KDC status string, referral realm (if
    /// applicable), and the issued TGT ticket ID (if available).
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the AS exchange event fails.
    ///
    /// C vtable field: `as_req`.
    fn as_req(
        &self,
        _success: bool,
        _state: AuditStateRef<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log a TGS exchange event.
    ///
    /// Called after each TGS request is processed.  `success` is `true` when
    /// a service ticket was issued.
    ///
    /// `state` provides: the request, primary TGT ticket ID, client address
    /// and port, request ID, processing stage, KDC status, KDC reply (if
    /// available), and the output ticket ID (if available).
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the TGS exchange event fails.
    ///
    /// C vtable field: `tgs_req`.
    fn tgs_req(
        &self,
        _success: bool,
        _state: AuditStateRef<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log an S4U2SELF (Service-for-User-to-Self) event.
    ///
    /// Called after an S4U2SELF TGS exchange.  `success` is `true` when the
    /// service ticket was issued.
    ///
    /// `state` provides: the request, requesting server's TGT ID, the
    /// impersonated user principal (`s4u2self_user`), the service or referral
    /// TGT ticket ID, and any policy violation recorded.
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the S4U2SELF event fails.
    ///
    /// C vtable field: `tgs_s4u2self`.
    fn tgs_s4u2self(
        &self,
        _success: bool,
        _state: AuditStateRef<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log an S4U2PROXY (Service-for-User-to-Proxy) event.
    ///
    /// Called after an S4U2PROXY TGS exchange.  `success` is `true` when the
    /// service ticket was issued.
    ///
    /// `state` provides: the request, requesting server's TGT ID, the
    /// delegated user principal name, the evidence ticket ID (`evid_tkt_id`),
    /// and any recorded policy violation.
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the S4U2PROXY event fails.
    ///
    /// C vtable field: `tgs_s4u2proxy`.
    fn tgs_s4u2proxy(
        &self,
        _success: bool,
        _state: AuditStateRef<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Log a User-to-User (U2U) TGS exchange event.
    ///
    /// Called after a U2U TGS request.  `success` is `true` when the service
    /// ticket was issued.
    ///
    /// `state` provides: the requestor's TGT ID, the service ticket ID
    /// (stored in `evid_tkt_id`), the client principal from the second ticket,
    /// and the KDC status (if available).
    ///
    /// The default is a silent no-op (`Ok(())`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if logging the U2U event fails.
    ///
    /// C vtable field: `tgs_u2u`.
    fn tgs_u2u(
        &self,
        _success: bool,
        _state: AuditStateRef<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal no-op module for testing default implementations
    // -----------------------------------------------------------------------

    struct NoopAudit;

    impl AuditModule for NoopAudit {
        const NAME: &'static CStr = c"noop_audit";
        fn open() -> Result<Self, Krb5Error> {
            Ok(NoopAudit)
        }
    }

    // -----------------------------------------------------------------------
    // Construction and NAME constant
    // -----------------------------------------------------------------------

    #[test]
    fn open_returns_ok() {
        assert!(NoopAudit::open().is_ok());
    }

    #[test]
    fn name_is_set() {
        assert_eq!(NoopAudit::NAME, c"noop_audit");
    }

    // -----------------------------------------------------------------------
    // Default implementations return Ok(())
    // -----------------------------------------------------------------------

    #[test]
    fn default_close_ok() {
        let m = NoopAudit::open().unwrap();
        assert!(m.close().is_ok());
    }

    #[test]
    fn default_kdc_start_ok() {
        let m = NoopAudit;
        assert!(m.kdc_start(true).is_ok());
        assert!(m.kdc_start(false).is_ok());
    }

    #[test]
    fn default_kdc_stop_ok() {
        let m = NoopAudit;
        assert!(m.kdc_stop(true).is_ok());
        assert!(m.kdc_stop(false).is_ok());
    }

    // Default event methods with a null-pointer AuditStateRef.  The defaults
    // ignore all arguments, so no dereference occurs.
    fn null_state() -> AuditStateRef<'static> {
        AuditStateRef {
            ptr: std::ptr::null(),
            _phantom: PhantomData,
        }
    }

    #[test]
    fn default_as_req_ok() {
        let m = NoopAudit;
        assert!(m.as_req(true, null_state()).is_ok());
    }

    #[test]
    fn default_tgs_req_ok() {
        let m = NoopAudit;
        assert!(m.tgs_req(false, null_state()).is_ok());
    }

    #[test]
    fn default_tgs_s4u2self_ok() {
        let m = NoopAudit;
        assert!(m.tgs_s4u2self(true, null_state()).is_ok());
    }

    #[test]
    fn default_tgs_s4u2proxy_ok() {
        let m = NoopAudit;
        assert!(m.tgs_s4u2proxy(false, null_state()).is_ok());
    }

    #[test]
    fn default_tgs_u2u_ok() {
        let m = NoopAudit;
        assert!(m.tgs_u2u(true, null_state()).is_ok());
    }

    // -----------------------------------------------------------------------
    // AuditStateRef accessors with a stack-allocated state struct
    // -----------------------------------------------------------------------

    #[test]
    fn state_stage_accessor() {
        let mut raw: kurbu5_sys::_krb5_audit_state =
            unsafe { std::mem::zeroed() };
        raw.stage = 4; // ISSUE_TKT
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert_eq!(state.stage(), 4);
    }

    #[test]
    fn state_cl_port_accessor() {
        let mut raw: kurbu5_sys::_krb5_audit_state =
            unsafe { std::mem::zeroed() };
        raw.cl_port = 65535;
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert_eq!(state.cl_port(), 65535);
    }

    #[test]
    fn state_violation_accessor() {
        let mut raw: kurbu5_sys::_krb5_audit_state =
            unsafe { std::mem::zeroed() };
        raw.violation = 2; // LOCAL_POLICY
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert_eq!(state.violation(), 2);
    }

    #[test]
    fn state_status_none_when_null() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.status().is_none());
    }

    #[test]
    fn state_status_some_when_set() {
        let mut raw: kurbu5_sys::_krb5_audit_state =
            unsafe { std::mem::zeroed() };
        raw.status = c"ISSUE".as_ptr();
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert_eq!(state.status(), Some("ISSUE"));
    }

    #[test]
    fn state_req_id_empty_when_zeroed() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert_eq!(state.req_id(), "");
    }

    #[test]
    fn state_req_id_returns_content() {
        let mut raw: kurbu5_sys::_krb5_audit_state =
            unsafe { std::mem::zeroed() };
        // Write "ABCD\0..." into req_id (zeroed init ensures null terminator).
        raw.req_id[0] = b'A' as libc::c_char;
        raw.req_id[1] = b'B' as libc::c_char;
        raw.req_id[2] = b'C' as libc::c_char;
        raw.req_id[3] = b'D' as libc::c_char;
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert_eq!(state.req_id(), "ABCD");
    }

    #[test]
    fn state_tkt_in_id_none_when_null() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.tkt_in_id().is_none());
    }

    #[test]
    fn state_tkt_out_id_none_when_null() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.tkt_out_id().is_none());
    }

    #[test]
    fn state_evid_tkt_id_none_when_null() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.evid_tkt_id().is_none());
    }

    #[test]
    fn state_request_raw_null_when_zeroed() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.request_raw().is_null());
    }

    #[test]
    fn state_reply_raw_null_when_zeroed() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.reply_raw().is_null());
    }

    #[test]
    fn state_cl_addr_raw_null_when_zeroed() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.cl_addr_raw().is_null());
    }

    #[test]
    fn state_cl_realm_raw_null_when_zeroed() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.cl_realm_raw().is_null());
    }

    #[test]
    fn state_s4u2self_user_raw_null_when_zeroed() {
        let raw: kurbu5_sys::_krb5_audit_state = unsafe { std::mem::zeroed() };
        let state = AuditStateRef {
            ptr: &raw as *const _,
            _phantom: PhantomData,
        };
        assert!(state.s4u2self_user_raw().is_null());
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers end-to-end.
    //
    // These tests drive open → event callbacks → close through the raw C
    // vtable slots produced by make_audit_vtable without a live krb5_context.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::super::{AuditModule, AuditStateRef};
        use crate::audit::glue::make_audit_vtable;
        use crate::error::Krb5Error;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Plugin that records whether tgs_req was called.
        static TGS_CALLED: AtomicBool = AtomicBool::new(false);

        struct RecordingAudit;

        impl AuditModule for RecordingAudit {
            const NAME: &'static std::ffi::CStr = c"recording_audit";

            fn open() -> Result<Self, Krb5Error> {
                Ok(RecordingAudit)
            }

            fn tgs_req(
                &self,
                _success: bool,
                _state: AuditStateRef<'_>,
            ) -> Result<(), Krb5Error> {
                TGS_CALLED.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        /// open → tgs_req → close: all vtable slots must return 0 and the
        /// moddata pointer must be non-null after open.
        #[test]
        fn vtable_open_tgs_req_close() {
            let vt = make_audit_vtable::<RecordingAudit>();

            let mut moddata: kurbu5_sys::krb5_audit_moddata =
                std::ptr::null_mut();
            let open_fn = vt.open.expect("open slot must be set");
            // SAFETY: moddata is a stack out-pointer; open writes a Box<M> ptr.
            let code = unsafe { open_fn(&mut moddata) };
            assert_eq!(code, 0, "open must succeed");
            assert!(!moddata.is_null(), "moddata must be non-null after open");

            let raw_state: kurbu5_sys::_krb5_audit_state =
                unsafe { std::mem::zeroed() };
            let tgs_fn = vt.tgs_req.expect("tgs_req slot must be set");
            // SAFETY: moddata was set by open (Box<M>); raw_state is a valid
            // stack struct that the tgs_req bridge borrows for the call.
            let code = unsafe {
                tgs_fn(
                    moddata,
                    1, // ev_success = true (krb5_boolean = u32)
                    &raw_state as *const kurbu5_sys::krb5_audit_state
                        as *mut kurbu5_sys::krb5_audit_state,
                )
            };
            assert_eq!(code, 0, "tgs_req must succeed");
            assert!(
                TGS_CALLED.load(Ordering::SeqCst),
                "tgs_req must have called the Rust impl"
            );

            let close_fn = vt.close.expect("close slot must be set");
            // SAFETY: moddata was set by open; close recovers and drops Box<M>.
            let code = unsafe { close_fn(moddata) };
            assert_eq!(code, 0, "close must succeed");
        }

        /// Verify every optional vtable slot is populated (the no-op defaults).
        #[test]
        fn vtable_all_slots_set() {
            let vt = make_audit_vtable::<RecordingAudit>();
            assert!(vt.open.is_some(), "open must be set");
            assert!(vt.close.is_some(), "close must be set");
            assert!(vt.kdc_start.is_some(), "kdc_start must be set");
            assert!(vt.kdc_stop.is_some(), "kdc_stop must be set");
            assert!(vt.as_req.is_some(), "as_req must be set");
            assert!(vt.tgs_req.is_some(), "tgs_req must be set");
            assert!(vt.tgs_s4u2self.is_some(), "tgs_s4u2self must be set");
            assert!(vt.tgs_s4u2proxy.is_some(), "tgs_s4u2proxy must be set");
            assert!(vt.tgs_u2u.is_some(), "tgs_u2u must be set");
        }

        /// Verify the vtable name field matches MODULE::NAME.
        #[test]
        fn vtable_name_matches_module_name() {
            let vt = make_audit_vtable::<RecordingAudit>();
            // SAFETY: vt.name is set from RecordingAudit::NAME.as_ptr() —
            // a 'static null-terminated CStr.
            let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
            assert_eq!(name, RecordingAudit::NAME);
        }

        /// open() failure: the error code is propagated and moddata stays null.
        struct FailingAudit;

        impl AuditModule for FailingAudit {
            const NAME: &'static std::ffi::CStr = c"failing_audit";
            fn open() -> Result<Self, Krb5Error> {
                Err(Krb5Error::Custom(libc::EACCES))
            }
        }

        #[test]
        fn vtable_open_failure_propagates_error() {
            let vt = make_audit_vtable::<FailingAudit>();
            let mut moddata: kurbu5_sys::krb5_audit_moddata =
                std::ptr::null_mut();
            let open_fn = vt.open.expect("open slot must be set");
            // SAFETY: moddata is a stack out-pointer.
            let code = unsafe { open_fn(&mut moddata) };
            assert_ne!(code, 0, "open must fail");
            assert_eq!(code, libc::EACCES, "error code must be EACCES");
        }
    }
}
