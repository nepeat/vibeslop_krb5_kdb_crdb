//! Shared error type for all `kurbu5-rs` plugin interfaces.
//!
//! `Krb5Error` wraps the raw `krb5_error_code` integers used by every
//! non-KDB plugin interface.  The named variants cover the error codes that
//! the plugin framework itself uses by name in the plugin header comments and
//! the `KRB5_PLUGIN_*` family.  For any other error code, use `Custom(i32)`.
//!
//! # `KRB5_PLUGIN_NO_HANDLE` semantics
//!
//! `NoHandle` means "this plugin has no opinion about this request; try the
//! next registered plugin".  It is the correct default return for all optional
//! interface methods.
//!
//! # `KRB5_PLUGIN_OP_NOTSUPP` semantics
//!
//! `OperationNotSupported` means "the operation slot exists in the vtable but
//! this plugin does not implement it".  Distinct from `NoHandle`.

use kurbu5_sys as sys;

/// Errors that a non-KDB plugin method can return.
///
/// Named variants correspond directly to named `krb5_error_code` constants
/// from the plugin interface headers.  `Custom` passes any other integer
/// through unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Krb5Error {
    /// This plugin has no opinion; libkrb5 should try the next plugin
    /// (`KRB5_PLUGIN_NO_HANDLE`).
    NoHandle,

    /// The vtable slot exists but the operation is not implemented by this
    /// plugin (`KRB5_PLUGIN_OP_NOTSUPP`).
    OperationNotSupported,

    /// The plugin version requested by the caller is not supported
    /// (`KRB5_PLUGIN_VER_NOTSUPP`).  Returned by `initvt_plugin!` when the
    /// `maj_ver` argument does not match the interface major version.
    VersionNotSupported,

    /// Memory allocation failure (`ENOMEM`).
    OutOfMemory,

    /// No principal-to-local-name translation exists (`KRB5_LNAME_NOTRANS`).
    /// Returned by LOCALAUTH `an2ln` when the principal has no mapping.
    LnameNotrans,

    /// Pass through any other `krb5_error_code` integer directly.
    Custom(i32),
}

impl Krb5Error {
    /// Convert to the raw `krb5_error_code` integer expected by libkrb5.
    #[must_use]
    pub fn into_error_code(self) -> i32 {
        match self {
            Krb5Error::NoHandle => sys::KRB5_PLUGIN_NO_HANDLE,
            Krb5Error::OperationNotSupported => sys::KRB5_PLUGIN_OP_NOTSUPP,
            Krb5Error::VersionNotSupported => sys::KRB5_PLUGIN_VER_NOTSUPP,
            Krb5Error::OutOfMemory => libc::ENOMEM,
            Krb5Error::LnameNotrans => sys::KRB5_LNAME_NOTRANS,
            Krb5Error::Custom(code) => code,
        }
    }

    /// Construct a `Krb5Error` from a raw error code.
    #[must_use]
    pub fn from_error_code(code: i32) -> Self {
        match code {
            c if c == sys::KRB5_PLUGIN_NO_HANDLE => Krb5Error::NoHandle,
            c if c == sys::KRB5_PLUGIN_OP_NOTSUPP => {
                Krb5Error::OperationNotSupported
            },
            c if c == sys::KRB5_PLUGIN_VER_NOTSUPP => {
                Krb5Error::VersionNotSupported
            },
            c if c == libc::ENOMEM => Krb5Error::OutOfMemory,
            c if c == sys::KRB5_LNAME_NOTRANS => Krb5Error::LnameNotrans,
            other => Krb5Error::Custom(other),
        }
    }
}

impl From<Krb5Error> for i32 {
    fn from(e: Krb5Error) -> i32 {
        e.into_error_code()
    }
}

impl From<i32> for Krb5Error {
    fn from(code: i32) -> Krb5Error {
        Krb5Error::from_error_code(code)
    }
}

impl std::fmt::Display for Krb5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Krb5Error::NoHandle => {
                write!(
                    f,
                    "KRB5_PLUGIN_NO_HANDLE: no plugin handles this request"
                )
            },
            Krb5Error::OperationNotSupported => write!(
                f,
                "KRB5_PLUGIN_OP_NOTSUPP: operation not supported by this plugin"
            ),
            Krb5Error::VersionNotSupported => {
                write!(
                    f,
                    "KRB5_PLUGIN_VER_NOTSUPP: plugin version not supported"
                )
            },
            Krb5Error::OutOfMemory => write!(f, "ENOMEM: out of memory"),
            Krb5Error::LnameNotrans => write!(
                f,
                "KRB5_LNAME_NOTRANS: no principal-to-local-name translation"
            ),
            Krb5Error::Custom(code) => write!(f, "krb5 error code {code}"),
        }
    }
}

impl std::error::Error for Krb5Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_no_handle() {
        let code: i32 = Krb5Error::NoHandle.into_error_code();
        assert_eq!(Krb5Error::from_error_code(code), Krb5Error::NoHandle);
    }

    #[test]
    fn round_trip_op_not_supported() {
        let code: i32 = Krb5Error::OperationNotSupported.into_error_code();
        assert_eq!(
            Krb5Error::from_error_code(code),
            Krb5Error::OperationNotSupported
        );
    }

    #[test]
    fn round_trip_version_not_supported() {
        let code: i32 = Krb5Error::VersionNotSupported.into_error_code();
        assert_eq!(
            Krb5Error::from_error_code(code),
            Krb5Error::VersionNotSupported
        );
    }

    #[test]
    fn round_trip_out_of_memory() {
        let code: i32 = Krb5Error::OutOfMemory.into_error_code();
        assert_eq!(Krb5Error::from_error_code(code), Krb5Error::OutOfMemory);
    }

    #[test]
    fn round_trip_lname_notrans() {
        let code: i32 = Krb5Error::LnameNotrans.into_error_code();
        assert_eq!(Krb5Error::from_error_code(code), Krb5Error::LnameNotrans);
    }

    #[test]
    fn round_trip_custom() {
        let orig = Krb5Error::Custom(12345);
        let code: i32 = orig.clone().into_error_code();
        assert_eq!(Krb5Error::from_error_code(code), orig);
    }

    #[test]
    fn from_into_symmetry() {
        let code: i32 = 12345;
        let err: Krb5Error = Krb5Error::from(code);
        let back: i32 = i32::from(err);
        assert_eq!(back, code);
    }
}
