//! Error types for the KDB driver API.

/// Errors that a KDB driver method can return.
///
/// Most variants correspond directly to a named `krb5_error_code` constant.
/// Use `Custom` to return any other Kerberos error code not listed here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdbError {
    /// Principal not found in the database (`KRB5_KDB_NOENTRY`).
    NoEntry,

    /// The requested operation is not supported by this plugin
    /// (`KRB5_PLUGIN_OP_NOTSUPP`).  Returning this causes libkdb5 to use its
    /// own default implementation for the corresponding vtable slot.
    NotSupported,

    /// This plugin does not handle the supplied data; libkrb5 should try the
    /// next handler (`KRB5_PLUGIN_NO_HANDLE`).
    NoHandle,

    /// The database is locked by another process (`KRB5_KDB_CANTLOCK_DB`).
    ///
    /// Note: the exact error code for lock contention varies by DAL version.
    /// Use `Custom` if you need a precise code.
    Locked,

    /// A generic I/O or operating-system error (maps to the errno value wrapped
    /// as a positive Kerberos error code via `errno_to_krb5`).
    Io(i32),

    /// Memory allocation failure (`ENOMEM`).
    OutOfMemory,

    /// Pass through any other `krb5_error_code` integer directly.
    Custom(i32),
}

impl KdbError {
    /// Convert to the raw `krb5_error_code` integer expected by libkdb5.
    #[must_use]
    pub fn into_error_code(self) -> i32 {
        match self {
            KdbError::NoEntry => kdb_sys::KRB5_KDB_NOENTRY,
            KdbError::NotSupported => kdb_sys::KRB5_PLUGIN_OP_NOTSUPP,
            KdbError::NoHandle => kdb_sys::KRB5_PLUGIN_NO_HANDLE,
            KdbError::Locked => kdb_sys::KRB5_KDB_CANTLOCK_DB,
            KdbError::Io(e) => e,
            KdbError::OutOfMemory => libc::ENOMEM,
            KdbError::Custom(code) => code,
        }
    }

    /// Construct a `KdbError` from a raw error code.
    #[must_use]
    pub fn from_error_code(code: i32) -> Self {
        match code {
            c if c == kdb_sys::KRB5_KDB_NOENTRY => KdbError::NoEntry,
            c if c == kdb_sys::KRB5_PLUGIN_OP_NOTSUPP => {
                KdbError::NotSupported
            },
            c if c == kdb_sys::KRB5_PLUGIN_NO_HANDLE => KdbError::NoHandle,
            c if c == kdb_sys::KRB5_KDB_CANTLOCK_DB => KdbError::Locked,
            c if c == libc::ENOMEM => KdbError::OutOfMemory,
            other => KdbError::Custom(other),
        }
    }
}

impl From<KdbError> for i32 {
    fn from(e: KdbError) -> i32 {
        e.into_error_code()
    }
}

impl From<i32> for KdbError {
    fn from(code: i32) -> KdbError {
        KdbError::from_error_code(code)
    }
}

/// The error returned when a KDC policy check fails.
///
/// Both `check_policy_as` and `check_policy_tgs` return this type on denial.
/// `status` is a null-terminated C string that the KDC logs; `e_data` is
/// optional structured data included in the KRB-ERROR response.
#[derive(Debug)]
pub struct PolicyDenied {
    /// Short ASCII description included in KDC logs.  Must be a null-terminated
    /// C string literal (`c"..."`) so the pointer is valid after the call
    /// returns and is usable directly from C.
    pub status: &'static std::ffi::CStr,

    /// Optional PA-DATA / error-data to include in the KRB-ERROR reply.
    /// If `Some`, the bytes are owned by this struct and will be freed when
    /// the error is consumed by the glue layer.
    pub e_data: Option<Vec<u8>>,
}

impl PolicyDenied {
    /// Construct a denial with a status message and no extra data.
    #[must_use]
    pub fn new(status: &'static std::ffi::CStr) -> Self {
        PolicyDenied {
            status,
            e_data: None,
        }
    }

    /// Construct a denial with a status message and attached error data.
    #[must_use]
    pub fn with_data(status: &'static std::ffi::CStr, data: Vec<u8>) -> Self {
        PolicyDenied {
            status,
            e_data: Some(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_no_entry() {
        let code: i32 = KdbError::NoEntry.into_error_code();
        assert_eq!(KdbError::from_error_code(code), KdbError::NoEntry);
    }

    #[test]
    fn round_trip_not_supported() {
        let code: i32 = KdbError::NotSupported.into_error_code();
        assert_eq!(KdbError::from_error_code(code), KdbError::NotSupported);
    }

    #[test]
    fn round_trip_custom() {
        let orig = KdbError::Custom(12345);
        let code: i32 = orig.clone().into_error_code();
        assert_eq!(KdbError::from_error_code(code), orig);
    }

    #[test]
    fn from_into_symmetry() {
        let code: i32 = 12345;
        let err: KdbError = KdbError::from(code);
        let back: i32 = i32::from(err);
        assert_eq!(back, code);
    }
}
