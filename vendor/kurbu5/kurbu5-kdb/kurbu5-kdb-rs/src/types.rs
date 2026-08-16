//! Foundational types and flag enumerations for the KDB driver API.

use bitflags::bitflags;

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// A Kerberos timestamp (seconds since the Unix epoch, stored as a signed
/// 32-bit integer to match `krb5_timestamp`).
///
/// The sign is intentional: krb5 uses `i32` to hold timestamps so that values
/// after 2038 wrap into negative numbers in the same way the C code does.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
pub struct Timestamp(pub i32);

impl Timestamp {
    /// The zero/unset timestamp.
    pub const ZERO: Timestamp = Timestamp(0);
}

impl From<i32> for Timestamp {
    fn from(v: i32) -> Self {
        Timestamp(v)
    }
}

impl From<Timestamp> for i32 {
    fn from(t: Timestamp) -> i32 {
        t.0
    }
}

// ---------------------------------------------------------------------------
// OpenMode
// ---------------------------------------------------------------------------

/// How a database context should be opened.
///
/// Passed to [`KdbModule::open`](crate::KdbModule::open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenMode {
    pub access: AccessMode,
    pub server: ServerType,
}

/// Read-write vs. read-only access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    ReadWrite,
    ReadOnly,
}

/// The type of server opening the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    Kdc,
    Admin,
    Other,
}

impl OpenMode {
    /// Reconstruct the raw C integer for passing to libkdb5 functions.
    #[must_use]
    pub fn as_raw(self) -> libc::c_int {
        let access_bit: libc::c_int = match self.access {
            AccessMode::ReadWrite => 0,
            AccessMode::ReadOnly => 1,
        };
        let server_bits: libc::c_int = match self.server {
            ServerType::Kdc => 0x0100,
            ServerType::Admin => 0x0200,
            ServerType::Other => 0,
        };
        access_bit | server_bits
    }

    /// Construct an `OpenMode` from the raw C integer passed to `init_module`.
    #[must_use]
    pub fn from_raw(raw: libc::c_int) -> Self {
        // The low bit selects RO vs RW; the upper nibble selects server type.
        let access = if raw & 0x01 != 0 {
            AccessMode::ReadOnly
        } else {
            AccessMode::ReadWrite
        };
        let server = match raw & 0xff00 {
            0x0100 => ServerType::Kdc,
            0x0200 => ServerType::Admin,
            _ => ServerType::Other,
        };
        OpenMode { access, server }
    }
}

// ---------------------------------------------------------------------------
// LockMode
// ---------------------------------------------------------------------------

/// Database lock mode passed to [`KdbModule::lock`](crate::KdbModule::lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Shared lock; may coexist with other shared locks.
    Shared,
    /// Exclusive lock; may not coexist with any other lock.
    Exclusive,
    /// Exclusive lock that survives process exit.
    Permanent,
}

impl LockMode {
    #[must_use]
    pub fn from_raw(raw: libc::c_int) -> Self {
        match raw {
            0x0001 => LockMode::Shared,
            0x0008 => LockMode::Permanent,
            _ => LockMode::Exclusive, // conservative default; covers 0x0002 and unknown values
        }
    }
}

// ---------------------------------------------------------------------------
// LookupFlags
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags passed to `get_principal` and related lookups.
    ///
    /// These correspond to the `KRB5_KDB_FLAG_*` constants in `kdb.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct LookupFlags: u32 {
        /// Referrals to other realms are permitted.
        const REFERRAL_OK = 0x0000_0010;
        /// Looking up a client principal (AS/TGS client, not server).
        const CLIENT = 0x0000_0040;
        /// Map foreign principals to local ones.
        const MAP_PRINCIPALS = 0x0000_0080;
        /// S4U2Self protocol transition.
        const PROTOCOL_TRANSITION = 0x0000_0100;
        /// S4U2Proxy constrained delegation.
        const CONSTRAINED_DELEGATION = 0x0000_0200;
        /// User-to-user request.
        const USER_TO_USER = 0x0000_0800;
        /// Cross-realm request.
        const CROSS_REALM = 0x0000_1000;
        /// The KDC is issuing a referral.
        const ISSUING_REFERRAL = 0x0000_4000;
    }
}

impl LookupFlags {
    #[must_use]
    pub fn from_raw(raw: libc::c_uint) -> Self {
        LookupFlags::from_bits_truncate(raw)
    }
}

// ---------------------------------------------------------------------------
// IterFlags
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags passed to `iterate_principals`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct IterFlags: u32 {
        /// The callback may write to the database.
        const WRITE = 0x0000_0001;
        /// Iterate in reverse order.
        const REVERSE = 0x0000_0002;
        /// Recurse into sub-trees (database-specific meaning).
        const RECURSE = 0x0000_0004;
    }
}

// ---------------------------------------------------------------------------
// PrincipalAttributes
// ---------------------------------------------------------------------------

bitflags! {
    /// Attribute flags stored in `krb5_db_entry::attributes`.
    ///
    /// These correspond to the `KRB5_KDB_*` attribute constants in `kdb.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct PrincipalAttributes: u32 {
        const DISALLOW_POSTDATED     = 0x0000_0001;
        const DISALLOW_FORWARDABLE   = 0x0000_0002;
        const DISALLOW_TGT_BASED     = 0x0000_0004;
        const DISALLOW_RENEWABLE     = 0x0000_0008;
        const DISALLOW_PROXIABLE     = 0x0000_0010;
        const DISALLOW_DUP_SKEY      = 0x0000_0020;
        const DISALLOW_ALL_TIX       = 0x0000_0040;
        const REQUIRES_PRE_AUTH      = 0x0000_0080;
        const REQUIRES_HW_AUTH       = 0x0000_0100;
        const REQUIRES_PWCHANGE      = 0x0000_0200;
        const DISALLOW_SVR           = 0x0000_1000;
        const PWCHANGE_SERVICE       = 0x0000_2000;
        const SUPPORT_DESMD5         = 0x0000_4000;
        const NEW_PRINC              = 0x0000_8000;
        const OK_AS_DELEGATE         = 0x0010_0000;
        const OK_TO_AUTH_AS_DELEGATE = 0x0020_0000;
        const NO_AUTH_DATA_REQUIRED  = 0x0040_0000;
        const LOCKDOWN_KEYS          = 0x0080_0000;
    }
}

// ---------------------------------------------------------------------------
// KdcOptions
// ---------------------------------------------------------------------------

bitflags! {
    /// KDC request options (RFC 4120 KDCOptions ASN.1 bit string).
    ///
    /// These correspond to the `KDC_OPT_*` constants in `krb5.h`, stored
    /// in the most-significant-bit-first order used by the protocol.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct KdcOptions: u32 {
        const FORWARDABLE             = 0x4000_0000;
        const FORWARDED               = 0x2000_0000;
        const PROXIABLE               = 0x1000_0000;
        const PROXY                   = 0x0800_0000;
        const ALLOW_POSTDATE          = 0x0400_0000;
        const POSTDATED               = 0x0200_0000;
        const RENEWABLE               = 0x0080_0000;
        const CNAME_IN_ADDL_TKT       = 0x0002_0000;
        const CANONICALIZE            = 0x0001_0000;
        const REQUEST_ANONYMOUS       = 0x0000_8000;
        const DISABLE_TRANSITED_CHECK = 0x0000_0020;
        const RENEWABLE_OK            = 0x0000_0010;
        const ENC_TKT_IN_SKEY         = 0x0000_0008;
        const RENEW                   = 0x0000_0002;
        const VALIDATE                = 0x0000_0001;
    }
}

// ---------------------------------------------------------------------------
// TicketFlags
// ---------------------------------------------------------------------------

bitflags! {
    /// Ticket flags stored in the encrypted part of a `krb5_ticket`.
    ///
    /// These correspond to the `TKT_FLG_*` constants in `krb5.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TicketFlags: u32 {
        const FORWARDABLE            = 0x4000_0000;
        const FORWARDED              = 0x2000_0000;
        const PROXIABLE              = 0x1000_0000;
        const PROXY                  = 0x0800_0000;
        const MAY_POSTDATE           = 0x0400_0000;
        const POSTDATED              = 0x0200_0000;
        const INVALID                = 0x0100_0000;
        const RENEWABLE              = 0x0080_0000;
        const INITIAL                = 0x0040_0000;
        const PRE_AUTH               = 0x0020_0000;
        const HW_AUTH                = 0x0010_0000;
        const TRANSIT_POLICY_CHECKED = 0x0008_0000;
        const OK_AS_DELEGATE         = 0x0004_0000;
        const ENC_PA_REP             = 0x0001_0000;
        const ANONYMOUS              = 0x0000_8000;
    }
}

// ---------------------------------------------------------------------------
// TlDataType
// ---------------------------------------------------------------------------

/// Known tagged-length data types stored in `krb5_tl_data`.
///
/// The `Other(u16)` variant covers types defined by external modules or
/// future versions of the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlDataType {
    LastPwdChange,
    ModPrinc,
    KadmData,
    KadmEData,
    Rb1Challenge,
    UserCertificate,
    MkVno,
    ActKvno,
    MkeyAux,
    StringAttrs,
    AliasTarget,
    PacLogonInfo,
    ServerReferral,
    SvrReferralData,
    ConstrainedDelegationAcl,
    LmKey,
    X509SubjectIssuerName,
    LastAdminUnlock,
    DbArgs,
    Other(u16),
}

impl TlDataType {
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            TlDataType::LastPwdChange => 0x0001,
            TlDataType::ModPrinc => 0x0002,
            TlDataType::KadmData => 0x0003,
            TlDataType::KadmEData => 0x0004,
            TlDataType::Rb1Challenge => 0x0005,
            TlDataType::UserCertificate => 0x0007,
            TlDataType::MkVno => 0x0008,
            TlDataType::ActKvno => 0x0009,
            TlDataType::MkeyAux => 0x000a,
            TlDataType::StringAttrs => 0x000b,
            TlDataType::AliasTarget => 0x000c,
            TlDataType::PacLogonInfo => 0x0100,
            TlDataType::ServerReferral => 0x0200,
            TlDataType::SvrReferralData => 0x0300,
            TlDataType::ConstrainedDelegationAcl => 0x0400,
            TlDataType::LmKey => 0x0500,
            TlDataType::X509SubjectIssuerName => 0x0600,
            TlDataType::LastAdminUnlock => 0x0700,
            TlDataType::DbArgs => 0x7fff,
            TlDataType::Other(v) => v,
        }
    }
}

impl From<u16> for TlDataType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => TlDataType::LastPwdChange,
            0x0002 => TlDataType::ModPrinc,
            0x0003 => TlDataType::KadmData,
            0x0004 => TlDataType::KadmEData,
            0x0005 => TlDataType::Rb1Challenge,
            0x0007 => TlDataType::UserCertificate,
            0x0008 => TlDataType::MkVno,
            0x0009 => TlDataType::ActKvno,
            0x000a => TlDataType::MkeyAux,
            0x000b => TlDataType::StringAttrs,
            0x000c => TlDataType::AliasTarget,
            0x0100 => TlDataType::PacLogonInfo,
            0x0200 => TlDataType::ServerReferral,
            0x0300 => TlDataType::SvrReferralData,
            0x0400 => TlDataType::ConstrainedDelegationAcl,
            0x0500 => TlDataType::LmKey,
            0x0600 => TlDataType::X509SubjectIssuerName,
            0x0700 => TlDataType::LastAdminUnlock,
            0x7fff => TlDataType::DbArgs,
            other => TlDataType::Other(other),
        }
    }
}

impl From<TlDataType> for u16 {
    fn from(t: TlDataType) -> u16 {
        t.as_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tl_data_type_round_trip() {
        let known = [
            TlDataType::LastPwdChange,
            TlDataType::ModPrinc,
            TlDataType::StringAttrs,
            TlDataType::DbArgs,
            TlDataType::Other(0xdead),
        ];
        for ty in known {
            let raw = u16::from(ty);
            assert_eq!(TlDataType::from(raw), ty);
        }
    }

    #[test]
    fn lookup_flags_from_raw() {
        let flags = LookupFlags::from_raw(0x0000_0050); // CLIENT | REFERRAL_OK
        assert!(flags.contains(LookupFlags::CLIENT));
        assert!(flags.contains(LookupFlags::REFERRAL_OK));
        assert!(!flags.contains(LookupFlags::MAP_PRINCIPALS));
    }

    #[test]
    fn principal_attributes_bitwise() {
        let a = PrincipalAttributes::REQUIRES_PRE_AUTH
            | PrincipalAttributes::OK_AS_DELEGATE;
        assert_eq!(a.bits(), 0x0010_0080);
    }

    #[test]
    fn open_mode_from_raw_kdc_rw() {
        let m = OpenMode::from_raw(0x0100); // KRB5_KDB_SRV_TYPE_KDC | RW
        assert_eq!(m.access, AccessMode::ReadWrite);
        assert_eq!(m.server, ServerType::Kdc);
    }

    #[test]
    fn open_mode_from_raw_admin_ro() {
        let m = OpenMode::from_raw(0x0201); // KRB5_KDB_SRV_TYPE_ADMIN | RO
        assert_eq!(m.access, AccessMode::ReadOnly);
        assert_eq!(m.server, ServerType::Admin);
    }

    #[test]
    fn timestamp_ordering() {
        assert!(Timestamp(1000) < Timestamp(2000));
        assert_eq!(Timestamp::ZERO, Timestamp(0));
    }
}
