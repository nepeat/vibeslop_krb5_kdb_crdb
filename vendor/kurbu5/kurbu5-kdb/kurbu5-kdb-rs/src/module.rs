//! The `KdbModule` trait — the primary user-facing API for KDB driver authors.

use std::marker::PhantomData;

use crate::context::KdbContext;
use crate::error::{KdbError, PolicyDenied};
use crate::key_data::{
    DecryptKeyRequest, EncryptKeyRequest, KeyBlock, KeyDataOwned, KeyDataRef,
    KeySalt,
};
use crate::policy::PolicyEntry;
use crate::principal::{PrincipalEntry, PrincipalEntryRef, PrincipalRef};
use crate::types::{
    IterFlags, KdcOptions, LockMode, LookupFlags, OpenMode, TicketFlags,
    Timestamp,
};

// ---------------------------------------------------------------------------
// Opaque C-type wrappers (stubs; fleshed out in iteration 6)
// ---------------------------------------------------------------------------

/// Zero-copy view of a `krb5_kdc_req` (shared by AS and TGS requests).
pub struct KdcRequestRef<'a> {
    pub(crate) ptr: *const kdb_sys::krb5_kdc_req,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> KdcRequestRef<'a> {
    /// Requested ticket options (`KDCOptions` bit string from RFC 4120).
    #[must_use]
    pub fn kdc_options(&self) -> KdcOptions {
        // SAFETY: self.ptr is valid for 'a (construction invariant).
        KdcOptions::from_bits_truncate(
            unsafe { (*self.ptr).kdc_options }.cast_unsigned(),
        )
    }

    /// Encryption types the client is willing to accept, in preference order.
    ///
    /// Values are IANA-assigned `krb5_enctype` integers (e.g. 17 = AES128-CTS,
    /// 18 = AES256-CTS, 23 = RC4-HMAC).
    #[must_use]
    pub fn requested_enctypes(&self) -> &'a [i32] {
        // SAFETY: ktype points to nktypes consecutive i32 values valid for 'a.
        let n = unsafe { (*self.ptr).nktypes };
        let ptr = unsafe { (*self.ptr).ktype };
        if ptr.is_null() || n <= 0 {
            return &[];
        }
        unsafe {
            std::slice::from_raw_parts(
                ptr.cast_const(),
                n.cast_unsigned() as usize,
            )
        }
    }

    /// Iterator over the pre-authentication data type codes present in the
    /// request.  Values are `krb5_preauthtype` (i32) constants, e.g.:
    ///   2  = `ENC_TIMESTAMP`, 16 = `PK_AS_REQ` (PKINIT), 19 = `ETYPE_INFO2`,
    ///   133 = `FX_COOKIE`, 136 = `FX_FAST` (FAST tunnel), 151 = SPAKE,
    ///   167 = `ENCRYPTED_CHALLENGE`.
    #[must_use]
    pub fn padata_types(&self) -> PaDataIter<'a> {
        PaDataIter {
            // SAFETY: padata is a null-terminated *mut *mut krb5_pa_data valid for 'a.
            ptr: unsafe { (*self.ptr).padata },
            _phantom: PhantomData,
        }
    }

    /// Requested ticket end time (absolute, seconds since epoch).
    #[must_use]
    pub fn till(&self) -> Timestamp {
        Timestamp(unsafe { (*self.ptr).till })
    }

    /// Requested renewable end time (0 if not requested).
    #[must_use]
    pub fn rtime(&self) -> Timestamp {
        Timestamp(unsafe { (*self.ptr).rtime })
    }
}

/// Iterator over PA-data type codes in a null-terminated `krb5_pa_data **`.
pub struct PaDataIter<'a> {
    ptr: *mut *mut kdb_sys::krb5_pa_data,
    _phantom: PhantomData<&'a ()>,
}

impl Iterator for PaDataIter<'_> {
    type Item = i32;

    fn next(&mut self) -> Option<i32> {
        if self.ptr.is_null() {
            return None;
        }
        // SAFETY: self.ptr is a valid null-terminated array for 'a.
        let pa = unsafe { *self.ptr };
        if pa.is_null() {
            return None;
        }
        self.ptr = unsafe { self.ptr.add(1) };
        Some(unsafe { (*pa).pa_type })
    }
}

/// Zero-copy view of a `krb5_ticket`.
pub struct TicketRef<'a> {
    pub(crate) ptr: *const kdb_sys::krb5_ticket,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> TicketRef<'a> {
    /// Client principal from the decrypted ticket part (`enc_part2->client`).
    ///
    /// Returns `None` if the ticket has not been decrypted by the KDC yet,
    /// which should not occur in `check_policy_tgs` callbacks.
    #[must_use]
    pub fn client(&self) -> Option<PrincipalRef<'a>> {
        // SAFETY: self.ptr is valid for 'a.
        let enc = unsafe { (*self.ptr).enc_part2 };
        if enc.is_null() {
            return None;
        }
        let client = unsafe { (*enc).client };
        if client.is_null() {
            return None;
        }
        // SAFETY: client is owned by the ticket, which lives for at least 'a.
        Some(unsafe { PrincipalRef::from_raw(client.cast_const()) })
    }

    /// Ticket flags from the decrypted part (see [`TicketFlags`]).
    #[must_use]
    pub fn ticket_flags(&self) -> TicketFlags {
        // SAFETY: self.ptr is valid for 'a.
        let enc = unsafe { (*self.ptr).enc_part2 };
        if enc.is_null() {
            return TicketFlags::empty();
        }
        TicketFlags::from_bits_truncate(
            unsafe { (*enc).flags }.cast_unsigned(),
        )
    }

    /// Authentication time recorded when the initial TGT was issued.
    #[must_use]
    pub fn authtime(&self) -> Timestamp {
        let enc = unsafe { (*self.ptr).enc_part2 };
        if enc.is_null() {
            return Timestamp::ZERO;
        }
        Timestamp(unsafe { (*enc).times.authtime })
    }

    /// Ticket expiry time.
    #[must_use]
    pub fn endtime(&self) -> Timestamp {
        let enc = unsafe { (*self.ptr).enc_part2 };
        if enc.is_null() {
            return Timestamp::ZERO;
        }
        Timestamp(unsafe { (*enc).times.endtime })
    }

    /// Renewal deadline (0 if the ticket is not renewable).
    #[must_use]
    pub fn renew_till(&self) -> Timestamp {
        let enc = unsafe { (*self.ptr).enc_part2 };
        if enc.is_null() {
            return Timestamp::ZERO;
        }
        Timestamp(unsafe { (*enc).times.renew_till })
    }
}

/// Zero-copy view of a `krb5_pac` for reading.
pub struct PacRef<'a> {
    #[allow(dead_code)]
    pub(crate) pac: kdb_sys::krb5_pac,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

/// Mutable access to a `krb5_pac` being constructed.
pub struct PacBuilder<'a> {
    #[allow(dead_code)]
    pub(crate) pac: kdb_sys::krb5_pac,
    pub(crate) _phantom: PhantomData<&'a mut ()>,
}

/// Zero-copy view of a `krb5_address`.
pub struct AddressRef<'a> {
    pub(crate) ptr: *const kdb_sys::krb5_address,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> AddressRef<'a> {
    /// Address type: `ADDRTYPE_INET` (2) for IPv4, `ADDRTYPE_INET6` (24) for IPv6.
    ///
    /// Other values correspond to less common address families (e.g. `NetBIOS`,
    /// `DECnet`) defined in `krb5.h`.
    #[must_use]
    pub fn addrtype(&self) -> i32 {
        // SAFETY: self.ptr is valid for 'a.
        unsafe { (*self.ptr).addrtype }
    }

    /// Raw address bytes.
    ///
    /// For IPv4 (`addrtype == 2`) this is 4 bytes in network byte order.
    /// For IPv6 (`addrtype == 24`) this is 16 bytes.
    #[must_use]
    pub fn contents(&self) -> &'a [u8] {
        // SAFETY: contents points to length bytes valid for 'a.
        let len = unsafe { (*self.ptr).length } as usize;
        let ptr = unsafe { (*self.ptr).contents };
        if ptr.is_null() || len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(ptr.cast_const(), len) }
    }

    /// Format as a human-readable IP address string.
    ///
    /// Returns `Some("a.b.c.d")` for IPv4 and `Some("…")` for IPv6.
    /// Returns `None` for unrecognised address families.
    #[must_use]
    pub fn display(&self) -> Option<String> {
        match self.addrtype() {
            2 => {
                // ADDRTYPE_INET — 4-byte network-order IPv4 address.
                let b = self.contents();
                if b.len() == 4 {
                    Some(
                        std::net::Ipv4Addr::from([b[0], b[1], b[2], b[3]])
                            .to_string(),
                    )
                } else {
                    None
                }
            },
            24 => {
                // ADDRTYPE_INET6 — 16-byte IPv6 address.
                let b = self.contents();
                if b.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(b);
                    Some(std::net::Ipv6Addr::from(arr).to_string())
                } else {
                    None
                }
            },
            _ => None,
        }
    }
}

/// Mutable wrapper around the authentication indicators list.
///
/// The KDC passes a `krb5_data ***` (pointer to a null-terminated array of
/// `krb5_data *`).  `issue_pac` may read and modify the list.
pub struct AuthIndicators {
    #[allow(dead_code)]
    pub(crate) ptr: *mut *mut *mut kdb_sys::krb5_data,
}

// ---------------------------------------------------------------------------
// Input record types
//
// These group related parameters for methods that would otherwise require
// more than two or three arguments.  A struct documents the role of each
// field and allows callers to use field-init syntax.
// ---------------------------------------------------------------------------

/// All inputs for an AS request policy check.
pub struct AsPolicyRequest<'a> {
    /// The AS request being evaluated.
    pub request: KdcRequestRef<'a>,
    /// Database entry for the requesting client principal.
    pub client: PrincipalEntryRef<'a>,
    /// Database entry for the requested service principal.
    pub server: PrincipalEntryRef<'a>,
    /// Current KDC time.
    pub kdc_time: Timestamp,
}

/// All inputs for a TGS request policy check.
pub struct TgsPolicyRequest<'a> {
    /// The TGS request being evaluated.
    pub request: KdcRequestRef<'a>,
    /// Database entry for the requested service principal.
    pub server: PrincipalEntryRef<'a>,
    /// The TGT (header ticket) used in the request.
    pub ticket: TicketRef<'a>,
    // Note: kdc_time is not passed by the DAL v9 vtable for TGS checks.
}

/// All inputs for a traditional constrained delegation check (`S4U2Proxy`).
pub struct DelegationRequest<'a> {
    /// The client whose identity is being delegated.
    pub client: Option<PrincipalRef<'a>>,
    /// The intermediate service requesting delegation.
    pub server: Option<PrincipalEntryRef<'a>>,
    /// The target service to delegate to, or `None` to check whether *any*
    /// delegation target exists for `server`.
    pub proxy: Option<PrincipalRef<'a>>,
}

/// All inputs for a resource-based constrained delegation check (`S4U2Proxy` RBCD).
pub struct ResourceDelegationRequest<'a> {
    /// The client whose identity is being delegated.
    pub client: Option<PrincipalRef<'a>>,
    /// The intermediate service (impersonator).
    pub server: Option<PrincipalRef<'a>>,
    /// The PAC from the intermediate service's ticket (verified by KDC).
    pub server_pac: PacRef<'a>,
    /// The target service entry (the "proxy" in Microsoft documentation).
    pub proxy: Option<PrincipalEntryRef<'a>>,
}

/// All inputs for an AS request audit notification.
pub struct AsAuditEvent<'a> {
    /// The completed AS request.
    pub request: KdcRequestRef<'a>,
    /// Local KDC address, if known.
    pub local_addr: Option<AddressRef<'a>>,
    /// Remote client address, if known.
    pub remote_addr: Option<AddressRef<'a>>,
    /// Client principal entry (`None` when the client was not found).
    pub client: Option<PrincipalEntryRef<'a>>,
    /// Server principal entry (`None` when the server was not found).
    pub server: Option<PrincipalEntryRef<'a>>,
    /// Authentication time recorded in the issued ticket.
    pub authtime: Timestamp,
    /// `0` on success; a Kerberos error code on failure.
    pub error_code: i32,
}

/// All inputs for an S4U X.509 principal lookup.
pub struct S4uX509Request<'a> {
    /// Raw DER bytes of the client certificate.
    pub client_cert: &'a [u8],
    /// Principal hint from the request (may have an empty data section).
    pub princ: PrincipalRef<'a>,
    /// Lookup flags (e.g. whether referrals are permitted).
    pub flags: LookupFlags,
}

/// All inputs for PAC issuance.
pub struct PacIssuanceRequest<'a> {
    /// KDB flags (`KRB5_KDB_FLAG`_* bitmask) for this issuance context.
    pub flags: u32,
    /// Client principal entry; `None` for pure renewal/validation requests.
    pub client: Option<PrincipalEntryRef<'a>>,
    /// If the AS reply key was replaced by a preauth mechanism (e.g. PKINIT),
    /// this contains the replacement key; otherwise `None`.
    pub replaced_reply_key: Option<KeyBlock>,
    /// Server principal entry (may be a referral TGS); `None` for some
    /// `S4U2Self` paths where the server entry is not yet resolved.
    pub server: Option<PrincipalEntryRef<'a>>,
    /// The krbtgt used to sign `old_pac`; `None` for initial AS requests
    /// (no existing PAC to verify).
    pub signing_krbtgt: Option<PrincipalEntryRef<'a>>,
    /// Authentication time from the client's ticket.
    pub authtime: Timestamp,
    /// PAC from the header ticket for TGS requests; `None` for initial AS.
    pub old_pac: Option<PacRef<'a>>,
}

/// Mutable outputs for PAC issuance.
///
/// Passed alongside [`PacIssuanceRequest`] so that `issue_pac` can write
/// its results without needing additional return-value types.
pub struct PacIssuanceOutput<'a> {
    /// The new PAC being constructed.  Call `krb5_pac_add_buffer` (via a
    /// future `PacBuilder` method) to add buffers.
    pub new_pac: PacBuilder<'a>,
    /// Authentication indicators.  May be read and modified.
    pub auth_indicators: AuthIndicators,
}

// ---------------------------------------------------------------------------
// The KdbModule trait
// ---------------------------------------------------------------------------

/// Implement this trait to create a KDB driver plugin.
///
/// Use the [`kdb_plugin!`](crate::kdb_plugin) macro to export the C vtable.
///
/// # Lifetime contract
///
/// `KdbModule` requires `Sized + Send + 'static`.
/// - `Sized` allows storing in `Box<M>` and recovering via `Box::from_raw`.
/// - `Send` allows the `Box` to be moved between threads (the calling
///   application may change threads between successive KDC requests).
/// - `'static` prevents the module from holding references into caller stacks.
///
/// # Default implementations
///
/// Methods without a mandatory implementation return `Err(KdbError::NotSupported)`,
/// which signals libkdb5 to use its built-in default (for methods with
/// defaults) or to reject the operation (for purely optional methods).
pub trait KdbModule: Sized + Send + 'static {
    // -----------------------------------------------------------------------
    // Library lifecycle
    // -----------------------------------------------------------------------

    /// Called once when the first database of this type is opened.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn init_library() -> Result<(), KdbError> {
        Ok(())
    }

    /// Called once when the last database of this type is closed.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn fini_library() -> Result<(), KdbError> {
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Context lifecycle
    // -----------------------------------------------------------------------

    /// Open (initialise) a database context.
    ///
    /// `ctx` wraps the `krb5_context` passed by libkdb5 to `init_module`.
    /// Overlay plugins need it to copy the context for a backing database.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn open(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
        mode: OpenMode,
    ) -> Result<Self, KdbError>;

    /// Close (finalise) this context.  Consumes `self`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn close(self) -> Result<(), KdbError> {
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Database lifecycle (optional)
    //
    // Each lifecycle operation has a paired `SUPPORTS_*` constant.  Set the
    // constant to `true` *and* provide a real implementation when your driver
    // owns the on-disk database creation / destruction / promotion.
    //
    // When `SUPPORTS_*` is `false` (the default), the corresponding vtable
    // slot is set to `NULL`.  `libkdb5` returns `KRB5_PLUGIN_OP_NOTSUPP`
    // for that operation, which is the correct behaviour for overlay plugins
    // or read-only drivers that delegate database management elsewhere.
    //
    // **If you set `SUPPORTS_CREATE = true`, your `create()` implementation
    // is fully responsible for leaving the `krb5_context` in an initialized
    // state** (i.e. it must arrange for subsequent KDB operations to work
    // without a prior `open()` call) — exactly as `klmdb_create()` does by
    // calling `configure_context()` to set `db_context`.
    // -----------------------------------------------------------------------

    /// Expose `create` in the vtable.  Default: `false`.
    const SUPPORTS_CREATE: bool = false;

    /// Expose `destroy` in the vtable.  Default: `false`.
    const SUPPORTS_DESTROY: bool = false;

    /// Expose `promote_db` in the vtable.  Default: `false`.
    const SUPPORTS_PROMOTE_DB: bool = false;

    /// Expose `decrypt_key_data` in the vtable.  Default: `false` — libkdb5
    /// uses `krb5_dbe_def_decrypt_key_data` directly when this is not set.
    const SUPPORTS_DECRYPT_KEY_DATA: bool = false;

    /// Expose `encrypt_key_data` in the vtable.  Default: `false` — libkdb5
    /// uses `krb5_dbe_def_encrypt_key_data` directly when this is not set.
    const SUPPORTS_ENCRYPT_KEY_DATA: bool = false;
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn create(
        _ctx: &KdbContext<'_>,
        _conf_section: &str,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn destroy(
        _ctx: &KdbContext<'_>,
        _conf_section: &str,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn promote_db(
        _ctx: &KdbContext<'_>,
        _conf_section: &str,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Locking (optional)
    // -----------------------------------------------------------------------
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn lock(&self, _mode: LockMode) -> Result<(), KdbError> {
        Ok(())
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn unlock(&self) -> Result<(), KdbError> {
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Principal CRUD
    // -----------------------------------------------------------------------

    /// Look up a principal by name.
    ///
    /// Return `Ok(None)` if not found; `Ok(Some(entry))` on success.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError>;

    /// Store (create or update) a principal entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn put_principal(
        &self,
        _ctx: &KdbContext<'_>,
        _entry: PrincipalEntryRef<'_>,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    /// Delete a principal.  Return `Err(KdbError::NoEntry)` if not found.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn delete_principal(
        &self,
        _ctx: &KdbContext<'_>,
        _search_for: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    /// Rename a principal.  Return `Err(KdbError::NoEntry)` if source is absent.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn rename_principal(
        &self,
        _ctx: &KdbContext<'_>,
        _source: PrincipalRef<'_>,
        _target: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    /// Iterate over principals.
    ///
    /// `match_entry` is an optional regex hint; may be ignored by the module.
    /// The callback receives a zero-copy view of each entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn iterate_principals(
        &self,
        _ctx: &KdbContext<'_>,
        _match_entry: Option<&str>,
        _flags: IterFlags,
        _callback: &mut dyn FnMut(
            PrincipalEntryRef<'_>,
        ) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Password policy CRUD (all optional)
    // -----------------------------------------------------------------------
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn create_policy(
        &self,
        _ctx: &KdbContext<'_>,
        _policy: &PolicyEntry,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn get_policy(
        &self,
        _ctx: &KdbContext<'_>,
        _name: &str,
    ) -> Result<Option<PolicyEntry>, KdbError> {
        Err(KdbError::NotSupported)
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn put_policy(
        &self,
        _ctx: &KdbContext<'_>,
        _policy: &PolicyEntry,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn iter_policy(
        &self,
        _ctx: &KdbContext<'_>,
        _match_entry: Option<&str>,
        _callback: &mut dyn FnMut(&PolicyEntry) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn delete_policy(
        &self,
        _ctx: &KdbContext<'_>,
        _name: &str,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Key encryption (optional)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Master key operations (optional, each defaults to libkdb5 implementation)
    // -----------------------------------------------------------------------

    /// Retrieve the master keyblock from the stash file `db_args`.
    ///
    /// Returns `(key, kvno)`.  `NotSupported` → libkdb5 reads from the
    /// keytab or old-format stash file.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn fetch_master_key(
        &self,
        _ctx: &KdbContext<'_>,
        _mname: PrincipalRef<'_>,
        _db_args: &str,
    ) -> Result<(KeyBlock, u32), KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Key search (optional)
    // -----------------------------------------------------------------------

    /// Search the key data of `entry` for a key matching the given criteria.
    ///
    /// `start` is an in-out parameter: on entry it is the position to start
    /// searching from; on success it is updated to point past the found key.
    /// Pass `ktype`, `stype`, or `kvno` as negative to match any value.
    ///
    /// `NotSupported` → libkdb5 scans the key array using its built-in
    /// default implementation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn dbe_search_enctype<'entry>(
        &self,
        _ctx: &KdbContext<'_>,
        _entry: PrincipalEntryRef<'entry>,
        _start: &mut i32,
        _ktype: i32,
        _stype: i32,
        _kvno: i32,
    ) -> Result<Option<KeyDataRef<'entry>>, KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Key encryption (optional)
    // -----------------------------------------------------------------------

    /// Decrypt key data.  `NotSupported` → libkdb5 uses its default.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn decrypt_key_data(
        &self,
        _ctx: &KdbContext<'_>,
        _req: DecryptKeyRequest<'_>,
    ) -> Result<(KeyBlock, Option<KeySalt>), KdbError> {
        Err(KdbError::NotSupported)
    }

    /// Encrypt key data.  `NotSupported` → libkdb5 uses its default.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn encrypt_key_data(
        &self,
        _ctx: &KdbContext<'_>,
        _req: EncryptKeyRequest<'_>,
    ) -> Result<KeyDataOwned, KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // KDC policy hooks (optional)
    // -----------------------------------------------------------------------

    /// Additional AS request policy check.
    ///
    /// Return `Ok(())` to permit; `Err(PolicyDenied { .. })` to deny.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn check_policy_as(
        &self,
        _ctx: &KdbContext<'_>,
        _req: AsPolicyRequest<'_>,
    ) -> Result<(), PolicyDenied> {
        Ok(())
    }

    /// Additional TGS request policy check.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn check_policy_tgs(
        &self,
        _ctx: &KdbContext<'_>,
        _req: TgsPolicyRequest<'_>,
    ) -> Result<(), PolicyDenied> {
        Ok(())
    }

    /// Cross-realm transited-field policy check.
    ///
    /// Return `Err(KdbError::NoHandle)` to fall through to libkrb5's default.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn check_transited_realms(
        &self,
        _ctx: &KdbContext<'_>,
        _tr_contents: &[u8],
        _client_realm: &[u8],
        _server_realm: &[u8],
    ) -> Result<(), KdbError> {
        Err(KdbError::NoHandle)
    }

    /// `S4U2Proxy` traditional delegation check.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn check_allowed_to_delegate(
        &self,
        _ctx: &KdbContext<'_>,
        _req: DelegationRequest<'_>,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    /// `S4U2Proxy` resource-based constrained delegation check.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn allowed_to_delegate_from(
        &self,
        _ctx: &KdbContext<'_>,
        _req: ResourceDelegationRequest<'_>,
    ) -> Result<(), KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Audit hooks (optional, infallible)
    // -----------------------------------------------------------------------

    /// Notification of a completed AS request (success or failure).
    fn audit_as_req(&self, _ctx: &KdbContext<'_>, _event: AsAuditEvent<'_>) {}

    /// Notification that the KDC received SIGHUP (reload config).
    fn refresh_config(&self, _ctx: &KdbContext<'_>) {}

    // -----------------------------------------------------------------------
    // S4U X.509 principal lookup (optional)
    // -----------------------------------------------------------------------
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn get_s4u_x509_principal(
        &self,
        _ctx: &KdbContext<'_>,
        _req: S4uX509Request<'_>,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        Err(KdbError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // PAC issuance (optional)
    // -----------------------------------------------------------------------

    /// Add buffers to `output.new_pac` and optionally modify
    /// `output.auth_indicators` before the KDC signs the PAC.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    fn issue_pac(
        &self,
        _ctx: &KdbContext<'_>,
        _req: PacIssuanceRequest<'_>,
        _output: &mut PacIssuanceOutput<'_>,
    ) -> Result<(), KdbError> {
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Memory management hook (optional)
    // -----------------------------------------------------------------------

    /// Free the `e_data` pointer of a principal entry.
    ///
    /// Override if your module uses a custom allocator for `e_data`.
    /// The default no-ops; libkdb5 falls back to calling `free()` directly
    /// when this vtable slot is `NULL`.
    fn free_principal_e_data(&self, _e_data: *mut u8) {}
}
