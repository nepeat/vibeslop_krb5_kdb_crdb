//! `KdbContext` — a safe wrapper around `krb5_context` for use inside driver
//! callbacks.
//!
//! This module provides zero-cost access to the krb5 context and wraps the
//! libkdb5/libkrb5 utility functions that drivers commonly need.

use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::error::KdbError;
use crate::module::{KdbModule, PacBuilder, PacRef};
use crate::principal::{OwnedPrincipal, PrincipalEntryRef, PrincipalRef};
use crate::tl_data::TlDataRef;
use crate::types::{Timestamp, TlDataType};

// ---------------------------------------------------------------------------
// MIT Kerberos profile API — used to read [dbmodules] settings.
//
// These symbols are exported by libkrb5.so (already a direct dependency via
// libkdb5).  The profile_t handle is opaque; we represent it as *mut c_void.
// ---------------------------------------------------------------------------

extern "C" {
    fn krb5_get_profile(
        ctx: kdb_sys::krb5_context,
        profile: *mut *mut libc::c_void,
    ) -> kdb_sys::krb5_error_code;

    fn profile_get_string(
        profile: *mut libc::c_void,
        name: *const libc::c_char,
        subname: *const libc::c_char,
        subsubname: *const libc::c_char,
        def_val: *const libc::c_char,
        ret_string: *mut *mut libc::c_char,
    ) -> libc::c_long;

    fn profile_release_string(s: *mut libc::c_char);

    fn profile_release(profile: *mut libc::c_void);
}

// ---------------------------------------------------------------------------
// KdbContext
// ---------------------------------------------------------------------------

/// A zero-cost wrapper around `*mut krb5_context` providing safe utilities.
///
/// `'ctx` is the lifetime of the context pointer.  All values borrowed from
/// the context (e.g. the realm string) carry this lifetime.
///
/// `KdbContext` is passed by reference to every `KdbModule` method.  It must
/// not be stored beyond the duration of the call.
pub struct KdbContext<'ctx> {
    // krb5_context is typedef *mut _krb5_context — already a pointer type.
    ctx: kdb_sys::krb5_context,
    _phantom: PhantomData<&'ctx ()>,
}

impl KdbContext<'_> {
    /// Wrap a raw context pointer.
    ///
    /// # Safety (caller — `glue.rs` only)
    ///
    /// `ctx` must be non-null and valid for at least `'ctx`.
    pub(crate) unsafe fn from_raw(ctx: kdb_sys::krb5_context) -> Self {
        debug_assert!(!ctx.is_null());
        KdbContext {
            ctx,
            _phantom: PhantomData,
        }
    }

    /// The raw context pointer, needed by utility call wrappers below.
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> kdb_sys::krb5_context {
        self.ctx
    }

    /// Store a module instance as the `db_context` for this `KdbContext`.
    ///
    /// Called by [`KdbModule::create`] implementations that need to initialise
    /// the overlay context inline — mirroring the pattern in the reference C
    /// implementation where `kuserdb_create` calls `kuserdb_create_context`
    /// (which calls `krb5_db_set_context`) before delegating to the backing
    /// database's create.
    ///
    /// After this call succeeds, subsequent KDB operations on the same
    /// `krb5_context` (e.g. `krb5_db_put_principal`) will find the module
    /// in `db_context` and work without a separate `krb5_db_open` call.
    ///
    /// # Precondition
    ///
    /// `db_context` must be null when this is called.  If a module is already
    /// stored, the old value is overwritten and leaked.  In practice this is
    /// only called from `create()` before any `open()` has run.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn set_module<M: KdbModule>(&self, module: M) -> Result<(), KdbError> {
        let raw = Box::into_raw(Box::new(module)).cast::<libc::c_void>();
        // SAFETY: self.ctx is valid (KdbContext invariant); raw is a valid
        // heap pointer created by Box::into_raw.
        let code = unsafe { kdb_sys::krb5_db_set_context(self.ctx, raw) };
        if code != 0 {
            // SAFETY: raw was just created by Box::into_raw and has not been
            // shared, so we are the sole owner and may reclaim it.
            unsafe { drop(Box::from_raw(raw.cast::<M>())) };
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Realm
    // -----------------------------------------------------------------------

    /// Return the default realm as an owned `String`.
    ///
    /// Calls `krb5_get_default_realm` which allocates; the C string is freed
    /// immediately after copying into Rust.  Returns `Err` if no default realm
    /// is configured or the call fails.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn realm(&self) -> Result<String, KdbError> {
        let mut realm_ptr: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: ctx is valid; realm_ptr receives a malloc'd C string.
        let code = unsafe {
            kdb_sys::krb5_get_default_realm(self.ctx, &raw mut realm_ptr)
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        if realm_ptr.is_null() {
            return Err(KdbError::Custom(libc::ENODATA));
        }
        // SAFETY: realm_ptr is a valid null-terminated string.
        let s = unsafe {
            CStr::from_ptr(realm_ptr).to_string_lossy().into_owned()
        };
        // SAFETY: free via the matching libkrb5 function.
        unsafe { kdb_sys::krb5_free_default_realm(self.ctx, realm_ptr) };
        Ok(s)
    }

    // -----------------------------------------------------------------------
    // KDC profile helpers
    // -----------------------------------------------------------------------

    /// Read a string from `[dbmodules]/<conf_section>/<key>` in the KDC profile.
    ///
    /// Returns `None` if the key is absent or an error occurs.  The caller
    /// passes the `conf_section` value received from libkdb5 in `init_module`.
    ///
    /// Overlay plugins use this to read their own config keys (e.g.
    /// `database_name`, `disallow_name_aliases`) so they can forward them to
    /// the backing database as `db_args`.
    #[must_use]
    pub fn db_module_string(
        &self,
        conf_section: &str,
        key: &str,
    ) -> Option<String> {
        let csection = CString::new(conf_section).ok()?;
        let ckey = CString::new(key).ok()?;

        let mut profile: *mut libc::c_void = std::ptr::null_mut();
        // SAFETY: self.ctx is valid; profile receives the allocated handle.
        let code = unsafe { krb5_get_profile(self.ctx, &raw mut profile) };
        if code != 0 || profile.is_null() {
            return None;
        }

        let mut value: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: profile and all C strings are valid; def_val=NULL means
        // return NULL (not the string "null") when the key is absent.
        let ret = unsafe {
            profile_get_string(
                profile,
                c"dbmodules".as_ptr(),
                csection.as_ptr(),
                ckey.as_ptr(),
                std::ptr::null(), // no default — NULL value means absent
                &raw mut value,
            )
        };
        // SAFETY: profile was allocated by krb5_get_profile.
        unsafe { profile_release(profile) };

        if ret != 0 || value.is_null() {
            return None;
        }

        // SAFETY: value is a valid null-terminated string from profile_get_string.
        let s =
            unsafe { CStr::from_ptr(value).to_string_lossy().into_owned() };
        // SAFETY: value was allocated by profile_get_string; free via its API.
        unsafe { profile_release_string(value) };
        Some(s)
    }

    // -----------------------------------------------------------------------
    // Principal name operations
    // -----------------------------------------------------------------------

    /// Unparse a principal in short form — omitting the realm component.
    ///
    /// Calls `krb5_unparse_name_flags` with `KRB5_PRINCIPAL_UNPARSE_SHORT`.
    /// Returns just the name components joined by `/` (e.g. `"user"` or
    /// `"host/server.example.com"`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn unparse_principal_short(
        &self,
        princ: PrincipalRef<'_>,
    ) -> Result<String, KdbError> {
        let mut out: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: ctx and princ are valid; out receives a malloc'd string.
        let code = unsafe {
            kdb_sys::krb5_unparse_name_flags(
                self.ctx,
                princ.as_raw(),
                kdb_sys::KRB5_PRINCIPAL_UNPARSE_SHORT.cast_signed(),
                &raw mut out,
            )
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        let s = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        // SAFETY: out was allocated by krb5_unparse_name_flags; free via libkrb5.
        unsafe { kdb_sys::krb5_free_unparsed_name(self.ctx, out) };
        Ok(s)
    }

    /// Unparse a principal to a string (e.g. `"user@REALM"`).
    ///
    /// Allocates a `String`; the C-allocated unparsed name is immediately
    /// copied and freed.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn unparse_principal(
        &self,
        princ: PrincipalRef<'_>,
    ) -> Result<String, KdbError> {
        let mut out: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: ctx and princ are valid; out receives a malloc'd string.
        let code = unsafe {
            kdb_sys::krb5_unparse_name(self.ctx, princ.as_raw(), &raw mut out)
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        let s = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        // SAFETY: out was allocated by krb5_unparse_name; free via libkrb5.
        unsafe { kdb_sys::krb5_free_unparsed_name(self.ctx, out) };
        Ok(s)
    }

    /// Parse a principal name string into an `OwnedPrincipal`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn parse_principal(
        &self,
        name: &str,
    ) -> Result<OwnedPrincipal, KdbError> {
        let cname =
            CString::new(name).map_err(|_| KdbError::Custom(libc::EINVAL))?;
        let mut out: kdb_sys::krb5_principal = std::ptr::null_mut();
        // SAFETY: ctx is valid; cname is a valid C string; out receives
        // a krb5_principal_data allocated by krb5_parse_name.
        let code = unsafe {
            kdb_sys::krb5_parse_name(self.ctx, cname.as_ptr(), &raw mut out)
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        // SAFETY: out is non-null on success and was allocated by libkrb5.
        let out = unsafe { NonNull::new_unchecked(out) };
        Ok(unsafe { OwnedPrincipal::from_raw(self.ctx, out) })
    }

    // -----------------------------------------------------------------------
    // TL-data helpers
    // -----------------------------------------------------------------------

    /// Find the first TL-data record of the given type in an entry.
    ///
    /// Returns a zero-copy view; no allocation occurs.
    #[must_use]
    pub fn lookup_tl_data<'e>(
        &self,
        entry: &PrincipalEntryRef<'e>,
        ty: TlDataType,
    ) -> Option<TlDataRef<'e>> {
        entry.find_tl_data(ty)
    }

    /// Insert or replace a TL-data record in an entry using
    /// `krb5_dbe_update_tl_data`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than `u16::MAX` bytes (65535).
    pub fn update_tl_data(
        &self,
        entry: &mut crate::principal::PrincipalEntry,
        ty: TlDataType,
        data: &[u8],
    ) -> Result<(), KdbError> {
        // We need a raw krb5_tl_data on the stack for the call.
        let mut tl = kdb_sys::krb5_tl_data {
            tl_data_next: std::ptr::null_mut(),
            tl_data_type: ty.as_u16().cast_signed(),
            tl_data_length: u16::try_from(data.len())
                .expect("TL-data length fits in u16"),
            // krb5_dbe_update_tl_data copies the contents; we can pass a
            // pointer to our data directly.
            tl_data_contents: data.as_ptr().cast_mut(),
        };
        // SAFETY: ctx is valid; entry.ptr is valid; tl is on the stack.
        let code = unsafe {
            kdb_sys::krb5_dbe_update_tl_data(
                self.ctx,
                entry.as_raw_mut(),
                &raw mut tl,
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // String attribute helpers
    // -----------------------------------------------------------------------

    /// Retrieve a string attribute by key from an entry's TL-data.
    ///
    /// Returns `None` if the key is not present.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn get_string_attr(
        &self,
        entry: &PrincipalEntryRef<'_>,
        key: &str,
    ) -> Result<Option<String>, KdbError> {
        // krb5_dbe_get_string allocates; we own the returned pointer.
        let ckey =
            CString::new(key).map_err(|_| KdbError::Custom(libc::EINVAL))?;
        let mut value: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: ctx and the entry raw pointer are valid.
        let code = unsafe {
            kdb_sys::krb5_dbe_get_string(
                self.ctx,
                // get_string takes *mut, but does not modify the entry.
                entry.as_raw().cast_mut(),
                ckey.as_ptr(),
                &raw mut value,
            )
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        if value.is_null() {
            return Ok(None);
        }
        // SAFETY: value is a null-terminated string allocated by libkdb5.
        let s = unsafe {
            CStr::from_ptr(value)
                .to_str()
                .map(std::borrow::ToOwned::to_owned)
        };
        // SAFETY: value was allocated by krb5_dbe_get_string; free via its API.
        unsafe { kdb_sys::krb5_dbe_free_string(self.ctx, value) };
        s.map(Some).map_err(|_| KdbError::Custom(libc::EINVAL))
    }

    /// Set or delete a string attribute in an entry.
    ///
    /// Pass `value = None` to delete the key.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn set_string_attr(
        &self,
        entry: &mut crate::principal::PrincipalEntry,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), KdbError> {
        let ckey =
            CString::new(key).map_err(|_| KdbError::Custom(libc::EINVAL))?;
        let cval_opt = value
            .map(|v| {
                CString::new(v).map_err(|_| KdbError::Custom(libc::EINVAL))
            })
            .transpose()?;
        let cval_ptr =
            cval_opt.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        // SAFETY: ctx and entry are valid.
        let code = unsafe {
            kdb_sys::krb5_dbe_set_string(
                self.ctx,
                entry.as_raw_mut(),
                ckey.as_ptr(),
                cval_ptr,
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Set the modification-principal TL-data (`KRB5_TL_MOD_PRINC`) in an entry.
    ///
    /// libkrb5 checks for this record in `krb5_dbe_lookup_mod_princ_data()` and
    /// returns `KRB5_KDB_TRUNCATED_RECORD` when it is absent or too short.  Any
    /// entry that may be inspected by kadmin or other kdb5 callers (not only the
    /// KDC AS path) must have this record present.
    ///
    /// Pass the current wall-clock time as `mod_date` and the principal that
    /// "created" the entry as `mod_princ` (e.g. the principal being synthesised).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn update_mod_princ_data(
        &self,
        entry: &mut crate::principal::PrincipalEntry,
        mod_date: Timestamp,
        mod_princ: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        // SAFETY: ctx, entry, and mod_princ are all valid for the duration of
        // this call.  krb5_dbe_update_mod_princ_data encodes the data into a
        // new TL-data record attached to entry->tl_data.
        let code = unsafe {
            kdb_sys::krb5_dbe_update_mod_princ_data(
                self.ctx,
                entry.as_raw_mut(),
                mod_date.0,
                mod_princ.as_raw(),
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Timestamp helpers
    // -----------------------------------------------------------------------

    /// Look up the last password-change timestamp from an entry's TL-data.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn lookup_last_pwd_change(
        &self,
        entry: &PrincipalEntryRef<'_>,
    ) -> Result<Option<Timestamp>, KdbError> {
        let mut stamp: kdb_sys::krb5_timestamp = 0;
        // SAFETY: ctx is valid; entry raw pointer is valid.
        let code = unsafe {
            kdb_sys::krb5_dbe_lookup_last_pwd_change(
                self.ctx,
                entry.as_raw().cast_mut(),
                &raw mut stamp,
            )
        };
        match code {
            0 => Ok(Some(Timestamp(stamp))),
            c if c == crate::error::KdbError::NoEntry.into_error_code() => {
                Ok(None)
            },
            other => Err(KdbError::from_error_code(other)),
        }
    }

    /// Update the last password-change timestamp in an entry's TL-data.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn update_last_pwd_change(
        &self,
        entry: &mut crate::principal::PrincipalEntry,
        stamp: Timestamp,
    ) -> Result<(), KdbError> {
        // SAFETY: ctx and entry raw pointer are valid.
        let code = unsafe {
            kdb_sys::krb5_dbe_update_last_pwd_change(
                self.ctx,
                entry.as_raw_mut(),
                stamp.0,
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Look up the last-modification principal and timestamp.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn lookup_mod_princ(
        &self,
        entry: &PrincipalEntryRef<'_>,
    ) -> Result<Option<(Timestamp, OwnedPrincipal)>, KdbError> {
        let mut stamp: kdb_sys::krb5_timestamp = 0;
        let mut mod_princ: kdb_sys::krb5_principal = std::ptr::null_mut();
        // SAFETY: ctx is valid; entry raw pointer is valid.
        let code = unsafe {
            kdb_sys::krb5_dbe_lookup_mod_princ_data(
                self.ctx,
                entry.as_raw().cast_mut(),
                &raw mut stamp,
                &raw mut mod_princ,
            )
        };
        match code {
            0 => Ok(NonNull::new(mod_princ).map(|nn| {
                // SAFETY: mod_princ is non-null and was allocated by libkrb5.
                let princ = unsafe { OwnedPrincipal::from_raw(self.ctx, nn) };
                (Timestamp(stamp), princ)
            })),
            c if c == KdbError::NoEntry.into_error_code() => Ok(None),
            other => Err(KdbError::from_error_code(other)),
        }
    }

    /// Update the last-modification principal and timestamp in an entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn update_mod_princ(
        &self,
        entry: &mut crate::principal::PrincipalEntry,
        stamp: Timestamp,
        mod_princ: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        // SAFETY: ctx, entry, and mod_princ are all valid.
        let code = unsafe {
            kdb_sys::krb5_dbe_update_mod_princ_data(
                self.ctx,
                entry.as_raw_mut(),
                stamp.0,
                mod_princ.as_raw(),
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // PAC buffer helpers
    // -----------------------------------------------------------------------

    /// Return the buffer type IDs present in a PAC.
    ///
    /// Returns an empty vec if the PAC has no buffers or on error.
    #[must_use]
    pub fn pac_get_buffer_types(&self, pac: &PacRef<'_>) -> Vec<u32> {
        let mut count: usize = 0;
        let mut types_ptr: *mut kdb_sys::krb5_ui_4 = std::ptr::null_mut();
        // SAFETY: ctx and pac.pac are valid for this call.
        let code = unsafe {
            kdb_sys::krb5_pac_get_types(
                self.ctx,
                pac.pac,
                &raw mut count,
                &raw mut types_ptr,
            )
        };
        if code != 0 || types_ptr.is_null() {
            return vec![];
        }
        // SAFETY: types_ptr points to count elements of krb5_ui_4.
        let result =
            unsafe { std::slice::from_raw_parts(types_ptr, count) }.to_vec();
        // SAFETY: types_ptr was allocated by libkrb5 with malloc.
        unsafe { libc::free(types_ptr.cast::<libc::c_void>()) };
        result
    }

    /// Return the contents of a specific PAC buffer, or `None` on error.
    #[must_use]
    pub fn pac_get_buffer(
        &self,
        pac: &PacRef<'_>,
        buf_type: u32,
    ) -> Option<Vec<u8>> {
        let mut data = kdb_sys::krb5_data::default();
        // SAFETY: ctx and pac.pac are valid; data is a valid out-parameter.
        let code = unsafe {
            kdb_sys::krb5_pac_get_buffer(
                self.ctx,
                pac.pac,
                buf_type as kdb_sys::krb5_ui_4,
                &raw mut data,
            )
        };
        if code != 0 {
            return None;
        }
        let result = if data.data.is_null() || data.length == 0 {
            vec![]
        } else {
            // SAFETY: data.data points to data.length bytes allocated by libkrb5.
            unsafe {
                std::slice::from_raw_parts(
                    data.data as *const u8,
                    data.length as usize,
                )
            }
            .to_vec()
        };
        if !data.data.is_null() {
            // SAFETY: data.data was allocated by libkrb5 with malloc.
            unsafe { libc::free(data.data.cast::<libc::c_void>()) };
        }
        Some(result)
    }

    /// Add a buffer to a PAC under construction.
    ///
    /// `buf_type` is the PAC buffer type ID (e.g. `KRB5_PAC_LOGON_INFO = 1`).
    /// `data` is the raw buffer contents; libkrb5 copies them internally.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    ///
    /// # Panics
    ///
    /// Panics if `data` is longer than `u32::MAX` bytes.
    pub fn pac_add_buffer(
        &self,
        pac: &mut PacBuilder<'_>,
        buf_type: u32,
        data: &[u8],
    ) -> Result<(), KdbError> {
        let kdata = kdb_sys::krb5_data {
            length: u32::try_from(data.len()).expect("PAC buffer fits in u32"),
            data: data.as_ptr() as *mut libc::c_char,
            ..Default::default()
        };
        // SAFETY: ctx and pac.pac are valid; kdata borrows our slice which is
        // valid for the duration of this call; krb5_pac_add_buffer copies data.
        let code = unsafe {
            kdb_sys::krb5_pac_add_buffer(
                self.ctx,
                pac.pac,
                buf_type as kdb_sys::krb5_ui_4,
                &raw const kdata,
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Krb5Context — owned, RAII krb5_context
// ---------------------------------------------------------------------------

/// An owned Kerberos context.
///
/// Wraps the full lifecycle of a `krb5_context`:
/// - [`Krb5Context::new`] initialises via `krb5_init_context`.
/// - [`Clone`] copies via `krb5_copy_context`.
/// - [`Drop`] frees via `krb5_free_context`.
///
/// Useful for standalone tools, overlay plugins, and integration tests that
/// need to create a context independently of an active KDB callback.
///
/// # Example
///
/// ```rust,ignore
/// let ctx = Krb5Context::new().unwrap();
/// let kdb = ctx.as_kdb();
/// let princ = kdb.parse_principal("user@REALM.ORG").unwrap();
/// ```
pub struct Krb5Context {
    ctx: kdb_sys::krb5_context,
}

// SAFETY: Krb5Context exclusively owns its ctx pointer; all access goes
// through &self / &mut self, matching the krb5 single-thread-per-context
// contract.  Send (not Sync) is appropriate.
unsafe impl Send for Krb5Context {}

impl Krb5Context {
    /// Initialise a new Kerberos context via `krb5_init_context`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn new() -> Result<Self, KdbError> {
        let mut ctx: kdb_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: krb5_init_context writes a valid pointer into ctx on success.
        let code = unsafe { kdb_sys::krb5_init_context(&raw mut ctx) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(Krb5Context { ctx })
        }
    }

    /// Borrow as a [`KdbContext`] tied to the lifetime of this `Krb5Context`.
    #[must_use]
    pub fn as_kdb(&self) -> KdbContext<'_> {
        // SAFETY: self.ctx is valid for the lifetime of self.
        unsafe { KdbContext::from_raw(self.ctx) }
    }
}

impl Clone for Krb5Context {
    /// Copy the context via `krb5_copy_context`.  Panics if the copy fails.
    fn clone(&self) -> Self {
        let mut ctx: kdb_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: self.ctx is valid; ctx receives the allocated copy.
        let code =
            unsafe { kdb_sys::krb5_copy_context(self.ctx, &raw mut ctx) };
        assert_eq!(code, 0, "krb5_copy_context failed with code {code}");
        Krb5Context { ctx }
    }
}

impl Drop for Krb5Context {
    fn drop(&mut self) {
        // SAFETY: self.ctx was created by krb5_init_context or krb5_copy_context
        // and is exclusively owned by this struct.
        unsafe { kdb_sys::krb5_free_context(self.ctx) };
    }
}

// ---------------------------------------------------------------------------
// Integration tests (5.9)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "context_tests.rs"]
mod tests;
