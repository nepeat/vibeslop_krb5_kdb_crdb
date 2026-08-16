//! Local-mode KADM5 admin handle.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use kurbu5_kadm5_rs::admin::AdminHandle;
//! use kurbu5_kadm5_sys as sys;
//!
//! fn main() -> Result<(), sys::kadm5_ret_t> {
//!     let h = AdminHandle::open(None)?;
//!
//!     for name in h.list_principals(None)? {
//!         println!("{name}");
//!     }
//!
//!     let kvno = h.get_principal(
//!         "alice@EXAMPLE.COM",
//!         sys::KADM5_PRINCIPAL_NORMAL_MASK as i64,
//!         |ent| ent.kvno,
//!     )?;
//!     println!("kvno: {kvno}");
//!
//!     h.chpass_principal("alice@EXAMPLE.COM", false, &[], "s3cret")?;
//!     Ok(())
//! }
//! ```

use std::ffi::{CStr, CString, c_void};
use std::ptr;

use kurbu5_kadm5_sys as sys;

/// RAII wrapper around the opaque `void *` KADM5 server handle.
///
/// Created via [`AdminHandle::open`]; dropped via [`Drop`] which calls
/// `kadm5_destroy` and `krb5_free_context`.  One handle per operation is
/// appropriate — do not share across threads.
pub struct AdminHandle {
    handle: *mut c_void,
    ctx: sys::krb5_context,
}

// Each caller creates and destroys its own AdminHandle; no shared state.
unsafe impl Send for AdminHandle {}

impl AdminHandle {
    /// Open a local-mode KADM5 admin connection.
    ///
    /// Calls `krb5_init_context` then `kadm5_init_with_password` with NULL
    /// client/password/params and the `"kadmin/admin"` service name, which
    /// selects KDB-direct (local-mode) operation.
    ///
    /// `db_args` is passed as the `char **db_args` parameter.  Pass `None` to
    /// use defaults from `kdc.conf`; pass `Some(args)` to supply additional
    /// database arguments (e.g. `["dbmodule:path=/var/lib/krb5kdc/principal"]`).
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if context initialisation or the
    /// KADM5 init call fails.
    pub fn open(db_args: Option<&[&str]>) -> Result<Self, sys::kadm5_ret_t> {
        let mut ctx: sys::krb5_context = ptr::null_mut();
        // SAFETY: krb5_init_context writes into ctx; no other preconditions.
        let code = unsafe { sys::krb5_init_context(&raw mut ctx) };
        if code != 0 {
            return Err(i64::from(code));
        }

        // Convert db_args to a NULL-terminated C array.  The CString values
        // must outlive the kadm5_init_with_password call below.
        let (c_strings, mut c_ptrs): (Vec<CString>, Vec<*mut libc::c_char>);
        let db_args_ptr: *mut *mut libc::c_char = match db_args {
            None => ptr::null_mut(),
            Some(args) => {
                c_strings = args
                    .iter()
                    .map(|s| CString::new(*s).unwrap_or_default())
                    .collect();
                c_ptrs =
                    c_strings.iter().map(|s| s.as_ptr().cast_mut()).collect();
                c_ptrs.push(ptr::null_mut()); // NULL terminator
                c_ptrs.as_mut_ptr()
            },
        };

        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: ctx is valid; NULL client/pass/params selects local mode.
        let code = unsafe {
            sys::kadm5_init_with_password(
                ctx,
                ptr::null_mut(), // client_name = NULL
                ptr::null_mut(), // pass = NULL
                c"kadmin/admin".as_ptr().cast_mut(),
                ptr::null_mut(), // params = NULL
                sys::KADM5_STRUCT_VERSION,
                sys::KADM5_API_VERSION_4,
                db_args_ptr,
                &raw mut handle,
            )
        };
        if code != 0 {
            // SAFETY: ctx was initialised above; free on error path.
            unsafe { sys::krb5_free_context(ctx) };
            return Err(code);
        }

        Ok(AdminHandle { handle, ctx })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Parse a principal name string into a `krb5_principal`.
    ///
    /// The returned pointer must be freed with `krb5_free_principal`.
    fn parse_name(
        &self,
        name: &str,
    ) -> Result<sys::krb5_principal, sys::kadm5_ret_t> {
        let name_c =
            CString::new(name).map_err(|_| i64::from(libc::EINVAL))?;
        let mut princ: sys::krb5_principal = ptr::null_mut();
        // SAFETY: self.ctx is valid; name_c is null-terminated.
        let code = unsafe {
            sys::krb5_parse_name(self.ctx, name_c.as_ptr(), &raw mut princ)
        };
        if code != 0 {
            Err(i64::from(code))
        } else {
            Ok(princ)
        }
    }

    /// Map a raw `kadm5_ret_t` to `Result<(), kadm5_ret_t>`.
    fn ret(code: sys::kadm5_ret_t) -> Result<(), sys::kadm5_ret_t> {
        if code == 0 { Ok(()) } else { Err(code) }
    }

    // -----------------------------------------------------------------------
    // Convenience operation (kept from original implementation)
    // -----------------------------------------------------------------------

    /// Create or update a principal with the given `password`.
    ///
    /// Tries `kadm5_create_principal_3` first (sets `REQUIRES_PRE_AUTH`);
    /// if the principal already exists (`KADM5_DUP`), falls back to
    /// `kadm5_chpass_principal_3`.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing, creation, or
    /// password change fails.
    pub fn create_or_chpass_principal(
        &self,
        principal_name: &str,
        password: &str,
    ) -> Result<(), sys::kadm5_ret_t> {
        let pw_c = CString::new(password)
            .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))?;
        let princ = self.parse_name(principal_name)?;

        // Minimal entry: principal name + REQUIRES_PRE_AUTH.
        let mut ent = sys::_kadm5_principal_ent_t {
            principal: princ,
            #[allow(clippy::cast_possible_wrap)]
            attributes: sys::KRB5_KDB_REQUIRES_PRE_AUTH as sys::krb5_flags,
            ..Default::default()
        };
        let mask = i64::from(sys::KADM5_PRINCIPAL | sys::KADM5_ATTRIBUTES);

        // SAFETY: self.handle, ent, pw_c are all valid.
        let create_code = unsafe {
            sys::kadm5_create_principal_3(
                self.handle,
                &raw mut ent,
                mask,
                0,
                ptr::null_mut(),
                pw_c.as_ptr().cast_mut(),
            )
        };

        let final_code = if create_code == i64::from(sys::KADM5_DUP) {
            // SAFETY: all pointers valid; keepold=0 replaces old keys.
            unsafe {
                sys::kadm5_chpass_principal_3(
                    self.handle,
                    princ,
                    0,
                    0,
                    ptr::null_mut(),
                    pw_c.as_ptr().cast_mut(),
                )
            }
        } else {
            create_code
        };

        // SAFETY: princ was allocated by krb5_parse_name.
        unsafe { sys::krb5_free_principal(self.ctx, princ) };

        Self::ret(final_code)
    }

    // -----------------------------------------------------------------------
    // Principal management
    // -----------------------------------------------------------------------

    /// Delete the named principal.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn delete_principal(
        &self,
        name: &str,
    ) -> Result<(), sys::kadm5_ret_t> {
        let princ = self.parse_name(name)?;
        // SAFETY: handle and princ are valid.
        let code = unsafe { sys::kadm5_delete_principal(self.handle, princ) };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        Self::ret(code)
    }

    /// Rename a principal.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if either name cannot be parsed or
    /// the KADM5 call fails.
    pub fn rename_principal(
        &self,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), sys::kadm5_ret_t> {
        let old = self.parse_name(old_name)?;
        let new = match self.parse_name(new_name) {
            Ok(p) => p,
            Err(e) => {
                unsafe { sys::krb5_free_principal(self.ctx, old) };
                return Err(e);
            },
        };
        // SAFETY: handle, old, new are valid.
        let code =
            unsafe { sys::kadm5_rename_principal(self.handle, old, new) };
        unsafe {
            sys::krb5_free_principal(self.ctx, old);
            sys::krb5_free_principal(self.ctx, new);
        }
        Self::ret(code)
    }

    /// Modify a principal entry.  Only fields indicated by `mask` are updated.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn modify_principal(
        &self,
        ent: &mut sys::_kadm5_principal_ent_t,
        mask: i64,
    ) -> Result<(), sys::kadm5_ret_t> {
        // SAFETY: handle and ent are valid; mask controls which fields are read.
        let code =
            unsafe { sys::kadm5_modify_principal(self.handle, ent, mask) };
        Self::ret(code)
    }

    /// Retrieve a principal entry and pass it to a closure.
    ///
    /// The entry is freed after the closure returns.  `mask` controls which
    /// fields are populated (use `KADM5_PRINCIPAL_NORMAL_MASK` for all fields).
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn get_principal<F, T>(
        &self,
        name: &str,
        mask: i64,
        f: F,
    ) -> Result<T, sys::kadm5_ret_t>
    where
        F: FnOnce(&sys::_kadm5_principal_ent_t) -> T,
    {
        let princ = self.parse_name(name)?;
        let mut ent = sys::_kadm5_principal_ent_t::default();
        // SAFETY: handle, princ, ent are valid.
        let code = unsafe {
            sys::kadm5_get_principal(self.handle, princ, &raw mut ent, mask)
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        if code != 0 {
            return Err(code);
        }
        let result = f(&ent);
        // SAFETY: ent was populated by kadm5_get_principal.
        unsafe { sys::kadm5_free_principal_ent(self.handle, &raw mut ent) };
        Ok(result)
    }

    /// List principals matching a glob expression.  `None` returns all.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the glob string contains interior
    /// NUL bytes or the KADM5 call fails.
    pub fn list_principals(
        &self,
        glob: Option<&str>,
    ) -> Result<Vec<String>, sys::kadm5_ret_t> {
        let glob_c = glob
            .map(|g| {
                CString::new(g)
                    .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))
            })
            .transpose()?;
        let glob_ptr = glob_c
            .as_ref()
            .map_or(ptr::null_mut(), |c| c.as_ptr().cast_mut());

        let mut names: *mut *mut libc::c_char = ptr::null_mut();
        let mut count: libc::c_int = 0;
        // SAFETY: handle, glob_ptr are valid; names/count are out-params.
        let code = unsafe {
            sys::kadm5_get_principals(
                self.handle,
                glob_ptr,
                &raw mut names,
                &raw mut count,
            )
        };
        if code != 0 {
            return Err(code);
        }
        let result = Self::collect_name_list(names, count);
        // SAFETY: names was allocated by kadm5_get_principals.
        unsafe { sys::kadm5_free_name_list(self.handle, names, count) };
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Password / key operations
    // -----------------------------------------------------------------------

    /// Change a principal's password (latest variant, API version 3).
    ///
    /// `keepold` retains the existing keys alongside the new ones.
    /// `ks_tuples` restricts which enctypes are generated; pass `&[]` for defaults.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn chpass_principal(
        &self,
        name: &str,
        keepold: bool,
        ks_tuples: &[sys::krb5_key_salt_tuple],
        password: &str,
    ) -> Result<(), sys::kadm5_ret_t> {
        let pw_c = CString::new(password)
            .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))?;
        let princ = self.parse_name(name)?;
        let n =
            libc::c_int::try_from(ks_tuples.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: all pointers valid; ks_tuples slice may be empty.
        let code = unsafe {
            sys::kadm5_chpass_principal_3(
                self.handle,
                princ,
                libc::c_uint::from(keepold),
                n,
                ks_tuples.as_ptr().cast_mut(),
                pw_c.as_ptr().cast_mut(),
            )
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        Self::ret(code)
    }

    /// Randomize a principal's keys (latest variant, API version 3).
    ///
    /// The new keys are not returned.  `keepold` retains the existing keys
    /// alongside the new ones.  `ks_tuples` restricts which enctypes are
    /// generated; pass `&[]` for defaults.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn randkey_principal(
        &self,
        name: &str,
        keepold: bool,
        ks_tuples: &[sys::krb5_key_salt_tuple],
    ) -> Result<(), sys::kadm5_ret_t> {
        let princ = self.parse_name(name)?;
        let n =
            libc::c_int::try_from(ks_tuples.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: all pointers valid; NULL keyblocks/n_keys discards the output.
        let code = unsafe {
            sys::kadm5_randkey_principal_3(
                self.handle,
                princ,
                libc::c_uint::from(keepold),
                n,
                ks_tuples.as_ptr().cast_mut(),
                ptr::null_mut(), // keyblocks out — discard
                ptr::null_mut(), // n_keys out — discard
            )
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        Self::ret(code)
    }

    /// Set specific keys for a principal (latest variant, API version 4).
    ///
    /// `keepold` retains the existing keys alongside the new ones.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn setkey_principal(
        &self,
        name: &str,
        keepold: bool,
        key_data: &[sys::kadm5_key_data],
    ) -> Result<(), sys::kadm5_ret_t> {
        let princ = self.parse_name(name)?;
        let n =
            libc::c_int::try_from(key_data.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: handle, princ, key_data slice are valid.
        let code = unsafe {
            sys::kadm5_setkey_principal_4(
                self.handle,
                princ,
                libc::c_uint::from(keepold),
                key_data.as_ptr().cast_mut(),
                n,
            )
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        Self::ret(code)
    }

    /// Retrieve the keys for a principal at a given kvno and pass them to a closure.
    ///
    /// The key data is freed after the closure returns.  Pass `kvno = 0` to
    /// retrieve the current keys.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn get_principal_keys<F, T>(
        &self,
        name: &str,
        kvno: sys::krb5_kvno,
        f: F,
    ) -> Result<T, sys::kadm5_ret_t>
    where
        F: FnOnce(&[sys::kadm5_key_data]) -> T,
    {
        let princ = self.parse_name(name)?;
        let mut key_data: *mut sys::kadm5_key_data = ptr::null_mut();
        let mut n_key_data: libc::c_int = 0;
        // SAFETY: handle, princ are valid; key_data/n_key_data are out-params.
        let code = unsafe {
            sys::kadm5_get_principal_keys(
                self.handle,
                princ,
                kvno,
                &raw mut key_data,
                &raw mut n_key_data,
            )
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        if code != 0 {
            return Err(code);
        }
        let n = usize::try_from(n_key_data).unwrap_or(0);
        let slice = if key_data.is_null() || n == 0 {
            &[]
        } else {
            // SAFETY: key_data points to n elements allocated by kadm5.
            unsafe { std::slice::from_raw_parts(key_data, n) }
        };
        let result = f(slice);
        if !key_data.is_null() {
            // SAFETY: key_data was allocated by kadm5_get_principal_keys.
            unsafe {
                sys::kadm5_free_kadm5_key_data(self.ctx, n_key_data, key_data)
            };
        }
        Ok(result)
    }

    /// Purge old keys for a principal, retaining only those at `keepkvno` and higher.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn purge_keys(
        &self,
        name: &str,
        keepkvno: i32,
    ) -> Result<(), sys::kadm5_ret_t> {
        let princ = self.parse_name(name)?;
        // SAFETY: handle and princ are valid.
        let code =
            unsafe { sys::kadm5_purgekeys(self.handle, princ, keepkvno) };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        Self::ret(code)
    }

    // -----------------------------------------------------------------------
    // Policy management
    // -----------------------------------------------------------------------

    /// Create a new password policy.  Only fields indicated by `mask` are set.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn create_policy(
        &self,
        ent: &mut sys::_kadm5_policy_ent_t,
        mask: i64,
    ) -> Result<(), sys::kadm5_ret_t> {
        // SAFETY: handle and ent are valid.
        Self::ret(unsafe { sys::kadm5_create_policy(self.handle, ent, mask) })
    }

    /// Delete the named password policy.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the policy name contains interior
    /// NUL bytes or the KADM5 call fails.
    pub fn delete_policy(&self, name: &str) -> Result<(), sys::kadm5_ret_t> {
        let name_c = CString::new(name)
            .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))?;
        // SAFETY: handle and name_c are valid.
        Self::ret(unsafe {
            sys::kadm5_delete_policy(self.handle, name_c.as_ptr().cast_mut())
        })
    }

    /// Modify a password policy.  Only fields indicated by `mask` are updated.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn modify_policy(
        &self,
        ent: &mut sys::_kadm5_policy_ent_t,
        mask: i64,
    ) -> Result<(), sys::kadm5_ret_t> {
        // SAFETY: handle and ent are valid.
        Self::ret(unsafe { sys::kadm5_modify_policy(self.handle, ent, mask) })
    }

    /// Retrieve a policy entry and pass it to a closure.
    ///
    /// The entry is freed after the closure returns.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the policy name contains interior
    /// NUL bytes or the KADM5 call fails.
    pub fn get_policy<F, T>(
        &self,
        name: &str,
        f: F,
    ) -> Result<T, sys::kadm5_ret_t>
    where
        F: FnOnce(&sys::_kadm5_policy_ent_t) -> T,
    {
        let name_c = CString::new(name)
            .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))?;
        let mut ent = sys::_kadm5_policy_ent_t::default();
        // SAFETY: handle, name_c, ent are valid.
        let code = unsafe {
            sys::kadm5_get_policy(
                self.handle,
                name_c.as_ptr().cast_mut(),
                &raw mut ent,
            )
        };
        if code != 0 {
            return Err(code);
        }
        let result = f(&ent);
        // SAFETY: ent was populated by kadm5_get_policy.
        unsafe { sys::kadm5_free_policy_ent(self.handle, &raw mut ent) };
        Ok(result)
    }

    /// List policies matching a glob expression.  `None` returns all.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the glob string contains interior
    /// NUL bytes or the KADM5 call fails.
    pub fn list_policies(
        &self,
        glob: Option<&str>,
    ) -> Result<Vec<String>, sys::kadm5_ret_t> {
        let glob_c = glob
            .map(|g| {
                CString::new(g)
                    .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))
            })
            .transpose()?;
        let glob_ptr = glob_c
            .as_ref()
            .map_or(ptr::null_mut(), |c| c.as_ptr().cast_mut());

        let mut names: *mut *mut libc::c_char = ptr::null_mut();
        let mut count: libc::c_int = 0;
        // SAFETY: handle, glob_ptr are valid; names/count are out-params.
        let code = unsafe {
            sys::kadm5_get_policies(
                self.handle,
                glob_ptr,
                &raw mut names,
                &raw mut count,
            )
        };
        if code != 0 {
            return Err(code);
        }
        let result = Self::collect_name_list(names, count);
        // SAFETY: names was allocated by kadm5_get_policies.
        unsafe { sys::kadm5_free_name_list(self.handle, names, count) };
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // String attributes
    // -----------------------------------------------------------------------

    /// Retrieve all string attributes for a principal as `(key, value)` pairs.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing or the KADM5
    /// call fails.
    pub fn get_strings(
        &self,
        name: &str,
    ) -> Result<Vec<(String, String)>, sys::kadm5_ret_t> {
        let princ = self.parse_name(name)?;
        let mut strings: *mut sys::krb5_string_attr = ptr::null_mut();
        let mut count: libc::c_int = 0;
        // SAFETY: handle, princ are valid; strings/count are out-params.
        let code = unsafe {
            sys::kadm5_get_strings(
                self.handle,
                princ,
                &raw mut strings,
                &raw mut count,
            )
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        if code != 0 {
            return Err(code);
        }
        let n = usize::try_from(count).unwrap_or(0);
        let mut result = Vec::with_capacity(n);
        for i in 0..n {
            // SAFETY: strings[i] is a valid element allocated by kadm5.
            let attr = unsafe { &*strings.add(i) };
            let key = unsafe { CStr::from_ptr(attr.key) }
                .to_string_lossy()
                .into_owned();
            let value = unsafe { CStr::from_ptr(attr.value) }
                .to_string_lossy()
                .into_owned();
            result.push((key, value));
        }
        if !strings.is_null() {
            // SAFETY: strings was allocated by kadm5_get_strings.
            unsafe { sys::kadm5_free_strings(self.handle, strings, count) };
        }
        Ok(result)
    }

    /// Set a string attribute on a principal.  Passing `value = None` removes
    /// the attribute.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if principal parsing, string
    /// conversion, or the KADM5 call fails.
    pub fn set_string(
        &self,
        name: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), sys::kadm5_ret_t> {
        let princ = self.parse_name(name)?;
        let key_c = CString::new(key)
            .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))?;
        let value_c = value
            .map(|v| {
                CString::new(v)
                    .map_err(|_| sys::kadm5_ret_t::from(libc::EINVAL))
            })
            .transpose()?;
        let value_ptr = value_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        // SAFETY: handle, princ, key_c, value_ptr are valid.
        let code = unsafe {
            sys::kadm5_set_string(
                self.handle,
                princ,
                key_c.as_ptr(),
                value_ptr,
            )
        };
        unsafe { sys::krb5_free_principal(self.ctx, princ) };
        Self::ret(code)
    }

    // -----------------------------------------------------------------------
    // Miscellaneous
    // -----------------------------------------------------------------------

    /// Flush any pending changes to the database.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn flush(&self) -> Result<(), sys::kadm5_ret_t> {
        // SAFETY: handle is valid.
        Self::ret(unsafe { sys::kadm5_flush(self.handle) })
    }

    /// Lock the database for exclusive access.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn lock(&self) -> Result<(), sys::kadm5_ret_t> {
        // SAFETY: handle is valid.
        Self::ret(unsafe { sys::kadm5_lock(self.handle) })
    }

    /// Release the database lock acquired by [`lock`](Self::lock).
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn unlock(&self) -> Result<(), sys::kadm5_ret_t> {
        // SAFETY: handle is valid.
        Self::ret(unsafe { sys::kadm5_unlock(self.handle) })
    }

    /// Return the privilege bitmask for the current admin identity.
    ///
    /// Bits: `KADM5_PRIV_GET` (0x01), `KADM5_PRIV_ADD` (0x02),
    /// `KADM5_PRIV_MODIFY` (0x04), `KADM5_PRIV_DELETE` (0x08).
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if the KADM5 call fails.
    pub fn get_privs(&self) -> Result<i64, sys::kadm5_ret_t> {
        let mut privs: libc::c_long = 0;
        // SAFETY: handle and privs are valid.
        let code =
            unsafe { sys::kadm5_get_privs(self.handle, &raw mut privs) };
        if code != 0 { Err(code) } else { Ok(privs) }
    }

    /// Create a principal alias pointing to `target`.
    ///
    /// # Errors
    /// Returns a `kadm5_ret_t` error code if either name cannot be parsed or
    /// the KADM5 call fails.
    pub fn create_alias(
        &self,
        alias: &str,
        target: &str,
    ) -> Result<(), sys::kadm5_ret_t> {
        let alias_princ = self.parse_name(alias)?;
        let target_princ = match self.parse_name(target) {
            Ok(p) => p,
            Err(e) => {
                unsafe { sys::krb5_free_principal(self.ctx, alias_princ) };
                return Err(e);
            },
        };
        // SAFETY: handle, alias_princ, target_princ are valid.
        let code = unsafe {
            sys::kadm5_create_alias(self.handle, alias_princ, target_princ)
        };
        unsafe {
            sys::krb5_free_principal(self.ctx, alias_princ);
            sys::krb5_free_principal(self.ctx, target_princ);
        }
        Self::ret(code)
    }

    // -----------------------------------------------------------------------
    // Private utility
    // -----------------------------------------------------------------------

    /// Collect a `char **` C array of `count` strings into a `Vec<String>`.
    ///
    /// Does not free the array; the caller is responsible for that.
    fn collect_name_list(
        names: *mut *mut libc::c_char,
        count: libc::c_int,
    ) -> Vec<String> {
        let n = usize::try_from(count).unwrap_or(0);
        if names.is_null() || n == 0 {
            return Vec::new();
        }
        (0..n)
            .map(|i| {
                // SAFETY: names[i] is a valid, null-terminated C string allocated
                // by kadm5; we copy it into a Rust String before it gets freed.
                let ptr = unsafe { *names.add(i) };
                if ptr.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(ptr) }
                        .to_string_lossy()
                        .into_owned()
                }
            })
            .collect()
    }
}

impl Drop for AdminHandle {
    fn drop(&mut self) {
        // SAFETY: handle and ctx were both successfully initialised in open().
        unsafe {
            sys::kadm5_destroy(self.handle);
            sys::krb5_free_context(self.ctx);
        }
    }
}
