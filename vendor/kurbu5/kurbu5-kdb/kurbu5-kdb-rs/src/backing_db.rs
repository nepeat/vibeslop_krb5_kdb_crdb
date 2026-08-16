//! `BackingDb` — an owned `krb5_context` with a delegated KDB module loaded.
//!
//! Overlay plugins (such as `kurbu5-kdb-userdb`) hold a `BackingDb` to forward
//! database operations to another KDB module (typically `klmdb`) while
//! intercepting selected operations.
//!
//! # Lifecycle
//!
//! `BackingDb::open` copies the parent context, loads the backing module, and
//! opens the database.  The `Drop` implementation calls `krb5_db_fini` then
//! `krb5_free_context`, so no explicit close call is needed.
//!
//! # Using `BackingDb` as a delegate field
//!
//! `BackingDb` implements [`KdbModule`] so it can serve as the `delegate`
//! field for `#[derive(KdbModule)]` overlay plugins:
//!
//! ```rust,ignore
//! #[derive(KdbModule)]
//! #[kdb(delegate = backing, plugin = "my_overlay")]
//! struct MyOverlay {
//!     backing: BackingDb,   // <-- BackingDb: KdbModule
//! }
//! ```
//!
//! The generated `impl KdbModule for MyOverlay` calls
//! `<BackingDb as KdbModule>::method(&self.backing, ctx, …)` for every
//! non-overridden method, routing delegation through the trait rather than
//! any same-named inherent method on `BackingDb`.
//!
//! Note that [`BackingDb::open`] via the trait always panics with
//! `unimplemented!()` — `BackingDb` requires an explicit module name and
//! cannot be opened generically.  Overlay plugins must provide their own
//! `open` implementation via `#[kdb_method]`.  Similarly, `create`,
//! `destroy`, and `promote_db` are not forwarded; list them in
//! `overrides(create, destroy, promote_db)` and implement them using
//! [`BackingDb::create_db`], [`BackingDb::destroy_db`], and
//! [`BackingDb::promote_db`] respectively.
//!
//! # Two access patterns
//!
//! | Pattern | When to use |
//! |---------|-------------|
//! | Inherent methods (`BackingDb::get_principal(…)`) | Ad-hoc calls in custom `get_principal` / `create` implementations where you control the arguments |
//! | Trait methods (`<BackingDb as KdbModule>::put_principal(…)`) | Used implicitly by `#[derive(KdbModule)]` delegation; rarely called directly |
//!
//! # Safety model
//!
//! All unsafe code in this module carries a `// SAFETY:` comment.
//! The `BackingDb` may be sent across threads (`unsafe impl Send`) because
//! it exclusively owns its `krb5_context` — no shared references exist.

use std::ffi::CString;
use std::ptr::NonNull;

use crate::context::KdbContext;
use crate::error::{KdbError, PolicyDenied};
use crate::module::{AsAuditEvent, AsPolicyRequest, KdbModule};
use crate::policy::{PolicyEntry, PolicyEntryRef};
use crate::principal::{PrincipalEntry, PrincipalEntryRef, PrincipalRef};
use crate::types::{IterFlags, LockMode, LookupFlags, OpenMode};

/// An owned `krb5_context` with a KDB module (e.g. `klmdb`) loaded.
///
/// Created by [`BackingDb::open`] and destroyed by [`Drop`], which finalises
/// the database and frees the context.
pub struct BackingDb {
    ctx: kdb_sys::krb5_context,
}

// SAFETY: BackingDb owns ctx exclusively; no other references exist.
// krb5_context is not Send by default (it is a raw C pointer), but since
// we are its sole owner and guard all access behind &self / &mut self,
// it is safe to send between threads.
unsafe impl Send for BackingDb {}

impl BackingDb {
    /// Copy `src_ctx`, load `module_name`, then open the database.
    ///
    /// `db_args` and `mode` are forwarded to `krb5_db_open`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn open(
        src_ctx: &KdbContext<'_>,
        module_name: &str,
        db_args: &[&str],
        mode: OpenMode,
    ) -> Result<Self, KdbError> {
        let mut ctx: kdb_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: src_ctx.as_raw() is valid; ctx receives the allocated copy.
        let code = unsafe {
            kdb_sys::krb5_copy_context(src_ctx.as_raw(), &raw mut ctx)
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }

        let cmodule = CString::new(module_name)
            .map_err(|_| KdbError::Custom(libc::EINVAL))?;
        // SAFETY: ctx is valid; cmodule is a null-terminated string.
        let code =
            unsafe { kdb_sys::krb5_db_load_module(ctx, cmodule.as_ptr()) };
        if code != 0 {
            unsafe { kdb_sys::krb5_free_context(ctx) };
            return Err(KdbError::from_error_code(code));
        }

        let cargs: Vec<CString> = db_args
            .iter()
            .filter_map(|s| CString::new(*s).ok())
            .collect();
        let mut argv: Vec<*mut libc::c_char> =
            cargs.iter().map(|c| c.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());

        // SAFETY: ctx is valid; argv is null-terminated.
        let code = unsafe {
            kdb_sys::krb5_db_open(ctx, argv.as_mut_ptr(), mode.as_raw())
        };
        if code != 0 {
            unsafe { kdb_sys::krb5_free_context(ctx) };
            return Err(KdbError::from_error_code(code));
        }

        Ok(BackingDb { ctx })
    }

    // -----------------------------------------------------------------------
    // Factory helpers: one-shot operations that do not require an open DB
    //
    // These copy the parent context, load the named module without opening
    // the database, perform a single operation, then free the context.
    // -----------------------------------------------------------------------

    /// Create the named backing module's database (e.g. for `kdb5_util create`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn create_db(
        src_ctx: &KdbContext<'_>,
        module_name: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> {
        Self::with_module_ctx(
            src_ctx,
            module_name,
            |ctx, argv| unsafe { kdb_sys::krb5_db_create(ctx, argv) },
            db_args,
        )
    }

    /// Destroy the named backing module's database (e.g. for `kdb5_util destroy`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn destroy_db(
        src_ctx: &KdbContext<'_>,
        module_name: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> {
        Self::with_module_ctx(
            src_ctx,
            module_name,
            |ctx, argv| unsafe { kdb_sys::krb5_db_destroy(ctx, argv) },
            db_args,
        )
    }

    /// Promote the named backing module's staging database to live.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn promote_db(
        src_ctx: &KdbContext<'_>,
        module_name: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> {
        Self::with_module_ctx(
            src_ctx,
            module_name,
            |ctx, argv| unsafe { kdb_sys::krb5_db_promote(ctx, argv) },
            db_args,
        )
    }

    /// Internal: copy context, load module, run `f(ctx, argv)`, free context.
    fn with_module_ctx<F>(
        src_ctx: &KdbContext<'_>,
        module_name: &str,
        f: F,
        db_args: &[&str],
    ) -> Result<(), KdbError>
    where
        F: FnOnce(
            kdb_sys::krb5_context,
            *mut *mut libc::c_char,
        ) -> kdb_sys::krb5_error_code,
    {
        let mut ctx: kdb_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: src_ctx.as_raw() is valid; ctx receives the allocated copy.
        let code = unsafe {
            kdb_sys::krb5_copy_context(src_ctx.as_raw(), &raw mut ctx)
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }

        let cmodule = CString::new(module_name)
            .map_err(|_| KdbError::Custom(libc::EINVAL))?;
        // SAFETY: ctx is valid; cmodule is null-terminated.
        let code =
            unsafe { kdb_sys::krb5_db_load_module(ctx, cmodule.as_ptr()) };
        if code != 0 {
            unsafe { kdb_sys::krb5_free_context(ctx) };
            return Err(KdbError::from_error_code(code));
        }

        let cargs: Vec<CString> = db_args
            .iter()
            .filter_map(|s| CString::new(*s).ok())
            .collect();
        let mut argv: Vec<*mut libc::c_char> =
            cargs.iter().map(|c| c.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());

        // SAFETY: ctx and argv are valid for this call.
        let code = f(ctx, argv.as_mut_ptr());
        // SAFETY: ctx was allocated by krb5_copy_context.
        unsafe { kdb_sys::krb5_free_context(ctx) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Database lifecycle
    // -----------------------------------------------------------------------

    /// Create the backing database storage.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn create(&self, db_args: &[&str]) -> Result<(), KdbError> {
        let cargs: Vec<CString> = db_args
            .iter()
            .filter_map(|s| CString::new(*s).ok())
            .collect();
        let mut argv: Vec<*mut libc::c_char> =
            cargs.iter().map(|c| c.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        // SAFETY: ctx and argv are valid.
        let code =
            unsafe { kdb_sys::krb5_db_create(self.ctx, argv.as_mut_ptr()) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Destroy the backing database storage.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn destroy(&self, db_args: &[&str]) -> Result<(), KdbError> {
        let cargs: Vec<CString> = db_args
            .iter()
            .filter_map(|s| CString::new(*s).ok())
            .collect();
        let mut argv: Vec<*mut libc::c_char> =
            cargs.iter().map(|c| c.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        // SAFETY: ctx and argv are valid.
        let code =
            unsafe { kdb_sys::krb5_db_destroy(self.ctx, argv.as_mut_ptr()) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Promote a staging database to live.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn promote(&self, db_args: &[&str]) -> Result<(), KdbError> {
        let cargs: Vec<CString> = db_args
            .iter()
            .filter_map(|s| CString::new(*s).ok())
            .collect();
        let mut argv: Vec<*mut libc::c_char> =
            cargs.iter().map(|c| c.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        // SAFETY: ctx and argv are valid.
        let code =
            unsafe { kdb_sys::krb5_db_promote(self.ctx, argv.as_mut_ptr()) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Principal CRUD
    // -----------------------------------------------------------------------

    /// Look up a principal by name.  Returns `Ok(None)` if not found.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn get_principal(
        &self,
        princ: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        let mut entry: *mut kdb_sys::krb5_db_entry = std::ptr::null_mut();
        // SAFETY: ctx and princ are valid.
        let code = unsafe {
            kdb_sys::krb5_db_get_principal(
                self.ctx,
                princ.as_raw(),
                flags.bits(),
                &raw mut entry,
            )
        };
        match code {
            0 => Ok(NonNull::new(entry)
                // SAFETY: entry was allocated by the backing module via malloc.
                .map(|nn| unsafe { PrincipalEntry::from_raw(nn) })),
            c if c == KdbError::NoEntry.into_error_code() => Ok(None),
            other => Err(KdbError::from_error_code(other)),
        }
    }

    /// Look up a principal, substituting the host component with `hostname`.
    ///
    /// Copies `template`, replaces component\[1\].data/length with the bytes
    /// of `hostname` (no null terminator needed — krb5 data is length-prefixed),
    /// performs the lookup, restores the original data, then frees the copy.
    ///
    /// `template` must have at least two components.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    ///
    /// # Panics
    ///
    /// Panics if `hostname` is longer than `u32::MAX` bytes, which cannot
    /// occur for a valid Kerberos hostname.
    pub fn get_principal_with_hostname(
        &self,
        template: PrincipalRef<'_>,
        hostname: &str,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        let mut copy: kdb_sys::krb5_principal = std::ptr::null_mut();
        // SAFETY: self.ctx and template are valid.
        let code = unsafe {
            kdb_sys::krb5_copy_principal(
                self.ctx,
                template.as_raw(),
                &raw mut copy,
            )
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }

        // SAFETY: copy is valid; component[1] exists (caller checked).
        let result = unsafe {
            let comp1 = (*copy).data.add(1);
            let old_length = (*comp1).length;
            let old_data = (*comp1).data;

            // Substitute the host component bytes.  The backing DB uses
            // length-prefixed data so no null terminator is needed.
            (*comp1).length = u32::try_from(hostname.len())
                .expect("hostname length fits in u32");
            (*comp1).data = hostname.as_ptr() as *mut libc::c_char;

            let mut entry: *mut kdb_sys::krb5_db_entry = std::ptr::null_mut();
            let code = kdb_sys::krb5_db_get_principal(
                self.ctx,
                copy,
                flags.bits(),
                &raw mut entry,
            );

            // Restore before freeing.
            (*comp1).length = old_length;
            (*comp1).data = old_data;

            match code {
                0 => Ok(NonNull::new(entry)
                    // SAFETY: entry is non-null (NonNull::new ensures this),
                    // allocated by krb5_db_get_principal via the backing
                    // module's system allocator, and not aliased.
                    // The surrounding unsafe block covers this call.
                    .map(|nn| PrincipalEntry::from_raw(nn))),
                code if code == KdbError::NoEntry.into_error_code() => {
                    Ok(None)
                },
                code => Err(KdbError::from_error_code(code)),
            }
        };

        // SAFETY: copy was allocated by krb5_copy_principal.
        unsafe { kdb_sys::krb5_free_principal(self.ctx, copy) };
        result
    }

    /// Store (create or update) a principal entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn put_principal(
        &self,
        entry: PrincipalEntryRef<'_>,
    ) -> Result<(), KdbError> {
        // SAFETY: ctx and entry are valid.
        let code = unsafe {
            kdb_sys::krb5_db_put_principal(self.ctx, entry.as_raw().cast_mut())
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Delete a principal.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn delete_principal(
        &self,
        princ: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        // SAFETY: ctx and princ are valid.
        let code = unsafe {
            kdb_sys::krb5_db_delete_principal(
                self.ctx,
                princ.as_raw().cast_mut(),
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Iterate over all principals in the backing database.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn iterate_principals(
        &self,
        match_entry: Option<&str>,
        flags: IterFlags,
        callback: &mut dyn FnMut(
            PrincipalEntryRef<'_>,
        ) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        struct State<'a> {
            cb: &'a mut dyn FnMut(
                PrincipalEntryRef<'_>,
            ) -> Result<(), KdbError>,
            result: Result<(), KdbError>,
        }

        extern "C" fn trampoline(
            arg: *mut libc::c_void,
            entry: *mut kdb_sys::krb5_db_entry,
        ) -> kdb_sys::krb5_error_code {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                // SAFETY: arg is &mut State cast to *mut c_void.
                let state = &mut *arg.cast::<State<'_>>();
                if entry.is_null() {
                    return 0;
                }
                // SAFETY: entry is valid for the duration of this callback.
                let eref = PrincipalEntryRef::from_raw(entry.cast_const());
                match (state.cb)(eref) {
                    Ok(()) => 0,
                    Err(e) => {
                        let code = e.clone().into_error_code();
                        state.result = Err(e);
                        code
                    },
                }
            }))
            .unwrap_or(libc::EINVAL)
        }

        let match_c = match_entry
            .map(|s| {
                CString::new(s).map_err(|_| KdbError::Custom(libc::EINVAL))
            })
            .transpose()?;
        let match_ptr = match_c
            .as_ref()
            .map_or(std::ptr::null_mut(), |c| c.as_ptr().cast_mut());

        let mut state = State {
            cb: callback,
            result: Ok(()),
        };

        // SAFETY: ctx and trampoline are valid; state outlives this call.
        let code = unsafe {
            kdb_sys::krb5_db_iterate(
                self.ctx,
                match_ptr,
                Some(trampoline),
                (&raw mut state).cast::<libc::c_void>(),
                flags.bits().cast_signed(),
            )
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        state.result
    }

    // -----------------------------------------------------------------------
    // Policy CRUD
    // -----------------------------------------------------------------------

    /// Create a password policy.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn create_policy(&self, policy: &PolicyEntry) -> Result<(), KdbError> {
        let raw = policy.clone().into_raw().ok_or(KdbError::OutOfMemory)?;
        // SAFETY: ctx and raw are valid.
        let code = unsafe { kdb_sys::krb5_db_create_policy(self.ctx, raw) };
        unsafe { kdb_sys::krb5_db_free_policy(self.ctx, raw) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Retrieve a password policy by name.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn get_policy(
        &self,
        name: &str,
    ) -> Result<Option<PolicyEntry>, KdbError> {
        let cname =
            CString::new(name).map_err(|_| KdbError::Custom(libc::EINVAL))?;
        let mut raw: kdb_sys::osa_policy_ent_t = std::ptr::null_mut();
        // SAFETY: ctx and cname are valid.
        let code = unsafe {
            kdb_sys::krb5_db_get_policy(
                self.ctx,
                cname.as_ptr().cast_mut(),
                &raw mut raw,
            )
        };
        if code != 0 {
            return if code == KdbError::NoEntry.into_error_code() {
                Ok(None)
            } else {
                Err(KdbError::from_error_code(code))
            };
        }
        if raw.is_null() {
            return Ok(None);
        }
        // SAFETY: raw is a valid osa_policy_ent_rec allocated by libkdb5.
        let entry = PolicyEntry::from_ref(unsafe {
            PolicyEntryRef::from_raw(raw.cast_const())
        });
        unsafe { kdb_sys::krb5_db_free_policy(self.ctx, raw) };
        Ok(Some(entry))
    }

    /// Store (create or update) a password policy.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn put_policy(&self, policy: &PolicyEntry) -> Result<(), KdbError> {
        let raw = policy.clone().into_raw().ok_or(KdbError::OutOfMemory)?;
        // SAFETY: ctx and raw are valid.
        let code = unsafe { kdb_sys::krb5_db_put_policy(self.ctx, raw) };
        unsafe { kdb_sys::krb5_db_free_policy(self.ctx, raw) };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Iterate over password policies.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn iter_policy(
        &self,
        match_entry: Option<&str>,
        callback: &mut dyn FnMut(&PolicyEntry) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        struct State<'a> {
            cb: &'a mut dyn FnMut(&PolicyEntry) -> Result<(), KdbError>,
            result: Result<(), KdbError>,
        }

        extern "C" fn trampoline(
            arg: *mut libc::c_void,
            policy: kdb_sys::osa_policy_ent_t,
        ) {
            let catch = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| unsafe {
                    let state = &mut *arg.cast::<State<'_>>();
                    if policy.is_null() {
                        return;
                    }
                    // SAFETY: policy is valid for the duration of this callback.
                    let entry = PolicyEntry::from_ref(
                        PolicyEntryRef::from_raw(policy.cast_const()),
                    );
                    if let Err(e) = (state.cb)(&entry) {
                        state.result = Err(e);
                    }
                }),
            );
            if catch.is_err() {
                // A panic occurred; record a sentinel so iter_policy does not
                // silently return Ok(()) after an aborted iteration.
                // SAFETY: arg is &mut State cast to *mut c_void; the panic
                // unwind has completed so arg is no longer aliased.
                let state = unsafe { &mut *arg.cast::<State<'_>>() };
                if state.result.is_ok() {
                    state.result = Err(KdbError::Custom(libc::EINVAL));
                }
            }
        }

        let match_c = match_entry
            .map(|s| {
                CString::new(s).map_err(|_| KdbError::Custom(libc::EINVAL))
            })
            .transpose()?;
        let match_ptr = match_c
            .as_ref()
            .map_or(std::ptr::null_mut(), |c| c.as_ptr().cast_mut());

        let mut state = State {
            cb: callback,
            result: Ok(()),
        };

        // SAFETY: ctx, trampoline, and state are valid.
        let code = unsafe {
            kdb_sys::krb5_db_iter_policy(
                self.ctx,
                match_ptr,
                Some(trampoline),
                (&raw mut state).cast::<libc::c_void>(),
            )
        };
        if code != 0 {
            return Err(KdbError::from_error_code(code));
        }
        state.result
    }

    /// Delete a password policy by name.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn delete_policy(&self, name: &str) -> Result<(), KdbError> {
        let cname =
            CString::new(name).map_err(|_| KdbError::Custom(libc::EINVAL))?;
        // SAFETY: ctx and cname are valid.
        let code = unsafe {
            kdb_sys::krb5_db_delete_policy(self.ctx, cname.as_ptr().cast_mut())
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // KDC policy hooks
    // -----------------------------------------------------------------------

    /// Delegate an AS policy check to the backing KDB module.
    ///
    /// Returns `Ok(())` if the backing module permits the request, or
    /// `Err(KdbError)` on denial or internal failure.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying KDB operation fails.
    pub fn check_policy_as(
        &self,
        req: &AsPolicyRequest<'_>,
    ) -> Result<(), KdbError> {
        let mut status: *const libc::c_char = std::ptr::null();
        let mut e_data: *mut *mut kdb_sys::krb5_pa_data = std::ptr::null_mut();
        // SAFETY: all pointers derive from valid AsPolicyRequest fields.
        let code = unsafe {
            kdb_sys::krb5_db_check_policy_as(
                self.ctx,
                req.request.ptr.cast_mut(),
                req.client.as_raw().cast_mut(),
                req.server.as_raw().cast_mut(),
                req.kdc_time.0,
                &raw mut status,
                &raw mut e_data,
            )
        };
        if code != 0 {
            Err(KdbError::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Delegate an AS audit notification to the backing KDB module.
    pub fn audit_as_req(&self, event: &AsAuditEvent<'_>) {
        let local_ptr = event
            .local_addr
            .as_ref()
            .map_or(std::ptr::null(), |a| a.ptr);
        let remote_ptr = event
            .remote_addr
            .as_ref()
            .map_or(std::ptr::null(), |a| a.ptr);
        let client_ptr = event
            .client
            .as_ref()
            .map_or(std::ptr::null_mut(), |c| c.as_raw().cast_mut());
        let server_ptr = event
            .server
            .as_ref()
            .map_or(std::ptr::null_mut(), |s| s.as_raw().cast_mut());
        // SAFETY: all pointers derive from valid AsAuditEvent fields.
        // client_ptr and server_ptr may be null; krb5_db_audit_as_req accepts
        // null for both when the principal was not found.
        unsafe {
            kdb_sys::krb5_db_audit_as_req(
                self.ctx,
                event.request.ptr.cast_mut(),
                local_ptr,
                remote_ptr,
                client_ptr,
                server_ptr,
                event.authtime.0,
                event.error_code,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Raw access
    // -----------------------------------------------------------------------

    /// Return the raw `krb5_context` for operations not wrapped by `BackingDb`.
    ///
    /// # Safety
    ///
    /// The returned pointer must not be stored beyond the lifetime of the
    /// `BackingDb`, must not be freed, and must not be passed to any function
    /// that would modify its KDB association in a way that conflicts with the
    /// `BackingDb` lifecycle.
    #[must_use]
    pub unsafe fn as_raw_ctx(&self) -> kdb_sys::krb5_context {
        self.ctx
    }
}

impl Drop for BackingDb {
    fn drop(&mut self) {
        if self.ctx.is_null() {
            return;
        }
        // SAFETY: ctx was opened by BackingDb::open; we are the sole owner.
        unsafe {
            kdb_sys::krb5_db_fini(self.ctx);
            kdb_sys::krb5_free_context(self.ctx);
        }
        self.ctx = std::ptr::null_mut();
    }
}

// ---------------------------------------------------------------------------
// KdbModule impl — enables #[derive(KdbModule)] overlays to delegate to BackingDb
// ---------------------------------------------------------------------------

/// `BackingDb` implements `KdbModule` so that overlay plugins can use
/// `#[derive(KdbModule)]` with `#[kdb(delegate = backing)]` and have the
/// generated code route delegation calls through this trait.
///
/// Static lifecycle methods (`open`, `create`, `destroy`, `promote_db`) are
/// not meaningful on `BackingDb` — use the dedicated `BackingDb::open` /
/// `BackingDb::create_db` etc. constructors directly.  Overlays that need
/// these operations must mark them with `overrides(create, destroy, promote_db)`
/// and implement them as `#[kdb_method]` functions.
impl KdbModule for BackingDb {
    fn open(
        _ctx: &KdbContext<'_>,
        _conf_section: &str,
        _db_args: &[&str],
        _mode: OpenMode,
    ) -> Result<Self, KdbError> {
        // BackingDb cannot be opened via the KdbModule::open trait method;
        // it requires an explicit module name.  Use BackingDb::open directly.
        unimplemented!(
            "BackingDb::open via KdbModule is not supported; \
             use BackingDb::open(ctx, module_name, db_args, mode) directly"
        )
    }

    fn get_principal(
        &self,
        _ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        BackingDb::get_principal(self, search_for, flags)
    }

    fn close(self) -> Result<(), KdbError> {
        // Drop handles krb5_db_fini + krb5_free_context.
        Ok(())
    }

    fn lock(&self, _mode: LockMode) -> Result<(), KdbError> {
        Ok(())
    }

    fn unlock(&self) -> Result<(), KdbError> {
        Ok(())
    }

    fn put_principal(
        &self,
        _ctx: &KdbContext<'_>,
        entry: PrincipalEntryRef<'_>,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        BackingDb::put_principal(self, entry)
    }

    fn delete_principal(
        &self,
        _ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        BackingDb::delete_principal(self, search_for)
    }

    fn iterate_principals(
        &self,
        _ctx: &KdbContext<'_>,
        match_entry: Option<&str>,
        flags: IterFlags,
        callback: &mut dyn FnMut(
            PrincipalEntryRef<'_>,
        ) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        BackingDb::iterate_principals(self, match_entry, flags, callback)
    }

    fn create_policy(
        &self,
        _ctx: &KdbContext<'_>,
        policy: &PolicyEntry,
    ) -> Result<(), KdbError> {
        BackingDb::create_policy(self, policy)
    }

    fn get_policy(
        &self,
        _ctx: &KdbContext<'_>,
        name: &str,
    ) -> Result<Option<PolicyEntry>, KdbError> {
        BackingDb::get_policy(self, name)
    }

    fn put_policy(
        &self,
        _ctx: &KdbContext<'_>,
        policy: &PolicyEntry,
    ) -> Result<(), KdbError> {
        BackingDb::put_policy(self, policy)
    }

    fn iter_policy(
        &self,
        _ctx: &KdbContext<'_>,
        match_entry: Option<&str>,
        callback: &mut dyn FnMut(&PolicyEntry) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        BackingDb::iter_policy(self, match_entry, callback)
    }

    fn delete_policy(
        &self,
        _ctx: &KdbContext<'_>,
        name: &str,
    ) -> Result<(), KdbError> {
        BackingDb::delete_policy(self, name)
    }

    fn check_policy_as(
        &self,
        _ctx: &KdbContext<'_>,
        req: AsPolicyRequest<'_>,
    ) -> Result<(), PolicyDenied> {
        BackingDb::check_policy_as(self, &req).map_err(|_| {
            PolicyDenied::new(c"policy check failed by backing KDB")
        })
    }

    fn audit_as_req(&self, _ctx: &KdbContext<'_>, event: AsAuditEvent<'_>) {
        BackingDb::audit_as_req(self, &event);
    }
}
