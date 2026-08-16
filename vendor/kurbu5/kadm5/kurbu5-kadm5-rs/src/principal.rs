//! Zero-copy view over `_kadm5_principal_ent_t`.
//!
//! `Kadm5PrincipalEntry<'a>` borrows a `_kadm5_principal_ent_t` struct
//! without copying its fields.  The lifetime `'a` binds the view to the
//! caller's borrow of the C struct; no allocation occurs.
//!
//! This type is used by:
//! - `Kadm5AuthModule::check_add_principal` / `check_modify_principal`
//! - `Kadm5HookModule::create` / `modify`
//!
//! # Mask-gated accessors
//!
//! Fields of `_kadm5_principal_ent_t` are only valid when the corresponding
//! bit is set in the `mask` parameter accompanying the entry.  Each accessor
//! documents which mask bit it requires.  Callers should check the mask
//! before calling field accessors; the accessors themselves do not panic on
//! missing mask bits — they return the raw field value regardless.

use std::marker::PhantomData;

use kurbu5_kadm5_sys as sys;

/// Zero-copy view over a `_kadm5_principal_ent_t`.
///
/// Accessors are safe and return Rust types.  The raw C pointer is not
/// exposed publicly.
pub struct Kadm5PrincipalEntry<'a> {
    pub(crate) ptr: *const sys::_kadm5_principal_ent_t,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> Kadm5PrincipalEntry<'a> {
    /// The raw pointer, used by glue code only.
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> *const sys::_kadm5_principal_ent_t {
        self.ptr
    }

    /// The principal this entry describes.
    ///
    /// Returns a reference into the entry; the pointer is valid for `'a`.
    /// Requires `KADM5_PRINCIPAL` to be set in the accompanying mask.
    #[must_use]
    pub fn principal(&self) -> Option<&'a sys::krb5_principal_data> {
        // SAFETY: self.ptr is non-null (enforced at construction); the struct
        // is valid for the lifetime 'a by the construction invariant.
        let p = unsafe { (*self.ptr).principal };
        if p.is_null() {
            None
        } else {
            // SAFETY: p is non-null and points to a krb5_principal_data that
            // is valid for 'a (it is owned by the same kadm5 operation that
            // owns this entry).
            Some(unsafe { &*p })
        }
    }

    /// The policy name, if one is set.
    ///
    /// Returns a `&str` borrowed from the entry for `'a`.
    /// Requires `KADM5_POLICY` to be set in the accompanying mask.
    #[must_use]
    pub fn policy(&self) -> Option<&'a str> {
        // SAFETY: self.ptr is non-null and valid for 'a.
        let p = unsafe { (*self.ptr).policy };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a valid null-terminated C string owned by the entry.
        unsafe { std::ffi::CStr::from_ptr(p).to_str().ok() }
    }

    /// The principal expiration time.
    ///
    /// Requires `KADM5_PRINC_EXPIRE_TIME` to be set in the accompanying mask.
    #[must_use]
    pub fn princ_expire_time(&self) -> sys::krb5_timestamp {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).princ_expire_time }
    }

    /// The password expiration time.
    ///
    /// Requires `KADM5_PW_EXPIRATION` to be set in the accompanying mask.
    #[must_use]
    pub fn pw_expiration(&self) -> sys::krb5_timestamp {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).pw_expiration }
    }

    /// Maximum ticket life.
    ///
    /// Requires `KADM5_MAX_LIFE` to be set in the accompanying mask.
    #[must_use]
    pub fn max_life(&self) -> sys::krb5_deltat {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).max_life }
    }

    /// Maximum renewable ticket life.
    ///
    /// Requires `KADM5_MAX_RLIFE` to be set in the accompanying mask.
    #[must_use]
    pub fn max_renewable_life(&self) -> sys::krb5_deltat {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).max_renewable_life }
    }

    /// Principal flags (e.g. `KRB5_KDB_DISALLOW_ALL_TIX`).
    ///
    /// Requires `KADM5_ATTRIBUTES` to be set in the accompanying mask.
    #[must_use]
    pub fn attributes(&self) -> sys::krb5_flags {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).attributes }
    }

    /// The key version number.
    ///
    /// Requires `KADM5_KVNO` to be set in the accompanying mask.
    #[must_use]
    pub fn kvno(&self) -> sys::krb5_kvno {
        // SAFETY: self.ptr is non-null and valid for 'a.
        unsafe { (*self.ptr).kvno }
    }
}
