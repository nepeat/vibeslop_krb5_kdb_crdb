//! Safe RAII wrapper around the MIT Kerberos profile API.
//!
//! The profile API provides read-only access to `krb5.conf` / `kdc.conf`
//! values.  This module wraps `profile_t` (a `*mut _profile_t`) in a safe
//! [`Profile`] struct that releases the handle on drop via `profile_abandon`.
//!
//! # Obtaining a `Profile`
//!
//! ```rust,ignore
//! use kurbu5_rs::{PluginContext, profile::Profile};
//!
//! fn my_init(ctx: &PluginContext<'_>) {
//!     let profile = Profile::from_context(ctx).unwrap();
//!     let server = profile
//!         .get_string("otp", "DEFAULT", Some("server"), None)
//!         .unwrap_or_default();
//! }
//! ```

use std::ffi::{CStr, CString};

use crate::context::PluginContext;
use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/// An RAII handle to a Kerberos profile (`krb5.conf` / `kdc.conf`).
///
/// Obtained from a [`PluginContext`] via [`Profile::from_context`].
/// The profile handle is released with `profile_abandon` when the struct
/// is dropped.
///
/// # Thread safety
///
/// The underlying `profile_t` is not thread-safe.  Do not share a `Profile`
/// across threads without external synchronisation.
pub struct Profile {
    /// Raw profile handle.  Non-null after construction.
    ptr: kurbu5_sys::profile_t,
}

impl Profile {
    /// Obtain the profile from a `krb5_context`.
    ///
    /// Calls `krb5_get_profile` on the context embedded in `ctx`.  The
    /// returned profile reflects the configuration loaded at context
    /// initialisation time.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `krb5_get_profile` fails (e.g. no config file found).
    pub fn from_context(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
        let mut ptr: kurbu5_sys::profile_t = std::ptr::null_mut();
        // SAFETY: ctx.as_raw() is a valid krb5_context; &mut ptr receives the
        // profile handle on success.
        let code = unsafe {
            kurbu5_sys::krb5_get_profile(ctx.as_raw(), &raw mut ptr)
        };
        if code != 0 {
            return Err(Krb5Error::from_error_code(code));
        }
        Ok(Profile { ptr })
    }

    /// Obtain the profile directly from a raw `krb5_context` pointer.
    ///
    /// Same as [`from_context`][Self::from_context] but accepts the raw pointer
    /// directly so that callers in other crates (e.g. `kurbu5-kadm5-rs`) that
    /// wrap a `krb5_context` in their own `PluginContext` type can still obtain
    /// a profile handle without a dependency on the `kurbu5-rs` `PluginContext`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `krb5_get_profile` fails (e.g. the context carries no
    /// profile or an internal libkrb5 error occurs).
    ///
    /// # Safety
    ///
    /// `ctx` must be a valid, non-null `krb5_context` for the duration of this
    /// call.  The returned `Profile` does not borrow `ctx`; the caller must
    /// ensure the context outlives any values read from the profile.
    pub unsafe fn from_raw_context(
        ctx: kurbu5_sys::krb5_context,
    ) -> Result<Self, Krb5Error> {
        let mut ptr: kurbu5_sys::profile_t = std::ptr::null_mut();
        // SAFETY: ctx is non-null (caller contract); &raw mut ptr receives the
        // profile handle on success.
        let code = unsafe { kurbu5_sys::krb5_get_profile(ctx, &raw mut ptr) };
        if code != 0 {
            return Err(Krb5Error::from_error_code(code));
        }
        Ok(Profile { ptr })
    }

    // -----------------------------------------------------------------------
    // String values
    // -----------------------------------------------------------------------

    /// Retrieve a string from the profile.
    ///
    /// Reads the value at `[name]` → `subname` → `subsubname` (if provided).
    ///
    /// Returns `default.unwrap_or_default()` when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for genuine libkrb5 errors (not "key not found").
    pub fn get_string(
        &self,
        name: &str,
        subname: &str,
        subsubname: Option<&str>,
        default: Option<&str>,
    ) -> Result<String, Krb5Error> {
        let cname = cstring(name)?;
        let csubname = cstring(subname)?;
        let csubsubname = subsubname.map(cstring).transpose()?;
        let cdefault = default.map(cstring).transpose()?;

        let subsub_ptr = csubsubname
            .as_ref()
            .map_or(std::ptr::null(), |c| c.as_ptr());
        let default_ptr =
            cdefault.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

        let mut out: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: self.ptr is valid; all *const c_char arguments are valid
        // CString pointers or null; out receives an allocated string on success.
        let code = unsafe {
            kurbu5_sys::profile_get_string(
                self.ptr,
                cname.as_ptr(),
                csubname.as_ptr(),
                subsub_ptr,
                default_ptr,
                &raw mut out,
            )
        };
        if code != 0 {
            let code32 = i32::try_from(code).unwrap_or(libc::EINVAL);
            return Err(Krb5Error::from_error_code(code32));
        }
        if out.is_null() {
            return Ok(default.unwrap_or("").to_owned());
        }
        // SAFETY: out is a valid null-terminated C string.
        let s = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        // SAFETY: out was allocated by profile_get_string; free via its API.
        unsafe { kurbu5_sys::profile_release_string(out) };
        Ok(s)
    }

    // -----------------------------------------------------------------------
    // Integer values
    // -----------------------------------------------------------------------

    /// Retrieve an integer from the profile.
    ///
    /// Reads the value at `[name]` → `subname` → `subsubname` (if provided).
    /// Returns `default` when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for genuine libkrb5 errors (not "key not found").
    pub fn get_integer(
        &self,
        name: &str,
        subname: &str,
        subsubname: Option<&str>,
        default: i32,
    ) -> Result<i32, Krb5Error> {
        let cname = cstring(name)?;
        let csubname = cstring(subname)?;
        let csubsubname = subsubname.map(cstring).transpose()?;
        let subsub_ptr = csubsubname
            .as_ref()
            .map_or(std::ptr::null(), |c| c.as_ptr());
        let mut out: libc::c_int = 0;
        // SAFETY: self.ptr is valid; C string arguments are valid or null.
        let code = unsafe {
            kurbu5_sys::profile_get_integer(
                self.ptr,
                cname.as_ptr(),
                csubname.as_ptr(),
                subsub_ptr,
                default,
                &raw mut out,
            )
        };
        if code != 0 {
            let code32 = i32::try_from(code).unwrap_or(libc::EINVAL);
            Err(Krb5Error::from_error_code(code32))
        } else {
            Ok(out)
        }
    }

    // -----------------------------------------------------------------------
    // Boolean values
    // -----------------------------------------------------------------------

    /// Retrieve a boolean from the profile.
    ///
    /// Reads the value at `[name]` → `subname` → `subsubname` (if provided).
    /// Returns `default` when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for genuine libkrb5 errors (not "key not found").
    pub fn get_boolean(
        &self,
        name: &str,
        subname: &str,
        subsubname: Option<&str>,
        default: bool,
    ) -> Result<bool, Krb5Error> {
        let cname = cstring(name)?;
        let csubname = cstring(subname)?;
        let csubsubname = subsubname.map(cstring).transpose()?;
        let subsub_ptr = csubsubname
            .as_ref()
            .map_or(std::ptr::null(), |c| c.as_ptr());
        let mut out: libc::c_int = 0;
        // SAFETY: self.ptr is valid; C string arguments are valid or null.
        let code = unsafe {
            kurbu5_sys::profile_get_boolean(
                self.ptr,
                cname.as_ptr(),
                csubname.as_ptr(),
                subsub_ptr,
                libc::c_int::from(default),
                &raw mut out,
            )
        };
        if code != 0 {
            let code32 = i32::try_from(code).unwrap_or(libc::EINVAL);
            Err(Krb5Error::from_error_code(code32))
        } else {
            Ok(out != 0)
        }
    }

    // -----------------------------------------------------------------------
    // Subsection names
    // -----------------------------------------------------------------------

    /// Return the names of all subsections under the given section path.
    ///
    /// `names` is a slice of section name components forming the path.
    /// Returns an empty `Vec` if the section does not exist.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for genuine libkrb5 errors (not "section not found").
    pub fn get_subsection_names(
        &self,
        names: &[&str],
    ) -> Result<Vec<String>, Krb5Error> {
        let cnames: Vec<CString> =
            names.iter().map(|s| cstring(s)).collect::<Result<_, _>>()?;
        // Build a null-terminated array of *const c_char.
        let mut ptrs: Vec<*const libc::c_char> =
            cnames.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());

        let mut ret: *mut *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: self.ptr is valid; ptrs is null-terminated; ret receives
        // a heap-allocated null-terminated array on success.
        let code = unsafe {
            kurbu5_sys::profile_get_subsection_names(
                self.ptr,
                ptrs.as_mut_ptr(),
                &raw mut ret,
            )
        };
        if code != 0 {
            // PROF_NO_RELATION (-1_429_577_725) means "section not found".
            const PROF_NO_RELATION: libc::c_long = -1_429_577_725;
            if code == PROF_NO_RELATION {
                return Ok(vec![]);
            }
            let code32 = i32::try_from(code).unwrap_or(libc::EINVAL);
            return Err(Krb5Error::from_error_code(code32));
        }
        let result = collect_string_list(ret);
        // SAFETY: ret was allocated by profile_get_subsection_names.
        unsafe { kurbu5_sys::profile_free_list(ret) };
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Multiple string values
    // -----------------------------------------------------------------------

    /// Return all values for the relation at the given path.
    ///
    /// `names` is a slice of name components forming the path to a relation
    /// (not a subsection).  Returns an empty `Vec` if not found.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for genuine libkrb5 errors (not "not found").
    pub fn get_values(
        &self,
        names: &[&str],
    ) -> Result<Vec<String>, Krb5Error> {
        let cnames: Vec<CString> =
            names.iter().map(|s| cstring(s)).collect::<Result<_, _>>()?;
        let mut ptrs: Vec<*const libc::c_char> =
            cnames.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());

        let mut ret: *mut *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: self.ptr is valid; ptrs is a null-terminated *const c_char
        // array; ret receives a heap-allocated null-terminated array on success.
        let code = unsafe {
            kurbu5_sys::profile_get_values(
                self.ptr,
                ptrs.as_ptr(),
                &raw mut ret,
            )
        };
        if code != 0 {
            const PROF_NO_RELATION: libc::c_long = -1_429_577_725;
            if code == PROF_NO_RELATION {
                return Ok(vec![]);
            }
            let code32 = i32::try_from(code).unwrap_or(libc::EINVAL);
            return Err(Krb5Error::from_error_code(code32));
        }
        let result = collect_string_list(ret);
        // SAFETY: ret was allocated by profile_get_values.
        unsafe { kurbu5_sys::profile_free_list(ret) };
        Ok(result)
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        // SAFETY: self.ptr is non-null (invariant) and was obtained from
        // krb5_get_profile.  profile_abandon releases the handle.
        unsafe { kurbu5_sys::profile_abandon(self.ptr) };
    }
}

// Profile is not Send because the underlying _profile_t may contain
// thread-local state (file handles, cached data).  Do not derive Send.
// If you need cross-thread access, protect the Profile with a Mutex.

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Convert a `&str` to `CString`, mapping interior NUL errors to `Krb5Error`.
fn cstring(s: &str) -> Result<CString, Krb5Error> {
    CString::new(s).map_err(|_| Krb5Error::Custom(libc::EINVAL))
}

/// Walk a `*mut *mut c_char` null-terminated list and collect into `Vec<String>`.
///
/// # Safety
///
/// `list` must be either null or a null-terminated array of valid
/// null-terminated C strings.  The caller is responsible for freeing `list`
/// with `profile_free_list` after this call.
fn collect_string_list(list: *mut *mut libc::c_char) -> Vec<String> {
    if list.is_null() {
        return vec![];
    }
    let mut result = Vec::new();
    let mut i = 0;
    loop {
        // SAFETY: list is a valid null-terminated C string array.
        let ptr = unsafe { *list.add(i) };
        if ptr.is_null() {
            break;
        }
        // SAFETY: ptr is a valid null-terminated C string element.
        let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
        result.push(s);
        i += 1;
    }
    result
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a real krb5_context and a readable krb5.conf.
    // They are integration tests that call into libkrb5.

    unsafe fn make_ctx() -> kurbu5_sys::krb5_context {
        let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
        let code = kurbu5_sys::krb5_init_context(&mut ctx);
        assert_eq!(code, 0, "krb5_init_context failed");
        ctx
    }

    unsafe fn free_ctx(ctx: kurbu5_sys::krb5_context) {
        kurbu5_sys::krb5_free_context(ctx);
    }

    #[test]
    fn profile_from_context_succeeds() {
        // SAFETY: make_ctx / free_ctx follow the standard init/free contract.
        let ctx = unsafe { make_ctx() };
        let raw_ctx = ctx;
        // Wrap in PluginContext — reuse the from_raw / from_context path.
        // SAFETY: ctx is valid; we immediately drop the PluginContext.
        let plug_ctx = unsafe { PluginContext::from_raw(raw_ctx) };
        let profile = Profile::from_context(&plug_ctx);
        // profile_from_context should succeed as long as there's a readable
        // krb5.conf (which a standard installation always has).
        assert!(profile.is_ok(), "Profile::from_context failed");
        drop(profile);
        // SAFETY: ctx is no longer needed.
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn get_string_missing_key_returns_default() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let profile = Profile::from_context(&plug_ctx).expect("profile");
        let val = profile
            .get_string(
                "__no_such_section__",
                "__no_such_key__",
                None,
                Some("DEFAULT"),
            )
            .expect("get_string");
        assert_eq!(val, "DEFAULT");
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn get_integer_missing_key_returns_default() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let profile = Profile::from_context(&plug_ctx).expect("profile");
        let val = profile
            .get_integer("__no_such_section__", "__no_such_key__", None, 42)
            .expect("get_integer");
        assert_eq!(val, 42);
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn get_boolean_missing_key_returns_default() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let profile = Profile::from_context(&plug_ctx).expect("profile");
        let val = profile
            .get_boolean("__no_such_section__", "__no_such_key__", None, true)
            .expect("get_boolean");
        assert!(val);
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn get_subsection_names_missing_section_empty() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let profile = Profile::from_context(&plug_ctx).expect("profile");
        let names = profile
            .get_subsection_names(&["__no_such_section__"])
            .expect("get_subsection_names");
        assert!(names.is_empty());
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn get_values_missing_returns_empty() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let profile = Profile::from_context(&plug_ctx).expect("profile");
        let vals = profile
            .get_values(&["__no_such_section__", "__no_such_key__"])
            .expect("get_values");
        assert!(vals.is_empty());
        unsafe { free_ctx(ctx) };
    }
}
