//! `PluginContext<'ctx>` — a safe wrapper around `krb5_context` for use inside
//! KADM5 plugin callbacks.
//!
//! This module mirrors `PluginContext` in `kurbu5-rs/src/context.rs` exactly.
//! One shared `PluginContext` type serves both the `KADM5_AUTH` and `KADM5_HOOK`
//! interfaces; no per-interface context type is created.
//!
//! # Type note
//!
//! `krb5_context` is `*mut _krb5_context`.  The canonical definition comes
//! from `kurbu5-sys`; it is re-exported into `kurbu5-kadm5-sys` via
//! `pub use kurbu5_sys::*`.  All `krb5_*` function calls in this file use
//! `kurbu5_sys` directly to avoid type-alias confusion across crates.
//!
//! Principal parsing/building (`OwnedPrincipal`, `PrincipalRef`,
//! `PrincipalType`) is likewise not re-implemented here: `parse_principal`
//! and `build_principal` delegate directly to `kurbu5_rs::principal`, which
//! operates on the same `kurbu5_sys::krb5_context` /
//! `kurbu5_sys::krb5_principal_data` types this crate already uses.

use std::ffi::CStr;
use std::marker::PhantomData;

use kurbu5_rs::principal::{OwnedPrincipal, PrincipalRef, PrincipalType};

use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// PluginContext
// ---------------------------------------------------------------------------

/// A zero-cost wrapper around `krb5_context` for use inside KADM5 plugin
/// callbacks.
///
/// `'ctx` is the lifetime of the context pointer.  All values borrowed from
/// the context carry this lifetime.
///
/// `PluginContext` is passed by reference to every KADM5 plugin trait method.
/// It must not be stored beyond the duration of the call.
pub struct PluginContext<'ctx> {
    // krb5_context is typedef *mut _krb5_context from kurbu5_sys.
    // We store it as the kurbu5_sys type to avoid type mismatches when
    // calling libkrb5 functions (which expect kurbu5_sys::krb5_context).
    ctx: kurbu5_sys::krb5_context,
    _phantom: PhantomData<&'ctx ()>,
}

impl PluginContext<'_> {
    /// Wrap a raw context pointer.
    ///
    /// # Safety (caller — glue modules only)
    ///
    /// `ctx` must be non-null and valid for at least `'ctx`.
    pub(crate) unsafe fn from_raw(ctx: kurbu5_sys::krb5_context) -> Self {
        debug_assert!(!ctx.is_null());
        PluginContext {
            ctx,
            _phantom: PhantomData,
        }
    }

    /// The raw context pointer.
    ///
    /// Exposed publicly so that localkdc utility helpers (e.g. `random_bytes`)
    /// can accept a raw `krb5_context` without depending on `PluginContext`
    /// from either `kurbu5-rs` or `kurbu5-kadm5-rs`.
    #[must_use]
    pub fn as_raw(&self) -> kurbu5_sys::krb5_context {
        self.ctx
    }

    // -----------------------------------------------------------------------
    // Realm
    // -----------------------------------------------------------------------

    /// Return the default realm as an owned `String`.
    ///
    /// Calls `krb5_get_default_realm`, which allocates; the C string is freed
    /// immediately after copying into Rust.  Returns `Err` if no default realm
    /// is configured or the call fails.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::Custom(_))` if `krb5_get_default_realm` fails
    /// or if the context has no default realm configured.
    pub fn realm(&self) -> Result<String, Krb5Error> {
        let mut realm_ptr: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: self.ctx is valid (PluginContext invariant); realm_ptr
        // receives a malloc'd C string on success, or remains null on failure.
        let code = unsafe {
            kurbu5_sys::krb5_get_default_realm(self.ctx, &raw mut realm_ptr)
        };
        if code != 0 {
            return Err(Krb5Error::from_error_code(code));
        }
        if realm_ptr.is_null() {
            return Err(Krb5Error::Custom(libc::ENODATA));
        }
        // SAFETY: realm_ptr is a valid null-terminated string returned by
        // krb5_get_default_realm.
        let s = unsafe {
            CStr::from_ptr(realm_ptr).to_string_lossy().into_owned()
        };
        // SAFETY: realm_ptr was allocated by libkrb5; free via its own API.
        unsafe { kurbu5_sys::krb5_free_default_realm(self.ctx, realm_ptr) };
        Ok(s)
    }

    // -----------------------------------------------------------------------
    // Principal name operations
    // -----------------------------------------------------------------------

    /// Unparse a principal to a string (e.g. `"user@REALM"`).
    ///
    /// Accepts anything convertible to a `kurbu5_rs::principal::PrincipalRef`
    /// — a raw `&krb5_principal_data` reference, or a `&OwnedPrincipal` (as
    /// returned by [`PluginContext::parse_principal`] /
    /// [`PluginContext::build_principal`]).
    ///
    /// Allocates a `String`; the C-allocated unparsed name is immediately
    /// copied and freed.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::Custom(_))` if `krb5_unparse_name` fails.
    pub fn unparse_principal<'a>(
        &self,
        princ: impl Into<PrincipalRef<'a>>,
    ) -> Result<String, Krb5Error> {
        let princ = princ.into();
        let mut out: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: self.ctx is valid; princ.as_raw() is non-null and valid for
        // the duration of this call; out receives a malloc'd string on success.
        let code = unsafe {
            kurbu5_sys::krb5_unparse_name(
                self.ctx,
                princ.as_raw(),
                &raw mut out,
            )
        };
        if code != 0 {
            return Err(Krb5Error::from_error_code(code));
        }
        // SAFETY: out is a valid null-terminated string returned by libkrb5.
        let s = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        // SAFETY: out was allocated by krb5_unparse_name; free via libkrb5.
        unsafe { kurbu5_sys::krb5_free_unparsed_name(self.ctx, out) };
        Ok(s)
    }

    /// Parse a principal name string (e.g. `"user@REALM"`) into an
    /// `OwnedPrincipal`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `name` contains an interior NUL byte, or if
    /// `krb5_parse_name` fails (e.g. malformed input).
    pub fn parse_principal(
        &self,
        name: &str,
    ) -> Result<OwnedPrincipal, Krb5Error> {
        // SAFETY: self.ctx is valid for 'ctx (PluginContext invariant).
        unsafe { OwnedPrincipal::parse(self.ctx, name) }
    }

    /// Build a principal from a realm and an explicit list of components.
    ///
    /// Unlike [`PluginContext::parse_principal`], components are raw bytes:
    /// `/`, `@`, `\`, and embedded NUL bytes do not need krb5's
    /// string-quoting rules, since there is no round-trip through a parsed
    /// string.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::Custom(libc::EINVAL))` if `realm`, any
    /// component, or the component count is too large to fit in the
    /// corresponding `krb5_data`/`krb5_principal_data` field widths.
    /// Returns `Err(Krb5Error::OutOfMemory)` if allocation fails.
    pub fn build_principal<C: AsRef<[u8]>>(
        &self,
        realm: &str,
        components: &[C],
        name_type: PrincipalType,
    ) -> Result<OwnedPrincipal, Krb5Error> {
        // SAFETY: self.ctx is valid for 'ctx (PluginContext invariant).
        unsafe {
            OwnedPrincipal::build(self.ctx, realm, components, name_type)
        }
    }

    // -----------------------------------------------------------------------
    // Profile access
    // -----------------------------------------------------------------------

    /// Return a handle to the Kerberos profile (`krb5.conf` / `kdc.conf`).
    ///
    /// Delegates to [`kurbu5_rs::profile::Profile::from_raw_context`] so that
    /// KADM5 plugins can read the same configuration sections as KDC plugins
    /// without a dependency on the `kurbu5-rs` `PluginContext` type.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `krb5_get_profile` fails (e.g. config file unreadable).
    pub fn profile(&self) -> Result<kurbu5_rs::profile::Profile, Krb5Error> {
        // SAFETY: self.ctx is a valid, non-null krb5_context for the lifetime
        // of this PluginContext, satisfying the contract of from_raw_context.
        unsafe { kurbu5_rs::profile::Profile::from_raw_context(self.ctx) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: allocate a real krb5_context for tests.
    //
    // SAFETY: krb5_init_context initialises a new context; krb5_free_context
    // releases it. Both are called only within the scope of each test — the
    // context does not escape.
    struct TestCtx(kurbu5_sys::krb5_context);

    impl TestCtx {
        fn new() -> Self {
            let mut ctx = std::ptr::null_mut();
            // SAFETY: krb5_init_context requires a valid &mut pointer to
            // receive the new context; the pointer is valid for the
            // duration of the call and is initialised on return.
            let rc = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(rc, 0, "krb5_init_context failed");
            TestCtx(ctx)
        }

        fn as_plugin_ctx(&self) -> PluginContext<'_> {
            // SAFETY: self.0 is non-null (checked in TestCtx::new) and
            // remains valid for the lifetime tied to &self.
            unsafe { PluginContext::from_raw(self.0) }
        }
    }

    impl Drop for TestCtx {
        fn drop(&mut self) {
            // SAFETY: self.0 was returned by krb5_init_context and has not
            // been freed; this is the unique Drop call for this TestCtx.
            unsafe { kurbu5_sys::krb5_free_context(self.0) }
        }
    }

    #[test]
    fn parse_principal_delegates_to_kurbu5_rs() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let owned = ctx
            .parse_principal("user@REALM.EXAMPLE")
            .expect("parse_principal must succeed");
        assert_eq!(
            ctx.unparse_principal(&owned).unwrap(),
            "user@REALM.EXAMPLE"
        );
    }

    #[test]
    fn build_principal_delegates_to_kurbu5_rs() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let components = ["host", "server.example.org"];
        let owned = ctx
            .build_principal(
                "REALM.EXAMPLE",
                &components,
                PrincipalType::SrvHst,
            )
            .expect("build_principal must succeed");
        assert_eq!(
            ctx.unparse_principal(&owned).unwrap(),
            "host/server.example.org@REALM.EXAMPLE"
        );
    }
}
