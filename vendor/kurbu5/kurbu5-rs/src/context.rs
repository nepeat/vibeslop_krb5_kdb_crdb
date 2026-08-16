//! `PluginContext<'ctx>` — a safe wrapper around `krb5_context` for use inside
//! non-KDB plugin callbacks.
//!
//! This module provides zero-cost access to the Kerberos context and wraps the
//! libkrb5 utility functions that plugin modules commonly need.
//!
//! The design mirrors `KdbContext` in `kurbu5-kdb-rs/src/context.rs` exactly.
//! One shared `PluginContext` type serves all `kurbu5-rs` interfaces; no
//! per-interface context type is needed or created.

use std::ffi::CStr;
use std::marker::PhantomData;

use crate::error::Krb5Error;
use crate::principal::{OwnedPrincipal, PrincipalRef, PrincipalType};

// ---------------------------------------------------------------------------
// PluginContext
// ---------------------------------------------------------------------------

/// A zero-cost wrapper around `krb5_context` for use inside plugin callbacks.
///
/// `'ctx` is the lifetime of the context pointer.  All values borrowed from
/// the context carry this lifetime.
///
/// `PluginContext` is passed by reference to every plugin trait method.  It
/// must not be stored beyond the duration of the call.
pub struct PluginContext<'ctx> {
    // krb5_context is typedef *mut _krb5_context — already a pointer type.
    ctx: kurbu5_sys::krb5_context,
    _phantom: PhantomData<&'ctx ()>,
}

impl PluginContext<'_> {
    /// Wrap a raw context pointer.
    ///
    /// # Safety (caller — glue modules only)
    ///
    /// `ctx` must be non-null and valid for at least `'ctx`.
    #[allow(dead_code)]
    pub(crate) unsafe fn from_raw(ctx: kurbu5_sys::krb5_context) -> Self {
        debug_assert!(!ctx.is_null());
        PluginContext {
            ctx,
            _phantom: PhantomData,
        }
    }

    /// The raw `krb5_context` pointer.
    ///
    /// Exposed for use by plugin crates that need to pass the context to
    /// libkrb5 C functions directly (e.g. OTP free functions).
    ///
    /// # Safety (caller)
    ///
    /// The returned pointer is only valid for the lifetime `'ctx` of this
    /// `PluginContext`.  Do not store or use it beyond the call.
    #[must_use]
    #[allow(dead_code)]
    pub fn as_raw(&self) -> kurbu5_sys::krb5_context {
        self.ctx
    }

    // -----------------------------------------------------------------------
    // Realm
    // -----------------------------------------------------------------------

    /// Return the default realm as an owned `String`.
    ///
    /// Calls `krb5_get_default_realm`, which allocates; the C string is freed
    /// immediately after copying into Rust.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no default realm is configured or the call fails.
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
        // SAFETY: realm_ptr was allocated by libkrb5; free via its own API so
        // that the allocator is matched correctly on all platforms.
        unsafe { kurbu5_sys::krb5_free_default_realm(self.ctx, realm_ptr) };
        Ok(s)
    }

    // -----------------------------------------------------------------------
    // Principal name operations
    // -----------------------------------------------------------------------

    /// Unparse a principal to a string (e.g. `"user@REALM"`).
    ///
    /// Accepts anything convertible to a [`PrincipalRef`] — a raw
    /// `&krb5_principal_data` reference (as handed to plugin trait methods),
    /// or a `&OwnedPrincipal` (as returned by [`PluginContext::parse_principal`]
    /// / [`PluginContext::build_principal`]).
    ///
    /// Allocates a `String`; the C-allocated unparsed name is immediately
    /// copied and freed.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `krb5_unparse_name` fails.
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
    /// [`OwnedPrincipal`].
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
    fn parse_principal_then_unparse_round_trips() {
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
    fn build_principal_then_unparse_round_trips() {
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

    #[test]
    fn unparse_principal_accepts_raw_principal_data_reference() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let owned = ctx
            .parse_principal("svc@REALM.EXAMPLE")
            .expect("parse_principal must succeed");
        // SAFETY: owned.as_raw() is valid for the lifetime of `owned`.
        let raw_ref: &kurbu5_sys::krb5_principal_data =
            unsafe { &*owned.as_raw() };
        assert_eq!(
            ctx.unparse_principal(raw_ref).unwrap(),
            "svc@REALM.EXAMPLE"
        );
    }

    #[test]
    fn parse_principal_rejects_interior_nul() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let err = ctx
            .parse_principal("u\0ser@REALM")
            .expect_err("interior NUL must be rejected");
        assert_eq!(err, Krb5Error::Custom(libc::EINVAL));
    }
}
