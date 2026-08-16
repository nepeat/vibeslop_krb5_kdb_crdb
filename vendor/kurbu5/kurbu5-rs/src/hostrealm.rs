//! HOSTREALM — host-to-realm mapping plugin interface.
//!
//! A HOSTREALM plugin maps hostnames to Kerberos realm names.  libkrb5 calls
//! registered plugins in order; each plugin either returns a realm list or
//! returns `Err(Krb5Error::NoHandle)` to defer to the next plugin.
//!
//! The interface has two query categories:
//!
//! - *Authoritative* (`host_realm`): secure mechanisms such as DNS SRV,
//!   consulted before trying cross-realm referrals.
//! - *Fallback* (`fallback_realm`): heuristic mechanisms such as domain
//!   component stripping, consulted after referrals.
//! - *Default* (`default_realm`): the realm(s) of the local host itself.
//!
//! All three methods return `Err(Krb5Error::NoHandle)` by default; override
//! only the ones your plugin supports.  `init_module` and `fini_module`
//! handle the lifecycle of the per-module state.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::{initvt_plugin, PluginContext, Krb5Error};
//! use kurbu5_rs::hostrealm::HostrealmModule;
//!
//! pub struct MyHostrealm;
//!
//! impl HostrealmModule for MyHostrealm {
//!     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
//!         Ok(MyHostrealm)
//!     }
//!
//!     fn host_realm(
//!         &self,
//!         _ctx: &PluginContext<'_>,
//!         host: &str,
//!     ) -> Result<Vec<String>, Krb5Error> {
//!         if host.ends_with(".example.com") {
//!             Ok(vec!["EXAMPLE.COM".to_owned()])
//!         } else {
//!             Err(Krb5Error::NoHandle)
//!         }
//!     }
//! }
//!
//! initvt_plugin!(
//!     hostrealm_myplugin,
//!     1,
//!     MyHostrealm,
//!     kurbu5_rs::hostrealm::glue::make_hostrealm_vtable
//! );
//! ```

use crate::context::PluginContext;
use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// The HostrealmModule trait
// ---------------------------------------------------------------------------
//
// C vtable field → Rust method mapping:
//
//   name            (const char*)             — module name string literal;
//                                               set in glue::make_hostrealm_vtable
//   init            (ctx, **moddata) -> err   — init_module(&ctx) -> Result<Self>
//   fini            (ctx, moddata)            — fini_module(self)
//   host_realm      (ctx, data, host, ***out) — host_realm(&self, &ctx, host)
//   fallback_realm  (ctx, data, host, ***out) — fallback_realm(&self, &ctx, host)
//   default_realm   (ctx, data, ***out)       — default_realm(&self, &ctx)
//   free_list       (ctx, data, **list)       — glue-internal; drops Vec<CString>
//
// The `free_list` slot is never called with a null list pointer by libkrb5.
// It is wired in the glue layer to reclaim the `Vec<*mut c_char>` (plus each
// element's `CString`) that was allocated by the query bridge functions.

/// Implement this trait to create a HOSTREALM plugin.
///
/// Use [`initvt_plugin!`](crate::initvt_plugin) to export the `<name>_initvt`
/// C symbol.
///
/// # Lifetime contract
///
/// `HostrealmModule` requires `Sized + Send + 'static` for the same reasons
/// as `KdbModule`: `Sized` for `Box<M>`, `Send` because libkrb5 may move the
/// box between threads between successive requests, and `'static` to prevent
/// references into caller stacks inside the module state.
///
/// # Default implementations
///
/// Every method except `init_module` has a default body.  `fini_module`
/// is a no-op (the default `Drop` of `M` handles cleanup).  All three query
/// methods default to `Err(Krb5Error::NoHandle)`, which tells libkrb5 to try
/// the next registered plugin.
pub trait HostrealmModule: Sized + Send + 'static {
    /// The module name written into `krb5_hostrealm_vtable_st::name`.
    ///
    /// Used by libkrb5 for logging and plugin selection in `krb5.conf`.
    const NAME: &'static std::ffi::CStr;

    // -----------------------------------------------------------------------
    // Module lifecycle
    // -----------------------------------------------------------------------

    /// Initialise the module and return an instance of `Self`.
    ///
    /// Called once when libkrb5 loads the plugin.  The context is usable for
    /// reading the Kerberos configuration (e.g. `[libdefaults]` settings).
    ///
    /// Return `Err(Krb5Error::NoHandle)` if the plugin cannot initialise (e.g.
    /// a required config key is absent); libkrb5 will skip this plugin and try
    /// the next registered one.
    ///
    /// Maps to `init` in `krb5_hostrealm_vtable_st`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` if the plugin cannot initialise.
    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;

    /// Release resources held by this module instance.
    ///
    /// The default implementation is a no-op; the module's `Drop` impl (if
    /// any) handles cleanup automatically.  Override only when you need to
    /// perform actions that require the `krb5_context` (e.g. unregistering a
    /// handle stored inside the context).
    ///
    /// Maps to `fini` in `krb5_hostrealm_vtable_st`.
    fn fini_module(self) {}

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Determine the possible realms of `host` using authoritative mechanisms.
    ///
    /// "Authoritative" means the mechanism is trusted enough to be consulted
    /// *before* cross-realm referrals when obtaining a service ticket.  DNS
    /// SRV records or a local hostname→realm database are typical examples.
    ///
    /// Return `Ok(realms)` on success with a non-empty list; the first entry
    /// is the primary realm, subsequent entries are alternatives.  Return
    /// `Err(Krb5Error::NoHandle)` to defer to the next plugin.  Return any
    /// other error to abort processing for this hostname.
    ///
    /// Default: `Err(Krb5Error::NoHandle)` — defer to next plugin.
    ///
    /// Maps to `host_realm` in `krb5_hostrealm_vtable_st`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn host_realm(
        &self,
        _ctx: &PluginContext<'_>,
        _host: &str,
    ) -> Result<Vec<String>, Krb5Error> {
        Err(Krb5Error::NoHandle)
    }

    /// Determine the possible realms of `host` using heuristic mechanisms.
    ///
    /// "Fallback" means the mechanism is used *after* cross-realm referrals
    /// when `host_realm` and the referral path both failed to produce a
    /// result.  Domain-component stripping or `[domain_realm]` table lookups
    /// are typical examples.
    ///
    /// Same return semantics as `host_realm`.
    ///
    /// Default: `Err(Krb5Error::NoHandle)` — defer to next plugin.
    ///
    /// Maps to `fallback_realm` in `krb5_hostrealm_vtable_st`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn fallback_realm(
        &self,
        _ctx: &PluginContext<'_>,
        _host: &str,
    ) -> Result<Vec<String>, Krb5Error> {
        Err(Krb5Error::NoHandle)
    }

    /// Determine the possible default realms of the local host.
    ///
    /// Called when libkrb5 needs to determine the local host's realm (e.g.
    /// when no explicit realm is configured).  The list should typically
    /// contain exactly one entry for the local Kerberos realm.
    ///
    /// Same return semantics as `host_realm`.
    ///
    /// Default: `Err(Krb5Error::NoHandle)` — defer to next plugin.
    ///
    /// Maps to `default_realm` in `krb5_hostrealm_vtable_st`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn default_realm(
        &self,
        _ctx: &PluginContext<'_>,
    ) -> Result<Vec<String>, Krb5Error> {
        Err(Krb5Error::NoHandle)
    }
}

// ---------------------------------------------------------------------------
// Glue sub-module
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod glue;

// ---------------------------------------------------------------------------
// Unit tests (task 2.4)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Krb5Error;

    /// Construct a `PluginContext` wrapping a dangling (non-null but invalid)
    /// pointer.  Used in tests whose trait implementations never dereference
    /// the context, allowing unit testing without a live `krb5_context`.
    fn dangling_ctx() -> PluginContext<'static> {
        // SAFETY: The pointer is non-null (satisfying from_raw's debug_assert).
        // Test implementations under test do not dereference it.
        unsafe {
            PluginContext::from_raw(
                std::ptr::NonNull::<kurbu5_sys::_krb5_context>::dangling()
                    .as_ptr(),
            )
        }
    }

    // A minimal module with only init_module implemented; all query methods
    // fall through to the defaults.
    struct NoopHostrealm;

    impl HostrealmModule for NoopHostrealm {
        const NAME: &'static std::ffi::CStr = c"noop_hostrealm";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(NoopHostrealm)
        }
    }

    #[test]
    fn noop_host_realm_returns_no_handle() {
        // The default method bodies do not use the context; a dangling pointer
        // satisfies from_raw's non-null precondition without risk of dereference.
        let m = NoopHostrealm;
        let ctx = dangling_ctx();
        assert_eq!(
            m.host_realm(&ctx, "host.example.com"),
            Err(Krb5Error::NoHandle)
        );
        assert_eq!(
            m.fallback_realm(&ctx, "host.example.com"),
            Err(Krb5Error::NoHandle)
        );
        assert_eq!(m.default_realm(&ctx), Err(Krb5Error::NoHandle));
    }

    // A module that returns a realm list from host_realm.
    struct StaticHostrealm;

    impl HostrealmModule for StaticHostrealm {
        const NAME: &'static std::ffi::CStr = c"static_hostrealm";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(StaticHostrealm)
        }

        fn host_realm(
            &self,
            _ctx: &PluginContext<'_>,
            host: &str,
        ) -> Result<Vec<String>, Krb5Error> {
            if host == "kdc.example.org" {
                Ok(vec!["EXAMPLE.ORG".to_owned()])
            } else {
                Err(Krb5Error::NoHandle)
            }
        }
    }

    #[test]
    fn static_host_realm_matches() {
        let m = StaticHostrealm;
        let ctx = dangling_ctx();
        let result = m.host_realm(&ctx, "kdc.example.org");
        assert_eq!(result, Ok(vec!["EXAMPLE.ORG".to_owned()]));
    }

    #[test]
    fn static_host_realm_defers_unknown() {
        let m = StaticHostrealm;
        let ctx = dangling_ctx();
        assert_eq!(
            m.host_realm(&ctx, "other.example.net"),
            Err(Krb5Error::NoHandle)
        );
    }

    // A module that implements default_realm and fallback_realm.
    struct FullHostrealm {
        local_realm: String,
    }

    impl HostrealmModule for FullHostrealm {
        const NAME: &'static std::ffi::CStr = c"full_hostrealm";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(FullHostrealm {
                local_realm: "LOCAL.TEST".to_owned(),
            })
        }

        fn fallback_realm(
            &self,
            _ctx: &PluginContext<'_>,
            host: &str,
        ) -> Result<Vec<String>, Krb5Error> {
            // Strip leading component: "a.b.c" → look up "b.c"
            if let Some(dot) = host.find('.') {
                let domain = &host[dot + 1..];
                if !domain.is_empty() {
                    return Ok(vec![domain.to_uppercase()]);
                }
            }
            Err(Krb5Error::NoHandle)
        }

        fn default_realm(
            &self,
            _ctx: &PluginContext<'_>,
        ) -> Result<Vec<String>, Krb5Error> {
            Ok(vec![self.local_realm.clone()])
        }
    }

    #[test]
    fn full_module_fallback_strips_component() {
        let m = FullHostrealm {
            local_realm: "LOCAL.TEST".to_owned(),
        };
        let ctx = dangling_ctx();
        let result = m.fallback_realm(&ctx, "host.example.com");
        assert_eq!(result, Ok(vec!["EXAMPLE.COM".to_owned()]));
    }

    #[test]
    fn full_module_default_realm() {
        let m = FullHostrealm {
            local_realm: "LOCAL.TEST".to_owned(),
        };
        let ctx = dangling_ctx();
        assert_eq!(m.default_realm(&ctx), Ok(vec!["LOCAL.TEST".to_owned()]));
    }

    #[test]
    fn init_module_ok() {
        let ctx = dangling_ctx();
        let result = NoopHostrealm::init_module(&ctx);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers end-to-end.
    //
    // These tests drive init → host_realm / default_realm / fallback_realm
    // (with their alloc→use→free_list cycles) → fini through the raw C vtable
    // function pointers produced by make_hostrealm_vtable.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::super::HostrealmModule;
        use crate::context::PluginContext;
        use crate::error::Krb5Error;
        use crate::hostrealm::glue::make_hostrealm_vtable;
        use std::ffi::CStr;

        // Test plugin: returns "TEST.REALM" from host_realm and default_realm.
        // fallback_realm returns Err(NoHandle) via the default implementation.
        struct TestHostrealm;

        impl HostrealmModule for TestHostrealm {
            const NAME: &'static std::ffi::CStr = c"test_hostrealm";
            fn init_module(
                _ctx: &PluginContext<'_>,
            ) -> Result<Self, Krb5Error> {
                Ok(TestHostrealm)
            }

            fn host_realm(
                &self,
                _ctx: &PluginContext<'_>,
                _host: &str,
            ) -> Result<Vec<String>, Krb5Error> {
                Ok(vec!["TEST.REALM".to_string()])
            }

            fn default_realm(
                &self,
                _ctx: &PluginContext<'_>,
            ) -> Result<Vec<String>, Krb5Error> {
                Ok(vec!["TEST.REALM".to_string()])
            }
            // fallback_realm uses the default: Err(Krb5Error::NoHandle)
        }

        // Helper: create a real krb5_context.
        fn make_ctx() -> kurbu5_sys::krb5_context {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            // SAFETY: krb5_init_context writes a valid pointer on success.
            let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(code, 0, "krb5_init_context failed");
            ctx
        }

        // Helper: init the module through the vtable, returning moddata.
        unsafe fn vtable_init(
            ctx: kurbu5_sys::krb5_context,
        ) -> kurbu5_sys::krb5_hostrealm_moddata {
            let vt = make_hostrealm_vtable::<TestHostrealm>();
            let init_fn = vt.init.expect("init vtable slot must be set");
            let mut moddata: kurbu5_sys::krb5_hostrealm_moddata =
                std::ptr::null_mut();
            // SAFETY: ctx is valid; moddata is a stack out-pointer.
            let code = init_fn(ctx, &mut moddata);
            assert_eq!(code, 0, "init must succeed");
            assert!(!moddata.is_null(), "moddata must be non-null after init");
            moddata
        }

        /// host_realm through vtable: alloc → verify content → free_list.
        #[test]
        fn vtable_host_realm_alloc_free() {
            let ctx = make_ctx();
            let vt = make_hostrealm_vtable::<TestHostrealm>();

            // SAFETY: ctx is a valid context produced by krb5_init_context.
            let moddata = unsafe { vtable_init(ctx) };

            let host = b"kdc.example.com\0";
            let mut realms_out: *mut *mut libc::c_char = std::ptr::null_mut();

            let hr_fn =
                vt.host_realm.expect("host_realm vtable slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; host is null-terminated;
                // realms_out is a stack out-pointer.
                hr_fn(
                    ctx,
                    moddata,
                    host.as_ptr() as *const libc::c_char,
                    &mut realms_out,
                )
            };
            assert_eq!(code, 0, "host_realm must succeed");
            assert!(!realms_out.is_null(), "realms_out must be set");

            // Verify the first realm string.
            let first = unsafe {
                // SAFETY: realms_out points to a null-terminated array allocated
                // by the hostrealm glue via build_realm_list.
                *realms_out
            };
            assert!(!first.is_null(), "first realm pointer must not be null");
            let realm_str = unsafe {
                // SAFETY: first is a valid null-terminated CString from the glue.
                CStr::from_ptr(first)
                    .to_str()
                    .expect("realm must be valid UTF-8")
            };
            assert_eq!(realm_str, "TEST.REALM");

            // Free the realm list through the vtable's free_list slot.
            let free_fn =
                vt.free_list.expect("free_list vtable slot must be set");
            unsafe {
                // SAFETY: realms_out was produced by host_realm_bridge via
                // build_realm_list; free_list_bridge is its matching deallocator.
                free_fn(ctx, moddata, realms_out);
            }

            // Tear down.
            let fini_fn = vt.fini.expect("fini vtable slot must be set");
            unsafe {
                // SAFETY: moddata was set by init; this is the single reclamation.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }

        /// default_realm through vtable: alloc → verify content → free_list.
        #[test]
        fn vtable_default_realm_alloc_free() {
            let ctx = make_ctx();
            let vt = make_hostrealm_vtable::<TestHostrealm>();

            // SAFETY: ctx is valid.
            let moddata = unsafe { vtable_init(ctx) };

            let mut realms_out: *mut *mut libc::c_char = std::ptr::null_mut();
            let dr_fn = vt
                .default_realm
                .expect("default_realm vtable slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; realms_out is a stack pointer.
                dr_fn(ctx, moddata, &mut realms_out)
            };
            assert_eq!(code, 0, "default_realm must succeed");
            assert!(!realms_out.is_null(), "realms_out must be set");

            let first = unsafe { *realms_out };
            assert!(!first.is_null(), "first realm must not be null");
            let realm_str = unsafe {
                // SAFETY: first is a valid CString from build_realm_list.
                CStr::from_ptr(first)
                    .to_str()
                    .expect("realm must be valid UTF-8")
            };
            assert_eq!(realm_str, "TEST.REALM");

            let free_fn = vt.free_list.expect("free_list slot must be set");
            unsafe {
                // SAFETY: realms_out was allocated by default_realm_bridge.
                free_fn(ctx, moddata, realms_out);
            }

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was allocated by init; this is its only drop.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }

        /// fallback_realm through vtable: default implementation returns NoHandle.
        #[test]
        fn vtable_fallback_realm_no_handle() {
            let ctx = make_ctx();
            let vt = make_hostrealm_vtable::<TestHostrealm>();

            // SAFETY: ctx is valid.
            let moddata = unsafe { vtable_init(ctx) };

            let host = b"host.example.com\0";
            let mut realms_out: *mut *mut libc::c_char = std::ptr::null_mut();
            let fb_fn = vt
                .fallback_realm
                .expect("fallback_realm vtable slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; host is null-terminated.
                fb_fn(
                    ctx,
                    moddata,
                    host.as_ptr() as *const libc::c_char,
                    &mut realms_out,
                )
            };
            assert_eq!(
                code,
                kurbu5_sys::KRB5_PLUGIN_NO_HANDLE,
                "fallback_realm default must return KRB5_PLUGIN_NO_HANDLE"
            );
            // realms_out is not written on error; it remains null.
            assert!(realms_out.is_null());

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }
    }
}
