//! LOCALAUTH — principal-to-local-account mapping plugin interface.
//!
//! A LOCALAUTH plugin maps Kerberos principal names to local UNIX account
//! names.  libkrb5 consults registered LOCALAUTH plugins when an application
//! calls `krb5_aname_to_localname` or `krb5_kuserok`.  Multiple plugins may
//! be registered; libkrb5 tries each in order and uses the first definitive
//! result.
//!
//! # Interface summary
//!
//! | Vtable field    | Rust method          | Mandatory |
//! |-----------------|----------------------|-----------|
//! | `name`          | `NAME` constant      | yes       |
//! | `an2ln_types`   | `AN2LN_TYPES` const  | no        |
//! | `init`          | `init_module`        | no        |
//! | `fini`          | `fini_module`        | no        |
//! | `userok`        | `userok`             | no        |
//! | `an2ln`         | `an2ln`              | no        |
//! | `free_string`   | (glue-managed)       | no (mandatory if `an2ln`) |
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::{initvt_plugin, PluginContext, Krb5Error};
//! use kurbu5_rs::localauth::LocalauthModule;
//!
//! pub struct MyLocalauth;
//!
//! impl LocalauthModule for MyLocalauth {
//!     const NAME: &'static str = "my_localauth";
//!
//!     fn userok(
//!         &self,
//!         _ctx: &PluginContext<'_>,
//!         _aname: &kurbu5_rs::sys::krb5_principal_data,
//!         local_user: &str,
//!     ) -> Result<(), Krb5Error> {
//!         // Allow "admin@REALM" to map to any local user whose name starts
//!         // with "admin_".
//!         if local_user.starts_with("admin_") {
//!             Ok(())
//!         } else {
//!             Err(Krb5Error::NoHandle)
//!         }
//!     }
//! }
//!
//! initvt_plugin!(
//!     localauth_my_localauth,
//!     1,
//!     MyLocalauth,
//!     kurbu5_rs::localauth::glue::make_localauth_vtable
//! );
//! // Exports C symbol: localauth_my_localauth_initvt
//! ```

use crate::context::PluginContext;
use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// LocalauthModule trait
//
// Vtable field → Rust method mapping (in vtable order):
//
//   name           → NAME: &'static str  (associated constant)
//   an2ln_types    → AN2LN_TYPES: Option<&'static [&'static str]>
//   init           → init_module(&mut ctx) → Result<(), Krb5Error>  [optional]
//   fini           → fini_module(&mut ctx)                          [optional]
//   userok         → userok(ctx, aname, lname) → Result<(), Krb5Error>  [optional]
//   an2ln          → an2ln(ctx, type_, residual, aname) → Result<String, Krb5Error> [optional]
//   free_string    → managed by glue (CString::from_raw on pointer from an2ln)
// ---------------------------------------------------------------------------

/// Plugin trait for the MIT Kerberos LOCALAUTH interface (`krb5/localauth_plugin.h`).
///
/// Implement this trait to provide a principal-to-local-account mapping plugin.
/// libkrb5 calls `userok` to authorise a principal for a given local account,
/// and `an2ln` to translate a principal name to a local account name.
///
/// All methods are optional.  The defaults return `Err(Krb5Error::NoHandle)`,
/// which tells libkrb5 to try the next registered plugin.
///
/// # Module name
///
/// The associated constant `NAME` is the C string placed in the `name` field
/// of the vtable.  It must be unique within a process; by convention it matches
/// the `localauth_<name>_initvt` C function exported by the plugin.
///
/// # `an2ln_types` and `an2ln`
///
/// If `AN2LN_TYPES` is `Some(...)`, the glue layer sets the vtable's
/// `an2ln_types` field to a null-terminated list of uppercase type strings.
/// libkrb5 will then call `an2ln` only when a `[libdefaults] auth_to_local`
/// value references one of those types.  The `type_` and `residual` parameters
/// to `an2ln` will reflect the type/residual pair from the profile.
///
/// If `AN2LN_TYPES` is `None` and `an2ln` is overridden, libkrb5 will call
/// `an2ln` unconditionally (before trying built-in mechanisms), with `type_`
/// and `residual` both set to `None`.
///
/// # Memory: `an2ln` and `free_string`
///
/// The `String` returned by `an2ln` is converted by the glue layer to a
/// `CString` (via `into_raw()`) and the raw pointer is stored in `*lname_out`.
/// libkrb5 later calls the vtable's `free_string` slot, which the glue maps to
/// `CString::from_raw()`.  Plugin authors never touch raw pointers.
pub trait LocalauthModule: Sized + Send + 'static {
    /// The name of this plugin module, written into `krb5_localauth_vtable_st::name`.
    ///
    /// By convention this matches the middle part of the exported C symbol
    /// `localauth_<NAME>_initvt`.
    const NAME: &'static std::ffi::CStr;

    /// Optional list of uppercase `auth_to_local` type strings.
    ///
    /// When set to `Some(types)`, the vtable's `an2ln_types` field is
    /// populated with a null-terminated array derived from these strings.
    /// libkrb5 will only call `an2ln` when a profile `auth_to_local` value
    /// has a type that appears in this list.
    ///
    /// When `None`, `an2ln_types` is set to null in the vtable.  If `an2ln`
    /// is also overridden, libkrb5 calls it for every principal with both
    /// `type_` and `residual` set to `None`.
    const AN2LN_TYPES: Option<&'static [&'static str]> = None;

    /// Initialise module-private state.
    ///
    /// Called once per plugin load.  The returned `Self` value is stored as
    /// the opaque `krb5_localauth_moddata` and passed to every subsequent
    /// call.
    ///
    /// The default implementation creates a zero-sized `Self` value with
    /// `Sized` — only works when `Self` is a unit struct.  Override when the
    /// module needs to read configuration or open resources.
    ///
    /// Corresponds to `krb5_localauth_init_fn`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` if the plugin cannot initialise.
    fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;

    /// Release module-private state.
    ///
    /// Called once when the plugin is unloaded.  The default is a no-op;
    /// any resources owned by `self` are freed when this method returns and
    /// `self` is dropped.
    ///
    /// Corresponds to `krb5_localauth_fini_fn`.
    fn fini_module(self, _ctx: &PluginContext<'_>) {}

    /// Decide whether `aname` is authorised to log in as the local account
    /// `local_user`.
    ///
    /// Return values:
    /// - `Ok(())` — `aname` is authorised; libkrb5 accepts the request.
    /// - `Err(Krb5Error::NoHandle)` — no opinion; try the next plugin
    ///   (`KRB5_PLUGIN_NO_HANDLE`).
    /// - `Err(Krb5Error::Custom(libc::EPERM))` — `aname` is explicitly
    ///   **not** authorised; libkrb5 rejects the request without consulting
    ///   further plugins.
    /// - Any other error — a serious failure; libkrb5 propagates the error.
    ///
    /// The default returns `Err(Krb5Error::NoHandle)`.
    ///
    /// Corresponds to `krb5_localauth_userok_fn`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn userok(
        &self,
        _ctx: &PluginContext<'_>,
        _aname: &kurbu5_sys::krb5_principal_data,
        _local_user: &str,
    ) -> Result<(), Krb5Error> {
        Err(Krb5Error::NoHandle)
    }

    /// Map a principal name to a local account name.
    ///
    /// Return `Ok(name)` if a mapping can be determined, where `name` is the
    /// local account name.  The glue layer converts the returned `String` to a
    /// `CString` and passes its raw pointer back to libkrb5; libkrb5 later
    /// frees it via the vtable's `free_string` slot.
    ///
    /// Return `Err(Krb5Error::LnameNotrans)` (`KRB5_LNAME_NOTRANS`) when no
    /// mapping exists for this principal but the plugin has no opinion.
    /// Return `Err(Krb5Error::NoHandle)` to skip to the next plugin.
    /// Return any other error to halt the `krb5_aname_to_localname` call.
    ///
    /// Parameters:
    /// - `type_` — the `auth_to_local` type token from the profile, or `None`
    ///   when `AN2LN_TYPES` is not set.
    /// - `residual` — the residual string following the type in the profile
    ///   value, or `None` when `AN2LN_TYPES` is not set.
    /// - `aname` — the principal to translate.
    ///
    /// The default returns `Err(Krb5Error::NoHandle)`.
    ///
    /// Corresponds to `krb5_localauth_an2ln_fn`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn an2ln(
        &self,
        _ctx: &PluginContext<'_>,
        _type_: Option<&str>,
        _residual: Option<&str>,
        _aname: &kurbu5_sys::krb5_principal_data,
    ) -> Result<String, Krb5Error> {
        Err(Krb5Error::NoHandle)
    }
}

// ---------------------------------------------------------------------------
// Glue sub-module
// ---------------------------------------------------------------------------

/// Vtable construction for the LOCALAUTH interface.
///
/// This module is `#[doc(hidden)]` and `pub` so that the `initvt_plugin!`
/// macro can reference `make_localauth_vtable` from the plugin crate's
/// namespace.
#[doc(hidden)]
pub mod glue;

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Test helper: owned krb5_context
    //
    // Tests that exercise trait methods need a valid PluginContext.  We create
    // one via krb5_init_context and free it when the guard drops.
    // ---------------------------------------------------------------------------

    struct TestCtx(kurbu5_sys::krb5_context);

    impl TestCtx {
        fn new() -> Self {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            // SAFETY: krb5_init_context writes a valid pointer on success.
            let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(code, 0, "krb5_init_context failed");
            TestCtx(ctx)
        }

        fn as_plugin_ctx(&self) -> PluginContext<'_> {
            // SAFETY: self.0 is a valid krb5_context created by krb5_init_context
            // and valid for the lifetime of self.
            unsafe { PluginContext::from_raw(self.0) }
        }
    }

    impl Drop for TestCtx {
        fn drop(&mut self) {
            // SAFETY: self.0 was created by krb5_init_context and is exclusively
            // owned by this struct.
            unsafe { kurbu5_sys::krb5_free_context(self.0) };
        }
    }

    // ---------------------------------------------------------------------------
    // Test module implementations
    // ---------------------------------------------------------------------------

    // A minimal module that accepts everything for `userok` and returns a
    // fixed mapping for `an2ln`.
    struct AlwaysAllow;

    impl LocalauthModule for AlwaysAllow {
        const NAME: &'static std::ffi::CStr = c"always_allow";

        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(AlwaysAllow)
        }

        fn userok(
            &self,
            _ctx: &PluginContext<'_>,
            _aname: &kurbu5_sys::krb5_principal_data,
            _local_user: &str,
        ) -> Result<(), Krb5Error> {
            Ok(())
        }

        fn an2ln(
            &self,
            _ctx: &PluginContext<'_>,
            _type_: Option<&str>,
            _residual: Option<&str>,
            _aname: &kurbu5_sys::krb5_principal_data,
        ) -> Result<String, Krb5Error> {
            Ok("testuser".to_owned())
        }
    }

    // A module that passes all calls through to the default (NoHandle).
    struct PassThrough;

    impl LocalauthModule for PassThrough {
        const NAME: &'static std::ffi::CStr = c"pass_through";

        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(PassThrough)
        }
    }

    // A module with an2ln_types set.
    struct TypedModule;

    impl LocalauthModule for TypedModule {
        const NAME: &'static std::ffi::CStr = c"typed_module";
        const AN2LN_TYPES: Option<&'static [&'static str]> = Some(&["MYRULE"]);

        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(TypedModule)
        }

        fn an2ln(
            &self,
            _ctx: &PluginContext<'_>,
            type_: Option<&str>,
            residual: Option<&str>,
            _aname: &kurbu5_sys::krb5_principal_data,
        ) -> Result<String, Krb5Error> {
            // Only handle our own type.
            match type_ {
                Some("MYRULE") => {
                    Ok(format!("mapped_{}", residual.unwrap_or("default")))
                },
                _ => Err(Krb5Error::LnameNotrans),
            }
        }
    }

    // Zeroed principal_data used when the test implementation ignores aname.
    fn zeroed_principal() -> kurbu5_sys::krb5_principal_data {
        kurbu5_sys::krb5_principal_data {
            magic: 0,
            realm: kurbu5_sys::krb5_data {
                magic: 0,
                length: 0,
                data: std::ptr::null_mut(),
            },
            data: std::ptr::null_mut(),
            length: 0,
            type_: 0,
        }
    }

    // ---------------------------------------------------------------------------
    // Tests: associated constants (no context needed)
    // ---------------------------------------------------------------------------

    /// The name constants are the strings we declared.
    #[test]
    fn names_are_correct() {
        assert_eq!(AlwaysAllow::NAME, c"always_allow");
        assert_eq!(PassThrough::NAME, c"pass_through");
        assert_eq!(TypedModule::NAME, c"typed_module");
    }

    /// AN2LN_TYPES defaults to None and can be Some.
    #[test]
    fn an2ln_types_constants() {
        assert!(AlwaysAllow::AN2LN_TYPES.is_none());
        assert!(PassThrough::AN2LN_TYPES.is_none());
        let types = TypedModule::AN2LN_TYPES.unwrap();
        assert_eq!(types, &["MYRULE"]);
    }

    // ---------------------------------------------------------------------------
    // Tests: trait method behaviour (requires a live krb5_context)
    // ---------------------------------------------------------------------------

    /// `userok` default returns `NoHandle`.
    #[test]
    fn userok_default_is_no_handle() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let data = zeroed_principal();
        let m = PassThrough;
        assert_eq!(m.userok(&ctx, &data, "nobody"), Err(Krb5Error::NoHandle));
    }

    /// `an2ln` default returns `NoHandle`.
    #[test]
    fn an2ln_default_is_no_handle() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let data = zeroed_principal();
        let m = PassThrough;
        assert_eq!(m.an2ln(&ctx, None, None, &data), Err(Krb5Error::NoHandle));
    }

    /// `AlwaysAllow::userok` returns `Ok(())` for any input.
    #[test]
    fn always_allow_userok_ok() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let data = zeroed_principal();
        let m = AlwaysAllow;
        assert_eq!(m.userok(&ctx, &data, "root"), Ok(()));
    }

    /// `AlwaysAllow::an2ln` returns the fixed mapping.
    #[test]
    fn always_allow_an2ln_maps() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let data = zeroed_principal();
        let m = AlwaysAllow;
        assert_eq!(
            m.an2ln(&ctx, None, None, &data),
            Ok("testuser".to_owned())
        );
    }

    /// `TypedModule::an2ln` maps MYRULE types, rejects others with LnameNotrans.
    #[test]
    fn typed_module_an2ln() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let data = zeroed_principal();
        let m = TypedModule;

        assert_eq!(
            m.an2ln(&ctx, Some("MYRULE"), Some("myres"), &data),
            Ok("mapped_myres".to_owned())
        );
        assert_eq!(
            m.an2ln(&ctx, Some("OTHER"), None, &data),
            Err(Krb5Error::LnameNotrans)
        );
        assert_eq!(
            m.an2ln(&ctx, Some("MYRULE"), None, &data),
            Ok("mapped_default".to_owned())
        );
    }

    /// `fini_module` default is a no-op; module drops cleanly.
    #[test]
    fn fini_module_default_no_op() {
        let tc = TestCtx::new();
        let ctx = tc.as_plugin_ctx();
        let m = PassThrough;
        // If fini_module panics or aborts, the test fails.
        m.fini_module(&ctx);
    }

    // ---------------------------------------------------------------------------
    // Tests: glue vtable construction
    // ---------------------------------------------------------------------------

    /// `make_localauth_vtable` sets all mandatory function pointers.
    #[test]
    fn vtable_function_pointers_are_set() {
        let vt =
            crate::localauth::glue::make_localauth_vtable::<AlwaysAllow>();
        assert!(vt.init.is_some(), "init must be set");
        assert!(vt.fini.is_some(), "fini must be set");
        assert!(vt.userok.is_some(), "userok must be set");
        assert!(vt.an2ln.is_some(), "an2ln must be set");
        assert!(vt.free_string.is_some(), "free_string must be set");
    }

    /// `make_localauth_vtable` sets the module name in the vtable.
    #[test]
    fn vtable_name_is_set() {
        let vt =
            crate::localauth::glue::make_localauth_vtable::<AlwaysAllow>();
        assert!(!vt.name.is_null(), "name must not be null");
        // SAFETY: the name pointer was set by make_localauth_vtable from
        // AlwaysAllow::NAME using Box::leak; it is a valid null-terminated string.
        let name_str =
            unsafe { std::ffi::CStr::from_ptr(vt.name).to_str().unwrap() };
        assert_eq!(name_str, "always_allow");
    }

    /// `make_localauth_vtable` leaves an2ln_types null when AN2LN_TYPES is None.
    #[test]
    fn vtable_an2ln_types_null_when_none() {
        let vt =
            crate::localauth::glue::make_localauth_vtable::<AlwaysAllow>();
        assert!(vt.an2ln_types.is_null(), "an2ln_types should be null");
    }

    /// `make_localauth_vtable` sets an2ln_types when AN2LN_TYPES is Some.
    #[test]
    fn vtable_an2ln_types_set_when_some() {
        let vt =
            crate::localauth::glue::make_localauth_vtable::<TypedModule>();
        assert!(!vt.an2ln_types.is_null(), "an2ln_types should not be null");
        // SAFETY: an2ln_types was set by make_localauth_vtable from
        // TypedModule::AN2LN_TYPES using Box::leak; it is a valid
        // null-terminated array of null-terminated strings.
        let first = unsafe { *vt.an2ln_types };
        assert!(!first.is_null());
        let type_str =
            unsafe { std::ffi::CStr::from_ptr(first).to_str().unwrap() };
        assert_eq!(type_str, "MYRULE");
        // The array must be null-terminated.
        let sentinel = unsafe { *vt.an2ln_types.add(1) };
        assert!(
            sentinel.is_null(),
            "an2ln_types array must be null-terminated"
        );
    }

    /// The an2ln + free_string round-trip: call an2ln bridge, then free_string.
    #[test]
    fn an2ln_free_string_round_trip() {
        use crate::localauth::glue;

        // Build an AlwaysAllow module, box it, and use the raw pointer as moddata.
        let tc = TestCtx::new();
        let module = Box::new(AlwaysAllow);
        let data_ptr = Box::into_raw(module)
            as *mut kurbu5_sys::krb5_localauth_moddata_st;

        // Build a zeroed principal.
        let principal = zeroed_principal();
        let mut lname_out: *mut libc::c_char = std::ptr::null_mut();

        // Call the an2ln bridge directly.
        // SAFETY: data_ptr is a valid Box<AlwaysAllow> cast to moddata_st;
        // aname is a reference to zeroed_principal (valid for this call);
        // type_ and residual are null; lname_out is a valid out-pointer.
        let rc = unsafe {
            glue::an2ln::<AlwaysAllow>(
                tc.0,
                data_ptr,
                std::ptr::null(),
                std::ptr::null(),
                &principal as *const kurbu5_sys::krb5_principal_data,
                &mut lname_out,
            )
        };
        assert_eq!(rc, 0, "an2ln bridge should return 0 on success");
        assert!(!lname_out.is_null(), "lname_out should be set");

        // Verify the string content.
        // SAFETY: lname_out was set by the an2ln bridge to a valid CString.
        let name =
            unsafe { std::ffi::CStr::from_ptr(lname_out).to_str().unwrap() };
        assert_eq!(name, "testuser");

        // Call free_string to release the allocation.
        // SAFETY: lname_out is valid and was allocated by the an2ln bridge.
        unsafe { glue::free_string(tc.0, data_ptr, lname_out) };

        // Clean up the module box.
        // SAFETY: data_ptr was created by Box::into_raw above and has not been
        // freed (fini was not called; we own it).
        drop(unsafe { Box::from_raw(data_ptr as *mut AlwaysAllow) });
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers end-to-end.
    //
    // These tests drive init → an2ln → free_string and init → userok → fini
    // through the raw C vtable slots produced by make_localauth_vtable.
    // -----------------------------------------------------------------------
    mod integration_tests {
        use super::{AlwaysAllow, PassThrough, zeroed_principal};
        use crate::localauth::glue::make_localauth_vtable;
        use std::ffi::CStr;

        // Helper: create a real krb5_context.
        fn make_ctx() -> kurbu5_sys::krb5_context {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            // SAFETY: krb5_init_context writes a valid pointer on success.
            let code = unsafe { kurbu5_sys::krb5_init_context(&mut ctx) };
            assert_eq!(code, 0, "krb5_init_context failed");
            ctx
        }

        /// an2ln through vtable → returned string == "testuser" → free_string.
        #[test]
        fn vtable_an2ln_alloc_free() {
            let ctx = make_ctx();
            let vt = make_localauth_vtable::<AlwaysAllow>();

            // init: allocate the module.
            let mut moddata: kurbu5_sys::krb5_localauth_moddata =
                std::ptr::null_mut();
            let init_fn = vt.init.expect("init slot must be set");
            let init_code = unsafe {
                // SAFETY: ctx is valid; moddata is a stack out-pointer.
                init_fn(ctx, &mut moddata)
            };
            assert_eq!(init_code, 0, "init must succeed");
            assert!(!moddata.is_null());

            // an2ln: map the principal to a local name.
            let principal = zeroed_principal();
            let mut lname_out: *mut libc::c_char = std::ptr::null_mut();
            let an2ln_fn = vt.an2ln.expect("an2ln slot must be set");
            let an2ln_code = unsafe {
                // SAFETY: ctx and moddata are valid; type_/residual are null
                // (accepted by AlwaysAllow); aname is a stack-valid principal;
                // lname_out is a stack out-pointer.
                an2ln_fn(
                    ctx,
                    moddata,
                    std::ptr::null(), // type_
                    std::ptr::null(), // residual
                    &principal as *const kurbu5_sys::krb5_principal_data,
                    &mut lname_out,
                )
            };
            assert_eq!(an2ln_code, 0, "an2ln must succeed");
            assert!(!lname_out.is_null(), "lname_out must be set");

            // Verify the returned string.
            let name_str = unsafe {
                // SAFETY: lname_out was produced by CString::into_raw in the
                // an2ln bridge; it is a valid null-terminated string.
                CStr::from_ptr(lname_out)
                    .to_str()
                    .expect("lname_out is valid UTF-8")
            };
            assert_eq!(name_str, "testuser");

            // free_string: release the CString.
            let free_fn =
                vt.free_string.expect("free_string slot must be set");
            unsafe {
                // SAFETY: lname_out was allocated by the an2ln bridge;
                // free_string is the matching deallocator (CString::from_raw).
                free_fn(ctx, moddata, lname_out);
            }

            // fini: drop the module.
            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was allocated by init; this is the sole drop.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }

        /// userok through vtable: AlwaysAllow → 0 for any local user.
        #[test]
        fn vtable_userok_ok() {
            let ctx = make_ctx();
            let vt = make_localauth_vtable::<AlwaysAllow>();

            let mut moddata: kurbu5_sys::krb5_localauth_moddata =
                std::ptr::null_mut();
            let init_fn = vt.init.expect("init slot must be set");
            unsafe {
                // SAFETY: ctx valid; moddata is a stack pointer.
                init_fn(ctx, &mut moddata);
            }

            let principal = zeroed_principal();
            let lname = b"testuser\0";
            let userok_fn = vt.userok.expect("userok slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata are valid; principal is stack-valid;
                // lname is null-terminated.
                userok_fn(
                    ctx,
                    moddata,
                    &principal as *const kurbu5_sys::krb5_principal_data,
                    lname.as_ptr() as *const libc::c_char,
                )
            };
            assert_eq!(code, 0, "AlwaysAllow::userok must return 0");

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }

        /// userok through vtable with PassThrough plugin → KRB5_PLUGIN_NO_HANDLE.
        #[test]
        fn vtable_userok_no_handle() {
            let ctx = make_ctx();
            let vt = make_localauth_vtable::<PassThrough>();

            let mut moddata: kurbu5_sys::krb5_localauth_moddata =
                std::ptr::null_mut();
            let init_fn = vt.init.expect("init slot must be set");
            unsafe {
                // SAFETY: ctx valid; moddata is a stack pointer.
                init_fn(ctx, &mut moddata);
            }

            let principal = zeroed_principal();
            let lname = b"other\0";
            let userok_fn = vt.userok.expect("userok slot must be set");
            let code = unsafe {
                // SAFETY: ctx and moddata valid; principal and lname are stack.
                userok_fn(
                    ctx,
                    moddata,
                    &principal as *const kurbu5_sys::krb5_principal_data,
                    lname.as_ptr() as *const libc::c_char,
                )
            };
            assert_eq!(
                code,
                kurbu5_sys::KRB5_PLUGIN_NO_HANDLE,
                "PassThrough::userok must return KRB5_PLUGIN_NO_HANDLE"
            );

            let fini_fn = vt.fini.expect("fini slot must be set");
            unsafe {
                // SAFETY: moddata was set by init.
                fini_fn(ctx, moddata);
                kurbu5_sys::krb5_free_context(ctx);
            }
        }
    }
}
