//! `KADM5_AUTH` — kadm5 authorization plugin interface.
//!
//! A `KADM5_AUTH` plugin authorizes kadmin operations before they are performed.
//! Multiple plugins may be registered; kadmind calls them all and applies the
//! following rule:
//!
//! - A request **succeeds** if at least one module explicitly authorizes it
//!   (returns `Ok(())`) and **none** of the modules explicitly deny it (return
//!   any error other than `Krb5Error::NoHandle`).
//! - `Krb5Error::NoHandle` means "this module has no opinion — try the next
//!   one".  If a method is absent from the vtable (not set), kadmind treats
//!   it as if the module returned `Krb5Error::NoHandle`.
//!
//! All check methods default to returning `Ok(())` (explicit authorization),
//! which matches the most common pattern of a policy plugin that approves
//! everything not explicitly blocked.  Override only the methods that your
//! plugin needs to restrict.
//!
//! # Interface contract (from `krb5/kadm5_auth_plugin.h`)
//!
//! Major version 1, minor version 2.  Vtable fields in declaration order:
//!
//! | C field           | Rust method                  | Required |
//! |-------------------|------------------------------|----------|
//! | `name`            | `NAME` constant              | Yes      |
//! | `init`            | `init_module`                | Yes      |
//! | `fini`            | `fini_module` (default: drop) | No      |
//! | `addprinc`        | `check_add_principal`        | No       |
//! | `modprinc`        | `check_modify_principal`     | No       |
//! | `setstr`          | `check_set_string`           | No       |
//! | `cpw`             | `check_change_password`      | No       |
//! | `chrand`          | `check_randomize_keys`       | No       |
//! | `setkey`          | `check_set_key`              | No       |
//! | `purgekeys`       | `check_purge_keys`           | No       |
//! | `delprinc`        | `check_delete_principal`     | No       |
//! | `renprinc`        | `check_rename_principal`     | No       |
//! | `getprinc`        | `check_get_principal`        | No       |
//! | `getstrs`         | `check_get_strings`          | No       |
//! | `extract`         | `check_extract_keys`         | No       |
//! | `listprincs`      | `check_list_principals`      | No       |
//! | `addpol`          | `check_add_policy`           | No       |
//! | `modpol`          | `check_modify_policy`        | No       |
//! | `delpol`          | `check_delete_policy`        | No       |
//! | `getpol`          | `check_get_policy`           | No       |
//! | `listpols`        | `check_list_policies`        | No       |
//! | `iprop`           | `check_iprop`                | No       |
//! | `end`             | `end_operation` (default: no-op) | No   |
//! | `free_restrictions` | `free_restrictions` (default: no-op) | No |
//! | `addalias`        | `check_add_alias` (`min_ver` 2) | No      |
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_kadm5_rs::{initvt_plugin, PluginContext, Krb5Error};
//! use kurbu5_kadm5_rs::auth::{Kadm5AuthModule, AddPrincRequest};
//!
//! pub struct DenyRoot;
//!
//! impl Kadm5AuthModule for DenyRoot {
//!     const NAME: &'static str = "deny_root";
//!
//!     fn init_module(
//!         _ctx: &PluginContext<'_>,
//!         _acl_file: Option<&str>,
//!     ) -> Result<Self, Krb5Error> {
//!         Ok(DenyRoot)
//!     }
//!
//!     fn check_add_principal<'a>(
//!         &self,
//!         ctx: &PluginContext<'_>,
//!         req: &AddPrincRequest<'a>,
//!     ) -> Result<Option<Box<kadm5_auth_restrictions>>, Krb5Error> {
//!         // Deny adding root/admin principals.
//!         if let Some(p) = req.target_entry.as_ref()
//!             .and_then(|e| e.principal())
//!             .and_then(|p| ctx.unparse_principal(p).ok())
//!         {
//!             if p.starts_with("root") || p.starts_with("admin") {
//!                 return Err(Krb5Error::Custom(libc::EPERM));
//!             }
//!         }
//!         Ok(None)
//!     }
//! }
//!
//! initvt_plugin!(
//!     kadm5_auth_deny_root, 1, DenyRoot,
//!     kurbu5_kadm5_rs::auth::glue::make_kadm5_auth_vtable
//! );
//! ```
//!
//! # Safety model
//!
//! All unsafe code is confined to [`glue`].  Plugin authors never write
//! `unsafe` themselves.

use crate::context::PluginContext;
use crate::error::Krb5Error;
use crate::principal::Kadm5PrincipalEntry;

// ---------------------------------------------------------------------------
// Sub-module: glue layer (all unsafe confined here)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod glue;

// ---------------------------------------------------------------------------
// Input record types
// ---------------------------------------------------------------------------

/// Inputs for an add-principal authorization check (`addprinc` vtable slot).
///
/// Groups the `client`, `target`, `entry`, and `mask` parameters that would
/// otherwise make the method signature unwieldy.
pub struct AddPrincRequest<'a> {
    /// The client performing the operation (e.g. the kadmin admin principal).
    pub client: &'a kurbu5_kadm5_sys::krb5_principal_data,
    /// The principal being added.
    pub target: &'a kurbu5_kadm5_sys::krb5_principal_data,
    /// The entry record for the new principal, if provided.
    ///
    /// `None` when the operation did not supply an entry struct (the C field
    /// may be NULL even when `mask` is non-zero).
    pub target_entry: Option<Kadm5PrincipalEntry<'a>>,
    /// Bitmask of valid fields in `target_entry` (see `KADM5_*` constants).
    pub mask: libc::c_long,
}

/// Inputs for a modify-principal authorization check (`modprinc` vtable slot).
pub struct ModPrincRequest<'a> {
    /// The client performing the operation.
    pub client: &'a kurbu5_kadm5_sys::krb5_principal_data,
    /// The principal being modified.
    pub target: &'a kurbu5_kadm5_sys::krb5_principal_data,
    /// The proposed new entry values, if provided.
    pub target_entry: Option<Kadm5PrincipalEntry<'a>>,
    /// Bitmask of valid (changed) fields in `target_entry`.
    pub mask: libc::c_long,
}

// ---------------------------------------------------------------------------
// Kadm5AuthModule trait
// ---------------------------------------------------------------------------

/// Plugin trait for the `KADM5_AUTH` authorization interface.
///
/// Implement this trait to control which kadmin operations are permitted.
/// kadmind calls every registered plugin and applies the union rule:
/// the request succeeds if at least one plugin returns `Ok(())` and none
/// return an error other than `Krb5Error::NoHandle`.
///
/// # Lifecycle
///
/// 1. kadmind calls `init_module` when loading the plugin.  On success, the
///    returned `Self` is stored and passed to all subsequent calls as `&self`
///    or `&mut self`.
/// 2. `fini_module` is called when kadmind is shutting down.  The default
///    implementation is an empty `drop` — the `Box<Self>` is deallocated.
/// 3. After each operation, kadmind calls `end_operation` (default: no-op).
///
/// # Default method semantics
///
/// - Check methods default to `Ok(())` — explicit authorization.  This
///   means a plugin that does not override a check method will always
///   authorize that operation.
/// - `end_operation` defaults to a no-op.
/// - `free_restrictions` defaults to a no-op (restrictions are dropped).
pub trait Kadm5AuthModule: Sized + Send + 'static {
    /// The module's name, used in kadmind log messages.
    ///
    /// The pointer is stored directly in the vtable and remains valid for
    /// the process lifetime (`'static`).
    const NAME: &'static std::ffi::CStr;

    /// Initialize the module and return a new instance.
    ///
    /// `acl_file` is the realm's configured ACL file path, or `None` if none
    /// was configured.  Return `Err(Krb5Error::NoHandle)` if the plugin is
    /// inoperable (e.g. due to misconfiguration); kadmind will skip it.
    /// Return any other error to abort kadmind startup.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` if the plugin is inoperable.
    /// Returns any other `Err(Krb5Error::*)` to abort kadmind startup.
    ///
    /// (C vtable field: `init`)
    fn init_module(
        ctx: &PluginContext<'_>,
        acl_file: Option<&str>,
    ) -> Result<Self, Krb5Error>;

    /// Release resources held by this module instance.
    ///
    /// The default implementation is a no-op: the `Box<Self>` is freed by
    /// the glue layer after this call returns.  Override if you need to
    /// perform cleanup beyond what `Drop` already handles.
    ///
    /// (C vtable field: `fini`)
    fn fini_module(self, _ctx: &PluginContext<'_>) {}

    /// Authorize an add-principal operation, and optionally produce
    /// restrictions on the new principal.
    ///
    /// Return `Ok(None)` to authorize without restrictions, or
    /// `Ok(Some(restrictions))` to authorize with restrictions.  The glue
    /// layer boxes and passes the restrictions struct to kadmind which
    /// calls `free_restrictions` to reclaim it when done.
    /// Return `Err(Krb5Error::NoHandle)` to abstain; any other `Err` denies.
    ///
    /// Default: `Ok(None)` — authorize without restrictions.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `addprinc`)
    fn check_add_principal(
        &self,
        _ctx: &PluginContext<'_>,
        _req: &AddPrincRequest<'_>,
    ) -> Result<Option<kurbu5_kadm5_sys::kadm5_auth_restrictions>, Krb5Error>
    {
        Ok(None)
    }

    /// Authorize a modify-principal operation, and optionally produce
    /// restrictions on the modified principal.
    ///
    /// Default: `Ok(None)` — authorize without restrictions.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `modprinc`)
    fn check_modify_principal(
        &self,
        _ctx: &PluginContext<'_>,
        _req: &ModPrincRequest<'_>,
    ) -> Result<Option<kurbu5_kadm5_sys::kadm5_auth_restrictions>, Krb5Error>
    {
        Ok(None)
    }

    /// Authorize a set-string (string attribute) operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `setstr`)
    fn check_set_string(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
        _key: &str,
        _value: Option<&str>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a change-password operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `cpw`)
    fn check_change_password(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a randomize-keys operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `chrand`)
    fn check_randomize_keys(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a set-key operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `setkey`)
    fn check_set_key(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a purge-keys operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `purgekeys`)
    fn check_purge_keys(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a delete-principal operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `delprinc`)
    fn check_delete_principal(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a rename-principal operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `renprinc`)
    fn check_rename_principal(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _src: &kurbu5_kadm5_sys::krb5_principal_data,
        _dest: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a get-principal operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `getprinc`)
    fn check_get_principal(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a get-strings operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `getstrs`)
    fn check_get_strings(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize an extract-keys operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `extract`)
    fn check_extract_keys(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a list-principals operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `listprincs`)
    fn check_list_principals(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize an add-policy operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `addpol`)
    fn check_add_policy(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _policy: &str,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a modify-policy operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `modpol`)
    fn check_modify_policy(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _policy: &str,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a delete-policy operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `delpol`)
    fn check_delete_policy(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _policy: &str,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a get-policy operation.
    ///
    /// `client_policy` is the name of the client's own policy, or `None` if
    /// the client has no associated policy.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `getpol`)
    fn check_get_policy(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _policy: &str,
        _client_policy: Option<&str>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize a list-policies operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `listpols`)
    fn check_list_policies(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Authorize an incremental propagation (iprop) operation.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `iprop`)
    fn check_iprop(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Receive a notification that the most recently authorized operation has
    /// ended.
    ///
    /// Called by kadmind after each authorized operation completes, including
    /// in cases where no check method was invoked beforehand.  The module must
    /// tolerate `end_operation` being called without a preceding check.
    ///
    /// Default: no-op.
    ///
    /// (C vtable field: `end`)
    fn end_operation(&self, _ctx: &PluginContext<'_>) {}

    /// Free a restrictions object previously returned by `check_add_principal`
    /// or `check_modify_principal`.
    ///
    /// The glue layer boxes the restrictions struct returned by those methods
    /// and passes ownership to kadmind.  When kadmind is done, it calls this
    /// method with the restrictions value reclaimed from its Box.
    ///
    /// The default implementation drops `rs` normally.  Override if your
    /// restrictions struct contains fields that require custom cleanup
    /// (e.g. a heap-allocated `policy` string inside `kadm5_auth_restrictions`
    /// that was not itself allocated with Rust's allocator).
    ///
    /// (C vtable field: `free_restrictions`)
    fn free_restrictions(
        &self,
        _ctx: &PluginContext<'_>,
        _rs: kurbu5_kadm5_sys::kadm5_auth_restrictions,
    ) {
        // Default: rs is dropped here, freeing the restrictions struct.
        // If the `policy` field inside rs was C-heap-allocated, override
        // this method and call libc::free on it before dropping rs.
    }

    /// Authorize an add-alias operation.
    ///
    /// `alias_princ` is the alias principal name; `target_princ` is the
    /// canonical principal it aliases.
    ///
    /// Available since minor version 2.
    ///
    /// Default: `Ok(())` — authorize.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::NoHandle)` to abstain; any other error denies
    /// the operation.
    ///
    /// (C vtable field: `addalias`, `min_ver` 2)
    fn check_add_alias(
        &self,
        _ctx: &PluginContext<'_>,
        _client: &kurbu5_kadm5_sys::krb5_principal_data,
        _alias_princ: &kurbu5_kadm5_sys::krb5_principal_data,
        _target_princ: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Derive integration tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "derive"))]
mod derive_tests {
    use super::*;
    use crate::{Krb5Error, PluginContext};

    // Inner: allow-all base implementation
    struct AllowAll;
    impl Kadm5AuthModule for AllowAll {
        const NAME: &'static std::ffi::CStr = c"allow_all";
        fn init_module(
            _ctx: &PluginContext<'_>,
            _acl: Option<&str>,
        ) -> Result<Self, Krb5Error> {
            Ok(AllowAll)
        }
    }

    // Full delegation: Wrapper delegates everything to AllowAll.
    #[derive(crate::Kadm5AuthModule)]
    #[plugin(crate = crate, delegate = inner)]
    struct Wrapper {
        inner: AllowAll,
    }

    #[test]
    fn full_delegation_name_inherited() {
        assert_eq!(
            <Wrapper as Kadm5AuthModule>::NAME,
            <AllowAll as Kadm5AuthModule>::NAME
        );
    }

    // Selective override: deny delete, allow everything else.
    struct Inner;
    impl Kadm5AuthModule for Inner {
        const NAME: &'static std::ffi::CStr = c"inner";
        fn init_module(
            _ctx: &PluginContext<'_>,
            _acl: Option<&str>,
        ) -> Result<Self, Krb5Error> {
            Ok(Inner)
        }
    }

    #[derive(crate::Kadm5AuthModule)]
    #[plugin(crate = crate, delegate = inner, overrides(check_delete_principal))]
    struct SelectiveWrapper {
        inner: Inner,
    }

    impl SelectiveWrapper {
        fn plugin_impl_check_delete_principal(
            &self,
            _ctx: &PluginContext<'_>,
            _client: &crate::sys::krb5_principal_data,
            _target: &crate::sys::krb5_principal_data,
        ) -> Result<(), Krb5Error> {
            Err(Krb5Error::Custom(1))
        }
    }

    #[test]
    fn selective_override_name_inherited() {
        assert_eq!(
            <SelectiveWrapper as Kadm5AuthModule>::NAME,
            <Inner as Kadm5AuthModule>::NAME
        );
    }
}
