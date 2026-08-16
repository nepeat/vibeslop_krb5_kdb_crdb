//! `KADM5_HOOK` — kadm5 operation hook plugin interface.
//!
//! A `KADM5_HOOK` plugin intercepts kadm5 principal modification, creation, and
//! password-change operations.  Each operation runs at two stages:
//!
//! - **Pre-commit** (`HookStage::Precommit`): runs before the database is
//!   updated.  A plugin failure prevents the operation from proceeding.
//! - **Post-commit** (`HookStage::Postcommit`): runs after the database is
//!   updated.  Failures are logged but otherwise ignored.
//!
//! All hook methods default to `Ok(())` (no-op / pass through).  Override
//! only the operations your plugin needs to intercept.
//!
//! # Interface contract (from `krb5/kadm5_hook_plugin.h`)
//!
//! Major version 1, minor version 3.  Vtable fields in declaration order:
//!
//! | C field    | Rust method          | Required |
//! |------------|----------------------|----------|
//! | `name`     | `NAME` constant      | Yes      |
//! | `init`     | `init_module`        | Yes      |
//! | `fini`     | `fini_module` (drop) | No       |
//! | `chpass`   | `chpass`             | No       |
//! | `create`   | `create`             | No       |
//! | `modify`   | `modify`             | No       |
//! | `remove`   | `remove`             | No       |
//! | `rename`   | `rename` (`min_ver` 2) | No       |
//! | `alias`    | `alias` (`min_ver` 3)  | No       |
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_kadm5_rs::{initvt_plugin, PluginContext, Krb5Error};
//! use kurbu5_kadm5_rs::hook::{Kadm5HookModule, HookStage, ChpassRequest};
//!
//! pub struct AuditHook;
//!
//! impl Kadm5HookModule for AuditHook {
//!     const NAME: &'static str = "audit_hook";
//!
//!     fn init_module(
//!         _ctx: &PluginContext<'_>,
//!     ) -> Result<Self, Krb5Error> {
//!         Ok(AuditHook)
//!     }
//!
//!     fn chpass(
//!         &self,
//!         ctx: &PluginContext<'_>,
//!         stage: HookStage,
//!         req: &ChpassRequest<'_>,
//!     ) -> Result<(), Krb5Error> {
//!         if stage == HookStage::Postcommit {
//!             // log the password change
//!         }
//!         Ok(())
//!     }
//! }
//!
//! initvt_plugin!(
//!     kadm5_hook_audit, 1, AuditHook,
//!     kurbu5_kadm5_rs::hook::glue::make_kadm5_hook_vtable
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
// HookStage
// ---------------------------------------------------------------------------

/// Whether the hook is running before or after the database update.
///
/// Mirrors `kadm5_hook_stage` from `kadm5_hook_plugin.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStage {
    /// Pre-commit: runs before the database is updated.  A failure aborts
    /// the operation.
    Precommit,
    /// Post-commit: runs after the database is updated.  Failures are logged
    /// but ignored.
    Postcommit,
}

impl HookStage {
    /// Construct from the C integer passed in the `stage` parameter.
    pub(crate) fn from_c(val: libc::c_int) -> Self {
        // The C enum values are:
        //   KADM5_HOOK_STAGE_PRECOMMIT  = 0
        //   KADM5_HOOK_STAGE_POSTCOMMIT = 1
        //
        // Any unknown (future) stage value is silently treated as Postcommit.
        // Post-commit hooks have weaker semantics (failures are logged but
        // ignored), so this is the safer default for an unrecognised value:
        // the hook runs but cannot abort the operation.
        if val == 0 {
            HookStage::Precommit
        } else {
            HookStage::Postcommit
        }
    }
}

// ---------------------------------------------------------------------------
// Input record types
// ---------------------------------------------------------------------------

/// Inputs for a chpass (change-password) hook.
///
/// Groups the parameters for the `chpass` vtable method to keep the trait
/// method signature readable.
pub struct ChpassRequest<'a> {
    /// The principal whose password is being changed.
    pub principal: &'a kurbu5_kadm5_sys::krb5_principal_data,
    /// Whether existing keys are being kept (randomization with keepold).
    pub keepold: bool,
    /// Key-salt tuples to use for the new keys.  Empty when the default
    /// enctypes are used.
    pub ks_tuples: &'a [kurbu5_kadm5_sys::krb5_key_salt_tuple],
    /// The new password in plaintext, or `None` if the keys are being
    /// randomized (no password provided).
    pub newpass: Option<&'a str>,
}

/// Inputs for a create-principal hook.
pub struct CreatePrincRequest<'a> {
    /// The new principal entry being created.
    pub entry: Kadm5PrincipalEntry<'a>,
    /// Bitmask of valid fields in `entry` (see `KADM5_*` constants).
    pub mask: libc::c_long,
    /// Key-salt tuples to use.  Empty when the default enctypes are used.
    pub ks_tuples: &'a [kurbu5_kadm5_sys::krb5_key_salt_tuple],
    /// The initial password, or `None` if keys are randomized.
    pub password: Option<&'a str>,
}

/// Inputs for a modify-principal hook.
pub struct ModifyPrincRequest<'a> {
    /// The modified principal entry.
    pub entry: Kadm5PrincipalEntry<'a>,
    /// Bitmask of changed fields in `entry` (see `KADM5_*` constants).
    pub mask: libc::c_long,
}

// ---------------------------------------------------------------------------
// Kadm5HookModule trait
// ---------------------------------------------------------------------------

/// Plugin trait for the `KADM5_HOOK` operation hook interface.
///
/// Implement this trait to intercept kadm5 principal lifecycle operations.
/// All methods default to `Ok(())` — a pure no-op pass-through.
///
/// # Lifecycle
///
/// 1. kadmind calls `init_module` when loading the plugin.
/// 2. `fini_module` is called on shutdown; the default is an empty no-op.
/// 3. Hook methods are called at pre- and post-commit stages for each
///    operation.
pub trait Kadm5HookModule: Sized + Send + 'static {
    /// The module's name, used in kadmind log messages.
    const NAME: &'static std::ffi::CStr;

    /// Initialize the module and return a new instance.
    ///
    /// Return any error to abort kadmind startup.
    ///
    /// # Errors
    ///
    /// Returns any `Err(Krb5Error::*)` to abort kadmind startup.
    ///
    /// (C vtable field: `init`)
    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;

    /// Release resources held by this module instance.
    ///
    /// Default: no-op.  The `Box<Self>` is freed by the glue layer after
    /// this call returns.
    ///
    /// (C vtable field: `fini`)
    fn fini_module(self, _ctx: &PluginContext<'_>) {}

    /// Intercept a password-change or key-randomization operation.
    ///
    /// `stage` indicates whether this is a pre-commit or post-commit call.
    /// Default: `Ok(())` — pass through.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::*)` to abort the operation (pre-commit only).
    ///
    /// (C vtable field: `chpass`)
    fn chpass(
        &self,
        _ctx: &PluginContext<'_>,
        _stage: HookStage,
        _req: &ChpassRequest<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Intercept a create-principal operation.
    ///
    /// Default: `Ok(())` — pass through.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::*)` to abort the operation (pre-commit only).
    ///
    /// (C vtable field: `create`)
    fn create(
        &self,
        _ctx: &PluginContext<'_>,
        _stage: HookStage,
        _req: &CreatePrincRequest<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Intercept a modify-principal operation.
    ///
    /// Default: `Ok(())` — pass through.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::*)` to abort the operation (pre-commit only).
    ///
    /// (C vtable field: `modify`)
    fn modify(
        &self,
        _ctx: &PluginContext<'_>,
        _stage: HookStage,
        _req: &ModifyPrincRequest<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Intercept a delete-principal operation.
    ///
    /// `principal` is the principal being deleted.
    ///
    /// Default: `Ok(())` — pass through.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::*)` to abort the operation (pre-commit only).
    ///
    /// (C vtable field: `remove`)
    fn remove(
        &self,
        _ctx: &PluginContext<'_>,
        _stage: HookStage,
        _principal: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Intercept a rename-principal operation.
    ///
    /// `src` is the old name; `dest` is the new name.
    ///
    /// Available since minor version 2.
    ///
    /// Default: `Ok(())` — pass through.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::*)` to abort the operation (pre-commit only).
    ///
    /// (C vtable field: `rename`, `min_ver` 2)
    fn rename(
        &self,
        _ctx: &PluginContext<'_>,
        _stage: HookStage,
        _src: &kurbu5_kadm5_sys::krb5_principal_data,
        _dest: &kurbu5_kadm5_sys::krb5_principal_data,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    /// Intercept an add-alias operation.
    ///
    /// `alias` is the alias principal; `target` is the canonical principal
    /// it aliases.
    ///
    /// Available since minor version 3.
    ///
    /// Default: `Ok(())` — pass through.
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::*)` to abort the operation (pre-commit only).
    ///
    /// (C vtable field: `alias`, `min_ver` 3)
    fn alias(
        &self,
        _ctx: &PluginContext<'_>,
        _stage: HookStage,
        _alias: &kurbu5_kadm5_sys::krb5_principal_data,
        _target: &kurbu5_kadm5_sys::krb5_principal_data,
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

    // Inner: no-op hook implementation.
    struct NoopHook;
    impl Kadm5HookModule for NoopHook {
        const NAME: &'static std::ffi::CStr = c"noop_hook";
        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(NoopHook)
        }
    }

    // Full delegation: Wrapper delegates everything to NoopHook.
    #[derive(crate::Kadm5HookModule)]
    #[plugin(crate = crate, delegate = inner)]
    struct Wrapper {
        inner: NoopHook,
    }

    #[test]
    fn full_delegation_name_inherited() {
        assert_eq!(
            <Wrapper as Kadm5HookModule>::NAME,
            <NoopHook as Kadm5HookModule>::NAME
        );
    }
}
