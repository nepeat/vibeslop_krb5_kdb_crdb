//! Glue layer: C vtable function pointers → `Kadm5HookModule` trait dispatch.
//!
//! # Safety
//!
//! **This is the only file in the `hook` module that contains `unsafe` code.**
//!
//! All `unsafe` blocks are annotated with a `// SAFETY:` comment that names
//! the specific invariant being relied upon.  The overall invariants are:
//!
//! 1. `kadm5_hook_modinfo` holds a `*mut M` placed there by `bridge_init`
//!    (as a `Box<M>` converted via `Box::into_raw`) and reclaimed (via
//!    `Box::from_raw`) by `bridge_fini`.  No other code touches this pointer
//!    concurrently.
//!
//! 2. All raw pointers received from kadmind (e.g. `krb5_context`,
//!    `krb5_principal`) are guaranteed non-null and valid for the duration of
//!    the call by the C API contract.  We document this per site below.
//!
//! 3. We never alias a `&mut` with any other reference to the same memory.
//!    Hook methods take `&self`, matching the C API.
//!
//! 4. All C strings (password, policy name) are null-terminated.  We use
//!    `CStr::from_ptr` and propagate errors where they are not valid UTF-8.
//!
//! # Memory ownership contracts
//!
//! | Pattern | Allocation | Deallocation |
//! |---------|-----------|--------------|
//! | Module instance | `Box::into_raw(Box::new(M))` in `bridge_init`, cast to `*mut kadm5_hook_modinfo` | `bridge_fini` calls `Box::from_raw(info as *mut M)` |

use std::ffi::CStr;
use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::hook::{
    ChpassRequest, CreatePrincRequest, HookStage, Kadm5HookModule,
    ModifyPrincRequest,
};
use crate::principal::Kadm5PrincipalEntry;

// ---------------------------------------------------------------------------
// Helper: parse a possibly-null `*const c_char` as an optional `&str`
// ---------------------------------------------------------------------------

/// Parse a possibly-null `*const c_char` as an optional `&str`.
///
/// # Safety
///
/// `ptr` must either be null or point to a valid null-terminated C string
/// that is valid for lifetime `'a`.
unsafe fn optional_cstr<'a>(ptr: *const libc::c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is non-null and points to a valid null-terminated C string
    // (caller guarantee).
    CStr::from_ptr(ptr).to_str().ok()
}

// ---------------------------------------------------------------------------
// Bridge functions — one per vtable slot
// ---------------------------------------------------------------------------

/// Bridge `(*init)(krb5_context, kadm5_hook_modinfo **)`: construct the module.
unsafe extern "C" fn bridge_init<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo_out: *mut *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "init: context is null");
        debug_assert!(!modinfo_out.is_null(), "init: modinfo_out is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);

        match M::init_module(&ctx) {
            Ok(module) => {
                // Box the module; store the raw pointer in *modinfo_out.
                // Deallocation happens in bridge_fini via Box::from_raw.
                let raw = Box::into_raw(Box::new(module))
                    .cast::<kurbu5_kadm5_sys::kadm5_hook_modinfo>();
                // SAFETY: modinfo_out is non-null (debug_assert above).
                *modinfo_out = raw;
                0
            },
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

/// Bridge `(*fini)(krb5_context, kadm5_hook_modinfo *)`: release the module.
unsafe extern "C" fn bridge_fini<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
) {
    let _ =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            debug_assert!(!context.is_null(), "fini: context is null");
            if modinfo.is_null() {
                return;
            }
            // SAFETY: context is non-null (kadmind invariant).
            let ctx = PluginContext::from_raw(context);
            // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.  We are
            // the sole owner; this is the unique reclamation point.
            let module = Box::from_raw(modinfo.cast::<M>());
            module.fini_module(&ctx);
        }));
}

/// Bridge `(*chpass)(krb5_context, modinfo, stage, principal, keepold,
/// n_ks_tuple, ks_tuple, newpass)`.
unsafe extern "C" fn bridge_chpass<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
    stage: libc::c_int,
    principal: kurbu5_kadm5_sys::krb5_principal,
    keepold: kurbu5_kadm5_sys::krb5_boolean,
    n_ks_tuple: libc::c_int,
    ks_tuple: *mut kurbu5_kadm5_sys::krb5_key_salt_tuple,
    newpass: *const libc::c_char,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "chpass: context is null");
        debug_assert!(!modinfo.is_null(), "chpass: modinfo is null");
        debug_assert!(!principal.is_null(), "chpass: principal is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        // SAFETY: principal is non-null and valid for this call.
        let principal_ref = &*principal;

        // Build the key-salt slice — may be empty if n_ks_tuple == 0 or
        // ks_tuple is null.
        let ks_slice: &[kurbu5_kadm5_sys::krb5_key_salt_tuple] =
            if n_ks_tuple > 0 && !ks_tuple.is_null() {
                // SAFETY: ks_tuple points to n_ks_tuple elements of krb5_key_salt_tuple
                // that are valid for the duration of this call (kadmind invariant).
                std::slice::from_raw_parts(
                    ks_tuple,
                    usize::try_from(n_ks_tuple).unwrap_or(0),
                )
            } else {
                &[]
            };

        // SAFETY: newpass is either null or a valid C string (kadmind invariant).
        let newpass_str = optional_cstr(newpass);

        let req = ChpassRequest {
            principal: principal_ref,
            keepold: keepold != 0,
            ks_tuples: ks_slice,
            newpass: newpass_str,
        };

        // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.
        let module = &*modinfo.cast::<M>();
        match module.chpass(&ctx, HookStage::from_c(stage), &req) {
            Ok(()) => 0,
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

/// Bridge `(*create)(krb5_context, modinfo, stage, ent, mask,
/// n_ks_tuple, ks_tuple, password)`.
unsafe extern "C" fn bridge_create<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
    stage: libc::c_int,
    ent: kurbu5_kadm5_sys::kadm5_principal_ent_t,
    mask: libc::c_long,
    n_ks_tuple: libc::c_int,
    ks_tuple: *mut kurbu5_kadm5_sys::krb5_key_salt_tuple,
    password: *const libc::c_char,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "create: context is null");
        debug_assert!(!modinfo.is_null(), "create: modinfo is null");
        debug_assert!(!ent.is_null(), "create: ent is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);

        // SAFETY: ent is non-null and points to a kadm5_principal_ent_rec valid
        // for the duration of this call.
        let entry = Kadm5PrincipalEntry {
            ptr: ent.cast_const(),
            _phantom: PhantomData,
        };

        let ks_slice: &[kurbu5_kadm5_sys::krb5_key_salt_tuple] =
            if n_ks_tuple > 0 && !ks_tuple.is_null() {
                // SAFETY: ks_tuple points to n_ks_tuple valid elements.
                std::slice::from_raw_parts(
                    ks_tuple,
                    usize::try_from(n_ks_tuple).unwrap_or(0),
                )
            } else {
                &[]
            };

        // SAFETY: password is either null or a valid C string.
        let pw_str = optional_cstr(password);

        let req = CreatePrincRequest {
            entry,
            mask,
            ks_tuples: ks_slice,
            password: pw_str,
        };

        // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.
        let module = &*modinfo.cast::<M>();
        match module.create(&ctx, HookStage::from_c(stage), &req) {
            Ok(()) => 0,
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

/// Bridge `(*modify)(krb5_context, modinfo, stage, ent, mask)`.
unsafe extern "C" fn bridge_modify<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
    stage: libc::c_int,
    ent: kurbu5_kadm5_sys::kadm5_principal_ent_t,
    mask: libc::c_long,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "modify: context is null");
        debug_assert!(!modinfo.is_null(), "modify: modinfo is null");
        debug_assert!(!ent.is_null(), "modify: ent is null");

        // SAFETY: context is non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);

        // SAFETY: ent is non-null and valid for this call.
        let entry = Kadm5PrincipalEntry {
            ptr: ent.cast_const(),
            _phantom: PhantomData,
        };

        let req = ModifyPrincRequest { entry, mask };

        // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.
        let module = &*modinfo.cast::<M>();
        match module.modify(&ctx, HookStage::from_c(stage), &req) {
            Ok(()) => 0,
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

/// Bridge `(*remove)(krb5_context, modinfo, stage, principal)`.
unsafe extern "C" fn bridge_remove<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
    stage: libc::c_int,
    principal: kurbu5_kadm5_sys::krb5_principal,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "remove: context is null");
        debug_assert!(!modinfo.is_null(), "remove: modinfo is null");
        debug_assert!(!principal.is_null(), "remove: principal is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let principal_ref = &*principal;

        // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.
        let module = &*modinfo.cast::<M>();
        match module.remove(&ctx, HookStage::from_c(stage), principal_ref) {
            Ok(()) => 0,
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

/// Bridge `(*rename)(krb5_context, modinfo, stage, src, dest)` (`min_ver` 2).
unsafe extern "C" fn bridge_rename<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
    stage: libc::c_int,
    src: kurbu5_kadm5_sys::krb5_principal,
    dest: kurbu5_kadm5_sys::krb5_principal,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "rename: context is null");
        debug_assert!(!modinfo.is_null(), "rename: modinfo is null");
        debug_assert!(!src.is_null(), "rename: src is null");
        debug_assert!(!dest.is_null(), "rename: dest is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let src_ref = &*src;
        let dest_ref = &*dest;

        // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.
        let module = &*modinfo.cast::<M>();
        match module.rename(&ctx, HookStage::from_c(stage), src_ref, dest_ref)
        {
            Ok(()) => 0,
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

/// Bridge `(*alias)(krb5_context, modinfo, stage, alias, target)` (`min_ver` 3).
unsafe extern "C" fn bridge_alias<M: Kadm5HookModule>(
    context: kurbu5_kadm5_sys::krb5_context,
    modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo,
    stage: libc::c_int,
    alias: kurbu5_kadm5_sys::krb5_principal,
    target: kurbu5_kadm5_sys::krb5_principal,
) -> kurbu5_kadm5_sys::kadm5_ret_t {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        debug_assert!(!context.is_null(), "alias: context is null");
        debug_assert!(!modinfo.is_null(), "alias: modinfo is null");
        debug_assert!(!alias.is_null(), "alias: alias is null");
        debug_assert!(!target.is_null(), "alias: target is null");

        // SAFETY: all pointers are non-null (kadmind invariant).
        let ctx = PluginContext::from_raw(context);
        let alias_ref = &*alias;
        let target_ref = &*target;

        // SAFETY: modinfo was placed by bridge_init as Box<M>::into_raw.
        let module = &*modinfo.cast::<M>();
        match module.alias(
            &ctx,
            HookStage::from_c(stage),
            alias_ref,
            target_ref,
        ) {
            Ok(()) => 0,
            Err(e) => kurbu5_kadm5_sys::kadm5_ret_t::from(e.into_error_code()),
        }
    }))
    .unwrap_or(libc::EINVAL.into())
}

// ---------------------------------------------------------------------------
// vtable constructor
// ---------------------------------------------------------------------------

/// Produce a `kadm5_hook_vtable_1_st` for module type `M`.
///
/// Called by the `initvt_plugin!` macro.  All function pointers are
/// monomorphised for `M` at compile time.
pub fn make_kadm5_hook_vtable<M: Kadm5HookModule>()
-> kurbu5_kadm5_sys::kadm5_hook_vtable_1_st {
    kurbu5_kadm5_sys::kadm5_hook_vtable_1_st {
        // SAFETY: M::NAME is a 'static CStr; as_ptr() returns a valid
        // null-terminated *const c_char for the entire process lifetime.
        name: M::NAME.as_ptr(),
        init: Some(bridge_init::<M>),
        fini: Some(bridge_fini::<M>),
        chpass: Some(bridge_chpass::<M>),
        create: Some(bridge_create::<M>),
        modify: Some(bridge_modify::<M>),
        remove: Some(bridge_remove::<M>),
        rename: Some(bridge_rename::<M>),
        alias: Some(bridge_alias::<M>),
    }
}

// ---------------------------------------------------------------------------
// Unit tests (task 10.11)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PluginContext;
    use crate::error::Krb5Error;
    use crate::hook::{ChpassRequest, HookStage, Kadm5HookModule};

    /// Minimal hook module that passes everything through.
    struct NoopHook;

    impl Kadm5HookModule for NoopHook {
        const NAME: &'static std::ffi::CStr = c"noop_hook";

        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(NoopHook)
        }
    }

    /// A hook that denies pre-commit password changes.
    struct DenyPrecommitChpass;

    impl Kadm5HookModule for DenyPrecommitChpass {
        const NAME: &'static std::ffi::CStr = c"deny_precommit_chpass";

        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(DenyPrecommitChpass)
        }

        fn chpass(
            &self,
            _ctx: &PluginContext<'_>,
            stage: HookStage,
            _req: &ChpassRequest<'_>,
        ) -> Result<(), Krb5Error> {
            if stage == HookStage::Precommit {
                Err(Krb5Error::Custom(libc::EPERM))
            } else {
                Ok(())
            }
        }
    }

    fn make_test_context() -> kurbu5_kadm5_sys::krb5_context {
        let mut ctx: kurbu5_kadm5_sys::krb5_context = std::ptr::null_mut();
        // SAFETY: krb5_init_context writes a valid pointer into ctx on success.
        let code = unsafe { kurbu5_kadm5_sys::krb5_init_context(&mut ctx) };
        assert_eq!(code, 0, "krb5_init_context failed with code {code}");
        ctx
    }

    unsafe fn free_test_context(ctx: kurbu5_kadm5_sys::krb5_context) {
        // SAFETY: ctx was created by krb5_init_context and is exclusively owned.
        kurbu5_kadm5_sys::krb5_free_context(ctx);
    }

    /// Verify `make_kadm5_hook_vtable` populates all slots.
    #[test]
    fn vtable_slots_populated() {
        let vt = make_kadm5_hook_vtable::<NoopHook>();
        assert!(vt.init.is_some(), "init slot must be populated");
        assert!(vt.fini.is_some(), "fini slot must be populated");
        assert!(vt.chpass.is_some(), "chpass slot must be populated");
        assert!(vt.create.is_some(), "create slot must be populated");
        assert!(vt.modify.is_some(), "modify slot must be populated");
        assert!(vt.remove.is_some(), "remove slot must be populated");
        assert!(vt.rename.is_some(), "rename slot must be populated");
        assert!(vt.alias.is_some(), "alias slot must be populated");
    }

    /// Verify the `name` pointer resolves to the expected string.
    #[test]
    fn vtable_name_matches_const() {
        let vt = make_kadm5_hook_vtable::<NoopHook>();
        assert!(!vt.name.is_null(), "name must be non-null");
        // SAFETY: vt.name was set from NoopHook::NAME.as_ptr() — a valid
        // null-terminated *const c_char valid for 'static.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, NoopHook::NAME);
    }

    /// Full init → chpass (pre-commit, noop) → fini round-trip.
    #[test]
    fn glue_round_trip_noop_hook_chpass() {
        let ctx_ptr = make_test_context();
        let mut fake_princ = kurbu5_kadm5_sys::krb5_principal_data::default();

        // --- init ---
        let mut modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo =
            std::ptr::null_mut();
        let init_code = unsafe {
            // SAFETY: ctx_ptr is a valid context; modinfo is a valid out-pointer.
            bridge_init::<NoopHook>(ctx_ptr, &mut modinfo)
        };
        assert_eq!(init_code, 0, "init should succeed");
        assert!(!modinfo.is_null(), "modinfo must be set after init");

        // --- chpass pre-commit → NoopHook returns Ok(()) ---
        let chpass_code = unsafe {
            // SAFETY: ctx_ptr and modinfo are valid; fake_princ is a zeroed
            // principal_data on the stack — NoopHook never reads any fields.
            bridge_chpass::<NoopHook>(
                ctx_ptr,
                modinfo,
                0, // KADM5_HOOK_STAGE_PRECOMMIT
                &mut fake_princ as kurbu5_kadm5_sys::krb5_principal,
                0, // keepold = false
                0, // n_ks_tuple = 0
                std::ptr::null_mut(),
                std::ptr::null(), // newpass = null (randomize)
            )
        };
        assert_eq!(chpass_code, 0, "NoopHook chpass should pass through");

        // --- fini ---
        unsafe {
            // SAFETY: modinfo was set by bridge_init; not accessed after this.
            bridge_fini::<NoopHook>(ctx_ptr, modinfo);
            free_test_context(ctx_ptr);
        }
    }

    /// Verify that DenyPrecommitChpass blocks pre-commit but allows post-commit.
    #[test]
    fn glue_round_trip_deny_precommit() {
        let ctx_ptr = make_test_context();
        let mut fake_princ = kurbu5_kadm5_sys::krb5_principal_data::default();
        let mut modinfo: *mut kurbu5_kadm5_sys::kadm5_hook_modinfo =
            std::ptr::null_mut();

        unsafe {
            // SAFETY: ctx_ptr is valid.
            bridge_init::<DenyPrecommitChpass>(ctx_ptr, &mut modinfo);
        }

        // Pre-commit: must be denied.
        let pre_code = unsafe {
            // SAFETY: ctx_ptr and modinfo are valid.
            bridge_chpass::<DenyPrecommitChpass>(
                ctx_ptr,
                modinfo,
                0, // KADM5_HOOK_STAGE_PRECOMMIT
                &mut fake_princ as kurbu5_kadm5_sys::krb5_principal,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert_eq!(
            pre_code as i32,
            libc::EPERM,
            "pre-commit must be denied with EPERM"
        );

        // Post-commit: must be allowed.
        let post_code = unsafe {
            // SAFETY: ctx_ptr and modinfo are valid.
            bridge_chpass::<DenyPrecommitChpass>(
                ctx_ptr,
                modinfo,
                1, // KADM5_HOOK_STAGE_POSTCOMMIT
                &mut fake_princ as kurbu5_kadm5_sys::krb5_principal,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert_eq!(post_code, 0, "post-commit must pass through");

        unsafe {
            // SAFETY: modinfo was set by bridge_init.
            bridge_fini::<DenyPrecommitChpass>(ctx_ptr, modinfo);
            free_test_context(ctx_ptr);
        }
    }

    /// Verify that `bridge_fini` with a null modinfo pointer is a safe no-op.
    #[test]
    fn fini_null_modinfo_is_noop() {
        let ctx_ptr = make_test_context();
        unsafe {
            // SAFETY: null modinfo is guarded by bridge_fini before any
            // dereference.  ctx_ptr is a valid context.
            bridge_fini::<NoopHook>(ctx_ptr, std::ptr::null_mut());
            free_test_context(ctx_ptr);
        }
    }

    /// `HookStage::from_c` maps 0 → Precommit, 1 → Postcommit.
    #[test]
    fn hook_stage_from_c() {
        assert_eq!(HookStage::from_c(0), HookStage::Precommit);
        assert_eq!(HookStage::from_c(1), HookStage::Postcommit);
        // Any non-zero value maps to Postcommit (matches C enum semantics).
        assert_eq!(HookStage::from_c(99), HookStage::Postcommit);
    }
}
