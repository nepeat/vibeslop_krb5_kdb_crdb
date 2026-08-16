//! Integration tests for `KdbContext` (iteration 5.9).
//!
//! Every method on `KdbContext` is exercised against a real `krb5_context`
//! produced by `Krb5Context::new()` or by the `make_context_with_realm`
//! helper (which uses a temporary profile to guarantee a known default realm).
//!
//! Methods not covered here because they require an open KDB backend:
//!   - `db_module_string` — reads `[dbmodules]/<section>/<key>` from profile.
//!   - `set_module` — stores a KdbModule pointer in the context db_context.

use std::ffi::CString;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{KdbContext, Krb5Context};
use crate::module::{PacBuilder, PacRef};
use crate::principal::PrincipalEntry;
use crate::types::{Timestamp, TlDataType};

// ---------------------------------------------------------------------------
// MIT profile library — used to build a custom profile for test contexts.
// These symbols are exported by libkrb5.so (same pattern as context.rs).
// ---------------------------------------------------------------------------

extern "C" {
    fn profile_init(
        files: *const *const libc::c_char,
        ret_profile: *mut *mut libc::c_void,
    ) -> libc::c_long;

    fn profile_release(profile: *mut libc::c_void);
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create a `Krb5Context` configured with a given default realm.
///
/// Writes a minimal `krb5.conf` to a temp file, initialises a profile from
/// it, then calls `krb5_init_context_profile`.  The temp file is removed
/// immediately after the context is created.
fn make_context_with_realm(realm: &str) -> Krb5Context {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("krb5-test-{}-{n}.conf", std::process::id()));

    std::fs::write(
        &path,
        format!("[libdefaults]\n    default_realm = {realm}\n"),
    )
    .expect("write temp krb5.conf");

    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let files: [*const libc::c_char; 2] = [cpath.as_ptr(), std::ptr::null()];

    let mut profile: *mut libc::c_void = std::ptr::null_mut();
    // SAFETY: files is a NULL-terminated array of valid C strings.
    let code = unsafe { profile_init(files.as_ptr(), &mut profile) };
    assert_eq!(code, 0, "profile_init failed: {code}");

    let mut ctx: kdb_sys::krb5_context = std::ptr::null_mut();
    // SAFETY: profile is a valid _profile_t pointer; ctx receives the context.
    let code = unsafe {
        kdb_sys::krb5_init_context_profile(
            profile as *mut kdb_sys::_profile_t,
            0,
            &mut ctx,
        )
    };
    // SAFETY: profile was created by profile_init.
    unsafe { profile_release(profile) };
    std::fs::remove_file(&path).ok();

    assert_eq!(code, 0, "krb5_init_context_profile failed: {code}");
    Krb5Context { ctx }
}

// ---------------------------------------------------------------------------
// Principal name operations
// ---------------------------------------------------------------------------

#[test]
fn parse_and_unparse_principal() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();
    let owned = kdb.parse_principal("user@TESTME.ORG").unwrap();
    let s = kdb.unparse_principal(owned.as_ref()).unwrap();
    assert_eq!(s, "user@TESTME.ORG");
}

#[test]
fn unparse_principal_short_simple() {
    let ctx = make_context_with_realm("TESTME.ORG");
    let kdb = ctx.as_kdb();
    let owned = kdb.parse_principal("user@TESTME.ORG").unwrap();
    let short = kdb.unparse_principal_short(owned.as_ref()).unwrap();
    assert_eq!(short, "user");
}

#[test]
fn unparse_principal_short_service() {
    let ctx = make_context_with_realm("TESTME.ORG");
    let kdb = ctx.as_kdb();
    let owned = kdb
        .parse_principal("host/server.example.com@TESTME.ORG")
        .unwrap();
    let short = kdb.unparse_principal_short(owned.as_ref()).unwrap();
    assert_eq!(short, "host/server.example.com");
}

// ---------------------------------------------------------------------------
// Realm
// ---------------------------------------------------------------------------

#[test]
fn realm_returns_configured_value() {
    let ctx = make_context_with_realm("EXAMPLE.TEST");
    let kdb = ctx.as_kdb();
    assert_eq!(kdb.realm().unwrap(), "EXAMPLE.TEST");
}

// ---------------------------------------------------------------------------
// TL-data helpers
// ---------------------------------------------------------------------------

#[test]
fn update_and_lookup_tl_data() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();
    let mut entry = PrincipalEntry::new();
    kdb.update_tl_data(&mut entry, TlDataType::StringAttrs, b"k\0v\0")
        .unwrap();
    let view = entry.as_ref();
    let tl = kdb.lookup_tl_data(&view, TlDataType::StringAttrs);
    assert!(tl.is_some());
    assert_eq!(tl.unwrap().data, b"k\0v\0");
}

// ---------------------------------------------------------------------------
// String attribute helpers
// ---------------------------------------------------------------------------

#[test]
fn set_and_get_string_attr() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();
    let mut entry = PrincipalEntry::new();
    kdb.set_string_attr(&mut entry, "testkey", Some("testval"))
        .unwrap();
    let view = entry.as_ref();
    let got = kdb.get_string_attr(&view, "testkey").unwrap();
    assert_eq!(got.as_deref(), Some("testval"));
}

#[test]
fn delete_string_attr() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();
    let mut entry = PrincipalEntry::new();
    kdb.set_string_attr(&mut entry, "toremove", Some("value"))
        .unwrap();
    // Delete by passing None.
    kdb.set_string_attr(&mut entry, "toremove", None).unwrap();
    let view = entry.as_ref();
    let got = kdb.get_string_attr(&view, "toremove").unwrap();
    assert!(got.is_none(), "deleted key must not be present");
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

#[test]
fn update_and_lookup_last_pwd_change() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();
    let ts = Timestamp(1_700_000_000);
    let mut entry = PrincipalEntry::new();
    kdb.update_last_pwd_change(&mut entry, ts).unwrap();
    let view = entry.as_ref();
    let got = kdb.lookup_last_pwd_change(&view).unwrap();
    assert_eq!(got, Some(ts));
}

#[test]
fn update_and_lookup_mod_princ() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();
    let ts = Timestamp(1_700_000_001);
    let mod_princ = kdb.parse_principal("admin@TESTME.ORG").unwrap();

    let mut entry = PrincipalEntry::new();
    kdb.update_mod_princ(&mut entry, ts, mod_princ.as_ref())
        .unwrap();

    let view = entry.as_ref();
    let (got_ts, got_princ) = kdb.lookup_mod_princ(&view).unwrap().unwrap();
    assert_eq!(got_ts, ts);
    let name = kdb.unparse_principal(got_princ.as_ref()).unwrap();
    assert_eq!(name, "admin@TESTME.ORG");
}

// ---------------------------------------------------------------------------
// PAC buffer helpers
// ---------------------------------------------------------------------------

#[test]
fn pac_buffer_roundtrip() {
    let ctx = Krb5Context::new().unwrap();
    let kdb = ctx.as_kdb();

    // Allocate an empty PAC.
    let mut raw_pac: kdb_sys::krb5_pac = std::ptr::null_mut();
    // SAFETY: kdb.as_raw() is a valid krb5_context; raw_pac receives the
    // allocated PAC handle on success.
    let code = unsafe { kdb_sys::krb5_pac_init(kdb.as_raw(), &mut raw_pac) };
    assert_eq!(code, 0, "krb5_pac_init failed with code {code}");

    // A freshly allocated PAC has no buffer types.
    let reader = PacRef {
        pac: raw_pac,
        _phantom: PhantomData,
    };
    assert!(
        kdb.pac_get_buffer_types(&reader).is_empty(),
        "fresh PAC must have no buffer types"
    );

    // Add a buffer with an arbitrary type ID and payload.
    let mut builder = PacBuilder {
        pac: raw_pac,
        _phantom: PhantomData,
    };
    kdb.pac_add_buffer(&mut builder, 42, b"hello pac").unwrap();

    // The type now appears in the type list.
    let types = kdb.pac_get_buffer_types(&reader);
    assert!(types.contains(&42), "type 42 must be present after add");

    // The payload is retrievable by type.
    let data = kdb.pac_get_buffer(&reader, 42);
    assert_eq!(
        data.as_deref(),
        Some(b"hello pac" as &[u8]),
        "retrieved buffer must match what was added"
    );

    // A non-existent type returns None.
    assert!(
        kdb.pac_get_buffer(&reader, 999).is_none(),
        "absent buffer type must return None"
    );

    // SAFETY: raw_pac was allocated by krb5_pac_init and is exclusively owned
    // within this test scope.
    unsafe { kdb_sys::krb5_pac_free(kdb.as_raw(), raw_pac) };
}

// Suppress the unused-import warning: KdbContext is only referenced via the
// return type of Krb5Context::as_kdb(), not by name in this file.
const _: fn() = || {
    let _: KdbContext<'_>;
};
