//! Kerberos principal name types, zero-copy views, and owned principals.
//!
//! [`PrincipalType`] mirrors the `krb5_principal_data.type` field
//! (`KRB5_NT_*` in `krb5.h`). [`PrincipalRef`] wraps a
//! `&kurbu5_sys::krb5_principal_data` reference — the kind every non-KDB
//! plugin trait method already hands to plugin authors — with friendly
//! accessors (realm, components, name type).
//!
//! [`OwnedPrincipal`] is the owned counterpart: an RAII wrapper around a
//! `krb5_principal` allocated by [`OwnedPrincipal::parse`] (via
//! `krb5_parse_name`) or [`OwnedPrincipal::build`] (assembled directly from
//! a realm and a list of components, without going through libkrb5's C
//! variadic `krb5_build_principal_ext`, which Rust cannot call with a
//! runtime-determined argument count). It releases the principal with
//! `krb5_free_principal` on `Drop`.

use std::ptr::NonNull;

use crate::error::Krb5Error;

// ---------------------------------------------------------------------------
// PrincipalType
// ---------------------------------------------------------------------------

/// Kerberos principal name type (RFC 4120 §6.2; `KRB5_NT_*` in `krb5.h`).
///
/// Mirrors the `krb5_principal_data.type` field. These are protocol-level
/// constants that have been stable since RFC 4120, so they are hardcoded
/// here rather than routed through `kurbu5-sys`/bindgen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalType {
    /// `KRB5_NT_UNKNOWN` (0) — name type not known.
    Unknown,
    /// `KRB5_NT_PRINCIPAL` (1) — just the name of the principal, as for users.
    Principal,
    /// `KRB5_NT_SRV_INST` (2) — service and other unique instance (e.g. `krbtgt`).
    SrvInst,
    /// `KRB5_NT_SRV_HST` (3) — service with hostname as instance (e.g. `HTTP/host`).
    SrvHst,
    /// `KRB5_NT_SRV_XHST` (4) — service with host as remaining components.
    SrvXhst,
    /// `KRB5_NT_UID` (5) — unique ID.
    Uid,
    /// `KRB5_NT_X500_PRINCIPAL` (6) — PKINIT X.500 principal.
    X500Principal,
    /// `KRB5_NT_SMTP_NAME` (7) — SMTP email-style name.
    SmtpName,
    /// `KRB5_NT_ENTERPRISE_PRINCIPAL` (10) — Windows UPN.
    EnterprisePrincipal,
    /// `KRB5_NT_WELLKNOWN` (11) — well-known (special) principal, e.g. anonymous.
    WellKnown,
    /// Any other value, preserved verbatim.
    Other(i32),
}

impl PrincipalType {
    /// Convert to the raw `krb5_principal_data.type` integer value.
    #[must_use]
    pub fn as_raw(self) -> i32 {
        match self {
            PrincipalType::Unknown => 0,
            PrincipalType::Principal => 1,
            PrincipalType::SrvInst => 2,
            PrincipalType::SrvHst => 3,
            PrincipalType::SrvXhst => 4,
            PrincipalType::Uid => 5,
            PrincipalType::X500Principal => 6,
            PrincipalType::SmtpName => 7,
            PrincipalType::EnterprisePrincipal => 10,
            PrincipalType::WellKnown => 11,
            PrincipalType::Other(v) => v,
        }
    }

    /// Construct from a raw `krb5_principal_data.type` integer value.
    #[must_use]
    pub fn from_raw(v: i32) -> Self {
        match v {
            0 => PrincipalType::Unknown,
            1 => PrincipalType::Principal,
            2 => PrincipalType::SrvInst,
            3 => PrincipalType::SrvHst,
            4 => PrincipalType::SrvXhst,
            5 => PrincipalType::Uid,
            6 => PrincipalType::X500Principal,
            7 => PrincipalType::SmtpName,
            10 => PrincipalType::EnterprisePrincipal,
            11 => PrincipalType::WellKnown,
            other => PrincipalType::Other(other),
        }
    }
}

// ---------------------------------------------------------------------------
// PrincipalRef — zero-copy view of a krb5_principal_data
// ---------------------------------------------------------------------------

/// A zero-copy view of a Kerberos principal name (`&krb5_principal_data`).
#[derive(Debug, Clone, Copy)]
pub struct PrincipalRef<'a>(&'a kurbu5_sys::krb5_principal_data);

impl<'a> PrincipalRef<'a> {
    /// The realm component as a byte slice.
    #[must_use]
    pub fn realm(&self) -> &'a [u8] {
        let data = &self.0.realm;
        if data.data.is_null() || data.length == 0 {
            return &[];
        }
        // SAFETY: data.data points to data.length initialised bytes, valid
        // for 'a — guaranteed by the krb5_principal_data this was built from.
        unsafe {
            std::slice::from_raw_parts(
                data.data.cast::<u8>(),
                data.length as usize,
            )
        }
    }

    /// The realm component as a `&str`, or `None` if it is not valid UTF-8.
    #[must_use]
    pub fn realm_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.realm()).ok()
    }

    /// The number of name components (not counting the realm).
    #[must_use]
    pub fn num_components(&self) -> usize {
        usize::try_from(self.0.length).unwrap_or(0)
    }

    /// Iterate over the name components as byte slices.
    pub fn components(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let inner = self.0;
        (0..self.num_components()).map(move |i| {
            // SAFETY: i < inner.length (loop bound); inner.data points to an
            // array of at least `length` krb5_data entries, valid for 'a.
            let comp = unsafe { &*inner.data.add(i) };
            if comp.data.is_null() || comp.length == 0 {
                &[][..]
            } else {
                // SAFETY: comp.data points to comp.length initialised bytes,
                // valid for 'a.
                unsafe {
                    std::slice::from_raw_parts(
                        comp.data.cast::<u8>(),
                        comp.length as usize,
                    )
                }
            }
        })
    }

    /// The principal's name type.
    #[must_use]
    pub fn name_type(&self) -> PrincipalType {
        PrincipalType::from_raw(self.0.type_)
    }

    /// The raw `krb5_const_principal` pointer to the underlying data.
    #[must_use]
    pub fn as_raw(&self) -> kurbu5_sys::krb5_const_principal {
        std::ptr::from_ref(self.0)
    }
}

impl<'a> From<&'a kurbu5_sys::krb5_principal_data> for PrincipalRef<'a> {
    fn from(inner: &'a kurbu5_sys::krb5_principal_data) -> Self {
        PrincipalRef(inner)
    }
}

impl<'a> From<&'a OwnedPrincipal> for PrincipalRef<'a> {
    fn from(owned: &'a OwnedPrincipal) -> Self {
        owned.as_ref()
    }
}

// ---------------------------------------------------------------------------
// OwnedPrincipal — owned krb5_principal
// ---------------------------------------------------------------------------

/// An owned Kerberos principal name (`krb5_principal`), freed on `Drop`.
#[derive(Debug)]
pub struct OwnedPrincipal {
    ctx: kurbu5_sys::krb5_context,
    ptr: NonNull<kurbu5_sys::krb5_principal_data>,
}

impl OwnedPrincipal {
    /// Parse a principal name string (e.g. `"user@REALM"`) via `krb5_parse_name`.
    ///
    /// # Safety
    ///
    /// `ctx` must be non-null and remain valid for at least as long as the
    /// returned `OwnedPrincipal` (it is used again on `Drop`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if `name` contains an interior NUL byte, or if
    /// `krb5_parse_name` fails (e.g. malformed input).
    pub unsafe fn parse(
        ctx: kurbu5_sys::krb5_context,
        name: &str,
    ) -> Result<Self, Krb5Error> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        let mut out: kurbu5_sys::krb5_principal = std::ptr::null_mut();
        // SAFETY: ctx is valid (caller contract); cname is a valid C string;
        // out receives a krb5_principal_data allocated by krb5_parse_name.
        let code = unsafe {
            kurbu5_sys::krb5_parse_name(ctx, cname.as_ptr(), &raw mut out)
        };
        if code != 0 {
            return Err(Krb5Error::from_error_code(code));
        }
        // SAFETY: out is non-null on success (krb5_parse_name contract), and
        // was allocated by krb5_parse_name, so it is freeable via
        // krb5_free_principal.
        Ok(unsafe { OwnedPrincipal::from_raw(ctx, out) })
    }

    /// Build a principal from a realm and an explicit list of components.
    ///
    /// Unlike [`OwnedPrincipal::parse`], components are raw bytes: `/`, `@`,
    /// `\`, and embedded NUL bytes do not need krb5's string-quoting rules,
    /// since there is no round-trip through a parsed string.
    ///
    /// # Safety
    ///
    /// `ctx` must be non-null and remain valid for at least as long as the
    /// returned `OwnedPrincipal` (it is used again on `Drop`).
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::Custom(libc::EINVAL))` if `realm`, any
    /// component, or the component count is too large to fit in the
    /// corresponding `krb5_data`/`krb5_principal_data` field widths.
    /// Returns `Err(Krb5Error::OutOfMemory)` if allocation fails.
    pub unsafe fn build<C: AsRef<[u8]>>(
        ctx: kurbu5_sys::krb5_context,
        realm: &str,
        components: &[C],
        name_type: PrincipalType,
    ) -> Result<Self, Krb5Error> {
        let ncomp = components.len();
        let ncomp_i32 = i32::try_from(ncomp)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

        // SAFETY: calloc(1, size) zero-initialises one krb5_principal_data; a
        // zeroed struct has null realm/data pointers and length 0, which
        // krb5_free_principal treats as "nothing more to free" — the same
        // allocator krb5_free_principal releases with free().
        let princ_ptr = unsafe {
            libc::calloc(
                1,
                std::mem::size_of::<kurbu5_sys::krb5_principal_data>(),
            )
        }
        .cast::<kurbu5_sys::krb5_principal_data>();
        let Some(princ_ptr) = NonNull::new(princ_ptr) else {
            return Err(Krb5Error::OutOfMemory);
        };
        // SAFETY: ctx is valid (caller contract); princ_ptr was just
        // calloc'd and is exclusively owned here. From this point on, every
        // early return goes through `owned`'s Drop (krb5_free_principal),
        // which safely tears down whatever has been filled in so far — a
        // zeroed calloc'd field is exactly what krb5_parse_name would leave
        // behind for a principal with fewer components.
        let owned =
            unsafe { OwnedPrincipal::from_raw(ctx, princ_ptr.as_ptr()) };
        // SAFETY: owned.ptr is valid and exclusively owned.
        unsafe {
            (*owned.ptr.as_ptr()).magic = kurbu5_sys::KV5M_PRINCIPAL;
            (*owned.ptr.as_ptr()).type_ = name_type.as_raw();
            (*owned.ptr.as_ptr()).realm = alloc_krb5_data(realm.as_bytes())?;
        }

        if ncomp > 0 {
            // SAFETY: calloc(ncomp, size) zero-initialises ncomp krb5_data
            // entries; each zeroed entry has data=null, length=0.
            let arr = unsafe {
                libc::calloc(
                    ncomp,
                    std::mem::size_of::<kurbu5_sys::krb5_data>(),
                )
            }
            .cast::<kurbu5_sys::krb5_data>();
            let Some(arr) = NonNull::new(arr) else {
                return Err(Krb5Error::OutOfMemory);
            };
            // SAFETY: owned.ptr is valid and exclusively owned; arr is a
            // fresh calloc'd array of ncomp entries.
            unsafe {
                (*owned.ptr.as_ptr()).data = arr.as_ptr();
                (*owned.ptr.as_ptr()).length = ncomp_i32;
            }
            for (i, c) in components.iter().enumerate() {
                let d = alloc_krb5_data(c.as_ref())?;
                // SAFETY: i < ncomp (loop bound); arr has ncomp entries.
                unsafe {
                    *arr.as_ptr().add(i) = d;
                }
            }
        }

        Ok(owned)
    }

    /// Wrap a raw, already-owned principal pointer.
    ///
    /// # Safety
    ///
    /// `ctx` must be non-null and remain valid until the returned value is
    /// dropped. `ptr` must be non-null, not already owned elsewhere, and
    /// freeable via `krb5_free_principal` (e.g. produced by
    /// `krb5_parse_name`, `krb5_build_principal*`, or `krb5_copy_principal`).
    #[must_use]
    pub unsafe fn from_raw(
        ctx: kurbu5_sys::krb5_context,
        ptr: kurbu5_sys::krb5_principal,
    ) -> Self {
        debug_assert!(!ctx.is_null());
        debug_assert!(!ptr.is_null());
        OwnedPrincipal {
            ctx,
            // SAFETY: caller guarantees ptr is non-null.
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// Borrow as a [`PrincipalRef`].
    #[must_use]
    pub fn as_ref(&self) -> PrincipalRef<'_> {
        // SAFETY: self.ptr is valid for the lifetime of self (invariant).
        PrincipalRef(unsafe { self.ptr.as_ref() })
    }

    /// The raw pointer, still owned by `self`.
    ///
    /// # Safety (caller)
    ///
    /// The returned pointer is only valid for as long as `self` is alive;
    /// do not free it directly.
    #[must_use]
    pub fn as_raw(&self) -> kurbu5_sys::krb5_principal {
        self.ptr.as_ptr()
    }

    /// Consume `self` and return the raw pointer, transferring ownership to
    /// the caller (typically libkrb5, via an output parameter).
    ///
    /// The caller becomes responsible for eventually releasing the
    /// principal with `krb5_free_principal`.
    #[must_use]
    pub fn into_raw(self) -> kurbu5_sys::krb5_principal {
        let ptr = self.ptr.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl Drop for OwnedPrincipal {
    fn drop(&mut self) {
        // SAFETY: self.ctx and self.ptr are valid per the OwnedPrincipal
        // invariant; this only runs when into_raw did not already forget self.
        unsafe {
            kurbu5_sys::krb5_free_principal(self.ctx, self.ptr.as_ptr());
        }
    }
}

/// Allocate a `krb5_data` copy of `bytes` with `libc::malloc`, matching the
/// allocator `krb5_free_principal` releases with `free()`.
fn alloc_krb5_data(bytes: &[u8]) -> Result<kurbu5_sys::krb5_data, Krb5Error> {
    let len = bytes.len();
    let len_u32 =
        u32::try_from(len).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
    // SAFETY: malloc(n) with n >= 1 returns either null or a fresh
    // allocation of at least n bytes.
    let buf = unsafe { libc::malloc(len.max(1)) }.cast::<libc::c_char>();
    if buf.is_null() {
        return Err(Krb5Error::OutOfMemory);
    }
    if len > 0 {
        // SAFETY: buf is a fresh, unaliased allocation of at least len
        // bytes; bytes.as_ptr() is valid for len bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                buf.cast::<u8>(),
                len,
            );
        }
    }
    Ok(kurbu5_sys::krb5_data {
        magic: kurbu5_sys::KV5M_DATA,
        length: len_u32,
        data: buf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PrincipalType
    // -----------------------------------------------------------------------

    #[test]
    fn principal_type_round_trips_named_variants() {
        let variants = [
            PrincipalType::Unknown,
            PrincipalType::Principal,
            PrincipalType::SrvInst,
            PrincipalType::SrvHst,
            PrincipalType::SrvXhst,
            PrincipalType::Uid,
            PrincipalType::X500Principal,
            PrincipalType::SmtpName,
            PrincipalType::EnterprisePrincipal,
            PrincipalType::WellKnown,
        ];
        for v in variants {
            assert_eq!(PrincipalType::from_raw(v.as_raw()), v);
        }
    }

    #[test]
    fn principal_type_other_round_trips_unknown_values() {
        assert_eq!(PrincipalType::from_raw(42).as_raw(), 42);
        assert_eq!(PrincipalType::from_raw(-128), PrincipalType::Other(-128));
    }

    // -----------------------------------------------------------------------
    // PrincipalRef
    // -----------------------------------------------------------------------

    fn make_data(bytes: &mut [u8]) -> kurbu5_sys::krb5_data {
        kurbu5_sys::krb5_data {
            magic: 0,
            length: bytes.len() as u32,
            data: bytes.as_mut_ptr().cast::<libc::c_char>(),
        }
    }

    #[test]
    fn principal_ref_reads_realm_and_components() {
        let mut realm_bytes = *b"EXAMPLE.ORG";
        let mut comp0 = *b"host";
        let mut comp1 = *b"server.example.org";
        let mut comps = [make_data(&mut comp0), make_data(&mut comp1)];

        let princ = kurbu5_sys::krb5_principal_data {
            magic: 0,
            realm: make_data(&mut realm_bytes),
            data: comps.as_mut_ptr(),
            length: 2,
            type_: 3, // KRB5_NT_SRV_HST
        };

        let r = PrincipalRef::from(&princ);
        assert_eq!(r.realm(), b"EXAMPLE.ORG".as_slice());
        assert_eq!(r.realm_str(), Some("EXAMPLE.ORG"));
        assert_eq!(r.num_components(), 2);
        let collected: Vec<&[u8]> = r.components().collect();
        assert_eq!(
            collected,
            vec![b"host".as_slice(), b"server.example.org".as_slice()]
        );
        assert_eq!(r.name_type(), PrincipalType::SrvHst);
    }

    #[test]
    fn principal_ref_empty_principal_reads_as_empty() {
        let princ = kurbu5_sys::krb5_principal_data::default();
        let r = PrincipalRef::from(&princ);
        assert!(r.realm().is_empty());
        assert_eq!(r.num_components(), 0);
        assert_eq!(r.components().count(), 0);
        assert_eq!(r.name_type(), PrincipalType::Unknown);
    }

    // -----------------------------------------------------------------------
    // OwnedPrincipal
    // -----------------------------------------------------------------------

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
    }

    impl Drop for TestCtx {
        fn drop(&mut self) {
            // SAFETY: self.0 was returned by krb5_init_context and has not
            // been freed; this is the unique Drop call for this TestCtx.
            unsafe { kurbu5_sys::krb5_free_context(self.0) }
        }
    }

    fn unparse(
        ctx: kurbu5_sys::krb5_context,
        princ: PrincipalRef<'_>,
    ) -> String {
        let mut out: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: ctx is valid (TestCtx invariant); princ.as_raw() is valid
        // for the duration of this call; out receives a malloc'd string.
        let code = unsafe {
            kurbu5_sys::krb5_unparse_name(ctx, princ.as_raw(), &raw mut out)
        };
        assert_eq!(code, 0, "krb5_unparse_name failed");
        // SAFETY: out is a valid null-terminated string on success.
        let s = unsafe {
            std::ffi::CStr::from_ptr(out).to_string_lossy().into_owned()
        };
        // SAFETY: out was allocated by krb5_unparse_name.
        unsafe { kurbu5_sys::krb5_free_unparsed_name(ctx, out) };
        s
    }

    #[test]
    fn parse_and_unparse_round_trip() {
        let tc = TestCtx::new();
        // SAFETY: tc.0 is valid for the duration of this test.
        let owned =
            unsafe { OwnedPrincipal::parse(tc.0, "user@REALM.EXAMPLE") }
                .expect("parse must succeed");
        assert_eq!(unparse(tc.0, owned.as_ref()), "user@REALM.EXAMPLE");
        assert_eq!(owned.as_ref().realm(), b"REALM.EXAMPLE".as_slice());
        let comps: Vec<&[u8]> = owned.as_ref().components().collect();
        assert_eq!(comps, vec![b"user".as_slice()]);
    }

    #[test]
    fn parse_rejects_interior_nul() {
        let tc = TestCtx::new();
        // SAFETY: tc.0 is valid for the duration of this test.
        let err = unsafe { OwnedPrincipal::parse(tc.0, "u\0ser@REALM") }
            .expect_err("interior NUL must be rejected");
        assert_eq!(err, Krb5Error::Custom(libc::EINVAL));
    }

    #[test]
    fn into_raw_transfers_ownership() {
        let tc = TestCtx::new();
        // SAFETY: tc.0 is valid for the duration of this test.
        let owned =
            unsafe { OwnedPrincipal::parse(tc.0, "svc@REALM.EXAMPLE") }
                .expect("parse must succeed");
        let raw = owned.into_raw();
        assert!(!raw.is_null());
        // SAFETY: raw was returned by into_raw, which forgot the
        // OwnedPrincipal's Drop; this is now the sole owner and release.
        unsafe { kurbu5_sys::krb5_free_principal(tc.0, raw) };
    }

    #[test]
    fn from_raw_round_trips_through_drop() {
        let tc = TestCtx::new();
        let mut raw: kurbu5_sys::krb5_principal = std::ptr::null_mut();
        let cname = std::ffi::CString::new("host/svc@REALM.EXAMPLE").unwrap();
        // SAFETY: tc.0 is valid; cname is a valid C string; raw receives an
        // allocation from krb5_parse_name.
        let code = unsafe {
            kurbu5_sys::krb5_parse_name(tc.0, cname.as_ptr(), &raw mut raw)
        };
        assert_eq!(code, 0);
        // SAFETY: raw was just allocated by krb5_parse_name and is not yet
        // owned by anything else.
        let owned = unsafe { OwnedPrincipal::from_raw(tc.0, raw) };
        assert_eq!(unparse(tc.0, owned.as_ref()), "host/svc@REALM.EXAMPLE");
        // owned drops here, freeing raw via krb5_free_principal.
    }

    // -----------------------------------------------------------------------
    // OwnedPrincipal::build
    // -----------------------------------------------------------------------

    #[test]
    fn build_with_components_unparses_correctly() {
        let tc = TestCtx::new();
        let components = ["a", "bb"];
        // SAFETY: tc.0 is valid for the duration of this test.
        let owned = unsafe {
            OwnedPrincipal::build(
                tc.0,
                "REALM.EXAMPLE",
                &components,
                PrincipalType::Principal,
            )
        }
        .expect("build must succeed");
        assert_eq!(unparse(tc.0, owned.as_ref()), "a/bb@REALM.EXAMPLE");
        assert_eq!(owned.as_ref().realm(), b"REALM.EXAMPLE".as_slice());
        let comps: Vec<&[u8]> = owned.as_ref().components().collect();
        assert_eq!(comps, vec![b"a".as_slice(), b"bb".as_slice()]);
        assert_eq!(owned.as_ref().name_type(), PrincipalType::Principal);
    }

    #[test]
    fn build_with_zero_components_unparses_bare_realm() {
        let tc = TestCtx::new();
        let components: [&str; 0] = [];
        // SAFETY: tc.0 is valid for the duration of this test.
        let owned = unsafe {
            OwnedPrincipal::build(
                tc.0,
                "REALM.EXAMPLE",
                &components,
                PrincipalType::WellKnown,
            )
        }
        .expect("build must succeed");
        assert_eq!(owned.as_ref().num_components(), 0);
        assert_eq!(unparse(tc.0, owned.as_ref()), "@REALM.EXAMPLE");
    }

    #[test]
    fn build_accepts_zero_length_component() {
        let tc = TestCtx::new();
        let components = ["", "x"];
        // SAFETY: tc.0 is valid for the duration of this test.
        let owned = unsafe {
            OwnedPrincipal::build(
                tc.0,
                "REALM.EXAMPLE",
                &components,
                PrincipalType::Principal,
            )
        }
        .expect("build must succeed");
        let comps: Vec<&[u8]> = owned.as_ref().components().collect();
        assert_eq!(comps, vec![b"".as_slice(), b"x".as_slice()]);
    }

    #[test]
    fn build_accepts_bytes_with_special_characters() {
        let tc = TestCtx::new();
        // '@' and '/' would need krb5 quoting through parse(); build()
        // accepts them as raw bytes directly.
        let components: [&[u8]; 1] = [b"weird/name@here"];
        // SAFETY: tc.0 is valid for the duration of this test.
        let owned = unsafe {
            OwnedPrincipal::build(
                tc.0,
                "REALM.EXAMPLE",
                &components,
                PrincipalType::Principal,
            )
        }
        .expect("build must succeed");
        let comps: Vec<&[u8]> = owned.as_ref().components().collect();
        assert_eq!(comps, vec![b"weird/name@here".as_slice()]);
    }
}
