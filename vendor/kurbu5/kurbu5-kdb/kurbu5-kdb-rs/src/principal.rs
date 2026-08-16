//! Zero-copy views and owned types for Kerberos principals and DB entries.

use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::context::KdbContext;
use crate::key_data::{KeyDataBuilder, KeyDataSlice};
use crate::tl_data::{
    GenericFree, OwnedTlDataList, TlDataFreePolicy, TlDataIter, TlDataRef,
};
use crate::types::{PrincipalAttributes, Timestamp, TlDataType};

// ---------------------------------------------------------------------------
// PrincipalRef — zero-copy view of a krb5_principal
// ---------------------------------------------------------------------------

/// A zero-copy reference to a Kerberos principal name (`krb5_principal`).
///
/// Borrows the C-allocated memory for the duration of `'a`.
/// No copy or allocation occurs on construction.
#[derive(Debug, Clone, Copy)]
pub struct PrincipalRef<'a> {
    inner: kdb_sys::krb5_const_principal,
    _phantom: PhantomData<&'a kdb_sys::krb5_principal_data>,
}

impl<'a> PrincipalRef<'a> {
    /// Construct from a raw const pointer.
    ///
    /// # Safety (caller — `glue.rs`)
    ///
    /// `ptr` must be non-null and valid for the duration of `'a`.
    pub(crate) unsafe fn from_raw(ptr: kdb_sys::krb5_const_principal) -> Self {
        debug_assert!(!ptr.is_null());
        PrincipalRef {
            inner: ptr,
            _phantom: PhantomData,
        }
    }

    /// The raw pointer, needed by glue and `KdbContext` utilities.
    pub(crate) fn as_raw(self) -> kdb_sys::krb5_const_principal {
        self.inner
    }

    /// The realm component as a byte slice.
    #[must_use]
    pub fn realm(&self) -> &'a [u8] {
        // SAFETY: self.inner is valid for 'a (construction invariant).
        let data = unsafe { &(*self.inner).realm };
        if data.data.is_null() || data.length == 0 {
            return &[];
        }
        // SAFETY: realm.data points to realm.length bytes valid for 'a.
        unsafe {
            std::slice::from_raw_parts(
                data.data.cast::<u8>(),
                data.length as usize,
            )
        }
    }

    /// The number of name components (not counting the realm).
    #[must_use]
    pub fn num_components(&self) -> usize {
        // SAFETY: self.inner is valid for 'a (construction invariant).
        // krb5_principal_data.length is krb5_int32 (i32); non-negative by
        // Kerberos protocol, so the sign-lossless cast is safe.
        usize::try_from(unsafe { (*self.inner).length }).unwrap_or(0)
    }

    /// Iterate over the name components as byte slices.
    pub fn components(&self) -> impl Iterator<Item = &'a [u8]> {
        let inner = self.inner;
        (0..self.num_components()).map(move |i| {
            // SAFETY: data[i] is within the valid component array.
            let comp = unsafe { &*(*inner).data.add(i) };
            if comp.data.is_null() || comp.length == 0 {
                &[][..]
            } else {
                // SAFETY: comp.data points to comp.length bytes valid for 'a.
                unsafe {
                    std::slice::from_raw_parts(
                        comp.data.cast::<u8>(),
                        comp.length as usize,
                    )
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// PrincipalEntryRef — zero-copy view of a krb5_db_entry
// ---------------------------------------------------------------------------

/// A zero-copy reference to a `krb5_db_entry` principal database record.
///
/// Constructed whenever libkdb5 passes a `krb5_db_entry *` to a driver
/// callback (e.g. `put_principal`, `iterate`).  All field access is
/// zero-allocation: scalar fields are read directly, lists are accessed via
/// iterators that follow C pointers without copying.
#[derive(Debug, Clone, Copy)]
pub struct PrincipalEntryRef<'a> {
    inner: &'a kdb_sys::krb5_db_entry,
}

impl<'a> PrincipalEntryRef<'a> {
    /// Wrap a reference to a C entry.
    ///
    /// # Safety (caller — `glue.rs`)
    ///
    /// `ptr` must be non-null and valid for `'a`.
    pub(crate) unsafe fn from_raw(ptr: *const kdb_sys::krb5_db_entry) -> Self {
        debug_assert!(!ptr.is_null());
        PrincipalEntryRef { inner: &*ptr }
    }

    /// The principal name.
    #[must_use]
    pub fn princ(&self) -> PrincipalRef<'a> {
        // SAFETY: princ is valid if the entry is valid.
        unsafe { PrincipalRef::from_raw(self.inner.princ) }
    }

    /// Attribute flags (see [`PrincipalAttributes`]).
    #[must_use]
    pub fn attributes(&self) -> PrincipalAttributes {
        PrincipalAttributes::from_bits_truncate(u32::from_ne_bytes(
            self.inner.attributes.to_ne_bytes(),
        ))
    }

    /// Maximum ticket lifetime (`krb5_deltat`, seconds).
    #[must_use]
    pub fn max_life(&self) -> i32 {
        self.inner.max_life
    }

    /// Maximum renewable lifetime (seconds).
    #[must_use]
    pub fn max_renewable_life(&self) -> i32 {
        self.inner.max_renewable_life
    }

    /// Principal expiration timestamp (0 = never).
    #[must_use]
    pub fn expiration(&self) -> Timestamp {
        Timestamp(self.inner.expiration)
    }

    /// Password expiration timestamp (0 = never).
    #[must_use]
    pub fn pw_expiration(&self) -> Timestamp {
        Timestamp(self.inner.pw_expiration)
    }

    /// Timestamp of the last successful authentication.
    #[must_use]
    pub fn last_success(&self) -> Timestamp {
        Timestamp(self.inner.last_success)
    }

    /// Timestamp of the last failed authentication attempt.
    #[must_use]
    pub fn last_failed(&self) -> Timestamp {
        Timestamp(self.inner.last_failed)
    }

    /// Number of consecutive failed authentication attempts.
    #[must_use]
    pub fn fail_auth_count(&self) -> u32 {
        self.inner.fail_auth_count
    }

    /// Entry format version / base-length field (`KRB5_KDB_V1_BASE_LENGTH`).
    ///
    /// libkrb5 rejects entries with `len < KRB5_KDB_V1_BASE_LENGTH` as
    /// truncated records.  [`PrincipalEntry::new`] initialises this to
    /// `KRB5_KDB_V1_BASE_LENGTH` automatically.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> u16 {
        self.inner.len
    }

    /// Bitmask indicating which fields have been modified (for `put_principal`).
    #[must_use]
    pub fn mask(&self) -> u32 {
        self.inner.mask
    }

    /// Zero-copy iterator over the TL-data linked list.
    #[must_use]
    pub fn tl_data(&self) -> TlDataIter<'a> {
        // SAFETY: tl_data is valid for 'a as it is part of self.inner.
        unsafe { TlDataIter::from_raw(self.inner.tl_data) }
    }

    /// Find the first TL-data record with the given type.
    #[must_use]
    pub fn find_tl_data(&self, ty: TlDataType) -> Option<TlDataRef<'a>> {
        let want = ty.as_u16();
        self.tl_data().find(|r| r.ty == want)
    }

    /// Zero-copy slice view over the `key_data` array.
    #[must_use]
    pub fn key_data(&self) -> KeyDataSlice<'a> {
        // SAFETY: key_data is valid for 'a; n_key_data gives the element count.
        // n_key_data is i16; non-negative values are the valid range.
        unsafe {
            KeyDataSlice::from_raw(
                self.inner.key_data,
                usize::try_from(self.inner.n_key_data).unwrap_or(0),
            )
        }
    }

    /// Return the raw const pointer to the entry.
    /// Used internally by `context.rs` and `glue.rs`.
    pub(crate) fn as_raw(self) -> *const kdb_sys::krb5_db_entry {
        std::ptr::from_ref(self.inner)
    }

    /// Extra data slice (`e_data`), if present.
    #[must_use]
    pub fn e_data(&self) -> &'a [u8] {
        if self.inner.e_length == 0 || self.inner.e_data.is_null() {
            return &[];
        }
        // SAFETY: e_data points to e_length bytes valid for 'a.
        unsafe {
            std::slice::from_raw_parts(
                self.inner.e_data,
                self.inner.e_length as usize,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// OwnedPrincipal — owned krb5_principal name
// ---------------------------------------------------------------------------

/// An owned Kerberos principal name that can be embedded in a [`PrincipalEntry`].
///
/// Wraps a `*mut krb5_principal_data` allocated by `krb5_parse_name`.
/// On drop, releases the principal with `krb5_free_principal` using the
/// stored context.  When ownership is transferred to C via `into_raw`,
/// `mem::forget` is called so the destructor does not run.
pub struct OwnedPrincipal {
    ctx: kdb_sys::krb5_context,
    ptr: NonNull<kdb_sys::krb5_principal_data>,
}

impl OwnedPrincipal {
    /// Consume and return the raw pointer, transferring ownership to C.
    pub(crate) fn into_raw(self) -> NonNull<kdb_sys::krb5_principal_data> {
        let ptr = self.ptr;
        std::mem::forget(self);
        ptr
    }

    /// Wrap a raw pointer, taking ownership.
    ///
    /// # Safety (caller — `context.rs`)
    ///
    /// `ctx` must remain valid for the lifetime of this value.
    /// `ptr` must be non-null, freshly allocated by `krb5_parse_name` or
    /// equivalent, and not already owned elsewhere.
    pub(crate) unsafe fn from_raw(
        ctx: kdb_sys::krb5_context,
        ptr: NonNull<kdb_sys::krb5_principal_data>,
    ) -> Self {
        debug_assert!(!ctx.is_null());
        OwnedPrincipal { ctx, ptr }
    }

    /// Borrow as a `PrincipalRef`.
    #[must_use]
    pub fn as_ref(&self) -> PrincipalRef<'_> {
        // SAFETY: self.ptr is valid for the lifetime of self.
        unsafe { PrincipalRef::from_raw(self.ptr.as_ptr()) }
    }
}

impl Drop for OwnedPrincipal {
    fn drop(&mut self) {
        // SAFETY: ctx and ptr are valid; ptr was allocated by krb5_parse_name.
        // This path is taken only when ownership was NOT transferred to C
        // (into_raw calls mem::forget to prevent this drop).
        unsafe { kdb_sys::krb5_free_principal(self.ctx, self.ptr.as_ptr()) };
    }
}

// ---------------------------------------------------------------------------
// PrincipalEntry — owned krb5_db_entry
// ---------------------------------------------------------------------------

/// An owned principal database entry, suitable for returning from
/// [`KdbModule::get_principal`](crate::KdbModule::get_principal).
///
/// Backed by a `NonNull<krb5_db_entry>` allocated with the system allocator
/// (which is the same allocator krb5 uses on POSIX, per `kdb.h`).
/// When libkdb5 takes ownership via `into_raw`, it will
/// eventually free the entry with `krb5_db_free_principal`, which uses
/// `free()` on all embedded pointers.
pub struct PrincipalEntry {
    ptr: NonNull<kdb_sys::krb5_db_entry>,
}

impl PrincipalEntry {
    /// Allocate a new, zeroed principal entry.
    ///
    /// # Panics
    ///
    /// Panics if the system allocator cannot allocate memory for the entry.
    #[must_use]
    pub fn new() -> Self {
        // SAFETY: calloc returns zeroed memory; the resulting struct is a
        // valid all-zeroes krb5_db_entry (no invalid enum variants in C).
        let ptr = unsafe {
            libc::calloc(1, std::mem::size_of::<kdb_sys::krb5_db_entry>())
                .cast::<kdb_sys::krb5_db_entry>()
        };
        let Some(ptr) = NonNull::new(ptr) else {
            std::alloc::handle_alloc_error(std::alloc::Layout::new::<
                kdb_sys::krb5_db_entry,
            >());
        };
        // Set the magic number that libkdb5 checks.
        // KRB5_KDB_MAGIC_NUMBER is u32 but magic is krb5_magic = i32; reinterpret bits.
        unsafe {
            (*ptr.as_ptr()).magic = i32::from_ne_bytes(
                kdb_sys::KRB5_KDB_MAGIC_NUMBER.to_ne_bytes(),
            );
        }
        // Set len to KRB5_KDB_V1_BASE_LENGTH: libkrb5 rejects entries with
        // a smaller value as KRB5_KDB_TRUNCATED_RECORD ("Database record is
        // incomplete or corrupted").
        // KRB5_KDB_V1_BASE_LENGTH = 38; always fits in u16.
        unsafe {
            (*ptr.as_ptr()).len =
                u16::try_from(kdb_sys::KRB5_KDB_V1_BASE_LENGTH).unwrap();
        }
        PrincipalEntry { ptr }
    }

    // -- Builder setters --------------------------------------------------

    /// Set the principal name.  Takes ownership of `princ`.
    ///
    /// If the entry already holds a principal name, it is freed with
    /// `krb5_free_principal` before the new one is installed.
    pub fn set_princ(
        &mut self,
        ctx: &KdbContext<'_>,
        princ: OwnedPrincipal,
    ) -> &mut Self {
        // SAFETY: we own self.ptr and the embedded princ field.
        let old = unsafe { (*self.ptr.as_ptr()).princ };
        if !old.is_null() {
            // SAFETY: old was allocated by krb5 and is owned by this entry.
            unsafe { kdb_sys::krb5_free_principal(ctx.as_raw(), old) };
        }
        unsafe { (*self.ptr.as_ptr()).princ = princ.into_raw().as_ptr() };
        self
    }

    /// Set the attribute flags.
    pub fn set_attributes(&mut self, attrs: PrincipalAttributes) -> &mut Self {
        // attributes is krb5_flags = i32; reinterpret bits from the u32 flag value.
        unsafe {
            (*self.ptr.as_ptr()).attributes =
                i32::from_ne_bytes(attrs.bits().to_ne_bytes());
        }
        self
    }

    /// Set the maximum ticket lifetime (seconds).
    pub fn set_max_life(&mut self, v: i32) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively
        // owned; the write targets a valid field within the krb5_db_entry.
        unsafe { (*self.ptr.as_ptr()).max_life = v };
        self
    }

    /// Set the maximum renewable lifetime (seconds).
    pub fn set_max_renewable_life(&mut self, v: i32) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).max_renewable_life = v };
        self
    }

    /// Set the principal expiration timestamp (0 = never expires).
    pub fn set_expiration(&mut self, t: Timestamp) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).expiration = t.0 };
        self
    }

    /// Set the password expiration timestamp (0 = never expires).
    pub fn set_pw_expiration(&mut self, t: Timestamp) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).pw_expiration = t.0 };
        self
    }

    /// Set the last-success timestamp.
    pub fn set_last_success(&mut self, t: Timestamp) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).last_success = t.0 };
        self
    }

    /// Set the last-failed timestamp.
    pub fn set_last_failed(&mut self, t: Timestamp) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).last_failed = t.0 };
        self
    }

    /// Set the failed-auth count.
    pub fn set_fail_auth_count(&mut self, n: u32) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).fail_auth_count = n };
        self
    }

    /// Set the entry format version / base-length field.
    ///
    /// [`PrincipalEntry::new`] initialises this to `KRB5_KDB_V1_BASE_LENGTH`
    /// (38).  Use this setter if the caller needs to record the actual
    /// serialised size of the entry (e.g. when building entries whose on-disk
    /// representation differs from the base size).
    pub fn set_len(&mut self, v: u16) -> &mut Self {
        // SAFETY: self.ptr is non-null (NonNull invariant) and exclusively owned.
        unsafe { (*self.ptr.as_ptr()).len = v };
        self
    }

    /// Attach TL-data.  Replaces any previously set TL-data.
    ///
    /// Ownership of the linked list is transferred to the entry.
    pub fn set_tl_data<P: TlDataFreePolicy>(
        &mut self,
        list: OwnedTlDataList<P>,
    ) -> &mut Self {
        // Null out the stored pointer *before* freeing the old list so that if
        // list.into_raw() aborts (OOM) the Drop impl cannot see a dangling
        // pointer.
        let old_tl = unsafe { (*self.ptr.as_ptr()).tl_data };
        unsafe {
            (*self.ptr.as_ptr()).tl_data = std::ptr::null_mut();
            (*self.ptr.as_ptr()).n_tl_data = 0;
        }
        if !old_tl.is_null() {
            // SAFETY: GenericFree::free walks the list freeing each node's
            // contents and then the node itself via libc::free.
            unsafe { GenericFree::free(old_tl) };
        }
        let (head, count) = list.into_raw();
        unsafe {
            (*self.ptr.as_ptr()).tl_data = head;
            (*self.ptr.as_ptr()).n_tl_data = count;
        }
        self
    }

    /// Attach key data.  Replaces any previously set key data.
    pub fn set_key_data(&mut self, builder: KeyDataBuilder) -> &mut Self {
        // Null out the stored pointer *before* freeing the old array so that if
        // builder.into_raw() aborts (OOM) the Drop impl cannot see a dangling
        // pointer.
        let old_kd = unsafe { (*self.ptr.as_ptr()).key_data };
        let old_count =
            usize::try_from(unsafe { (*self.ptr.as_ptr()).n_key_data })
                .unwrap_or(0);
        unsafe {
            (*self.ptr.as_ptr()).key_data = std::ptr::null_mut();
            (*self.ptr.as_ptr()).n_key_data = 0;
        }
        if !old_kd.is_null() && old_count > 0 {
            for i in 0..old_count {
                // SAFETY: krb5_dbe_free_key_data_contents does not use the
                // context parameter; null is safe here.
                unsafe {
                    kdb_sys::krb5_dbe_free_key_data_contents(
                        std::ptr::null_mut(),
                        old_kd.add(i),
                    );
                };
            }
            unsafe { libc::free(old_kd.cast::<libc::c_void>()) };
        }
        let (ptr, count) = builder.into_raw();
        unsafe {
            (*self.ptr.as_ptr()).key_data = ptr;
            (*self.ptr.as_ptr()).n_key_data = count;
        }
        self
    }

    /// Borrow as a `PrincipalEntryRef` for read-back / inspection.
    #[must_use]
    pub fn as_ref(&self) -> PrincipalEntryRef<'_> {
        // SAFETY: self.ptr is valid for the lifetime of self.
        unsafe { PrincipalEntryRef::from_raw(self.ptr.as_ptr()) }
    }

    /// Return the raw const pointer.  Used by `context.rs` utility wrappers.
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> *const kdb_sys::krb5_db_entry {
        self.ptr.as_ptr()
    }

    /// Return the raw mutable pointer.  Used by `context.rs` utility wrappers.
    #[allow(dead_code)]
    pub(crate) fn as_raw_mut(&mut self) -> *mut kdb_sys::krb5_db_entry {
        self.ptr.as_ptr()
    }

    /// Return the raw pointer with non-null guarantee.
    #[allow(dead_code)]
    pub(crate) fn as_non_null(&mut self) -> NonNull<kdb_sys::krb5_db_entry> {
        self.ptr
    }

    /// Wrap a raw `krb5_db_entry` pointer returned by a backing KDB call.
    ///
    /// # Safety (caller — `backing_db.rs`)
    ///
    /// `ptr` must be allocated by the backing KDB module via the
    /// system allocator, and not already owned by Rust or C.  All embedded
    /// pointers must also be system-malloc'd (klmdb guarantees this).
    pub(crate) unsafe fn from_raw(
        ptr: NonNull<kdb_sys::krb5_db_entry>,
    ) -> Self {
        PrincipalEntry { ptr }
    }

    /// Consume and return the raw pointer, transferring ownership to C.
    ///
    /// After this call the Rust value is gone and libkdb5 owns the memory.
    /// `krb5_db_free_principal` will free all embedded structures.
    pub(crate) fn into_raw(self) -> NonNull<kdb_sys::krb5_db_entry> {
        let ptr = self.ptr;
        std::mem::forget(self);
        ptr
    }
}

impl Default for PrincipalEntry {
    fn default() -> Self {
        PrincipalEntry::new()
    }
}

impl Drop for PrincipalEntry {
    fn drop(&mut self) {
        // Free embedded structures.  For types with canonical libkdb5 free
        // functions that do not use the context parameter, call those directly.

        // Free principal name.
        let princ = unsafe { (*self.ptr.as_ptr()).princ };
        if !princ.is_null() {
            // Free each component's data, then the data array, then the struct.
            let ncomp =
                usize::try_from(unsafe { (*princ).length }).unwrap_or(0);
            let comps = unsafe { (*princ).data };
            if !comps.is_null() {
                for i in 0..ncomp {
                    let comp = unsafe { &*comps.add(i) };
                    if !comp.data.is_null() {
                        unsafe {
                            libc::free(comp.data.cast::<libc::c_void>());
                        }
                    }
                }
                unsafe {
                    libc::free(comps.cast::<libc::c_void>());
                }
            }
            let realm = unsafe { &(*princ).realm };
            if !realm.data.is_null() {
                unsafe { libc::free(realm.data.cast::<libc::c_void>()) };
            }
            unsafe { libc::free(princ.cast::<libc::c_void>()) };
        }

        // Free TL-data list via GenericFree (libc::free walk).
        // krb5_dbe_free_tl_data is declared in kdb.h but not exported by
        // libkdb5.so in krb5 ≤ 1.22.x; the libc walk is equivalent on POSIX.
        // SAFETY: tl_data is either null (GenericFree::free is a no-op for
        // null) or a valid linked list allocated by libc::malloc.
        unsafe { GenericFree::free((*self.ptr.as_ptr()).tl_data) };

        // Free key data via the canonical kdb5 function (context unused).
        let kd = unsafe { (*self.ptr.as_ptr()).key_data };
        let kd_count =
            usize::try_from(unsafe { (*self.ptr.as_ptr()).n_key_data })
                .unwrap_or(0);
        if !kd.is_null() && kd_count > 0 {
            for i in 0..kd_count {
                // SAFETY: krb5_dbe_free_key_data_contents does not use context.
                unsafe {
                    kdb_sys::krb5_dbe_free_key_data_contents(
                        std::ptr::null_mut(),
                        kd.add(i),
                    );
                };
            }
            unsafe { libc::free(kd.cast::<libc::c_void>()) };
        }

        // Free e_data.
        let e_data = unsafe { (*self.ptr.as_ptr()).e_data };
        if !e_data.is_null() {
            unsafe { libc::free(e_data.cast::<libc::c_void>()) };
        }

        // Free the entry struct itself.
        unsafe { libc::free(self.ptr.as_ptr().cast::<libc::c_void>()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_entry_defaults() {
        let e = PrincipalEntry::new();
        let r = e.as_ref();
        assert_eq!(r.len(), kdb_sys::KRB5_KDB_V1_BASE_LENGTH as u16);
        assert_eq!(r.attributes(), PrincipalAttributes::empty());
        assert_eq!(r.max_life(), 0);
        assert_eq!(r.expiration(), Timestamp::ZERO);
        assert!(r.tl_data().next().is_none());
        assert!(r.key_data().is_empty());
    }

    #[test]
    fn set_and_read_scalars() {
        let mut e = PrincipalEntry::new();
        e.set_attributes(PrincipalAttributes::REQUIRES_PRE_AUTH)
            .set_max_life(86400)
            .set_expiration(Timestamp(9999999));
        let r = e.as_ref();
        assert!(
            r.attributes()
                .contains(PrincipalAttributes::REQUIRES_PRE_AUTH)
        );
        assert_eq!(r.max_life(), 86400);
        assert_eq!(r.expiration(), Timestamp(9999999));
    }

    #[test]
    fn tl_data_round_trip() {
        let mut b = crate::tl_data::TlDataBuilder::new();
        b.push(TlDataType::StringAttrs, b"k1\0v1\0".to_vec());
        let mut e = PrincipalEntry::new();
        e.set_tl_data(b.build());
        let r = e.as_ref();
        let tl: Vec<_> = r.tl_data().collect();
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].ty, TlDataType::StringAttrs.as_u16());
        assert_eq!(tl[0].data, b"k1\0v1\0");
    }
}
