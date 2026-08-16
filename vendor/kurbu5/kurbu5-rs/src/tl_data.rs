//! Generic `krb5_tl_data` views, builder, and owned list.
//!
//! `krb5_tl_data` is used across the KDB, KADM5, and other Kerberos
//! subsystems.  This module provides:
//!
//! - Zero-copy read types ([`TlDataRef`], [`TlDataIter`])
//! - An owned builder ([`TlDataBuilder`]) that produces [`TlDataList`]
//! - A parameterised owned-list type ([`OwnedTlDataList`]) whose [`Drop`]
//!   implementation is controlled by a [`TlDataFreePolicy`] marker
//!
//! # Free policies
//!
//! The default policy ([`GenericFree`]) walks the list with `libc::free`,
//! which is correct on POSIX/glibc systems where both Rust's allocator and
//! MIT Kerberos use the same underlying `malloc`.  Subsystems that need a
//! distinct free policy define their own [`TlDataFreePolicy`] implementor in
//! the relevant crate (e.g. `KdbFree` in `kurbu5-kdb-rs`, which currently
//! delegates to `GenericFree` because `krb5_dbe_free_tl_data` is declared in
//! `kdb.h` but not exported by `libkdb5.so` in krb5 ≤ 1.22.x).

use std::marker::PhantomData;

use kurbu5_sys as sys;

// ---------------------------------------------------------------------------
// Zero-copy read view
// ---------------------------------------------------------------------------

/// A zero-copy reference to one node in a `krb5_tl_data` linked list.
///
/// The lifetime `'a` is tied to the C-owned memory holding the list.
#[derive(Debug, Clone, Copy)]
pub struct TlDataRef<'a> {
    /// The raw tag (`tl_data_type`).
    pub ty: u16,
    /// The raw bytes of this TL-data record.
    pub data: &'a [u8],
}

// ---------------------------------------------------------------------------
// Zero-copy iterator
// ---------------------------------------------------------------------------

/// An iterator over a `krb5_tl_data` linked list.
///
/// Constructed from the owning entry's `tl_data()` accessor.
/// Does not allocate.
pub struct TlDataIter<'a> {
    current: *const sys::krb5_tl_data,
    _phantom: PhantomData<&'a sys::krb5_tl_data>,
}

impl TlDataIter<'_> {
    /// Construct an iterator from a raw pointer to the list head.
    ///
    /// # Safety
    ///
    /// `ptr` must be null (empty list) or point to a valid `krb5_tl_data`
    /// node that lives for at least `'a`.
    #[must_use]
    pub unsafe fn from_raw(ptr: *const sys::krb5_tl_data) -> Self {
        TlDataIter {
            current: ptr,
            _phantom: PhantomData,
        }
    }

    /// Return a null (empty) iterator.
    #[must_use]
    pub fn empty() -> Self {
        TlDataIter {
            current: std::ptr::null(),
            _phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for TlDataIter<'a> {
    type Item = TlDataRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }
        // SAFETY: checked for null; valid for 'a per from_raw() invariant.
        let node = unsafe { &*self.current };
        let data =
            if node.tl_data_length == 0 || node.tl_data_contents.is_null() {
                &[][..]
            } else {
                // SAFETY: tl_data_contents is valid for tl_data_length bytes.
                unsafe {
                    std::slice::from_raw_parts(
                        node.tl_data_contents,
                        node.tl_data_length as usize,
                    )
                }
            };
        let item = TlDataRef {
            ty: node.tl_data_type.cast_unsigned(),
            data,
        };
        self.current = node.tl_data_next;
        Some(item)
    }
}

// ---------------------------------------------------------------------------
// Free policy trait
// ---------------------------------------------------------------------------

/// Controls how an [`OwnedTlDataList`] is freed on drop.
///
/// # Safety
///
/// Implementors must free `head` and every node reachable via
/// `tl_data_next`, plus each `tl_data_contents` buffer, exactly once,
/// using allocator-compatible free calls.  The function must be a no-op
/// when `head` is null.
pub unsafe trait TlDataFreePolicy: Send + 'static {
    /// Free the linked list starting at `head`.
    ///
    /// # Safety
    ///
    /// `head` must be null or point to a valid `krb5_tl_data` linked list
    /// whose nodes and `tl_data_contents` buffers were allocated with the
    /// system allocator.  The caller must not access `head` after this call.
    unsafe fn free(head: *mut sys::krb5_tl_data);
}

// ---------------------------------------------------------------------------
// Owned list
// ---------------------------------------------------------------------------

/// An owned `krb5_tl_data` linked list whose drop behaviour is controlled
/// by the free policy `P`.
///
/// Use [`TlDataList`] (= `OwnedTlDataList<GenericFree>`) in generic,
/// KADM5, and KDB contexts.  KDB code may also use `KdbTlDataList` from
/// `kurbu5-kdb-rs` as a distinct marker type, though its drop behaviour is
/// currently identical to `TlDataList`.
pub struct OwnedTlDataList<P: TlDataFreePolicy> {
    head: *mut sys::krb5_tl_data,
    count: i16,
    _policy: PhantomData<P>,
}

// SAFETY: OwnedTlDataList has exclusive ownership of the pointer.
unsafe impl<P: TlDataFreePolicy> Send for OwnedTlDataList<P> {}

impl<P: TlDataFreePolicy> Drop for OwnedTlDataList<P> {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: sole owner; no borrows can exist in drop.
            unsafe { P::free(self.head) };
            self.head = std::ptr::null_mut();
        }
    }
}

impl<P: TlDataFreePolicy> OwnedTlDataList<P> {
    /// The number of records in the list.
    #[must_use]
    pub fn len(&self) -> i16 {
        self.count
    }

    /// Return `true` if the list contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over records without consuming the list.
    #[must_use]
    pub fn iter(&self) -> TlDataIter<'_> {
        // SAFETY: self.head is valid for the lifetime of self.
        unsafe { TlDataIter::from_raw(self.head) }
    }

    /// Extract the raw head pointer and count, transferring ownership to C.
    ///
    /// The list's `Drop` impl will **not** run.  The caller must free the
    /// list via the appropriate C function.
    #[must_use]
    pub fn into_raw(self) -> (*mut sys::krb5_tl_data, i16) {
        let (head, count) = (self.head, self.count);
        std::mem::forget(self);
        (head, count)
    }

    /// Convert to a different free policy without reallocating.
    ///
    /// Useful when transferring ownership to a subsystem with its own
    /// canonical free function.
    #[must_use]
    pub fn with_policy<Q: TlDataFreePolicy>(self) -> OwnedTlDataList<Q> {
        let (head, count) = self.into_raw();
        OwnedTlDataList {
            head,
            count,
            _policy: PhantomData,
        }
    }
}

impl<'a, P: TlDataFreePolicy> IntoIterator for &'a OwnedTlDataList<P> {
    type Item = TlDataRef<'a>;
    type IntoIter = TlDataIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// ---------------------------------------------------------------------------
// Default free policy — libc::free walk
// ---------------------------------------------------------------------------

/// Default free policy: walk the list freeing each node with `libc::free`.
///
/// Correct on POSIX/glibc systems (Rust's allocator and MIT Kerberos both
/// use glibc `malloc`).  Suitable for generic, KADM5, and KDB contexts.
///
/// `KdbFree` in `kurbu5-kdb-rs` delegates to this implementation because
/// `krb5_dbe_free_tl_data` (the canonical KDB free function) is declared in
/// `kdb.h` but is not exported by `libkdb5.so` in krb5 ≤ 1.22.x.
pub struct GenericFree;

// SAFETY: frees tl_data_contents and each node via libc::free; no-op on
// null; entire list freed exactly once.
unsafe impl TlDataFreePolicy for GenericFree {
    unsafe fn free(mut cur: *mut sys::krb5_tl_data) {
        while !cur.is_null() {
            let next = (*cur).tl_data_next;
            let contents = (*cur).tl_data_contents;
            if !contents.is_null() {
                libc::free(contents.cast::<libc::c_void>());
            }
            libc::free(cur.cast::<libc::c_void>());
            cur = next;
        }
    }
}

/// Owned `krb5_tl_data` list for generic and KADM5 contexts.
///
/// Freed with [`GenericFree`] (`libc::free` walk) on drop.  In KDB contexts
/// use `KdbTlDataList` from `kurbu5-kdb-rs` instead.
pub type TlDataList = OwnedTlDataList<GenericFree>;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `krb5_tl_data` linked list.
///
/// Call [`push`](Self::push) for each record, then [`build`](Self::build)
/// to produce a [`TlDataList`].
///
/// # Example
///
/// ```rust,ignore
/// use kurbu5_rs::tl_data::TlDataBuilder;
///
/// let mut b = TlDataBuilder::new();
/// b.push(0x000b_u16, b"source\0example\0".to_vec()); // StringAttrs = 0x000b
/// let list = b.build();
/// ```
#[derive(Debug, Default)]
pub struct TlDataBuilder {
    nodes: Vec<TlDataNode>,
}

#[derive(Debug)]
struct TlDataNode {
    ty: u16,
    data: Vec<u8>,
}

impl TlDataBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        TlDataBuilder::default()
    }

    /// Append a TL-data record.
    ///
    /// `ty` accepts a raw `u16` or any type implementing `Into<u16>` (e.g.
    /// `TlDataType` from `kurbu5-kdb-rs`).
    pub fn push(
        &mut self,
        ty: impl Into<u16>,
        data: impl Into<Vec<u8>>,
    ) -> &mut Self {
        self.nodes.push(TlDataNode {
            ty: ty.into(),
            data: data.into(),
        });
        self
    }

    /// Return the number of records added so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` if no records have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Consume the builder and produce a [`TlDataList`].
    ///
    /// # Memory layout
    ///
    /// Each `krb5_tl_data` node is `Box`-allocated (system/glibc allocator).
    /// Each `tl_data_contents` buffer is `libc::malloc`'d.
    ///
    /// # Panics
    ///
    /// Panics if the number of records exceeds `i16::MAX` (32767), or if any
    /// record's data length exceeds `u16::MAX` (65535).  Calls
    /// [`std::alloc::handle_alloc_error`] (process abort, not panic) on
    /// allocation failure.
    #[must_use]
    pub fn build(self) -> TlDataList {
        let count = i16::try_from(self.nodes.len())
            .expect("TL-data record count fits in i16");
        let mut next: *mut sys::krb5_tl_data = std::ptr::null_mut();
        for node in self.nodes.into_iter().rev() {
            let contents_ptr = if node.data.is_empty() {
                std::ptr::null_mut()
            } else {
                let len = node.data.len();
                // SAFETY: malloc with size > 0; null on OOM.
                let ptr = unsafe { libc::malloc(len).cast::<u8>() };
                if ptr.is_null() {
                    std::alloc::handle_alloc_error(
                        std::alloc::Layout::array::<u8>(len).unwrap(),
                    );
                }
                // SAFETY: ptr points to `len` writable bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        node.data.as_ptr(),
                        ptr,
                        len,
                    );
                }
                ptr
            };
            let tl_data_length = u16::try_from(node.data.len())
                .expect("TL-data record length fits in u16");
            let tl = Box::new(sys::krb5_tl_data {
                tl_data_next: next,
                tl_data_type: node.ty.cast_signed(),
                tl_data_length,
                tl_data_contents: contents_ptr,
            });
            next = Box::into_raw(tl);
        }
        OwnedTlDataList {
            head: next,
            count,
            _policy: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_preserves_order() {
        let mut b = TlDataBuilder::new();
        b.push(0x0001_u16, vec![1, 2, 3]); // LastPwdChange
        b.push(0x0002_u16, vec![4, 5]); // ModPrinc
        assert_eq!(b.len(), 2);
        assert!(!b.is_empty());
    }

    #[test]
    fn empty_builder() {
        let b = TlDataBuilder::new();
        assert!(b.is_empty());
        let list = b.build();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(list.iter().next().is_none());
    }

    #[test]
    fn single_record_round_trip() {
        let mut b = TlDataBuilder::new();
        b.push(0x000b_u16, b"hello".to_vec()); // StringAttrs
        let list = b.build();
        assert_eq!(list.len(), 1);
        let records: Vec<_> = list.iter().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ty, 0x000b);
        assert_eq!(records[0].data, b"hello");
    }

    #[test]
    fn multi_record_order() {
        let mut b = TlDataBuilder::new();
        b.push(0x0001_u16, vec![10]);
        b.push(0x0002_u16, vec![20]);
        b.push(0x0003_u16, vec![30]);
        let list = b.build();
        let records: Vec<_> = list.iter().collect();
        assert_eq!(records[0].ty, 0x0001);
        assert_eq!(records[1].ty, 0x0002);
        assert_eq!(records[2].ty, 0x0003);
    }

    #[test]
    fn with_policy_converts() {
        let mut b = TlDataBuilder::new();
        b.push(0x0001_u16, vec![1]);
        let list: TlDataList = b.build();
        // with_policy does not reallocate; just changes the drop behaviour.
        let list2: OwnedTlDataList<GenericFree> =
            list.with_policy::<GenericFree>();
        assert_eq!(list2.len(), 1);
    }
}
