//! KDB-layer re-exports and `KdbFree` policy for `krb5_tl_data`.
//!
//! The generic types ([`TlDataRef`], [`TlDataIter`], [`TlDataBuilder`],
//! [`TlDataList`], [`OwnedTlDataList`]) live in `kurbu5-rs` and are
//! re-exported here for convenience.
//!
//! This module adds [`KdbFree`] — a [`TlDataFreePolicy`] for KDB-layer owned
//! lists — and the [`KdbTlDataList`] alias for use inside KDB bridge code.

// Re-export the generic types so that users of `kurbu5-kdb-rs` can access
// everything from a single namespace.
pub use kurbu5_rs::tl_data::{
    GenericFree, OwnedTlDataList, TlDataBuilder, TlDataFreePolicy, TlDataIter,
    TlDataList, TlDataRef,
};

// ---------------------------------------------------------------------------
// KDB-specific free policy
// ---------------------------------------------------------------------------

/// Free policy for TL-data lists owned by the KDB layer.
///
/// `krb5_dbe_free_tl_data` is declared in `kdb.h` but is not exported by
/// `libkdb5.so` in current MIT Kerberos releases (as of 1.22.x).  We
/// therefore implement the same walk using `libc::free`, which is identical
/// in behaviour on POSIX/glibc systems (the kdb.h declaration simply calls
/// `free` on each node's contents and then on the node itself).  The type
/// exists as a distinct marker so that call sites can be updated to use the
/// canonical function if it is exported in a future release.
pub struct KdbFree;

// SAFETY: Identical to GenericFree — walks the linked list freeing
// tl_data_contents and then each node with libc::free.
unsafe impl TlDataFreePolicy for KdbFree {
    unsafe fn free(head: *mut kurbu5_sys::krb5_tl_data) {
        // krb5_dbe_free_tl_data is declared in kdb.h but not exported by
        // libkdb5.so in krb5 ≤ 1.22.x, so we use the equivalent libc walk.
        GenericFree::free(head);
    }
}

/// Owned `krb5_tl_data` list for use in KDB bridge code.
///
/// Lists produced by [`TlDataBuilder::build`] use [`TlDataList`]
/// ([`GenericFree`]); convert with [`OwnedTlDataList::with_policy`] if the
/// caller requires the KDB-layer type.
pub type KdbTlDataList = OwnedTlDataList<KdbFree>;
