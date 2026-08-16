//! KDB plugin API — re-exports all types and functions from [`kurbu5_sys`] and
//! ensures the `kdb5` shared library is linked.
//!
//! Downstream crates (`kurbu5-kdb-rs`, plugin crates) depend on this crate rather
//! than `kurbu5-sys` directly when they specifically implement KDB plugins.
//! Crates that need only the base libkrb5 API (e.g. future GSSAPI plugin
//! frameworks) can depend on `kurbu5-sys` directly without pulling in the KDB
//! linkage.

// Re-export everything from kurbu5-sys so that code depending on kurbu5-kdb-sys gets
// all libkrb5 + KDB types through a single dependency.
pub use kurbu5_sys::*;
