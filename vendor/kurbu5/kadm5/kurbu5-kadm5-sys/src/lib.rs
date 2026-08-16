//! KADM5 plugin API re-export — thin wrapper over kurbu5-sys adding
//! `libkadm5srv_mit` linkage.
//!
//! This crate re-exports all types and functions from [`kurbu5_sys`], which
//! includes the KADM5 plugin vtable structs (`kadm5_auth_vtable_st`,
//! `kadm5_hook_vtable_1_st`), the principal entry type
//! (`_kadm5_principal_ent_t`), and the full `krb5_*` type set.
//!
//! Downstream crates (`kurbu5-kadm5-rs`, KADM5 plugin crates) depend on this
//! crate rather than `kurbu5-sys` directly when they implement KADM5 plugins.
//! The `links = "kadm5srv_mit"` field ensures that exactly one crate emits
//! the `libkadm5srv_mit` link directive per compilation unit.
//!
//! # Safety
//!
//! All items in this crate are `unsafe` by nature — they are raw C types and
//! function pointers.  Plugin authors should use `kurbu5-kadm5-rs` which
//! provides safe wrappers.

// Re-export everything from kurbu5-sys so that code depending on
// kurbu5-kadm5-sys gets all libkrb5 + KADM5 types through a single dep.
pub use kurbu5_sys::*;
