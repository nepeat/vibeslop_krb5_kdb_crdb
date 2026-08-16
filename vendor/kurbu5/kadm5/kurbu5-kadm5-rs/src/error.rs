//! Shared error type for all `kurbu5-kadm5-rs` plugin interfaces.
//!
//! There is a single `krb5_error_code` integer space in MIT Kerberos shared
//! across all plugin interfaces (KDB, preauth, kadm5, localauth …).  Rather
//! than maintaining a parallel definition here, we re-export the canonical
//! [`Krb5Error`] from `kurbu5-rs` so that KADM5 plugins can pass errors
//! across crate boundaries without a lossy integer round-trip.

pub use kurbu5_rs::Krb5Error;
