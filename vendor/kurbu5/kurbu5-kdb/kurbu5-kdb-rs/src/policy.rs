//! Zero-copy views and owned types for `osa_policy_ent_rec` password policies.

use crate::tl_data::{TlDataBuilder, TlDataIter};
use std::ffi::CStr;

// ---------------------------------------------------------------------------
// Zero-copy read view
// ---------------------------------------------------------------------------

/// A zero-copy reference to a `osa_policy_ent_rec` password policy entry.
///
/// Borrowing from C-allocated memory for duration `'a`.
#[derive(Debug, Clone, Copy)]
pub struct PolicyEntryRef<'a> {
    inner: &'a kdb_sys::osa_policy_ent_rec,
}

impl<'a> PolicyEntryRef<'a> {
    /// Construct from a raw pointer.
    ///
    /// # Safety (caller — `glue.rs`)
    ///
    /// `ptr` must be non-null and valid for `'a`.
    pub(crate) unsafe fn from_raw(
        ptr: *const kdb_sys::osa_policy_ent_rec,
    ) -> Self {
        debug_assert!(!ptr.is_null());
        PolicyEntryRef { inner: &*ptr }
    }

    /// Policy name as a `str` (ASCII, null-terminated in C).
    #[must_use]
    pub fn name(&self) -> &'a str {
        if self.inner.name.is_null() {
            return "";
        }
        // SAFETY: name is a null-terminated C string valid for 'a.
        unsafe { CStr::from_ptr(self.inner.name).to_str().unwrap_or("") }
    }

    /// Minimum password lifetime (seconds).
    #[must_use]
    pub fn pw_min_life(&self) -> u32 {
        self.inner.pw_min_life
    }

    /// Maximum password lifetime (seconds).
    #[must_use]
    pub fn pw_max_life(&self) -> u32 {
        self.inner.pw_max_life
    }

    /// Minimum password length.
    #[must_use]
    pub fn pw_min_length(&self) -> u32 {
        self.inner.pw_min_length
    }

    /// Minimum number of character classes required.
    #[must_use]
    pub fn pw_min_classes(&self) -> u32 {
        self.inner.pw_min_classes
    }

    /// Password history depth.
    #[must_use]
    pub fn pw_history_num(&self) -> u32 {
        self.inner.pw_history_num
    }

    // Version > 1 fields.

    /// Maximum consecutive failures before lockout (0 = disabled).
    #[must_use]
    pub fn pw_max_fail(&self) -> u32 {
        if self.inner.version > 1 {
            self.inner.pw_max_fail
        } else {
            0
        }
    }

    /// Failure count reset interval (seconds; 0 = don't reset).
    #[must_use]
    pub fn pw_failcnt_interval(&self) -> u32 {
        if self.inner.version > 1 {
            self.inner.pw_failcnt_interval
        } else {
            0
        }
    }

    /// Lockout duration (seconds; 0 = permanent until admin unlock).
    #[must_use]
    pub fn pw_lockout_duration(&self) -> u32 {
        if self.inner.version > 1 {
            self.inner.pw_lockout_duration
        } else {
            0
        }
    }

    // Version > 2 fields.

    /// Policy-level attribute flags (version 3+).
    #[must_use]
    pub fn attributes(&self) -> u32 {
        if self.inner.version > 2 {
            self.inner.attributes
        } else {
            0
        }
    }

    /// Maximum ticket lifetime override (seconds; 0 = use realm default).
    #[must_use]
    pub fn max_life(&self) -> u32 {
        if self.inner.version > 2 {
            self.inner.max_life
        } else {
            0
        }
    }

    /// Maximum renewable lifetime override (seconds).
    #[must_use]
    pub fn max_renewable_life(&self) -> u32 {
        if self.inner.version > 2 {
            self.inner.max_renewable_life
        } else {
            0
        }
    }

    /// Allowed key-salt string, e.g. "aes256-cts:normal" (version 3+).
    #[must_use]
    pub fn allowed_keysalts(&self) -> Option<&'a str> {
        if self.inner.version <= 2 || self.inner.allowed_keysalts.is_null() {
            return None;
        }
        // SAFETY: allowed_keysalts is a null-terminated C string valid for 'a.
        unsafe {
            CStr::from_ptr(self.inner.allowed_keysalts)
                .to_str()
                .ok()
                .filter(|s| !s.is_empty())
        }
    }

    /// Iterate over the TL-data list embedded in the policy entry.
    #[must_use]
    pub fn tl_data(&self) -> TlDataIter<'a> {
        // SAFETY: tl_data is part of self.inner, valid for 'a.
        unsafe { TlDataIter::from_raw(self.inner.tl_data) }
    }
}

// ---------------------------------------------------------------------------
// Owned policy entry
// ---------------------------------------------------------------------------

/// An owned password policy entry, returned by
/// [`KdbModule::get_policy`](crate::KdbModule::get_policy) and passed to
/// `create_policy` / `put_policy`.
///
/// Version is always 3 (current maximum) when constructed by this API.
/// Older fields are always valid; version-gated fields default to 0/None.
#[derive(Debug, Clone)]
pub struct PolicyEntry {
    pub name: String,
    pub pw_min_life: u32,
    pub pw_max_life: u32,
    pub pw_min_length: u32,
    pub pw_min_classes: u32,
    pub pw_history_num: u32,
    // Version > 1
    pub pw_max_fail: u32,
    pub pw_failcnt_interval: u32,
    pub pw_lockout_duration: u32,
    // Version > 2
    pub attributes: u32,
    pub max_life: u32,
    pub max_renewable_life: u32,
    pub allowed_keysalts: Option<String>,
    // TL-data (rarely used for policies but supported by the API)
    tl_data: Vec<(u16, Vec<u8>)>,
}

impl PolicyEntry {
    /// Create a new, blank policy with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        PolicyEntry {
            name: name.into(),
            pw_min_life: 0,
            pw_max_life: 0,
            pw_min_length: 0,
            pw_min_classes: 0,
            pw_history_num: 0,
            pw_max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            allowed_keysalts: None,
            tl_data: vec![],
        }
    }

    /// Add a TL-data record.
    pub fn add_tl_data(&mut self, ty: u16, data: Vec<u8>) {
        self.tl_data.push((ty, data));
    }

    /// Iterate over the TL-data records, in insertion order.
    ///
    /// Symmetric with [`PolicyEntry::add_tl_data`]: backends that persist
    /// policies themselves need read access to round-trip TL-data.
    pub fn tl_data(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.tl_data.iter().map(|(ty, data)| (*ty, data.as_slice()))
    }

    /// Construct from a zero-copy view, copying all fields.
    pub fn from_ref(r: PolicyEntryRef<'_>) -> Self {
        let mut p = PolicyEntry::new(r.name());
        p.pw_min_life = r.pw_min_life();
        p.pw_max_life = r.pw_max_life();
        p.pw_min_length = r.pw_min_length();
        p.pw_min_classes = r.pw_min_classes();
        p.pw_history_num = r.pw_history_num();
        p.pw_max_fail = r.pw_max_fail();
        p.pw_failcnt_interval = r.pw_failcnt_interval();
        p.pw_lockout_duration = r.pw_lockout_duration();
        p.attributes = r.attributes();
        p.max_life = r.max_life();
        p.max_renewable_life = r.max_renewable_life();
        p.allowed_keysalts = r.allowed_keysalts().map(str::to_owned);
        p.tl_data = r.tl_data().map(|t| (t.ty, t.data.to_vec())).collect();
        p
    }

    /// Produce a heap-allocated `osa_policy_ent_rec` suitable for passing to
    /// libkdb5.  Returns `None` on OOM.  On `Some`, the caller (always
    /// `glue.rs`) must free it via `krb5_db_free_policy`.
    pub(crate) fn into_raw(self) -> Option<*mut kdb_sys::osa_policy_ent_rec> {
        use std::ffi::CString;

        // SAFETY: calloc returns zeroed memory; returns null on OOM.
        let ptr = unsafe {
            libc::calloc(1, std::mem::size_of::<kdb_sys::osa_policy_ent_rec>())
                .cast::<kdb_sys::osa_policy_ent_rec>()
        };
        if ptr.is_null() {
            return None;
        }

        let rec = unsafe { &mut *ptr };
        rec.version = 3;

        // Name — malloc'd C string.
        let cname = CString::new(self.name).unwrap_or_default();
        let name_bytes = cname.as_bytes_with_nul();
        let name_ptr =
            unsafe { libc::malloc(name_bytes.len()).cast::<libc::c_char>() };
        if name_ptr.is_null() {
            unsafe { libc::free(ptr.cast::<libc::c_void>()) };
            return None;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr().cast::<libc::c_char>(),
                name_ptr,
                name_bytes.len(),
            );
        };
        rec.name = name_ptr;

        rec.pw_min_life = self.pw_min_life;
        rec.pw_max_life = self.pw_max_life;
        rec.pw_min_length = self.pw_min_length;
        rec.pw_min_classes = self.pw_min_classes;
        rec.pw_history_num = self.pw_history_num;
        rec.pw_max_fail = self.pw_max_fail;
        rec.pw_failcnt_interval = self.pw_failcnt_interval;
        rec.pw_lockout_duration = self.pw_lockout_duration;
        rec.attributes = self.attributes;
        rec.max_life = self.max_life;
        rec.max_renewable_life = self.max_renewable_life;

        if let Some(ks) = self.allowed_keysalts {
            let cks = CString::new(ks).unwrap_or_default();
            let ks_bytes = cks.as_bytes_with_nul();
            let ks_ptr =
                unsafe { libc::malloc(ks_bytes.len()).cast::<libc::c_char>() };
            if ks_ptr.is_null() {
                // Free name and struct already allocated.
                unsafe {
                    libc::free(rec.name.cast::<libc::c_void>());
                    libc::free(ptr.cast::<libc::c_void>());
                }
                return None;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ks_bytes.as_ptr().cast::<libc::c_char>(),
                    ks_ptr,
                    ks_bytes.len(),
                );
            };
            rec.allowed_keysalts = ks_ptr;
        }

        // TL-data.
        if !self.tl_data.is_empty() {
            let mut builder = TlDataBuilder::new();
            for (ty, data) in self.tl_data {
                builder.push(ty, data);
            }
            let (head, count) = builder.build().into_raw();
            rec.tl_data = head;
            rec.n_tl_data = count;
        }

        Some(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_entry_defaults() {
        let p = PolicyEntry::new("testpol");
        assert_eq!(p.name, "testpol");
        assert_eq!(p.pw_min_life, 0);
        assert!(p.allowed_keysalts.is_none());
        assert!(p.tl_data.is_empty());
    }

    #[test]
    fn policy_entry_fields() {
        let mut p = PolicyEntry::new("pol");
        p.pw_min_length = 8;
        p.pw_max_life = 90 * 86400;
        p.allowed_keysalts = Some("aes256-cts:normal".into());
        assert_eq!(p.pw_min_length, 8);
        assert_eq!(p.allowed_keysalts.as_deref(), Some("aes256-cts:normal"));
    }
}
