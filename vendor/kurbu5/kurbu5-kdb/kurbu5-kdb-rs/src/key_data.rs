//! Zero-copy views and owned types for `krb5_key_data` arrays.

// ---------------------------------------------------------------------------
// Zero-copy read view
// ---------------------------------------------------------------------------

/// A zero-copy reference to one element of a `krb5_key_data` array.
///
/// Lifetime `'a` is bound to the `krb5_db_entry` that owns the array.
#[derive(Debug, Clone, Copy)]
pub struct KeyDataRef<'a> {
    inner: &'a kdb_sys::krb5_key_data,
}

impl<'a> KeyDataRef<'a> {
    /// Construct from a reference.  Called only from within this crate.
    pub(crate) fn from_ref(kd: &'a kdb_sys::krb5_key_data) -> Self {
        KeyDataRef { inner: kd }
    }

    /// Key version number.
    #[must_use]
    pub fn kvno(&self) -> u16 {
        self.inner.key_data_kvno
    }

    /// Encryption type of the key material.
    #[must_use]
    pub fn enctype(&self) -> i16 {
        self.inner.key_data_type[0]
    }

    /// Salt type (meaningful only when `key_data_ver == 2`).
    #[must_use]
    pub fn salttype(&self) -> i16 {
        self.inner.key_data_type[1]
    }

    /// Raw `key_data_ver`: 1 = key only, 2 = key + salt slot.
    ///
    /// Needed to distinguish a v2 key with a zero-length salt from a v1
    /// key — `salt_bytes()` returns empty for both.
    #[must_use]
    pub fn key_data_ver(&self) -> i16 {
        self.inner.key_data_ver
    }

    /// Whether a salt slot is present (`key_data_ver >= 2`), independent
    /// of the salt being empty.
    #[must_use]
    pub fn has_salt(&self) -> bool {
        self.inner.key_data_ver >= 2
    }

    /// Raw (encrypted) key bytes.
    #[must_use]
    pub fn key_bytes(&self) -> &'a [u8] {
        let len = self.inner.key_data_length[0] as usize;
        if len == 0 || self.inner.key_data_contents[0].is_null() {
            return &[];
        }
        // SAFETY: key_data_contents[0] points to key_data_length[0] bytes
        // allocated alongside the entry; valid for lifetime 'a.
        unsafe {
            std::slice::from_raw_parts(self.inner.key_data_contents[0], len)
        }
    }

    /// Raw salt bytes (empty if `key_data_ver < 2` or no salt stored).
    #[must_use]
    pub fn salt_bytes(&self) -> &'a [u8] {
        if self.inner.key_data_ver < 2 {
            return &[];
        }
        let len = self.inner.key_data_length[1] as usize;
        if len == 0 || self.inner.key_data_contents[1].is_null() {
            return &[];
        }
        // SAFETY: same as key_bytes().
        unsafe {
            std::slice::from_raw_parts(self.inner.key_data_contents[1], len)
        }
    }
}

// ---------------------------------------------------------------------------
// Slice view over the key_data array
// ---------------------------------------------------------------------------

/// A zero-copy view of the entire `key_data` array of a principal entry.
///
/// Keys are sorted by `kvno` in descending order (highest kvno first) as per
/// the contract in `kdb.h`.
#[derive(Debug, Clone, Copy)]
pub struct KeyDataSlice<'a> {
    slice: &'a [kdb_sys::krb5_key_data],
}

impl<'a> KeyDataSlice<'a> {
    /// Construct from a raw pointer and length.  Called only from `principal.rs`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to `len` consecutive valid `krb5_key_data` elements
    /// that live for at least `'a`.
    pub(crate) unsafe fn from_raw(
        ptr: *const kdb_sys::krb5_key_data,
        len: usize,
    ) -> Self {
        let slice = if ptr.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(ptr, len)
        };
        KeyDataSlice { slice }
    }

    /// Number of key data records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slice.len()
    }

    /// Return `true` if there are no key records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    /// Iterate over key data records.
    pub fn iter(&self) -> impl Iterator<Item = KeyDataRef<'a>> {
        self.slice.iter().map(KeyDataRef::from_ref)
    }

    /// Return the highest (most recent) key version number, if any.
    #[must_use]
    pub fn max_kvno(&self) -> Option<u16> {
        self.slice.first().map(|kd| kd.key_data_kvno)
    }
}

impl<'a> IntoIterator for KeyDataSlice<'a> {
    type Item = KeyDataRef<'a>;
    type IntoIter = KeyDataSliceIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        KeyDataSliceIter {
            inner: self.slice.iter(),
        }
    }
}

pub struct KeyDataSliceIter<'a> {
    inner: std::slice::Iter<'a, kdb_sys::krb5_key_data>,
}

impl<'a> Iterator for KeyDataSliceIter<'a> {
    type Item = KeyDataRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(KeyDataRef::from_ref)
    }
}

// ---------------------------------------------------------------------------
// Owned key types
// ---------------------------------------------------------------------------

/// An owned, decrypted keyblock (`krb5_keyblock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    /// Encryption type.
    pub enctype: i32,
    /// Raw key bytes.
    pub contents: Vec<u8>,
}

/// An owned key salt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySalt {
    /// Salt type.
    pub salttype: i32,
    /// Salt bytes (may be empty for implicit salts).
    pub data: Vec<u8>,
}

/// An owned, encoded `krb5_key_data` element (one key + optional salt),
/// allocated with C-compatible malloc so libkdb5 can free it.
///
/// Returned by [`KdbModule::encrypt_key_data`](crate::KdbModule::encrypt_key_data).
#[derive(Debug)]
pub struct KeyDataOwned {
    /// Whether salt data (`key_data` slot 1) is present.
    pub has_salt: bool,
    pub kvno: u16,
    pub enctype: i16,
    pub salttype: i16,
    /// Encrypted key bytes (malloc-allocated).
    pub key_bytes: Vec<u8>,
    /// Salt bytes (malloc-allocated; may be empty).
    pub salt_bytes: Vec<u8>,
}

impl KeyDataOwned {
    /// Write this key into a zeroed `krb5_key_data` struct.
    ///
    /// The caller is responsible for eventually freeing the contents via
    /// libkdb5 (`krb5_dbe_free_key_data_contents`).
    ///
    /// # Safety (caller — `glue.rs`)
    ///
    /// `kd` must point to a zeroed, writable `krb5_key_data`.
    pub(crate) unsafe fn write_into(
        self,
        kd: *mut kdb_sys::krb5_key_data,
    ) -> Result<(), ()> {
        let kd = &mut *kd;
        kd.key_data_ver = if self.has_salt { 2 } else { 1 };
        kd.key_data_kvno = self.kvno;
        kd.key_data_type[0] = self.enctype;
        kd.key_data_type[1] = self.salttype;

        // Allocate key contents.
        let key_len = self.key_bytes.len();
        kd.key_data_length[0] = u16::try_from(key_len).map_err(|_| ())?;
        if key_len > 0 {
            let ptr = libc::malloc(key_len).cast::<u8>();
            if ptr.is_null() {
                return Err(());
            }
            std::ptr::copy_nonoverlapping(
                self.key_bytes.as_ptr(),
                ptr,
                key_len,
            );
            kd.key_data_contents[0] = ptr;
        }

        // Allocate salt contents.
        let salt_len = self.salt_bytes.len();
        kd.key_data_length[1] = u16::try_from(salt_len).map_err(|_| ())?;
        if self.has_salt && salt_len > 0 {
            let ptr = libc::malloc(salt_len).cast::<u8>();
            if ptr.is_null() {
                // Free key contents already allocated above.
                if !kd.key_data_contents[0].is_null() {
                    libc::free(kd.key_data_contents[0].cast::<libc::c_void>());
                    kd.key_data_contents[0] = std::ptr::null_mut();
                    kd.key_data_length[0] = 0;
                }
                return Err(());
            }
            std::ptr::copy_nonoverlapping(
                self.salt_bytes.as_ptr(),
                ptr,
                salt_len,
            );
            kd.key_data_contents[1] = ptr;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key operation input records (referenced from module.rs)
// ---------------------------------------------------------------------------

/// Input for [`KdbModule::decrypt_key_data`](crate::KdbModule::decrypt_key_data).
pub struct DecryptKeyRequest<'a> {
    /// Master key to use, or `None` to try all known master keys.
    pub mkey: Option<&'a KeyBlock>,
    /// The encrypted key data to decrypt.
    pub key_data: KeyDataRef<'a>,
}

/// Input for [`KdbModule::encrypt_key_data`](crate::KdbModule::encrypt_key_data).
pub struct EncryptKeyRequest<'a> {
    /// Master key to encrypt with.
    pub mkey: &'a KeyBlock,
    /// The plaintext key to encrypt.
    pub dbkey: &'a KeyBlock,
    /// Optional salt; `None` means no salt is stored (`key_data_ver` = 1).
    pub keysalt: Option<&'a KeySalt>,
    /// Key version number to embed in the output.
    pub keyver: i32,
}

// ---------------------------------------------------------------------------
// Builder for a key_data array
// ---------------------------------------------------------------------------

/// A builder for assembling the `key_data` array of a [`PrincipalEntry`](crate::PrincipalEntry).
///
/// Keys should be added in descending kvno order to match the invariant
/// required by `kdb.h` (`key_data` must be sorted by kvno descending).
#[derive(Debug, Default)]
pub struct KeyDataBuilder {
    entries: Vec<KeyDataOwned>,
}

impl KeyDataBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        KeyDataBuilder::default()
    }

    /// Append one key entry (typically already sorted by the caller).
    pub fn push(&mut self, entry: KeyDataOwned) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no entries have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Consume the builder and produce a heap-allocated `krb5_key_data` array.
    ///
    /// Returns `(ptr, count)`.  The array is malloc-allocated so libkdb5 can
    /// free it via `krb5_dbe_free_key_data_contents` + `free`.
    pub(crate) fn into_raw(self) -> (*mut kdb_sys::krb5_key_data, i16) {
        let count = self.entries.len();
        if count == 0 {
            return (std::ptr::null_mut(), 0);
        }
        // SAFETY: calloc with size > 0; returns null on OOM.
        let arr = unsafe {
            libc::calloc(count, std::mem::size_of::<kdb_sys::krb5_key_data>())
                .cast::<kdb_sys::krb5_key_data>()
        };
        if arr.is_null() {
            std::alloc::handle_alloc_error(
                std::alloc::Layout::array::<kdb_sys::krb5_key_data>(count)
                    .unwrap(),
            );
        }
        for (i, entry) in self.entries.into_iter().enumerate() {
            // SAFETY: arr[i] is within the allocated array and zeroed.
            if unsafe { entry.write_into(arr.add(i)) }.is_err() {
                // Free already-written entries via the canonical kdb5 function,
                // then the array itself.
                for j in 0..i {
                    // SAFETY: krb5_dbe_free_key_data_contents does not use the
                    // context parameter; null is safe here.
                    unsafe {
                        kdb_sys::krb5_dbe_free_key_data_contents(
                            std::ptr::null_mut(),
                            arr.add(j),
                        );
                    };
                }
                unsafe { libc::free(arr.cast::<libc::c_void>()) };
                std::alloc::handle_alloc_error(std::alloc::Layout::new::<
                    kdb_sys::krb5_key_data,
                >());
            }
        }
        (arr, i16::try_from(count).unwrap_or(i16::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_block_clone() {
        let kb = KeyBlock {
            enctype: 18,
            contents: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(kb.clone(), kb);
    }

    #[test]
    fn builder_empty() {
        let b = KeyDataBuilder::new();
        assert!(b.is_empty());
        let (ptr, count) = b.into_raw();
        assert!(ptr.is_null());
        assert_eq!(count, 0);
    }

    #[test]
    fn builder_single_entry() {
        let mut b = KeyDataBuilder::new();
        b.push(KeyDataOwned {
            has_salt: false,
            kvno: 3,
            enctype: 18,
            salttype: 0,
            key_bytes: vec![0u8; 32],
            salt_bytes: vec![],
        });
        let (ptr, count) = b.into_raw();
        assert_eq!(count, 1);
        assert!(!ptr.is_null());
        // SAFETY: we just allocated this.
        unsafe {
            let kd = &*ptr;
            assert_eq!(kd.key_data_kvno, 3);
            assert_eq!(kd.key_data_type[0], 18);
            assert_eq!(kd.key_data_length[0], 32);
            assert_eq!(kd.key_data_ver, 1);
            // Free contents and array.
            if !kd.key_data_contents[0].is_null() {
                libc::free(kd.key_data_contents[0].cast::<libc::c_void>());
            }
            libc::free(ptr.cast::<libc::c_void>());
        }
    }
}
