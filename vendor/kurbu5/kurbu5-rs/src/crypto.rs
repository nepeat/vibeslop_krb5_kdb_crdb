//! Safe wrappers for MIT Kerberos symmetric-key crypto operations.
//!
//! This module wraps the `krb5_c_*` family of functions for encryption,
//! decryption, ciphertext-length queries, and random byte generation.
//!
//! All functions take a [`PluginContext`] and operate on `krb5_keyblock`
//! values, typically obtained from the callbacks layer.
//!
//! # Example
//!
//! ```rust,ignore
//! use kurbu5_rs::{PluginContext, crypto};
//! use kurbu5_rs::clpreauth::KeyblockRef;
//!
//! fn demo(ctx: &PluginContext<'_>, key: &KeyblockRef<'_>) {
//!     let plaintext = b"hello world";
//!     let enc = crypto::encrypt(ctx, key.as_ptr(), 7, plaintext).unwrap();
//!     let plain = crypto::decrypt(ctx, key.as_ptr(), 7, enc.as_enc_data()).unwrap();
//!     assert_eq!(plain, plaintext);
//! }
//! ```

use crate::context::PluginContext;
use crate::error::Krb5Error;
use libc;

// ---------------------------------------------------------------------------
// OwnedEncData — owned ciphertext result
// ---------------------------------------------------------------------------

/// Owned result of a [`encrypt`] call.
///
/// Holds the encryption type, key version number, and ciphertext bytes.
/// Use [`OwnedEncData::as_enc_data`] to borrow it as a `krb5_enc_data`
/// for passing to C functions (e.g. `krb5_c_decrypt`).
pub struct OwnedEncData {
    /// Encryption type used to produce this ciphertext.
    pub enctype: kurbu5_sys::krb5_enctype,
    /// Key version number (0 if not applicable).
    pub kvno: u32,
    /// The raw ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

impl OwnedEncData {
    /// Borrow as a `krb5_enc_data` for passing to C functions.
    ///
    /// The returned struct's `ciphertext.data` field points into
    /// `self.ciphertext`.  The struct is only valid as long as `self` is alive.
    ///
    /// # Panics
    ///
    /// Panics if the ciphertext length exceeds `u32::MAX` (4 GiB), which
    /// cannot occur for valid kerberos ciphertexts.
    #[must_use]
    pub fn as_enc_data(&self) -> kurbu5_sys::krb5_enc_data {
        kurbu5_sys::krb5_enc_data {
            magic: 0,
            enctype: self.enctype,
            kvno: self.kvno,
            ciphertext: kurbu5_sys::krb5_data {
                magic: 0,
                length: u32::try_from(self.ciphertext.len())
                    .expect("ciphertext length fits in u32"),
                // SAFETY: casting *const u8 to *mut c_char for the C API.
                // The C function reads it as const; mut is a C-API artefact.
                data: self
                    .ciphertext
                    .as_ptr()
                    .cast::<libc::c_char>()
                    .cast_mut(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// encrypt_length
// ---------------------------------------------------------------------------

/// Compute the output size required to encrypt `input_len` bytes.
///
/// Use this to allocate the output buffer before calling [`encrypt`].
///
/// # Errors
///
/// Returns `Err` if `krb5_c_encrypt_length` fails for the given enctype.
pub fn encrypt_length(
    ctx: &PluginContext<'_>,
    enctype: kurbu5_sys::krb5_enctype,
    input_len: usize,
) -> Result<usize, Krb5Error> {
    let mut len: usize = 0;
    // SAFETY: ctx.as_raw() is a valid krb5_context; len is a valid output slot.
    let code = unsafe {
        kurbu5_sys::krb5_c_encrypt_length(
            ctx.as_raw(),
            enctype,
            input_len,
            &raw mut len,
        )
    };
    if code != 0 {
        Err(Krb5Error::from_error_code(code))
    } else {
        Ok(len)
    }
}

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with `key` and `usage`, returning the ciphertext.
///
/// `key` is typically obtained from `KeyblockRef::as_ptr()`.
/// `usage` is a `krb5_keyusage` constant (e.g. `KRB5_KEYUSAGE_PA_OTP_REQUEST`).
///
/// This function:
/// 1. Calls [`encrypt_length`] to determine the output size.
/// 2. Allocates an output buffer of that size.
/// 3. Calls `krb5_c_encrypt` (no IV / cipher state).
/// 4. Returns an [`OwnedEncData`] that holds the ciphertext.
///
/// # Safety
///
/// `key` must be a non-null pointer to a valid `krb5_keyblock` for the
/// duration of this call.  Use `KeyblockRef::as_ptr()` to obtain a valid
/// pointer from the callbacks layer.
///
/// # Errors
///
/// Returns `Err` if `krb5_c_encrypt_length` or `krb5_c_encrypt` fails.
pub unsafe fn encrypt(
    ctx: &PluginContext<'_>,
    key: *const kurbu5_sys::krb5_keyblock,
    usage: kurbu5_sys::krb5_keyusage,
    plaintext: &[u8],
) -> Result<OwnedEncData, Krb5Error> {
    // SAFETY: key is non-null — enforced by the `unsafe fn` contract.
    let enctype = unsafe { (*key).enctype };
    let cipher_len = encrypt_length(ctx, enctype, plaintext.len())?;

    let mut cipher_buf: Vec<u8> = vec![0u8; cipher_len];

    let input = kurbu5_sys::krb5_data {
        magic: 0,
        length: u32::try_from(plaintext.len())
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?,
        // SAFETY: casting *const u8 to *mut c_char for the C read-only API.
        data: plaintext.as_ptr().cast::<libc::c_char>().cast_mut(),
    };

    let mut output: kurbu5_sys::krb5_enc_data = unsafe { std::mem::zeroed() };
    output.ciphertext.length = u32::try_from(cipher_len)
        .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
    // SAFETY: cipher_buf is a Vec<u8> with at least cipher_len bytes.
    output.ciphertext.data = cipher_buf.as_mut_ptr().cast::<libc::c_char>();

    // SAFETY: ctx and key are valid; input points into plaintext slice;
    // output.ciphertext.data points into cipher_buf; no IV is used (null).
    let code = unsafe {
        kurbu5_sys::krb5_c_encrypt(
            ctx.as_raw(),
            key,
            usage,
            std::ptr::null(), // no cipher state / IV
            std::ptr::from_ref(&input),
            &raw mut output,
        )
    };
    if code != 0 {
        return Err(Krb5Error::from_error_code(code));
    }

    // Transfer ownership of the buffer to OwnedEncData.  We use the actual
    // length written into output.ciphertext.length in case libkrb5 truncated.
    let actual_len = output.ciphertext.length as usize;
    cipher_buf.truncate(actual_len);

    Ok(OwnedEncData {
        enctype: output.enctype,
        kvno: output.kvno,
        ciphertext: cipher_buf,
    })
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

/// Decrypt `enc_data` with `key` and `usage`, returning the plaintext.
///
/// `key` is typically obtained from `KeyblockRef::as_ptr()`.
/// `enc_data` is typically an [`OwnedEncData::as_enc_data()`] borrow or a
/// `krb5_enc_data` from a decoded AS-REQ.
///
/// # Safety
///
/// `key` must be a non-null pointer to a valid `krb5_keyblock` for the
/// duration of this call.
///
/// # Errors
///
/// Returns `Err` if `krb5_c_decrypt` fails (e.g. integrity check failure).
pub unsafe fn decrypt(
    ctx: &PluginContext<'_>,
    key: *const kurbu5_sys::krb5_keyblock,
    usage: kurbu5_sys::krb5_keyusage,
    enc_data: &kurbu5_sys::krb5_enc_data,
) -> Result<Vec<u8>, Krb5Error> {
    // Allocate a buffer at least as large as the ciphertext; the plaintext
    // will be shorter (the AEAD overhead is stripped).
    let buf_len = enc_data.ciphertext.length as usize;
    let mut plain_buf: Vec<u8> = vec![0u8; buf_len];

    let mut output = kurbu5_sys::krb5_data {
        magic: 0,
        length: u32::try_from(buf_len)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?,
        // SAFETY: plain_buf has buf_len bytes allocated.
        data: plain_buf.as_mut_ptr().cast::<libc::c_char>(),
    };

    // SAFETY: ctx and key are valid; enc_data is a valid reference; output
    // points into plain_buf; no cipher state / IV is used (null).
    let code = unsafe {
        kurbu5_sys::krb5_c_decrypt(
            ctx.as_raw(),
            key,
            usage,
            std::ptr::null(), // no cipher state / IV
            std::ptr::from_ref(enc_data),
            &raw mut output,
        )
    };
    if code != 0 {
        return Err(Krb5Error::from_error_code(code));
    }

    plain_buf.truncate(output.length as usize);
    Ok(plain_buf)
}

// ---------------------------------------------------------------------------
// random_bytes
// ---------------------------------------------------------------------------

/// Fill `buf` with cryptographically random bytes.
///
/// Uses `krb5_c_random_make_octets` which sources entropy from the platform
/// PRNG seeded at context initialisation.
///
/// # Errors
///
/// Returns `Err` if `krb5_c_random_make_octets` fails.
pub fn random_bytes(
    ctx: &PluginContext<'_>,
    buf: &mut [u8],
) -> Result<(), Krb5Error> {
    let mut data = kurbu5_sys::krb5_data {
        magic: 0,
        length: u32::try_from(buf.len())
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?,
        // SAFETY: buf is mutably borrowed for the duration of this call.
        data: buf.as_mut_ptr().cast::<libc::c_char>(),
    };
    // SAFETY: ctx is valid; data.data points into buf which is mutably borrowed.
    let code = unsafe {
        kurbu5_sys::krb5_c_random_make_octets(ctx.as_raw(), &raw mut data)
    };
    if code != 0 {
        Err(Krb5Error::from_error_code(code))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// fx_cf2_simple — RFC 6113 key combination
// ---------------------------------------------------------------------------

/// Combine two keys using the KRB-FX-CF2 operation (RFC 6113).
///
/// Computes `out = PRF+(k1, pepper1) XOR PRF+(k2, pepper2)` using
/// `krb5_c_fx_cf2_simple`.
///
/// # Safety
///
/// `k1` and `k2` must be non-null pointers to valid `krb5_keyblock`s for
/// the duration of this call.
///
/// # Ownership
///
/// On success, returns a heap-allocated `krb5_keyblock`.  The caller must
/// free it with `kurbu5_sys::krb5_free_keyblock(ctx, ptr)`.
///
/// # Errors
///
/// Returns `Err` if `krb5_c_fx_cf2_simple` fails.
pub unsafe fn fx_cf2_simple(
    ctx: &PluginContext<'_>,
    k1: *const kurbu5_sys::krb5_keyblock,
    pepper1: &std::ffi::CStr,
    k2: *const kurbu5_sys::krb5_keyblock,
    pepper2: &std::ffi::CStr,
) -> Result<*mut kurbu5_sys::krb5_keyblock, Krb5Error> {
    let mut out: *mut kurbu5_sys::krb5_keyblock = std::ptr::null_mut();
    let code = kurbu5_sys::krb5_c_fx_cf2_simple(
        ctx.as_raw(),
        k1,
        pepper1.as_ptr(),
        k2,
        pepper2.as_ptr(),
        &raw mut out,
    );
    if code != 0 {
        Err(Krb5Error::from_error_code(code))
    } else {
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn make_ctx() -> kurbu5_sys::krb5_context {
        let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
        let code = kurbu5_sys::krb5_init_context(&mut ctx);
        assert_eq!(code, 0, "krb5_init_context failed");
        ctx
    }

    unsafe fn free_ctx(ctx: kurbu5_sys::krb5_context) {
        kurbu5_sys::krb5_free_context(ctx);
    }

    // Build a minimal AES-256-CTS-HMAC-SHA1-96 keyblock for testing.
    // enctype = 18 (ENCTYPE_AES256_CTS_HMAC_SHA1_96).
    fn make_test_keyblock() -> (Vec<u8>, kurbu5_sys::krb5_keyblock) {
        let key_bytes: Vec<u8> = (0u8..32).collect(); // 32 bytes for AES-256
        let kb = kurbu5_sys::krb5_keyblock {
            magic: 0,
            enctype: 18, // ENCTYPE_AES256_CTS_HMAC_SHA1_96
            length: 32,
            // SAFETY: key_bytes outlives kb; C reads this as const.
            contents: key_bytes.as_ptr().cast_mut(),
        };
        (key_bytes, kb)
    }

    #[test]
    fn encrypt_length_aes256_nonzero() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let len = encrypt_length(&plug_ctx, 18, 16).expect("encrypt_length");
        assert!(
            len > 0,
            "encrypt_length must return > 0 for non-empty input"
        );
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn random_bytes_fills_buffer() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let mut buf = [0u8; 16];
        random_bytes(&plug_ctx, &mut buf).expect("random_bytes");
        // Statistically near-zero chance all bytes are 0 for a real PRNG.
        assert_ne!(
            buf, [0u8; 16],
            "random_bytes must not leave buffer zeroed"
        );
        unsafe { free_ctx(ctx) };
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let ctx = unsafe { make_ctx() };
        let plug_ctx = unsafe { PluginContext::from_raw(ctx) };
        let (_key_bytes, kb) = make_test_keyblock();

        let plaintext = b"hello world 1234";
        let key_usage: kurbu5_sys::krb5_keyusage = 7;

        // SAFETY: &kb is a valid reference to a local krb5_keyblock.
        let enc = unsafe {
            encrypt(&plug_ctx, &kb as *const _, key_usage, plaintext)
        }
        .expect("encrypt");
        assert!(!enc.ciphertext.is_empty());

        let enc_data = enc.as_enc_data();
        // SAFETY: &kb is a valid reference to a local krb5_keyblock.
        let decrypted = unsafe {
            decrypt(&plug_ctx, &kb as *const _, key_usage, &enc_data)
        }
        .expect("decrypt");
        assert_eq!(decrypted, plaintext);

        unsafe { free_ctx(ctx) };
    }
}
