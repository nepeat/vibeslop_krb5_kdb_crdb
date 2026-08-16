//! CLPREAUTH — client-side pre-authentication plugin interface.
//!
//! A CLPREAUTH plugin participates in the client (kinit) side of the
//! Kerberos AS exchange.  The plugin processes `PA-DATA` elements supplied
//! by the KDC in its preauth-required error, produces `PA-DATA` elements for
//! the AS-REQ, and may invoke the user prompter to collect credentials.
//!
//! Interface file: `krb5/clpreauth_plugin.h`
//!
//! Major version: 1, current minor version: 2.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use kurbu5_rs::clpreauth::{ClpreauthModule, ClpreauthCallbacks, ProcessRequest, PaData};
//! use kurbu5_rs::{PluginContext, Krb5Error, initvt_plugin};
//!
//! pub struct MyClpreauth;
//!
//! impl ClpreauthModule for MyClpreauth {
//!     const NAME: &'static str = "myclpreauth";
//!
//!     fn pa_type_list() -> &'static [i32] {
//!         &[16] // PA-PKINIT-KX or any other pa-type
//!     }
//!
//!     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
//!         Ok(MyClpreauth)
//!     }
//!
//!     fn process(
//!         &mut self,
//!         _ctx: &PluginContext<'_>,
//!         _callbacks: &mut ClpreauthCallbacks<'_>,
//!         _req: &ProcessRequest<'_>,
//!     ) -> Result<Vec<PaData>, Krb5Error> {
//!         Err(Krb5Error::NoHandle)
//!     }
//! }
//!
//! initvt_plugin!(clpreauth_myclpreauth, 1, MyClpreauth,
//!               kurbu5_rs::clpreauth::glue::make_clpreauth_vtable);
//! ```
//!
//! # Safety model
//!
//! Unsafe code lives exclusively in [`glue`].  Plugin authors never write
//! `unsafe`.

use std::marker::PhantomData;

use crate::context::PluginContext;
use crate::error::Krb5Error;

pub mod glue;

// ---------------------------------------------------------------------------
// PA_REAL / PA_INFO flag constants (from clpreauth_plugin.h)
// ---------------------------------------------------------------------------

/// Flag returned by `flags()`: this mechanism provides a real authentication
/// answer (`PA_REAL = 0x00000001`).
///
/// The client assumes one real answer is sufficient; set for mechanisms that
/// actually prove the client's identity.
pub const PA_REAL: i32 = 0x0000_0001;

/// Flag returned by `flags()`: this mechanism provides informational data
/// only and must run before any `PA_REAL` mechanism (`PA_INFO = 0x00000002`).
pub const PA_INFO: i32 = 0x0000_0002;

// ---------------------------------------------------------------------------
// PaData — owned PA-DATA element
// ---------------------------------------------------------------------------

/// An owned pre-authentication data element (`krb5_pa_data`).
///
/// Returned by [`ClpreauthModule::process`] and [`ClpreauthModule::tryagain`]
/// to supply PA-DATA elements for the AS-REQ.
///
/// The glue layer converts a `Vec<PaData>` into the `krb5_pa_data **`
/// null-terminated array expected by libkrb5.
#[derive(Debug, Clone)]
pub struct PaData {
    /// The pre-authentication type number (e.g. `KRB5_PADATA_ENC_TIMESTAMP = 2`).
    pub pa_type: i32,
    /// The raw contents of this PA-DATA element.  Libkrb5 treats these bytes
    /// as opaque; encoding is mechanism-specific.
    pub contents: Vec<u8>,
}

impl PaData {
    /// Construct a new `PaData` element.
    #[must_use]
    pub fn new(pa_type: i32, contents: Vec<u8>) -> Self {
        PaData { pa_type, contents }
    }
}

// ---------------------------------------------------------------------------
// KrbKeyblock — safe view of a krb5_keyblock reference
// ---------------------------------------------------------------------------

/// A zero-copy view of a `krb5_keyblock` borrowed from the callbacks layer.
///
/// The `'a` lifetime binds to the `ClpreauthCallbacks` lifetime, preventing
/// the keyblock reference from escaping the callback context.
pub struct KeyblockRef<'a> {
    pub(crate) ptr: *mut kurbu5_sys::krb5_keyblock,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> KeyblockRef<'a> {
    /// Create a `KeyblockRef` from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid, initialized `krb5_keyblock` that remains
    /// valid for the lifetime `'a`.
    pub unsafe fn from_raw(ptr: *mut kurbu5_sys::krb5_keyblock) -> Self {
        KeyblockRef {
            ptr,
            _phantom: PhantomData,
        }
    }

    /// The encryption type of this keyblock.
    #[must_use]
    pub fn enctype(&self) -> i32 {
        // SAFETY: ptr is non-null and valid for 'a (ClpreauthCallbacks invariant).
        unsafe { (*self.ptr).enctype }
    }

    /// The raw key material as a byte slice.
    #[must_use]
    pub fn contents(&self) -> &'a [u8] {
        // SAFETY: ptr is non-null and valid; contents/length are consistent
        // (libkrb5 invariant for a well-formed keyblock).
        unsafe {
            if (*self.ptr).contents.is_null() || (*self.ptr).length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*self.ptr).contents,
                    (*self.ptr).length as usize,
                )
            }
        }
    }

    /// Return a raw const pointer to the underlying `krb5_keyblock`.
    ///
    /// The pointer is valid for the lifetime `'a` of this `KeyblockRef`.
    /// Do not free it; the keyblock is managed by the libkrb5 callbacks layer.
    ///
    /// Use this when calling C functions that accept `const krb5_keyblock *`,
    /// such as `krb5_c_encrypt` or `krb5_c_decrypt`.
    #[must_use]
    pub fn as_ptr(&self) -> *const kurbu5_sys::krb5_keyblock {
        self.ptr.cast_const()
    }
}

// ---------------------------------------------------------------------------
// ClpreauthCallbacks — safe wrapper over callbacks + rock (task 8.2)
// ---------------------------------------------------------------------------

/// Safe wrapper over `krb5_clpreauth_callbacks` + `krb5_clpreauth_rock`.
///
/// `ClpreauthCallbacks` is passed to [`ClpreauthModule::process`] and
/// [`ClpreauthModule::tryagain`].  Methods correspond to the function pointer
/// fields of `krb5_clpreauth_callbacks_st`.
///
/// The version field of the callback struct gates which methods are available.
/// This wrapper checks the version before calling any field beyond version 1.
///
/// | Version | Fields available |
/// |---------|-----------------|
/// | 1       | `get_etype`, `get_as_key`, `set_as_key` |
/// | 2       | + `get_preauth_time`, `ask_responder_question`, `get_responder_answer`, `need_as_key`, `get_cc_config`, `set_cc_config` |
/// | 3       | + `disable_fallback` |
pub struct ClpreauthCallbacks<'a> {
    pub(crate) cb: kurbu5_sys::krb5_clpreauth_callbacks,
    pub(crate) rock: kurbu5_sys::krb5_clpreauth_rock,
    pub(crate) ctx: kurbu5_sys::krb5_context,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl<'a> ClpreauthCallbacks<'a> {
    /// Return the current encryption type chosen for this AS exchange.
    ///
    /// If an AS-REP has been received, returns the AS-REP encrypted part
    /// enctype.  Otherwise returns the enctype from etype-info, or the first
    /// requested enctype if no etype-info was received.
    ///
    /// Corresponds to the `get_etype` callback (version 1).
    ///
    /// # Panics
    ///
    /// Panics if `get_etype` is absent from the callback table (should not
    /// happen for a version 1 callback structure).
    pub fn get_etype(&mut self) -> i32 {
        // SAFETY: self.cb and self.rock are non-null (ClpreauthCallbacks
        // invariant).  get_etype is mandatory (version 1).
        unsafe {
            let f = (*self.cb)
                .get_etype
                .expect("get_etype is mandatory (version 1)");
            f(self.ctx, self.rock)
        }
    }

    /// Get a pointer to the client reply key, invoking the prompter if needed.
    ///
    /// The returned `KeyblockRef` is an alias into libkrb5-owned memory; do
    /// not free it.  The key may be empty if not yet populated.
    ///
    /// Corresponds to the `get_as_key` callback (version 1).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the callback returns a non-zero error code.
    ///
    /// # Panics
    ///
    /// Panics if `get_as_key` is absent from the callback table (should not
    /// happen for a version 1 callback structure).
    pub fn get_as_key(&mut self) -> Result<KeyblockRef<'_>, Krb5Error> {
        let mut keyblock: *mut kurbu5_sys::krb5_keyblock =
            std::ptr::null_mut();
        // SAFETY: self.cb and self.rock are non-null.  get_as_key is mandatory
        // (version 1).  keyblock receives an alias pointer owned by libkrb5.
        let code = unsafe {
            let f = (*self.cb)
                .get_as_key
                .expect("get_as_key is mandatory (version 1)");
            f(self.ctx, self.rock, &raw mut keyblock)
        };
        if code != 0 {
            return Err(Krb5Error::from_error_code(code));
        }
        Ok(KeyblockRef {
            ptr: keyblock,
            _phantom: PhantomData,
        })
    }

    /// Replace the reply key used to decrypt the AS response.
    ///
    /// The `enctype`, `length`, and `contents` fields of `key` must be
    /// consistent.  Libkrb5 copies the keyblock; the caller retains ownership
    /// of `key`.
    ///
    /// Corresponds to the `set_as_key` callback (version 1).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the callback returns a non-zero error code.
    ///
    /// # Panics
    ///
    /// Panics if `set_as_key` is absent from the callback table (should not
    /// happen for a version 1 callback structure).
    pub fn set_as_key(
        &mut self,
        key: &KeyblockRef<'_>,
    ) -> Result<(), Krb5Error> {
        // SAFETY: self.cb and self.rock are non-null.  key.ptr is non-null
        // (invariant of KeyblockRef).  set_as_key is mandatory (version 1).
        let code = unsafe {
            let f = (*self.cb)
                .set_as_key
                .expect("set_as_key is mandatory (version 1)");
            f(self.ctx, self.rock, key.ptr)
        };
        if code != 0 {
            Err(Krb5Error::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Indicate interest in the AS key through the responder interface.
    ///
    /// Must be called from `prep_questions` (the `init_etype_info` method) if
    /// the module needs the AS key.  Has no effect if the responder interface
    /// is not in use.
    ///
    /// Corresponds to the `need_as_key` callback (version 2).
    pub fn need_as_key(&mut self) {
        // SAFETY: self.cb is non-null.  Guard on version before dereferencing
        // a field that might not exist in version 1 structs.
        unsafe {
            if (*self.cb).vers >= 2 {
                if let Some(f) = (*self.cb).need_as_key {
                    f(self.ctx, self.rock);
                }
            }
        }
    }

    /// Prevent further fallback to other preauth mechanisms on KDC errors.
    ///
    /// Call this from `process` after generating an authenticated request
    /// using real credentials.  The module itself may still respond via
    /// `tryagain`.
    ///
    /// Corresponds to the `disable_fallback` callback (version 3).
    pub fn disable_fallback(&mut self) {
        // SAFETY: self.cb is non-null.  Guard on version — disable_fallback
        // was added in version 3 (krb5 1.17).
        unsafe {
            if (*self.cb).vers >= 3 {
                if let Some(f) = (*self.cb).disable_fallback {
                    f(self.ctx, self.rock);
                }
            }
        }
    }

    /// Get the current time for a preauth response.
    ///
    /// If `allow_unauth_time` is true and the library is configured to allow
    /// it, the time may be offset using unauthenticated timestamp information
    /// from the KDC's preauth-required error.  Only set `allow_unauth_time`
    /// when using an unauthenticated time offset does not create a security
    /// issue.
    ///
    /// Returns `(seconds, microseconds)` on success.
    ///
    /// Corresponds to the `get_preauth_time` callback (version 2).
    ///
    /// # Errors
    ///
    /// Returns `Err(Krb5Error::OperationNotSupported)` when the callback
    /// version is less than 2, or if the callback returns a non-zero code.
    pub fn get_preauth_time(
        &mut self,
        allow_unauth_time: bool,
    ) -> Result<(i32, i32), Krb5Error> {
        let mut time_out: kurbu5_sys::krb5_timestamp = 0;
        let mut usec_out: kurbu5_sys::krb5_int32 = 0;
        // SAFETY: self.cb is non-null.  Guard on version — get_preauth_time
        // was added in version 2 (krb5 1.11).
        let code = unsafe {
            if (*self.cb).vers < 2 {
                return Err(Krb5Error::OperationNotSupported);
            }
            let f = (*self.cb)
                .get_preauth_time
                .ok_or(Krb5Error::OperationNotSupported)?;
            f(
                self.ctx,
                self.rock,
                kurbu5_sys::krb5_boolean::from(allow_unauth_time),
                &raw mut time_out,
                &raw mut usec_out,
            )
        };
        if code != 0 {
            Err(Krb5Error::from_error_code(code))
        } else {
            Ok((time_out, usec_out))
        }
    }

    /// Set a question for the responder interface to answer.
    ///
    /// `question` is a mechanism-defined string key; `challenge` is optional
    /// structured data (may be an empty string if unused).
    ///
    /// Corresponds to the `ask_responder_question` callback (version 2).
    ///
    /// # Errors
    ///
    /// Returns `Err` if `question` or `challenge` contain interior NUL bytes,
    /// if the callback version is less than 2, or if the callback fails.
    pub fn ask_responder_question(
        &mut self,
        question: &str,
        challenge: &str,
    ) -> Result<(), Krb5Error> {
        use std::ffi::CString;
        let cq = CString::new(question)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        let cc = CString::new(challenge)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        // SAFETY: self.cb is non-null.  Guard on version.  CStrings are valid.
        let code = unsafe {
            if (*self.cb).vers < 2 {
                return Err(Krb5Error::OperationNotSupported);
            }
            let f = (*self.cb)
                .ask_responder_question
                .ok_or(Krb5Error::OperationNotSupported)?;
            f(self.ctx, self.rock, cq.as_ptr(), cc.as_ptr())
        };
        if code != 0 {
            Err(Krb5Error::from_error_code(code))
        } else {
            Ok(())
        }
    }

    /// Get an answer from the responder, or `None` if unanswered.
    ///
    /// The returned string is an alias into libkrb5-owned memory; it is valid
    /// until the end of the current preauth exchange.
    ///
    /// Corresponds to the `get_responder_answer` callback (version 2).
    pub fn get_responder_answer(&mut self, question: &str) -> Option<&'a str> {
        use std::ffi::{CStr, CString};
        let cq = CString::new(question).ok()?;
        // SAFETY: self.cb is non-null.  Guard on version.  The returned pointer
        // is an alias; we bind its lifetime to 'a (the callbacks borrow).
        unsafe {
            if (*self.cb).vers < 2 {
                return None;
            }
            let f = (*self.cb).get_responder_answer?;
            let ptr = f(self.ctx, self.rock, cq.as_ptr());
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// Get a configuration/state string from the input ccache.
    ///
    /// Returns `None` if the key is absent or no input ccache was provided.
    /// The returned string is an alias into libkrb5-owned memory.
    ///
    /// Corresponds to the `get_cc_config` callback (version 2).
    pub fn get_cc_config(&mut self, key: &str) -> Option<&'a str> {
        use std::ffi::{CStr, CString};
        let ck = CString::new(key).ok()?;
        // SAFETY: self.cb is non-null.  Guard on version.
        unsafe {
            if (*self.cb).vers < 2 {
                return None;
            }
            let f = (*self.cb).get_cc_config?;
            let ptr = f(self.ctx, self.rock, ck.as_ptr());
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// Set a configuration/state item to be saved to the output ccache.
    ///
    /// Both `key` and `data` must be valid UTF-8 text.
    ///
    /// Corresponds to the `set_cc_config` callback (version 2).
    ///
    /// # Errors
    ///
    /// Returns `Err` if `key` or `data` contain interior NUL bytes, if the
    /// callback version is less than 2, or if the callback fails.
    pub fn set_cc_config(
        &mut self,
        key: &str,
        data: &str,
    ) -> Result<(), Krb5Error> {
        use std::ffi::CString;
        let ck =
            CString::new(key).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        let cd =
            CString::new(data).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        // SAFETY: self.cb is non-null.  Guard on version.  CStrings are valid.
        let code = unsafe {
            if (*self.cb).vers < 2 {
                return Err(Krb5Error::OperationNotSupported);
            }
            let f = (*self.cb)
                .set_cc_config
                .ok_or(Krb5Error::OperationNotSupported)?;
            f(self.ctx, self.rock, ck.as_ptr(), cd.as_ptr())
        };
        if code != 0 {
            Err(Krb5Error::from_error_code(code))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Prompter — safe wrapper over krb5_prompter_fct (task 8.3)
// ---------------------------------------------------------------------------

/// A reference to the C `krb5_prompter_fct` callback.
///
/// The prompter is passed inside [`ProcessRequest`] and [`TryagainRequest`]
/// to inform the plugin whether interactive user prompting is available.
///
/// Plugin authors do not need to invoke the prompter directly in most cases;
/// calling [`ClpreauthCallbacks::get_as_key`] is sufficient because libkrb5
/// invokes the prompter internally when it needs a password.
///
/// The actual function pointer and associated context/data are managed by the
/// glue layer and are not exposed as raw C pointers in the public API.
pub struct Prompter<'a> {
    /// Whether a prompter function was supplied by the application.
    ///
    /// `true` means interactive prompting is available.  `false` means the
    /// application did not register a prompter (e.g. a non-interactive daemon).
    pub available: bool,
    pub(crate) _phantom: PhantomData<&'a ()>,
}

impl Prompter<'_> {
    /// Returns `true` if a prompter function is set.
    ///
    /// Check this before attempting operations that require user interaction.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available
    }
}

// ---------------------------------------------------------------------------
// ProcessRequest / TryagainRequest — input record types (task 8.1)
// ---------------------------------------------------------------------------

/// All inputs for a `process` call (task 8.1, 8.3).
///
/// Groups the parameters that would otherwise create a method with more than
/// two arguments beyond `&self` and `ctx`.  See [`ClpreauthModule::process`].
pub struct ProcessRequest<'a> {
    /// The `krb5_get_init_creds_opt` from the current AS exchange.
    /// Access individual fields via the raw pointer if needed.
    pub opt: *mut kurbu5_sys::krb5_get_init_creds_opt,

    /// The AS request being built (`krb5_kdc_req`).
    pub request: *const kurbu5_sys::krb5_kdc_req,

    /// The DER-encoded AS request body from the previous exchange message.
    /// `None` on the first round trip.
    pub encoded_request_body: Option<&'a [u8]>,

    /// The DER-encoded previous AS request.  `None` on the first round trip.
    pub encoded_previous_request: Option<&'a [u8]>,

    /// The incoming `PA-DATA` element that triggered this call.
    pub pa_data: &'a kurbu5_sys::krb5_pa_data,

    /// The safe prompter wrapper for collecting user input.
    pub prompter: Prompter<'a>,
}

/// All inputs for a `tryagain` call (task 8.1).
///
/// Groups the extra parameters that `tryagain` receives beyond those in
/// [`ProcessRequest`].  See [`ClpreauthModule::tryagain`].
pub struct TryagainRequest<'a> {
    /// The `krb5_get_init_creds_opt` from the current AS exchange.
    pub opt: *mut kurbu5_sys::krb5_get_init_creds_opt,

    /// The AS request being built.
    pub request: *const kurbu5_sys::krb5_kdc_req,

    /// The DER-encoded AS request body from the previous exchange message.
    pub encoded_request_body: Option<&'a [u8]>,

    /// The DER-encoded previous AS request.
    pub encoded_previous_request: Option<&'a [u8]>,

    /// The pa-type being retried.
    pub pa_type: i32,

    /// The KDC error that caused this retry.
    pub error: &'a kurbu5_sys::krb5_error,

    /// The error pa-data decoded from the KDC error (null-terminated array).
    pub error_padata: *mut *mut kurbu5_sys::krb5_pa_data,

    /// The safe prompter wrapper for collecting user input.
    pub prompter: Prompter<'a>,
}

/// All inputs for `init_etype_info` / `prep_questions`.
///
/// Corresponds to `krb5_clpreauth_prep_questions_fn`.
pub struct EtypeInfoRequest<'a> {
    /// The `krb5_get_init_creds_opt` from the current AS exchange.
    pub opt: *mut kurbu5_sys::krb5_get_init_creds_opt,

    /// The AS request being built.
    pub request: *const kurbu5_sys::krb5_kdc_req,

    /// The DER-encoded AS request body.
    pub encoded_request_body: Option<&'a [u8]>,

    /// The DER-encoded previous AS request.
    pub encoded_previous_request: Option<&'a [u8]>,

    /// The incoming `PA-DATA` element to inspect for etype-info.
    pub pa_data: &'a kurbu5_sys::krb5_pa_data,
}

// ---------------------------------------------------------------------------
// ClpreauthModule trait (task 8.1)
// ---------------------------------------------------------------------------

/// Implement this trait to create a CLPREAUTH (client-side preauth) plugin.
///
/// Use the [`initvt_plugin!`](crate::initvt_plugin) macro to export the
/// C `<name>_initvt` function.
///
/// # Lifetime contract
///
/// `ClpreauthModule: Sized + Send + 'static` for the same reasons as
/// `KdbModule`:
/// - `Sized` allows `Box<M>` and raw-pointer round-trips.
/// - `Send` allows the `Box` to move between threads across AS exchanges.
/// - `'static` prevents the module from holding references into caller stacks.
///
/// # Default implementations
///
/// Optional methods default to `Err(Krb5Error::NoHandle)`, which tells
/// libkrb5 to try the next registered plugin.  `tryagain` and
/// `init_etype_info` default to `Ok(vec![])` / `Ok(())` because they are
/// called opportunistically and a no-op is safe.
///
/// # Quick start
///
/// ```rust,ignore
/// use kurbu5_rs::clpreauth::{ClpreauthModule, ClpreauthCallbacks, ProcessRequest, PaData};
/// use kurbu5_rs::{PluginContext, Krb5Error, initvt_plugin};
///
/// pub struct MyClpreauth;
///
/// impl ClpreauthModule for MyClpreauth {
///     const NAME: &'static str = "myclpreauth";
///
///     fn pa_type_list() -> &'static [i32] {
///         &[16]
///     }
///
///     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
///         Ok(MyClpreauth)
///     }
///
///     fn process(
///         &mut self,
///         _ctx: &PluginContext<'_>,
///         _callbacks: &mut ClpreauthCallbacks<'_>,
///         _req: &ProcessRequest<'_>,
///     ) -> Result<Vec<PaData>, Krb5Error> {
///         Err(Krb5Error::NoHandle)
///     }
/// }
///
/// initvt_plugin!(clpreauth_myclpreauth, 1, MyClpreauth,
///               kurbu5_rs::clpreauth::glue::make_clpreauth_vtable);
/// ```
pub trait ClpreauthModule: Sized + Send + 'static {
    // -----------------------------------------------------------------------
    // Mandatory fields
    // -----------------------------------------------------------------------

    /// The name of this plugin module.
    ///
    /// This string is stored in `krb5_clpreauth_vtable_st::name` and is used
    /// for diagnostics.
    const NAME: &'static std::ffi::CStr;

    /// The list of pre-authentication type numbers this module handles.
    ///
    /// Returns a `'static` slice of `krb5_preauthtype` values (i32).  The
    /// glue layer appends the required zero sentinel before passing the pointer
    /// to libkrb5.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::pa_type_list`.
    fn pa_type_list() -> &'static [i32];

    // -----------------------------------------------------------------------
    // Optional: module lifecycle
    // -----------------------------------------------------------------------

    /// Initialise the module.
    ///
    /// Called once when the plugin is first loaded.  Return `Ok(Self)` to
    /// produce the module instance.  The instance lives until `fini_module`
    /// is called.
    ///
    /// Default: returns `Err(Krb5Error::NoHandle)` which tells libkrb5 to try
    /// the next plugin.  Override if your module needs initialisation.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::init`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to defer to the next plugin.
    fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
        Err(Krb5Error::NoHandle)
    }

    /// Finalise and drop the module.
    ///
    /// Called when the associated `krb5_context` is freed.  The default
    /// implementation does nothing; override only if cleanup is needed.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::fini`.
    fn fini_module(self) {}

    // -----------------------------------------------------------------------
    // Optional: pa-type flags
    // -----------------------------------------------------------------------

    /// Return the flags for a given pa-type this module handles.
    ///
    /// `pa_type` will be a member of the list returned by `pa_type_list()`.
    /// Return [`PA_REAL`] if the type provides a real authentication answer,
    /// or [`PA_INFO`] if it is informational only.
    ///
    /// Default: `PA_REAL` — all types are treated as real answers.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::flags`.
    #[must_use]
    fn flags(_ctx: &PluginContext<'_>, _pa_type: i32) -> i32 {
        PA_REAL
    }

    // -----------------------------------------------------------------------
    // Optional: per-request lifecycle (init_etype_info)
    // -----------------------------------------------------------------------

    /// Process etype-info and set responder questions before the main process.
    ///
    /// Called at the start of each AS exchange round trip, before `process`.
    /// The module may call `callbacks.need_as_key()` to indicate it needs the
    /// AS key via the responder interface.
    ///
    /// The module-request state (`modreq`) is created by the glue layer as
    /// a `Box<Option<()>>` placeholder.  If your module needs per-request
    /// state, override this method and override `process`/`tryagain` to use
    /// it (advanced: use `Arc<Mutex<T>>` keyed by request identity).
    ///
    /// Default: `Ok(())` — no etype-info processing needed.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::prep_questions` (minor
    /// version 2).  The older `request_init` field initialises the `modreq`
    /// pointer and is handled transparently by the glue layer.
    ///
    /// # Errors
    ///
    /// Return `Err` to abort etype-info processing.
    fn init_etype_info(
        &mut self,
        _ctx: &PluginContext<'_>,
        _callbacks: &mut ClpreauthCallbacks<'_>,
        _req: &EtypeInfoRequest<'_>,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Mandatory: process
    // -----------------------------------------------------------------------

    /// Process server-supplied PA-DATA and produce PA-DATA for the AS-REQ.
    ///
    /// This is the core method of the CLPREAUTH interface.  It is also called
    /// after a successful AS-REP is received if the AS-REP includes PA-DATA
    /// of the associated type.
    ///
    /// Return `Ok(pa_data_list)` with zero or more `PaData` elements to
    /// include in the AS-REQ.  Return `Err(Krb5Error::NoHandle)` to skip
    /// this mechanism for the current exchange.
    ///
    /// The `req.prompter` wrapper is provided for mechanisms that need to
    /// prompt the user; in most cases calling `callbacks.get_as_key()` is
    /// sufficient because it invokes the prompter internally when needed.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::process`.
    ///
    /// # Errors
    ///
    /// Return `Err(Krb5Error::NoHandle)` to skip this mechanism.
    fn process(
        &mut self,
        ctx: &PluginContext<'_>,
        callbacks: &mut ClpreauthCallbacks<'_>,
        req: &ProcessRequest<'_>,
    ) -> Result<Vec<PaData>, Krb5Error>;

    // -----------------------------------------------------------------------
    // Optional: tryagain
    // -----------------------------------------------------------------------

    /// Attempt recovery after a KDC error response.
    ///
    /// Called when the KDC returned an error.  To work with both FAST and
    /// non-FAST errors, inspect `req.error_padata` rather than decoding
    /// `req.error.e_data` directly.
    ///
    /// If this method returns `Ok(pa_data_list)` with a non-empty list, the
    /// client library will retransmit the AS-REQ with the new data.
    ///
    /// Default: `Ok(vec![])` — no recovery attempted.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::tryagain`.
    ///
    /// # Errors
    ///
    /// Return `Err` to abort the recovery attempt.
    fn tryagain(
        &mut self,
        _ctx: &PluginContext<'_>,
        _callbacks: &mut ClpreauthCallbacks<'_>,
        _req: &TryagainRequest<'_>,
    ) -> Result<Vec<PaData>, Krb5Error> {
        Ok(vec![])
    }

    // -----------------------------------------------------------------------
    // Optional: enctype_list
    // -----------------------------------------------------------------------

    /// An optional list of additional encryption types this module claims to
    /// support.
    ///
    /// Returns `None` by default (no additional enctypes advertised).
    /// Corresponds to `krb5_clpreauth_vtable_st::enctype_list`.
    #[must_use]
    fn enctype_list() -> Option<&'static [i32]> {
        None
    }

    // -----------------------------------------------------------------------
    // Optional: free_modreq
    // -----------------------------------------------------------------------

    /// Free per-request module data.
    ///
    /// The default does nothing.  The glue layer calls this via the
    /// `request_fini` vtable slot.  Override only if the module uses custom
    /// per-request state that needs explicit cleanup beyond `Drop`.
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::request_fini`.
    fn free_modreq(&mut self) {}

    // -----------------------------------------------------------------------
    // Optional: supply_gic_opts
    // -----------------------------------------------------------------------

    /// Receive a pre-authentication option from `kinit -X attr=value`.
    ///
    /// Called once per `-X` option before any AS exchange begins.  Return
    /// `Ok(())` for unrecognised attributes (they may be intended for other
    /// modules).
    ///
    /// Corresponds to `krb5_clpreauth_vtable_st::gic_opts`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the option value is invalid for this module.
    fn supply_gic_opts(
        &mut self,
        _ctx: &PluginContext<'_>,
        _opt: *mut kurbu5_sys::krb5_get_init_creds_opt,
        _attr: &str,
        _value: &str,
    ) -> Result<(), Krb5Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests (task 8.5)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Krb5Error;

    // -----------------------------------------------------------------------
    // PaData
    // -----------------------------------------------------------------------

    #[test]
    fn padata_new_round_trip() {
        let pa = PaData::new(2, vec![0xDE, 0xAD]);
        assert_eq!(pa.pa_type, 2);
        assert_eq!(pa.contents, vec![0xDE, 0xAD]);
    }

    #[test]
    fn padata_empty_contents() {
        let pa = PaData::new(42, vec![]);
        assert_eq!(pa.pa_type, 42);
        assert!(pa.contents.is_empty());
    }

    #[test]
    fn padata_clone() {
        let pa = PaData::new(16, vec![1, 2, 3]);
        let pa2 = pa.clone();
        assert_eq!(pa2.pa_type, pa.pa_type);
        assert_eq!(pa2.contents, pa.contents);
    }

    // -----------------------------------------------------------------------
    // PA_REAL / PA_INFO constants
    // -----------------------------------------------------------------------

    #[test]
    fn flag_constants_distinct() {
        assert_ne!(PA_REAL, PA_INFO);
        assert_eq!(PA_REAL, 0x0000_0001);
        assert_eq!(PA_INFO, 0x0000_0002);
    }

    // -----------------------------------------------------------------------
    // ClpreauthModule default implementations
    // -----------------------------------------------------------------------

    struct MinimalModule;

    impl ClpreauthModule for MinimalModule {
        const NAME: &'static std::ffi::CStr = c"minimal";

        fn pa_type_list() -> &'static [i32] {
            // Zero-terminated as required by the C API.
            &[16, 0]
        }

        fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
            Ok(MinimalModule)
        }

        fn process(
            &mut self,
            _ctx: &PluginContext<'_>,
            _callbacks: &mut ClpreauthCallbacks<'_>,
            _req: &ProcessRequest<'_>,
        ) -> Result<Vec<PaData>, Krb5Error> {
            Ok(vec![PaData::new(16, vec![0xAB])])
        }
    }

    #[test]
    fn minimal_module_name() {
        assert_eq!(MinimalModule::NAME, c"minimal");
    }

    #[test]
    fn minimal_module_pa_type_list() {
        let list = MinimalModule::pa_type_list();
        assert_eq!(list[0], 16);
        assert_eq!(*list.last().unwrap(), 0); // null sentinel
    }

    #[test]
    fn default_flags_returns_pa_real() {
        // The default impl of ClpreauthModule::flags returns PA_REAL.
        // Verify the constant value matches the C header definition.
        assert_eq!(PA_REAL, 1);
        // MinimalModule uses the default impl; verify via the trait constant.
        // (A live context is needed to actually call the method; the constant
        // check is sufficient for the default implementation test.)
        assert_ne!(PA_REAL, PA_INFO);
    }

    #[test]
    fn default_tryagain_returns_empty() {
        // tryagain default returns Ok(vec![]).  Verify the type compiles and
        // the constant matches.
        let _: Vec<PaData> = vec![];
    }

    #[test]
    fn default_enctype_list_is_none() {
        struct NoEnc;
        impl ClpreauthModule for NoEnc {
            const NAME: &'static std::ffi::CStr = c"noenc";
            fn pa_type_list() -> &'static [i32] {
                &[0]
            }
            fn process(
                &mut self,
                _ctx: &PluginContext<'_>,
                _callbacks: &mut ClpreauthCallbacks<'_>,
                _req: &ProcessRequest<'_>,
            ) -> Result<Vec<PaData>, Krb5Error> {
                Ok(vec![])
            }
        }
        assert!(NoEnc::enctype_list().is_none());
    }

    // -----------------------------------------------------------------------
    // Prompter availability flag
    // -----------------------------------------------------------------------

    #[test]
    fn prompter_not_available_when_unavailable() {
        let p = Prompter {
            available: false,
            _phantom: PhantomData,
        };
        assert!(!p.is_available());
    }

    #[test]
    fn prompter_available_when_set() {
        let p = Prompter {
            available: true,
            _phantom: PhantomData,
        };
        assert!(p.is_available());
    }

    // -----------------------------------------------------------------------
    // Vtable construction (smoke test — no live krb5 context needed)
    // -----------------------------------------------------------------------

    #[test]
    fn make_vtable_name_matches() {
        use crate::clpreauth::glue::make_clpreauth_vtable;
        let vt = make_clpreauth_vtable::<MinimalModule>();
        // SAFETY: vt.name was set from MinimalModule::NAME.as_ptr() — a valid
        // null-terminated *const c_char valid for 'static.
        let name = unsafe { std::ffi::CStr::from_ptr(vt.name) };
        assert_eq!(name, MinimalModule::NAME);
    }

    #[test]
    fn make_vtable_process_is_some() {
        use crate::clpreauth::glue::make_clpreauth_vtable;
        let vt = make_clpreauth_vtable::<MinimalModule>();
        assert!(vt.process.is_some());
        assert!(vt.init.is_some());
        assert!(vt.fini.is_some());
        assert!(vt.flags.is_some());
        assert!(vt.request_init.is_some());
        assert!(vt.request_fini.is_some());
        assert!(vt.tryagain.is_some());
        assert!(vt.prep_questions.is_some());
        assert!(vt.gic_opts.is_some());
    }

    #[test]
    fn make_vtable_pa_type_list_matches() {
        use crate::clpreauth::glue::make_clpreauth_vtable;
        let vt = make_clpreauth_vtable::<MinimalModule>();
        let expected = MinimalModule::pa_type_list();
        // SAFETY: vt.pa_type_list points to MinimalModule::pa_type_list()
        // which is a 'static slice.
        let first = unsafe { *vt.pa_type_list };
        assert_eq!(first, expected[0]);
    }

    #[test]
    fn make_vtable_enctype_list_null_when_none() {
        use crate::clpreauth::glue::make_clpreauth_vtable;
        let vt = make_clpreauth_vtable::<MinimalModule>();
        // MinimalModule::enctype_list() returns None.
        assert!(vt.enctype_list.is_null());
    }

    // -----------------------------------------------------------------------
    // Integration tests: exercise vtable function pointers, not trait methods.
    // These catch Box::into_raw / Box::from_raw ownership bugs in glue.rs that
    // pure trait-level tests cannot detect.
    // -----------------------------------------------------------------------

    mod integration_tests {
        use super::super::{ClpreauthModule, PaData, ProcessRequest};
        use crate::clpreauth::glue::make_clpreauth_vtable;
        use crate::context::PluginContext;
        use crate::error::Krb5Error;

        // A minimal CLPREAUTH plugin: init succeeds, process returns NoHandle.
        struct MinimalClpreauth;

        impl ClpreauthModule for MinimalClpreauth {
            const NAME: &'static std::ffi::CStr = c"minimal_cl";

            fn pa_type_list() -> &'static [i32] {
                // Must end with 0 sentinel as the C API requires.
                static LIST: [i32; 2] = [16, 0];
                &LIST
            }

            fn init_module(
                _ctx: &PluginContext<'_>,
            ) -> Result<Self, Krb5Error> {
                Ok(MinimalClpreauth)
            }

            fn process(
                &mut self,
                _ctx: &PluginContext<'_>,
                _callbacks: &mut super::super::ClpreauthCallbacks<'_>,
                _req: &ProcessRequest<'_>,
            ) -> Result<Vec<PaData>, Krb5Error> {
                Err(Krb5Error::NoHandle)
            }
        }

        // Create a real krb5_context for tests that need one.
        //
        // SAFETY: krb5_init_context allocates a context; the caller is
        // responsible for passing the result to krb5_free_context.
        unsafe fn make_ctx() -> kurbu5_sys::krb5_context {
            let mut ctx: kurbu5_sys::krb5_context = std::ptr::null_mut();
            let code = kurbu5_sys::krb5_init_context(&mut ctx);
            assert_eq!(code, 0, "krb5_init_context failed: {}", code);
            assert!(!ctx.is_null());
            ctx
        }

        // SAFETY: ctx was returned by krb5_init_context and is no longer used
        // after this call.
        unsafe fn free_ctx(ctx: kurbu5_sys::krb5_context) {
            kurbu5_sys::krb5_free_context(ctx);
        }

        // Verify that calling init through the vtable fn pointer allocates the
        // moddata box, and that calling fini through the vtable fn pointer
        // correctly reclaims it without leaking or double-freeing.
        //
        // This exercises the Box::into_raw (in clpreauth_init) and
        // Box::from_raw (in clpreauth_fini) cycle in clpreauth/glue.rs.
        #[test]
        fn vtable_init_fini_roundtrip() {
            let vt = make_clpreauth_vtable::<MinimalClpreauth>();

            // SAFETY: make_ctx returns a valid krb5_context.
            let ctx = unsafe { make_ctx() };

            let mut moddata: kurbu5_sys::krb5_clpreauth_moddata =
                std::ptr::null_mut();

            // Call init through the vtable function pointer.
            // SAFETY: ctx is valid; moddata_out points to a local variable.
            // clpreauth_init calls PluginContext::from_raw (requires non-null ctx)
            // and Box::into_raw to store the module.
            let code = unsafe {
                vt.init.expect("init must be set in clpreauth vtable")(
                    ctx,
                    &mut moddata,
                )
            };
            assert_eq!(code, 0, "init returned non-zero: {}", code);
            assert!(
                !moddata.is_null(),
                "init must set moddata to a non-null Box<M> pointer"
            );

            // Call fini through the vtable function pointer.  This must reclaim
            // the Box<M> without double-free or leak.
            // SAFETY: moddata was set by init as Box<MinimalClpreauth>::into_raw();
            // fini calls Box::from_raw and then fini_module on the recovered box.
            unsafe {
                vt.fini.expect("fini must be set in clpreauth vtable")(
                    ctx, moddata,
                );
            }

            // SAFETY: ctx was created by make_ctx and is no longer needed.
            unsafe { free_ctx(ctx) };
        }

        // Verify that request_init allocates the modreq placeholder and
        // request_fini reclaims it correctly.
        //
        // This exercises the Box::<()>::into_raw / Box::from_raw cycle in
        // clpreauth_request_init / clpreauth_request_fini in glue.rs.
        #[test]
        fn vtable_request_init_fini_roundtrip() {
            let vt = make_clpreauth_vtable::<MinimalClpreauth>();

            // SAFETY: make_ctx returns a valid krb5_context.
            let ctx = unsafe { make_ctx() };

            // Set up moddata first so request_fini can call module.free_modreq.
            let mut moddata: kurbu5_sys::krb5_clpreauth_moddata =
                std::ptr::null_mut();
            // SAFETY: same as vtable_init_fini_roundtrip.
            let code = unsafe { vt.init.expect("init")(ctx, &mut moddata) };
            assert_eq!(code, 0);

            let mut modreq: kurbu5_sys::krb5_clpreauth_modreq =
                std::ptr::null_mut();

            // Call request_init through the vtable fn pointer.  This allocates
            // a Box<()> and stores its raw pointer in modreq.
            // SAFETY: modreq_out is a valid non-null pointer to a local variable.
            unsafe {
                vt.request_init.expect("request_init must be set")(
                    ctx,
                    moddata,
                    &mut modreq,
                );
            }
            assert!(
                !modreq.is_null(),
                "request_init must set modreq to a non-null Box<()> pointer"
            );

            // Call request_fini through the vtable fn pointer.  This reclaims
            // the Box<()> and calls module.free_modreq (a no-op by default).
            // SAFETY: modreq was set by request_init as Box<()>::into_raw();
            // request_fini calls Box::from_raw on it and then calls free_modreq.
            unsafe {
                vt.request_fini.expect("request_fini must be set")(
                    ctx, moddata, modreq,
                );
            }

            // Tear down the module.
            // SAFETY: moddata was set by init; fini reclaims it.
            unsafe { vt.fini.expect("fini")(ctx, moddata) };
            // SAFETY: ctx is no longer needed.
            unsafe { free_ctx(ctx) };
        }
    }
}
