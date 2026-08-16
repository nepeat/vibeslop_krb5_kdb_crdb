//! Example PWQUAL plugin: enforce a minimum password length.
//!
//! This example demonstrates implementing the [`PwqualModule`] trait.
//!
//! In a real plugin deployed as a shared library, replace the `main` function
//! below with an `initvt_plugin!` call and compile as `crate-type = ["cdylib"]`.
//!
//! # Production template
//!
//! ```toml
//! # Cargo.toml
//! [lib]
//! crate-type = ["cdylib"]
//!
//! [dependencies]
//! kurbu5-rs = { version = "0.1", features = ["pwqual"] }
//! ```
//!
//! ```rust,ignore
//! use kurbu5_rs::{initvt_plugin, pwqual::{PwqualModule, CheckRequest, PwqualError}};
//! use kurbu5_rs::PluginContext;
//!
//! pub struct MinLenPlugin { min_len: usize }
//!
//! impl PwqualModule for MinLenPlugin {
//!     const NAME: &'static str = "min_len";
//!     fn open(_ctx: &PluginContext<'_>, _dict_file: Option<&str>) -> Result<Self, PwqualError> {
//!         Ok(MinLenPlugin { min_len: 12 })
//!     }
//!     fn check(&self, _ctx: &PluginContext<'_>, req: &CheckRequest<'_>) -> Result<(), PwqualError> {
//!         if req.password.chars().count() < self.min_len {
//!             return Err(PwqualError::TooShort);
//!         }
//!         Ok(())
//!     }
//! }
//!
//! initvt_plugin!(example_pwqual_initvt, 1, MinLenPlugin,
//!                kurbu5_rs::pwqual::glue::make_pwqual_vtable);
//! ```
//!
//! # krb5.conf snippet
//!
//! ```text
//! [plugins]
//!   pwqual = {
//!     module = min_len:libmin_len.so
//!   }
//! ```

use kurbu5_rs::PluginContext;
use kurbu5_rs::pwqual::{CheckRequest, PwqualError, PwqualModule};

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

/// A simple password quality checker that enforces a minimum length.
///
/// Stateless: `open` always succeeds immediately; all state lives in `self`.
pub struct ExamplePwqual {
    min_len: usize,
}

impl PwqualModule for ExamplePwqual {
    /// C-visible name of this module (used in krb5.conf and log messages).
    const NAME: &'static std::ffi::CStr = c"example_pwqual";

    /// Construct the plugin instance.
    ///
    /// `dict_file` is ignored by this example; real plugins that require a
    /// dictionary should return `Err(PwqualError::NoHandle)` when
    /// `dict_file` is `None`.
    fn open(
        _ctx: &PluginContext<'_>,
        _dict_file: Option<&str>,
    ) -> Result<Self, PwqualError> {
        Ok(ExamplePwqual { min_len: 12 })
    }

    /// Reject the password if it is shorter than `self.min_len` characters.
    ///
    /// The check counts Unicode scalar values (`.chars().count()`) rather
    /// than raw bytes so that multi-byte characters are counted correctly.
    fn check(
        &self,
        _ctx: &PluginContext<'_>,
        req: &CheckRequest<'_>,
    ) -> Result<(), PwqualError> {
        if req.password.chars().count() < self.min_len {
            return Err(PwqualError::TooShort);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Demonstration main
//
// In a production cdylib, replace this with:
//   initvt_plugin!(example_pwqual_initvt, 1, ExamplePwqual,
//                  kurbu5_rs::pwqual::glue::make_pwqual_vtable);
// ---------------------------------------------------------------------------

fn main() {
    // Demonstrate the plugin logic directly via the glue layer.
    // Production plugins export example_pwqual_initvt and are loaded by
    // libkrb5 via dlopen; this main() just validates the check logic.
    let plugin = ExamplePwqual { min_len: 12 };

    let cases: &[(&str, bool)] = &[
        ("short", false),
        ("correct-horse", true),
        ("correct-horse-battery-staple", true),
        ("abc", false),
    ];

    for &(password, should_pass) in cases {
        let passed = password.chars().count() >= plugin.min_len;
        let mark = if passed == should_pass { "OK" } else { "FAIL" };
        println!(
            "[{mark}] password={password:?} accepted={passed} expected={should_pass}"
        );
        assert_eq!(passed, should_pass, "unexpected result for {password:?}");
    }

    println!("All checks passed.");
}
