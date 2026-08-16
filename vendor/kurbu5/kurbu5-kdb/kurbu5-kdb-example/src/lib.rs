//! Example KDB driver plugin.
//!
//! This is a minimal, read-only plugin that demonstrates the kurbu5-kdb-rs API.
//! It mirrors the capability of `plugins/kdb/test/kdb_test.c` but is written
//! in entirely safe Rust.
//!
//! Configuration (in krb5.conf / kdc.conf):
//!
//! ```text
//! [dbmodules]
//!     example = {
//!         db_library = kurbu5_kdb_example
//!         princs = {
//!             krbtgt/EXAMPLE.COM = {
//!                 flags = +preauth
//!                 maxlife = 1d
//!             }
//!         }
//!     }
//! ```
//!
//! To load: set `database_module = example` in `[realms]`.

use std::collections::HashMap;

use kurbu5_kdb_rs::{
    AsPolicyRequest, KdbContext, KdbError, KdbModule, LookupFlags, OpenMode,
    PacIssuanceOutput, PacIssuanceRequest, PolicyDenied, PrincipalAttributes,
    PrincipalEntry, PrincipalRef, Timestamp, TlDataBuilder, TlDataType,
    kdb_plugin,
};

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

/// Per-context state for the example plugin.
pub struct ExampleKdb {
    /// The name of the dbmodules section we were configured from.
    #[allow(dead_code)]
    conf_section: String,

    /// Hard-coded principal table: name → attributes.
    ///
    /// In a real driver this would be read from a database file or a
    /// connection pool, not hard-coded.
    principals: HashMap<String, PrincipalConfig>,
}

#[derive(Clone)]
struct PrincipalConfig {
    attributes: PrincipalAttributes,
    max_life: i32,
    max_renewable_life: i32,
}

impl PrincipalConfig {
    fn default_tgs() -> Self {
        PrincipalConfig {
            attributes: PrincipalAttributes::REQUIRES_PRE_AUTH,
            max_life: 86400,               // 1 day
            max_renewable_life: 7 * 86400, // 7 days
        }
    }
}

// ---------------------------------------------------------------------------
// KdbModule implementation
// ---------------------------------------------------------------------------

impl KdbModule for ExampleKdb {
    fn open(
        _ctx: &KdbContext<'_>,
        conf_section: &str,
        _db_args: &[&str],
        _mode: OpenMode,
    ) -> Result<Self, KdbError> {
        // In a real driver: read the configuration, open connections, etc.
        // Here we just remember the section name and seed a fake principal table.
        let mut principals = HashMap::new();
        principals.insert(
            "krbtgt/EXAMPLE.COM".to_string(),
            PrincipalConfig::default_tgs(),
        );
        principals.insert(
            "host/kdc.example.com".to_string(),
            PrincipalConfig {
                attributes: PrincipalAttributes::empty(),
                max_life: 86400,
                max_renewable_life: 86400,
            },
        );

        Ok(ExampleKdb {
            conf_section: conf_section.to_string(),
            principals,
        })
    }

    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        _flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        // Turn the principal into a string for the lookup.
        // This is the only allocation on the hot path; unavoidable because
        // we are using a HashMap<String, _>.
        let name = ctx.unparse_principal(search_for)?;

        // Strip the realm for the lookup key (name without @REALM).
        let lookup_key = name
            .find('@')
            .map_or(name.as_str(), |i| &name[..i])
            .to_string();

        let Some(cfg) = self.principals.get(&lookup_key) else {
            return Ok(None);
        };

        // Build the entry using the owned builder API — no unsafe code.
        let mut entry = PrincipalEntry::new();

        // Attach the principal name (parsed back from the string).
        let owned_princ = ctx.parse_principal(&name)?;
        entry.set_princ(ctx, owned_princ);

        entry
            .set_attributes(cfg.attributes)
            .set_max_life(cfg.max_life)
            .set_max_renewable_life(cfg.max_renewable_life)
            .set_expiration(Timestamp::ZERO) // never expires
            .set_pw_expiration(Timestamp::ZERO); // password never expires

        // Add a mod-princ TL-data record so kadmin tools work correctly.
        // The empty TlDataBuilder produces zero TL-data nodes.
        let mut tl = TlDataBuilder::new();
        // (A real driver would populate LastPwdChange, ModPrinc, etc.)
        // For the example we add a dummy string attribute.
        tl.push(TlDataType::StringAttrs, b"source\0example-kdb\0".to_vec());
        entry.set_tl_data(tl.build());

        Ok(Some(entry))
    }

    fn iterate_principals(
        &self,
        ctx: &KdbContext<'_>,
        match_entry: Option<&str>,
        _flags: kurbu5_kdb_rs::IterFlags,
        callback: &mut dyn FnMut(
            kurbu5_kdb_rs::PrincipalEntryRef<'_>,
        ) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        let realm_str =
            ctx.realm().unwrap_or_else(|_| "EXAMPLE.COM".to_string());

        for (key, cfg) in &self.principals {
            // Apply the regex hint (simplified: substring match).
            if let Some(pat) = match_entry {
                if !key.contains(pat) {
                    continue;
                }
            }

            let full_name = format!("{key}@{realm_str}");
            let owned_princ = ctx.parse_principal(&full_name)?;

            let mut entry = PrincipalEntry::new();
            entry
                .set_princ(ctx, owned_princ)
                .set_attributes(cfg.attributes)
                .set_max_life(cfg.max_life)
                .set_max_renewable_life(cfg.max_renewable_life);

            callback(entry.as_ref())?;
            // entry is dropped here; Drop frees the C-allocated memory.
        }
        Ok(())
    }

    fn check_policy_as(
        &self,
        _ctx: &KdbContext<'_>,
        req: AsPolicyRequest<'_>,
    ) -> Result<(), PolicyDenied> {
        // Deny any AS request from a principal that has been administratively
        // disabled (DISALLOW_ALL_TIX).  This is an example of attribute-based
        // access control in the plugin layer.
        if req
            .client
            .attributes()
            .contains(PrincipalAttributes::DISALLOW_ALL_TIX)
        {
            return Err(PolicyDenied::new(
                c"principal is administratively disabled",
            ));
        }
        Ok(())
    }

    fn issue_pac(
        &self,
        ctx: &KdbContext<'_>,
        req: PacIssuanceRequest<'_>,
        output: &mut PacIssuanceOutput<'_>,
    ) -> Result<(), KdbError> {
        // For TGS requests the old PAC (from the header ticket) is provided.
        // Copy all buffers from the old PAC into the new one so any
        // plugin-specific data placed at AS time is preserved across ticket
        // renewals and service-ticket exchanges.
        //
        // The KDC overwrites the standard Microsoft PAC buffers (logon info,
        // checksums, etc.) after this call, so copying them here is harmless.
        if let Some(ref old_pac) = req.old_pac {
            for buf_type in ctx.pac_get_buffer_types(old_pac) {
                if let Some(data) = ctx.pac_get_buffer(old_pac, buf_type) {
                    // Ignore per-buffer errors — best-effort copy.
                    let _ = ctx.pac_add_buffer(
                        &mut output.new_pac,
                        buf_type,
                        &data,
                    );
                }
            }
        }
        Ok(())
    }

    fn refresh_config(&self, _ctx: &KdbContext<'_>) {
        // In a real driver: re-read the config file.
    }
}

// ---------------------------------------------------------------------------
// Plugin export
// ---------------------------------------------------------------------------

// This single macro call:
//   1. Generates the C vtable `kdb_vftabl` for `ExampleKdb`.
//   2. Exports it as the C symbol `kdb_function_table`.
//
// libkdb5 selects this plugin via db_library = kurbu5_kdb_example in krb5.conf,
// loads libkurbu5_kdb_example.so, and dlsym's for `kdb_function_table`.

kdb_plugin!(kurbu5_kdb_example, ExampleKdb);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
