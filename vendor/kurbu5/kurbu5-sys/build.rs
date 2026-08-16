//! build.rs for kurbu5-sys
//!
//! Generates Rust FFI bindings for the MIT Kerberos libkrb5 API (krb5.h) and
//! the KDB plugin API (kdb.h) using bindgen.  Both headers are included here
//! because kdb.h types are tightly coupled to krb5.h types and must share the
//! same Rust type definitions to be ABI-compatible across crates.
//!
//! The generated file is written to `$OUT_DIR/bindings.rs`.
//!
//! Key design choices:
//!
//! * We include krb5.h (base types), kdb.h (KDB plugin API), and all non-KDB
//!   plugin interface headers from <krb5/>.  All are grouped in one bindgen
//!   invocation so they share the same krb5_* type definitions.
//!
//! * We allowlist only the symbols that are actually part of the public plugin
//!   surface.  This keeps the generated file small and avoids exposing
//!   internal krb5 types that may change between releases.
//!
//! * Layout tests are emitted so that any ABI mismatch between the C headers
//!   used at build time and the library loaded at runtime causes a test
//!   failure rather than silent corruption.

use std::{env, path::PathBuf};

fn main() {
    // ------------------------------------------------------------------
    // Locate the krb5 include directory.
    //
    // Search order:
    //   1. KRB5_INCLUDE_DIR environment variable (explicit override).
    //   2. pkg-config (krb5 >= 1.21).
    //   3. Default system paths (/usr/include, /usr/local/include).
    // ------------------------------------------------------------------
    let include_dir = find_krb5_include();

    // ------------------------------------------------------------------
    // Vendored private headers.
    //
    // Some MIT Kerberos plugin interfaces (e.g. audit_plugin.h) are declared
    // in private headers that are not installed alongside the public API.  We
    // vendor those headers under kurbu5-sys/include/ so bindgen can process
    // them even on systems where the full Kerberos source tree is absent.
    //
    // The vendored directory is always added as an *additional* search path
    // (not as a replacement for the system headers).  The audit_plugin.h
    // vendored copy includes <krb5/krb5.h>, which resolves against the system
    // include dir found above.
    // ------------------------------------------------------------------
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let vendored_include = format!("{manifest_dir}/include");
    println!("cargo:rerun-if-changed=include/krb5/audit_plugin.h");

    // Emit link search path so downstream crates' linker can find the libs.
    if let Some(lib_dir) = find_krb5_lib() {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }
    println!("cargo:rustc-link-lib=dylib=krb5");
    println!("cargo:rustc-link-lib=dylib=kdb5");

    // Rebuild if the headers or build script change.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=KRB5_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=KRB5_LIB_DIR");

    // ------------------------------------------------------------------
    // bindgen configuration
    // ------------------------------------------------------------------
    let bindings = configure_bindgen(&include_dir, &vendored_include)
        .generate()
        .expect("bindgen failed to generate krb5 + KDB bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

/// Build a fully-configured `bindgen::Builder` for the krb5 + KDB headers.
///
/// Separated from `main` to keep each function under the line-count limit.
fn configure_bindgen(
    include_dir: &str,
    vendored_include: &str,
) -> bindgen::Builder {
    // Include the base libkrb5 API, the KDB plugin API, and all non-KDB
    // plugin interface headers.  Grouping them in one bindgen invocation
    // guarantees that all headers share the same krb5_* type definitions.
    //
    // audit_plugin.h is a private MIT Kerberos header (not installed in the
    // system include tree).  It is included from the vendored copy under
    // kurbu5-sys/include/krb5/audit_plugin.h.  The vendored directory is
    // added via clang_arg below so the include resolves correctly.
    let builder = bindgen::Builder::default()
        .header_contents(
            "wrapper.h",
            &format!(
                "#include <{include_dir}/krb5.h>\n\
                 #include <{include_dir}/kdb.h>\n\
                 #include <{include_dir}/krb5/pwqual_plugin.h>\n\
                 #include <{include_dir}/krb5/hostrealm_plugin.h>\n\
                 #include <{include_dir}/krb5/localauth_plugin.h>\n\
                 #include <{include_dir}/krb5/ccselect_plugin.h>\n\
                 #include <{include_dir}/krb5/kdcpreauth_plugin.h>\n\
                 #include <{include_dir}/krb5/clpreauth_plugin.h>\n\
                 #include <{include_dir}/krb5/kdcpolicy_plugin.h>\n\
                 #include <{include_dir}/krb5/certauth_plugin.h>\n\
                 #include <{include_dir}/krb5/kadm5_auth_plugin.h>\n\
                 #include <{include_dir}/krb5/kadm5_hook_plugin.h>\n\
                 #include <{include_dir}/profile.h>\n\
                 #include <krb5/audit_plugin.h>\n",
            ),
        )
        // Vendored include directory: makes `#include <krb5/audit_plugin.h>`
        // resolve against our local copy when the system does not install it.
        .clang_arg(format!("-I{vendored_include}"))
        // Derive useful traits where the struct layout allows it.
        .derive_default(true)
        .derive_debug(true)
        // Emit layout (size + alignment) tests for ABI validation.
        .layout_tests(true)
        // Translate C enums as Rust constants rather than enums so that
        // unknown values do not cause undefined behaviour.
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        // Silence warnings about types that are intentionally incomplete.
        .blocklist_type("FILE")
        // Block glibc private types (e.g. __dev_t, __ino_t) but keep:
        //  - __krb5_* (MIT Kerberos internal types backing public typedefs)
        //  - __time* (__time_t backs time_t which some krb5 structs reference)
        .blocklist_type("__(?!krb5_|time).*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    apply_allowlists(builder)
}

/// Apply type allowlists for all plugin vtable and moddata types.
///
/// Separated from `configure_bindgen` to keep each function under the
/// line-count limit imposed by `clippy::too_many_lines`.
fn apply_allowlists(builder: bindgen::Builder) -> bindgen::Builder {
    let b = builder
        // Base libkrb5 types shared by all plugin interfaces.
        .allowlist_type("krb5_.*")
        // KDB plugin API types.
        .allowlist_type("kdb_vftabl")
        .allowlist_type("osa_policy_ent.*")
        // Non-KDB plugin vtable structs (one per plugin interface header).
        .allowlist_type("krb5_pwqual_vtable_st")
        .allowlist_type("krb5_hostrealm_vtable_st")
        .allowlist_type("krb5_localauth_vtable_st")
        .allowlist_type("krb5_ccselect_vtable_st")
        .allowlist_type("krb5_kdcpreauth_vtable_st")
        .allowlist_type("krb5_kdcpreauth_callbacks_st")
        .allowlist_type("krb5_clpreauth_vtable_st")
        .allowlist_type("krb5_clpreauth_callbacks_st")
        .allowlist_type("krb5_kdcpolicy_vtable_st")
        .allowlist_type("krb5_certauth_vtable_st")
        // Audit plugin vtable and state types (private MIT Kerberos interface;
        // sourced from the vendored copy of audit_plugin.h).
        .allowlist_type("krb5_audit_vtable_st")
        .allowlist_type("krb5_audit_moddata_st")
        .allowlist_type("_krb5_audit_state")
        // KADM5 plugin vtable structs.
        .allowlist_type("kadm5_auth_vtable_st")
        .allowlist_type("kadm5_hook_vtable_1_st")
        // Abstract plugin-data pointer types (opaque structs).
        .allowlist_type("krb5_pwqual_moddata_st")
        .allowlist_type("krb5_hostrealm_moddata_st")
        .allowlist_type("krb5_localauth_moddata_st")
        .allowlist_type("krb5_ccselect_moddata_st")
        .allowlist_type("krb5_kdcpreauth_moddata_st")
        .allowlist_type("krb5_kdcpreauth_modreq_st")
        .allowlist_type("krb5_kdcpreauth_rock_st")
        .allowlist_type("krb5_clpreauth_moddata_st")
        .allowlist_type("krb5_clpreauth_modreq_st")
        .allowlist_type("krb5_clpreauth_rock_st")
        .allowlist_type("krb5_kdcpolicy_moddata_st")
        .allowlist_type("krb5_certauth_moddata_st")
        // Audit plugin abstract data pointer type.
        .allowlist_type("krb5_audit_moddata_st")
        // KADM5 plugin abstract data pointer types.
        .allowlist_type("kadm5_auth_moddata_st")
        .allowlist_type("kadm5_hook_modinfo_st")
        // KADM5 principal and policy entry types.
        .allowlist_type("_kadm5_principal_ent_t")
        .allowlist_type("_kadm5_policy_ent_t")
        // KADM5 key data type (kvno + keyblock + keysalt).
        .allowlist_type("kadm5_key_data")
        // KADM5 admin API config params — opaque; embeds gssrpc/rpc.h types.
        .opaque_type("kadm5_config_params")
        // KADM5 auth restrictions struct (returned by addprinc/modprinc).
        .allowlist_type("kadm5_auth_restrictions")
        // KADM5 hook stage enum and return type.
        .allowlist_type("kadm5_hook_stage")
        .allowlist_type("kadm5_ret_t")
        // KADM5 principal/policy field mask constants.
        .allowlist_var("KADM5_.*")
        // Generic plugin vtable base (used by initvt functions).
        .allowlist_type("krb5_plugin_vtable_st")
        // Profile API type.
        .allowlist_type("_profile_t");
    apply_fn_and_var_allowlists(b)
}

/// Apply function and variable allowlists for krb5 and plugin APIs.
fn apply_fn_and_var_allowlists(builder: bindgen::Builder) -> bindgen::Builder {
    builder
        // KDB functions.
        .allowlist_function("krb5_db_.*")
        .allowlist_function("krb5_dbe_.*")
        .allowlist_function("krb5_def_.*")
        // Principal name operations used by context utilities.
        .allowlist_function("krb5_unparse_name")
        .allowlist_function("krb5_free_unparsed_name")
        .allowlist_function("krb5_parse_name")
        .allowlist_function("krb5_free_principal")
        // Realm accessor (context struct is opaque in the public API).
        .allowlist_function("krb5_get_default_realm")
        .allowlist_function("krb5_free_default_realm")
        // PAC (Privilege Attribute Certificate) operations.
        .allowlist_function("krb5_pac_.*")
        // Context lifecycle.
        .allowlist_function("krb5_init_context")
        .allowlist_function("krb5_init_context_profile")
        .allowlist_function("krb5_copy_context")
        .allowlist_function("krb5_free_context")
        // Profile API — read kdc.conf / krb5.conf values from a krb5_context.
        // krb5_get_profile retrieves a profile_t handle; the profile_* family
        // queries and frees profile values.  Used by preauth plugins that read
        // their configuration from the [otp] (or similar) kdc.conf section.
        .allowlist_function("krb5_get_profile")
        .allowlist_function("profile_abandon")
        .allowlist_function("profile_release")
        .allowlist_function("profile_free_list")
        .allowlist_function("profile_release_string")
        .allowlist_function("profile_get_subsection_names")
        .allowlist_function("profile_get_string")
        .allowlist_function("profile_get_integer")
        .allowlist_function("profile_get_boolean")
        .allowlist_function("profile_get_values")
        // Memory management for heap-allocated krb5_data.
        .allowlist_function("krb5_free_data")
        // Symmetric-key crypto operations (encrypt, decrypt, random).
        // Used by preauth plugins that encrypt/decrypt session-key material.
        .allowlist_function("krb5_c_encrypt_length")
        .allowlist_function("krb5_c_encrypt")
        .allowlist_function("krb5_c_decrypt")
        .allowlist_function("krb5_c_random_make_octets")
        // CF2 key combination (RFC 6113) — used by PKINIT-KX (RFC 6112).
        .allowlist_function("krb5_c_fx_cf2_simple")
        // Keyblock memory management.
        .allowlist_function("krb5_free_keyblock")
        .allowlist_function("krb5_free_keyblock_contents")
        // Key-usage constants for preauth crypto operations.
        .allowlist_var("KRB5_KEYUSAGE_.*")
        // Additional principal utilities used by overlay plugins.
        .allowlist_function("krb5_copy_principal")
        .allowlist_function("krb5_unparse_name_flags")
        .allowlist_var("KRB5_PRINCIPAL_UNPARSE_.*")
        // Error message API used by non-KDB plugin glue layers.
        .allowlist_function("krb5_set_error_message")
        .allowlist_function("krb5_vset_error_message")
        // Complete KADM5 admin API — kadm5/admin.h is pulled in transitively
        // via krb5/kadm5_hook_plugin.h.  All older function variants are also
        // bound at the sys level; the safe Rust layer wraps only the latest.
        //
        // Config-params helpers
        .allowlist_function("kadm5_get_config_params")
        .allowlist_function("kadm5_free_config_params")
        .allowlist_function("kadm5_get_admin_service_name")
        // Context init
        .allowlist_function("kadm5_init_krb5_context")
        // Handle init — all variants
        .allowlist_function("kadm5_init")
        .allowlist_function("kadm5_init_anonymous")
        .allowlist_function("kadm5_init_with_password")
        .allowlist_function("kadm5_init_with_skey")
        .allowlist_function("kadm5_init_with_creds")
        // Handle lifecycle
        .allowlist_function("kadm5_lock")
        .allowlist_function("kadm5_unlock")
        .allowlist_function("kadm5_flush")
        .allowlist_function("kadm5_destroy")
        .allowlist_function("kadm5_init_iprop")
        // Principal management — all versions
        .allowlist_function("kadm5_create_principal")
        .allowlist_function("kadm5_create_principal_3")
        .allowlist_function("kadm5_delete_principal")
        .allowlist_function("kadm5_modify_principal")
        .allowlist_function("kadm5_rename_principal")
        .allowlist_function("kadm5_get_principal")
        .allowlist_function("kadm5_get_principals")
        .allowlist_function("kadm5_free_principal_ent")
        // Password / key operations — all versions
        .allowlist_function("kadm5_chpass_principal")
        .allowlist_function("kadm5_chpass_principal_3")
        .allowlist_function("kadm5_chpass_principal_util")
        .allowlist_function("kadm5_randkey_principal")
        .allowlist_function("kadm5_randkey_principal_3")
        .allowlist_function("kadm5_setkey_principal")
        .allowlist_function("kadm5_setkey_principal_3")
        .allowlist_function("kadm5_setkey_principal_4")
        .allowlist_function("kadm5_decrypt_key")
        .allowlist_function("kadm5_get_principal_keys")
        .allowlist_function("kadm5_purgekeys")
        // Policy management
        .allowlist_function("kadm5_create_policy")
        .allowlist_function("kadm5_delete_policy")
        .allowlist_function("kadm5_modify_policy")
        .allowlist_function("kadm5_get_policy")
        .allowlist_function("kadm5_get_policies")
        .allowlist_function("kadm5_free_policy_ent")
        // Privilege query
        .allowlist_function("kadm5_get_privs")
        // String attributes
        .allowlist_function("kadm5_get_strings")
        .allowlist_function("kadm5_set_string")
        .allowlist_function("kadm5_free_strings")
        // Memory helpers
        .allowlist_function("kadm5_free_key_data")
        .allowlist_function("kadm5_free_kadm5_key_data")
        .allowlist_function("kadm5_free_name_list")
        // Alias
        .allowlist_function("kadm5_create_alias")
        // KDB constants.
        .allowlist_var("KRB5_KDB_.*")
        .allowlist_var("KRB5_DB_.*")
        .allowlist_var("KRB5_TL_.*")
        .allowlist_var("KRB5_PLUGIN_.*")
        // Magic numbers and KDC error codes used by the glue layer.
        .allowlist_var("KV5M_.*")
        .allowlist_var("KRB5KDC_ERR_.*")
        // Non-KDB plugin interface constants.
        .allowlist_var("KRB5_CCSELECT_PRIORITY_.*")
        .allowlist_var("KRB5_CC_NOTFOUND")
        .allowlist_var("KRB5_CERTAUTH_HWAUTH.*")
        .allowlist_var("KRB5_LNAME_NOTRANS")
        .allowlist_var("PA_HARDWARE")
        .allowlist_var("PA_REQUIRED")
        .allowlist_var("PA_SUFFICIENT")
        .allowlist_var("PA_REPLACES_KEY")
        .allowlist_var("PA_PSEUDO")
        .allowlist_var("PA_TYPED_E_DATA")
        .allowlist_var("PA_REAL")
        .allowlist_var("PA_INFO")
        // Audit plugin constants: KDC processing stages, violation types, and
        // the request-ID length.
        .allowlist_var("AUTHN_REQ_CL")
        .allowlist_var("SRVC_PRINC")
        .allowlist_var("VALIDATE_POL")
        .allowlist_var("ISSUE_TKT")
        .allowlist_var("ENCR_REP")
        .allowlist_var("PROT_CONSTRAINT")
        .allowlist_var("LOCAL_POLICY")
        .allowlist_var("REQID_LEN")
}

/// Return the krb5 include directory as a string suitable for use in
/// `#include <dir/krb5.h>`.
fn find_krb5_include() -> String {
    // 1. Explicit override.
    if let Ok(dir) = env::var("KRB5_INCLUDE_DIR") {
        return dir;
    }

    // 2. pkg-config.
    if let Ok(lib) = pkg_config::probe_library("krb5") {
        if let Some(path) = lib.include_paths.first() {
            return path.to_string_lossy().into_owned();
        }
    }

    // 3. Default.
    "/usr/include".to_string()
}

/// Return the directory containing libkrb5.so, if determinable.
fn find_krb5_lib() -> Option<PathBuf> {
    if let Ok(dir) = env::var("KRB5_LIB_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(lib) = pkg_config::probe_library("krb5") {
        return lib.link_paths.into_iter().next();
    }
    None
}
