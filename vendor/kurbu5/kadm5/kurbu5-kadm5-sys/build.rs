//! build.rs for kurbu5-kadm5-sys
//!
//! kurbu5-kadm5-sys is a thin re-export wrapper over kurbu5-sys.  All bindgen
//! work is done in kurbu5-sys which includes the KADM5 plugin headers
//! (`krb5/kadm5_auth_plugin.h` and `krb5/kadm5_hook_plugin.h`) alongside the
//! other plugin interface headers.  This build script only handles the
//! additional linkage of `libkadm5srv_mit` (the KADM5 server library).
//!
//! Library name confirmed by: `pkg-config --libs kadm-server` → `-lkadm5srv_mit`

fn main() {
    // libkrb5 is already linked via kurbu5-sys's cargo:rustc-link-lib emission.
    // We only add libkadm5srv_mit here.
    println!("cargo:rustc-link-lib=dylib=kadm5srv_mit");
    println!("cargo:rerun-if-changed=build.rs");
}
