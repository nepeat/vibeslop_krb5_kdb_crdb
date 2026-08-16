//! build.rs for kurbu5-kdb-sys
//!
//! kurbu5-kdb-sys is a thin re-export wrapper over kurbu5-sys.  All bindgen work is
//! done in kurbu5-sys.  This build script only handles the additional linkage
//! of libkdb5 (the KDB plugin loader library).

fn main() {
    // libkrb5 is already linked via kurbu5-sys's cargo:rustc-link-lib emission.
    // We only need to add libkdb5 here.
    println!("cargo:rustc-link-lib=dylib=kdb5");
    println!("cargo:rerun-if-changed=build.rs");
}
