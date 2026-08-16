{
  # Dev shell for kdb-crdb:
  #   nix develop --command cargo build
  #
  # nixpkgs-unstable for krb5 >= 1.22.1 — kurbu5 0.1.2 needs its headers
  # (krb5_db_load_module is not declared in 1.21's kdb.h). Version pinning
  # lives in flake.lock.
  description = "kdb-crdb dev environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems
        (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            pkg-config
            openssl # postgres-native-tls
            krb5 # kurbu5-sys bindgen + libkdb5 link
            # Rust from nixpkgs so the shell is self-contained on hosts
            # without rustup (e.g. the AWS ARM bench nodes).
            cargo
            rustc
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # The cdylib links openssl (native-tls). Nix-built krb5 daemons
          # resolve dlopen deps without the system ld cache, so give the
          # plugin an rpath to the nix openssl it was built against.
          RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.openssl.out}/lib";

          # bindgen drives clang directly and doesn't see the cc-wrapper's
          # default include paths, so spell them out: clang's builtin
          # headers (stddef.h), glibc, and the krb5 dev headers.
          BINDGEN_EXTRA_CLANG_ARGS = builtins.concatStringsSep " " [
            "-isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.libclang.version}/include"
            "-isystem ${pkgs.glibc.dev}/include"
            "-I${pkgs.krb5.dev}/include"
          ];
        };
      });
    };
}
