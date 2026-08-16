{
  # Dev shell + release artifacts for kdb-crdb:
  #   nix develop --command cargo build   # hacking
  #   nix build .#kdb-crdb                # the plugin cdylib -> result/lib
  #   nix build .#kdc-image               # KDC container (docker-archive tar.gz)
  #
  # nixpkgs-unstable for krb5 >= 1.22.1 — kurbu5 0.1.2 needs its headers
  # (krb5_db_load_module is not declared in 1.21's kdb.h). Version pinning
  # lives in flake.lock.
  description = "kdb-crdb dev environment + KDC container image";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems
        (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        default = kdb-crdb;

        kdb-crdb = pkgs.rustPlatform.buildRustPackage {
          pname = "kdb-crdb";
          version = "0.1.0";
          # Only what cargo needs — doc/infra edits don't rebuild the image.
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml ./Cargo.lock ./src ./vendor
            ];
          };
          # No git deps in the lockfile: kurbu5 is [patch]ed to vendor/.
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config pkgs.rustPlatform.bindgenHook ];
          buildInputs = [ pkgs.openssl pkgs.krb5 ];
          # store/marshal tests need a live CRDB cluster — see e2e/.
          doCheck = false;
        };

        tgsbench = pkgs.stdenv.mkDerivation {
          name = "tgsbench";
          dontUnpack = true;
          nativeBuildInputs = [ pkgs.krb5.dev ]; # krb5-config
          buildInputs = [ pkgs.krb5 ];
          buildPhase = ''
            cc -O2 -o tgsbench ${./e2e/tgsbench.c} \
              $(krb5-config --cflags --libs krb5) -lpthread
          '';
          installPhase = "install -Dm555 tgsbench $out/bin/tgsbench";
        };

        # Filesystem skeleton the daemons expect: the plugin under the
        # db_module_dir path, and a real /etc/passwd (without one,
        # kadmin.local needs -p — bit us in the k8s loadgen pod).
        kdc-rootfs = pkgs.runCommand "kdc-rootfs" { } ''
          install -d $out/etc $out/opt/kdb
          ln -s ${kdb-crdb}/lib/libkdb_crdb.so $out/opt/kdb/kdb_crdb.so
          cat > $out/etc/passwd <<'EOF'
          root:x:0:0:root:/var/lib/krb5kdc:/bin/sh
          kdc:x:1000:1000:kdc:/var/lib/krb5kdc:/bin/sh
          nobody:x:65534:65534:nobody:/:/bin/sh
          EOF
          cat > $out/etc/group <<'EOF'
          root:x:0:
          kdc:x:1000:
          nogroup:x:65534:
          EOF
          echo 'hosts: files dns' > $out/etc/nsswitch.conf
        '';

        # Config (/config) and secrets (/secrets) are mount points — the
        # image carries no realm state. Runs as root under podman; k8s
        # overrides to uid 1000 (paths are uid-agnostic).
        kdc-image = pkgs.dockerTools.buildLayeredImage {
          name = "localhost/kdc";
          tag = "latest";
          contents = [
            (pkgs.buildEnv {
              name = "kdc-bin";
              paths = with pkgs; [ krb5 bash coreutils gnugrep gawk tgsbench ];
              pathsToLink = [ "/bin" "/sbin" ];
            })
            kdc-rootfs
          ];
          extraCommands = ''
            mkdir -p tmp var/lib/krb5kdc
            chmod 1777 tmp
          '';
          config = {
            Cmd = [ "krb5kdc" "-n" ];
            Env = [
              "PATH=/bin:/sbin"
              "KRB5_CONFIG=/config/krb5.conf"
              "KRB5_KDC_PROFILE=/config/kdc.conf"
            ];
          };
        };
      });

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
