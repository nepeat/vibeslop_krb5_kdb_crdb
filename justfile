# Image build + publish. Everything else (tests, e2e) lives in e2e/ and
# `nix develop` — see CLAUDE.md.

# The hub is Harbor: repos live under a <project>/ prefix.
registry := "hub.generalprogramming.org"
image := registry + "/erinpublic/kdc"
tag := `git rev-parse --short HEAD` + `git diff --quiet HEAD 2>/dev/null || echo -dirty`

# aarch64 builds on x86 need qemu binfmt registered once per boot:
#   docker run --privileged --rm tonistiigi/binfmt --install arm64
# (flags must include F — check /proc/sys/fs/binfmt_misc/qemu-aarch64)

_default:
    @just --list

# Build the KDC image for one arch (x86_64 or aarch64); prints the tarball path.
image-build arch="x86_64":
    nix build --extra-platforms {{ arch }}-linux \
        .#packages.{{ arch }}-linux.kdc-image --print-out-paths --no-link

# Build for the host arch and load into the local docker daemon.
image-load:
    docker load -i $(nix build .#kdc-image --print-out-paths --no-link)

# Build both arches, push {{ image }}:{{ tag }} + :latest as a multi-arch manifest list (auth: ~/.docker/config.json).
image-push: (_push-arch "x86_64" "amd64") (_push-arch "aarch64" "arm64")
    nix run nixpkgs#manifest-tool -- push from-args \
        --platforms linux/amd64,linux/arm64 \
        --template {{ image }}:{{ tag }}-ARCH \
        --target {{ image }}:{{ tag }}
    nix run nixpkgs#manifest-tool -- push from-args \
        --platforms linux/amd64,linux/arm64 \
        --template {{ image }}:{{ tag }}-ARCH \
        --target {{ image }}:latest
    @echo "pushed {{ image }}:{{ tag }} and :latest (amd64+arm64)"

_push-arch arch docker_arch:
    nix run nixpkgs#skopeo -- copy \
        docker-archive:$(just image-build {{ arch }} | tail -1) \
        docker://{{ image }}:{{ tag }}-{{ docker_arch }}
