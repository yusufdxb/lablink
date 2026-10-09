# Release build environment. Ubuntu 20.04 (glibc 2.31) is the oldest
# supported target: binaries linked here run on 20.04, 22.04 and 24.04.
# The base image is pinned by digest and the Rust toolchain by version, so a
# rebuild of the same commit uses the same environment.
FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl git dpkg-dev binutils xz-utils \
    && rm -rf /var/lib/apt/lists/*
ARG RUST_TOOLCHAIN
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && /root/.cargo/bin/rustc --version
ENV PATH=/root/.cargo/bin:$PATH
WORKDIR /src
