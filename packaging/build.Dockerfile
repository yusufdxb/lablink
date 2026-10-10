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
# rustup-init pinned by version and SHA-256 (published at
# https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init.sha256);
# rustup then verifies the toolchain components it downloads.
ARG RUSTUP_VERSION=1.28.2
ARG RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
RUN curl --proto '=https' --tlsv1.2 -sSf -o /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && rm /tmp/rustup-init \
    && /root/.cargo/bin/rustc --version
ENV PATH=/root/.cargo/bin:$PATH
WORKDIR /src
