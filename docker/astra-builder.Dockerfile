# Astra Linux ubi18-based builder для Tessera с --features astra-mac.
# Pre-installs build deps, rust toolchain 1.95.0, parsec-base + symlinks.
FROM registry.astralinux.ru/library/astra/ubi18:latest

ARG RUST_VERSION=1.95.0
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
        debhelper dh-cargo \
        libssl-dev libudev-dev libdbus-1-dev libpam0g-dev libsystemd-dev \
        clang libclang-dev \
        pkg-config lintian devscripts fakeroot build-essential \
        parsec-base \
    && rm -rf /var/lib/apt/lists/*

# Best-effort dev headers (no failure if missing).
RUN apt-get update && (apt-get install -y libpdp-dev \
        || apt-get install -y libparsec-dev \
        || apt-get install -y parsec-base-dev \
        || echo "no pdp dev headers package available") \
    && rm -rf /var/lib/apt/lists/* || true

# Create unversioned symlinks for -lpdp / -lparsec-base / -lparsec-mic
# linker resolution (libparsec-mic.so.3 hosts getmicnam/freemicent_r).
RUN set -eux; \
    for L in pdp parsec-base parsec-mic; do \
        for D in /usr/lib /usr/lib/x86_64-linux-gnu /lib /lib/x86_64-linux-gnu; do \
            [ -e "$D/lib${L}.so" ] && break; \
            SRC="$(ls "$D/lib${L}.so."* 2>/dev/null | sort -V | tail -n1 || true)"; \
            if [ -n "$SRC" ]; then \
                ln -sfv "$SRC" "$D/lib${L}.so"; \
                break; \
            fi; \
        done; \
    done

# Rustup + pinned toolchain (matches rust-toolchain.toml).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain none --profile minimal \
    && rustup toolchain install ${RUST_VERSION} \
        --profile minimal \
        --component clippy \
        --component rustfmt \
    && rustup default ${RUST_VERSION}

# cargo-nextest: 30–50% faster test run via parallel runner +
# per-test process isolation. Pre-install pinned binary so CI doesn't
# pay the install cost every run.
ARG NEXTEST_VERSION=0.9.103
RUN curl -fsSL "https://get.nexte.st/${NEXTEST_VERSION}/linux" \
        | tar -xz -C /usr/local/cargo/bin cargo-nextest \
    && /usr/local/cargo/bin/cargo-nextest --version

# Sanity check
RUN gcc --version && rustc --version && \
    nm -D /usr/lib/libpdp.so* 2>/dev/null | grep -E 'pdpl_get_from_text|pdp_set_pid' | head && \
    nm -D /usr/lib/libparsec-base.so* /lib/libparsec-base.so* 2>/dev/null | grep parsec_capget | head

WORKDIR /workspace
