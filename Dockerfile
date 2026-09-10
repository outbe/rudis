# Multi-stage build for outbe-chain.
#
# Build context is the outbe-chain repository root:
#   docker build -f Dockerfile -t outbe-chain .
#
# The CI prerelease workflow uses the same context/path pair.

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM rust:1.96-bookworm AS builder

RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    libc++-dev \
    libc++abi-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the repository checkout.
COPY . .

WORKDIR /build

# Build release binaries
RUN cargo build --release --bin outbe-chain --bin outbe-keygen --bin outbe-cli

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libc++1 \
    libc++abi1 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /build/target/release/outbe-chain /usr/local/bin/
COPY --from=builder /build/target/release/outbe-keygen /usr/local/bin/
COPY --from=builder /build/target/release/outbe-cli /usr/local/bin/

# Default data directory
VOLUME /data

# Expose ports: P2P, RPC, Metrics, Consensus P2P
EXPOSE 30303 8545 9001 30400

ENTRYPOINT ["outbe-chain"]
CMD ["node", "--datadir", "/data"]
