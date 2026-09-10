# Immutable testnet release runtime. The build context is a verified, pre-signed
# SGX bundle produced by `cargo xtask release sgx sign`; it is never the source
# checkout. The pinned Gramine image contains no Outbe signing key.
FROM gramineproject/gramine:1.9-noble@sha256:bdf2d0ef9bd09fa10684e14fbe822236df35708d58a852209c5f235842ecb6d7

COPY rootfs/ /

ENTRYPOINT ["/opt/outbe/sgx/bin/outbe-tee-enclave-launch"]
