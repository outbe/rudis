# Upstream provenance

- Project: `paradigmxyz/reth`
- Package: `reth-transaction-pool`
- Release: `v2.2.0`
- Source commit: `88505c7fcbfdebfd3b56d88c86b62e950043c6c4`
- Local semantic delta: queued-lifetime maintenance emits one structured
  `outbe::txpool` warning for each transaction actually removed, including its
  hash, sender, nonce, and `queued_lifetime` reason.

The eviction filter, wall-clock deadline, interval, removal operation, blob
cleanup, transaction types, pool state, and all consensus behavior are
unchanged.
