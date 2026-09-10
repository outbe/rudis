# Upstream provenance

- Project: `commonwarexyz/monorepo`
- Package: `commonware-consensus`
- Release: `v2026.5.0`
- Source commit: `b8b0a8d8e2637cb54f36bfdf40336420f5d7bc24`
- Local semantic delta: the Simplex engine waits for the voter task during a
  global graceful shutdown, so the voter finishes its existing final journal
  `sync_all` before the engine handle resolves.

No wire type, journal format, consensus rule, cryptography, or storage API is
changed. The remaining source is the packaged upstream release.
