# Commonware runtime provenance

- Source: `https://github.com/commonwarexyz/monorepo`
- Baseline: tag `v2026.5.0`, commit
  `b8b0a8d8919a66b5649c9fdaceb881a55fbe5876`
- Vendored scope: `runtime/` only
- Local change: backport the Tokio runtime ownership portion of upstream commit
  `3b768fe8b0876ad821406c16732bf5d4af15ef41` (PR #4501).

The local patch keeps the concrete `tokio::runtime::Runtime` owned by
`Runner::start`; shared `Executor`/`Context` values retain only a
`tokio::runtime::Handle`. No public Commonware API, wire format, storage format,
or dependency version is changed.
