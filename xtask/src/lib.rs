pub mod ocomp;
pub mod protocol_bench;
pub mod stablecoin;

pub fn repository_root() -> eyre::Result<std::path::PathBuf> {
    use eyre::WrapErr;
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .wrap_err("resolve repository root")?;
    if !output.status.success() {
        eyre::bail!("git could not resolve repository root");
    }
    let path = String::from_utf8(output.stdout).wrap_err("decode repository root")?;
    std::fs::canonicalize(path.trim()).wrap_err("canonicalize repository root")
}
