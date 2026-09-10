use std::{ffi::OsString, path::Path, process::Command};

use eyre::{bail, eyre, Result, WrapErr};

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Run,
    BaselineCheck,
    BaselineUpdate,
}

impl Action {
    const fn as_argument(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::BaselineCheck => "baseline-check",
            Self::BaselineUpdate => "baseline-update",
        }
    }
}

#[derive(Debug)]
pub struct Options<'a> {
    pub samples: usize,
    pub filter: &'a str,
    pub json: Option<&'a Path>,
    pub baseline: Option<&'a Path>,
}

pub fn run(repo_root: &Path, action: Action, options: &Options<'_>) -> Result<()> {
    if options.samples < 3 {
        bail!("protocol benchmark requires at least 3 samples");
    }
    let mut arguments = vec![
        OsString::from("bench"),
        OsString::from("--locked"),
        OsString::from("--package"),
        OsString::from("outbe-protocol-benchmarks"),
        OsString::from("--bench"),
        OsString::from("protocol_operations"),
        OsString::from("--"),
        OsString::from(action.as_argument()),
        OsString::from("--samples"),
        OsString::from(options.samples.to_string()),
        OsString::from("--filter"),
        OsString::from(options.filter),
    ];
    if let Some(json) = options.json {
        arguments.push(OsString::from("--json"));
        arguments.push(json.as_os_str().to_owned());
    }
    if let Some(baseline) = options.baseline {
        arguments.push(OsString::from("--baseline"));
        arguments.push(baseline.as_os_str().to_owned());
    }
    run_command(repo_root, "cargo", &arguments)
}

fn run_command(repo_root: &Path, program: &str, arguments: &[OsString]) -> Result<()> {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(repo_root)
        .status()
        .wrap_err_with(|| format!("start {program}"))?;
    if !status.success() {
        return Err(eyre!("{program} exited with {status}"));
    }
    Ok(())
}
