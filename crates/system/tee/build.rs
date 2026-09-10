use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const PROJECT_TOOLCHAIN: &str = include_str!("../../../release/project-toolchain-v1.json");
const NATIVE_QVL_MANIFEST: &str = include_str!("../../../release/dcap-native-qvl-v1.json");

fn main() {
    // Declared unconditionally so `cfg(native_qvl_linked)` is a known cfg even
    // in builds that never reach the link path below.
    println!("cargo::rustc-check-cfg=cfg(native_qvl_linked)");
    println!("cargo:rerun-if-env-changed=OUTBE_NATIVE_DCAP");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NATIVE_DCAP");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NATIVE_DCAP_TEST_TRACE");
    println!("cargo:rerun-if-changed=../../../release/project-toolchain-v1.json");
    println!("cargo:rerun-if-changed=../../../release/dcap-native-qvl-v1.json");

    if std::env::var_os("CARGO_FEATURE_NATIVE_DCAP").is_none() {
        return;
    }

    let project_pin: serde_json::Value =
        serde_json::from_str(PROJECT_TOOLCHAIN).expect("project toolchain pin must be valid JSON");
    let qvl_manifest: serde_json::Value =
        serde_json::from_str(NATIVE_QVL_MANIFEST).expect("native-QVL manifest must be valid JSON");
    let package_pins = project_pin["system_packages"]
        .as_object()
        .expect("project toolchain must pin system_packages");
    let target = std::env::var("TARGET").expect("Cargo must set TARGET");
    let expected_target = project_pin["target"]
        .as_str()
        .expect("project toolchain must pin target");
    // native-QVL links a Linux SGX .so; on any other host
    // there is nothing to link, so skip. The real enclave build runs on the
    // pinned target and takes the full verification path below.
    if target != expected_target {
        skip_native_qvl_link(&format!("host {target} != pinned {expected_target}"));
        return;
    }

    let build_inputs = qvl_manifest["build_inputs"]
        .as_array()
        .expect("native-QVL manifest must declare build_inputs");
    let artifacts = qvl_manifest["artifacts"]
        .as_array()
        .expect("native-QVL manifest must declare artifacts");
    // The exact-pinned Intel stack only exists on the SGX build image. CI
    // lint/test runners and dev hosts have nothing to link, so skip; an
    // installed-but-mismatched stack still fails hard below.
    if let Some(missing) = build_inputs
        .iter()
        .chain(artifacts)
        .filter_map(|entry| entry["path"].as_str())
        .find(|path| !Path::new(path).exists())
    {
        skip_native_qvl_link(&format!("{missing} is not installed"));
        return;
    }

    let mut required_packages = BTreeSet::new();
    let dcap = qvl_manifest["intel_dcap"]
        .as_object()
        .expect("native-QVL manifest must declare intel_dcap");
    for (package_field, version_field) in [
        ("runtime_package", "runtime_package_version"),
        ("development_package", "development_package_version"),
        ("headers_package", "headers_package_version"),
    ] {
        let package = dcap[package_field]
            .as_str()
            .expect("native-QVL package name must be a string");
        let manifest_version = dcap[version_field]
            .as_str()
            .expect("native-QVL package version must be a string");
        assert_eq!(
            manifest_version,
            pinned_package_version(package_pins, package),
            "native-QVL package version must match the project toolchain pin: {package}"
        );
        required_packages.insert(package);
    }

    let verified_intel_include_dir = PathBuf::from(
        std::env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR for native-QVL build"),
    )
    .join("verified-intel-qvl-include-v1");
    std::fs::create_dir_all(&verified_intel_include_dir)
        .expect("create verified Intel QVL include directory");
    let mut verified_include_names = BTreeSet::new();
    for build_input in build_inputs {
        let package = build_input["package"]
            .as_str()
            .expect("native-QVL build-input package must be a string");
        let manifest_version = build_input["package_version"]
            .as_str()
            .expect("native-QVL build-input package version must be a string");
        assert_eq!(
            manifest_version,
            pinned_package_version(package_pins, package),
            "native-QVL build-input version must match the project toolchain pin: {package}"
        );
        required_packages.insert(package);

        let path = build_input["path"]
            .as_str()
            .expect("native-QVL build-input path must be a string");
        let expected_size = build_input["size"]
            .as_u64()
            .expect("native-QVL build-input size must be an unsigned integer");
        let expected_sha256 = build_input["sha256"]
            .as_str()
            .expect("native-QVL build-input SHA-256 must be a string");
        let payload = read_verified_artifact(path, expected_size, expected_sha256);
        let file_name = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("native-QVL build-input path must have a UTF-8 file name");
        assert!(
            verified_include_names.insert(file_name),
            "duplicate native-QVL build-input file name: {file_name}"
        );
        std::fs::write(verified_intel_include_dir.join(file_name), payload).unwrap_or_else(
            |error| panic!("stage verified native-QVL build input {file_name}: {error}"),
        );
        println!("cargo:rerun-if-changed={path}");
    }

    let mut qvl_library_dir = None;
    for artifact in artifacts {
        let package = artifact["package"]
            .as_str()
            .expect("native-QVL artifact package must be a string");
        let manifest_version = artifact["package_version"]
            .as_str()
            .expect("native-QVL artifact package version must be a string");
        assert_eq!(
            manifest_version,
            pinned_package_version(package_pins, package),
            "native-QVL artifact version must match the project toolchain pin: {package}"
        );
        required_packages.insert(package);

        let path = artifact["path"]
            .as_str()
            .expect("native-QVL artifact path must be a string");
        let expected_size = artifact["size"]
            .as_u64()
            .expect("native-QVL artifact size must be an unsigned integer");
        let expected_sha256 = artifact["sha256"]
            .as_str()
            .expect("native-QVL artifact SHA-256 must be a string");
        drop(read_verified_artifact(path, expected_size, expected_sha256));
        println!("cargo:rerun-if-changed={path}");
        if artifact["role"].as_str() == Some("qvl") {
            qvl_library_dir = Path::new(path).parent().map(Path::to_path_buf);
        }
    }
    for package in required_packages {
        verify_package(package, pinned_package_version(package_pins, package));
    }

    println!("cargo:rerun-if-changed=native/qvl_wrapper.c");
    let mut c = cc::Build::new();
    c.include(&verified_intel_include_dir)
        .file("native/qvl_wrapper.c")
        .flag_if_supported("-std=c11")
        .warnings_into_errors(true);
    if std::env::var_os("CARGO_FEATURE_NATIVE_DCAP_TEST_TRACE").is_some() {
        c.define("OUTBE_QVL_TEST_TRACE", None);
    }
    c.compile("outbe_native_qvl_wrapper");
    let qvl_library_dir: PathBuf =
        qvl_library_dir.expect("native-QVL manifest must contain the qvl artifact");
    println!(
        "cargo:rustc-link-search=native={}",
        qvl_library_dir.display()
    );
    println!("cargo:rustc-link-lib=dylib=sgx_dcap_quoteverify");
    println!("cargo:rustc-cfg=native_qvl_linked");
}

/// Leave `native_qvl_linked` unset: `verify_quote_native` then fails closed on
/// every call instead of forcing the SGX toolchain onto hosts that never verify
/// a quote. Builds that must carry the real QVL set `OUTBE_NATIVE_DCAP=require`.
fn skip_native_qvl_link(reason: &str) {
    assert!(
        std::env::var("OUTBE_NATIVE_DCAP").as_deref() != Ok("require"),
        "OUTBE_NATIVE_DCAP=require, but the pinned Intel native QVL cannot be linked: {reason}"
    );
    println!(
        "cargo:warning=outbe-tee: skipping native-dcap QVL link ({reason}); native quote verification fails closed"
    );
}

fn pinned_package_version<'a>(
    package_pins: &'a serde_json::Map<String, serde_json::Value>,
    package: &str,
) -> &'a str {
    package_pins
        .get(package)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("project toolchain does not pin required package: {package}"))
}

fn verify_package(package: &str, expected_version: &str) {
    let output = Command::new("dpkg-query")
        .args(["--show", "--showformat=${Version}", package])
        .output()
        .unwrap_or_else(|error| panic!("failed to query native-QVL package {package}: {error}"));
    assert!(
        output.status.success(),
        "required native-QVL package is not installed: {package}"
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("dpkg-query version must be UTF-8"),
        expected_version,
        "native-QVL package version mismatch: {package}"
    );
}

fn read_verified_artifact(path: &str, expected_size: u64, expected_sha256: &str) -> Vec<u8> {
    assert!(
        Path::new(path).is_absolute(),
        "native-QVL artifact path must be absolute"
    );
    let payload = std::fs::read(path)
        .unwrap_or_else(|error| panic!("failed to read native-QVL artifact {path}: {error}"));
    assert_eq!(
        u64::try_from(payload.len()).expect("artifact length must fit u64"),
        expected_size,
        "native-QVL artifact size mismatch: {path}"
    );
    let digest = Sha256::digest(&payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        digest, expected_sha256,
        "native-QVL artifact SHA-256 mismatch: {path}"
    );
    payload
}
