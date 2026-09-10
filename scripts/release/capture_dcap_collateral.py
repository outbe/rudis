#!/usr/bin/env python3
"""Capture one self-contained Intel DCAP collateral snapshot outside consensus."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
NATIVE_MANIFEST = REPO_ROOT / "release/dcap-native-qvl-v1.json"
PROJECT_PIN = REPO_ROOT / "release/project-toolchain-v1.json"
RFC3339_SECONDS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class _CollateralVersionParts(ctypes.Structure):
    _fields_ = [
        ("major_version", ctypes.c_uint16),
        ("minor_version", ctypes.c_uint16),
    ]


class _CollateralVersion(ctypes.Union):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("parts", _CollateralVersionParts),
    ]


class _QuoteCollateral(ctypes.Structure):
    _fields_ = [
        ("version", _CollateralVersion),
        ("tee_type", ctypes.c_uint32),
        ("pck_crl_issuer_chain", ctypes.c_void_p),
        ("pck_crl_issuer_chain_size", ctypes.c_uint32),
        ("root_ca_crl", ctypes.c_void_p),
        ("root_ca_crl_size", ctypes.c_uint32),
        ("pck_crl", ctypes.c_void_p),
        ("pck_crl_size", ctypes.c_uint32),
        ("tcb_info_issuer_chain", ctypes.c_void_p),
        ("tcb_info_issuer_chain_size", ctypes.c_uint32),
        ("tcb_info", ctypes.c_void_p),
        ("tcb_info_size", ctypes.c_uint32),
        ("qe_identity_issuer_chain", ctypes.c_void_p),
        ("qe_identity_issuer_chain_size", ctypes.c_uint32),
        ("qe_identity", ctypes.c_void_p),
        ("qe_identity_size", ctypes.c_uint32),
    ]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_type5_pck_chain(quote: bytes) -> bytes:
    """Return the exact type-5 certification data from a complete SGX quote v3."""
    fixed_quote_size = 436
    fixed_authentication_size = 64 + 64 + 384 + 64
    if len(quote) < fixed_quote_size + fixed_authentication_size + 8:
        raise ValueError("quote is shorter than the SGX v3 authentication structure")
    if int.from_bytes(quote[0:2], "little") != 3:
        raise ValueError("quote version is not SGX quote v3")
    if int.from_bytes(quote[4:8], "little") != 0:
        raise ValueError("quote tee_type is not SGX")

    authentication_size = int.from_bytes(quote[432:436], "little")
    if fixed_quote_size + authentication_size != len(quote):
        raise ValueError("quote has trailing or truncated authentication bytes")

    cursor = fixed_quote_size + fixed_authentication_size
    qe_authentication_size = int.from_bytes(quote[cursor : cursor + 2], "little")
    cursor += 2 + qe_authentication_size
    if cursor + 6 > len(quote):
        raise ValueError("quote certification-data header is truncated")
    certification_data_type = int.from_bytes(quote[cursor : cursor + 2], "little")
    certification_data_size = int.from_bytes(quote[cursor + 2 : cursor + 6], "little")
    cursor += 6
    end = cursor + certification_data_size
    if certification_data_type != 5:
        raise ValueError("quote certification data is not type 5")
    if end != len(quote):
        raise ValueError("quote has trailing or truncated certification data")

    pck_chain = quote[cursor:end]
    if (
        not pck_chain.startswith(b"-----BEGIN CERTIFICATE-----\n")
        or not pck_chain.endswith(b"\0")
        or b"\0" in pck_chain[:-1]
    ):
        raise ValueError("type-5 PCK certificate chain is not canonical PEM plus NUL")
    return pck_chain


def canonical_text_component(value: bytes, label: str) -> bytes:
    """Remove the QPL ABI terminator while rejecting ambiguous text bytes."""
    if not value.endswith(b"\0") or value.endswith(b"\0\0") or b"\0" in value[:-1]:
        raise ValueError(f"{label} is not terminated by exactly one NUL")
    canonical = value[:-1]
    if not canonical:
        raise ValueError(f"{label} is empty")
    try:
        canonical.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8") from error
    return canonical


def canonical_crl_component(value: bytes, minor_version: int, label: str) -> bytes:
    """Normalize PCS v3.0 hex CRLs and v3.1 raw CRLs to canonical DER."""
    if minor_version == 1:
        if not value:
            raise ValueError(f"{label} is empty")
        return value
    if minor_version != 0:
        raise ValueError(f"{label} uses unsupported collateral minor version")
    encoded = canonical_text_component(value, label)
    if len(encoded) % 2 != 0:
        raise ValueError(f"{label} contains odd-length hexadecimal DER")
    try:
        return bytes.fromhex(encoded.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"{label} is not canonical hexadecimal DER") from error


def _bytes_at(pointer: int | None, size: int, label: str) -> bytes:
    if not pointer or size == 0:
        raise ValueError(f"QPL returned empty {label}")
    return ctypes.string_at(pointer, size)


def _artifact(manifest: dict, role: str) -> dict:
    for artifact in manifest["artifacts"]:
        if artifact["role"] == role:
            return artifact
    raise ValueError(f"native manifest has no {role} artifact")


def _package_version(name: str) -> str:
    completed = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", name],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def load_host_qpl_pin() -> dict[str, str]:
    pin = json.loads(PROJECT_PIN.read_text(encoding="utf-8"))
    packages = pin.get("host_only_packages")
    if not isinstance(packages, dict) or set(packages) != {
        "libsgx-dcap-default-qpl"
    }:
        raise ValueError("single project pin lacks the exact host-only QPL package")
    version = packages["libsgx-dcap-default-qpl"]
    if not isinstance(version, str) or not version or any(
        character.isspace() for character in version
    ):
        raise ValueError("single project pin has an invalid host-only QPL version")
    return {"package": "libsgx-dcap-default-qpl", "version": version}


def _library_provenance(
    path: Path, package: str, expected_version: str | None = None
) -> dict:
    resolved = path.resolve(strict=True)
    package_version = _package_version(package)
    if expected_version is not None and package_version != expected_version:
        raise ValueError(
            f"host package {package} version {package_version!r} does not match "
            f"the single project pin {expected_version!r}"
        )
    return {
        "package": package,
        "package_version": package_version,
        "path": str(resolved),
        "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def crl_provenance(path: Path, crl_type: str) -> dict:
    if crl_type not in {"processor", "platform", "root"}:
        raise ValueError(f"unsupported CRL type: {crl_type}")
    completed = subprocess.run(
        [
            "openssl",
            "crl",
            "-inform",
            "DER",
            "-in",
            str(path),
            "-noout",
            "-issuer",
            "-lastupdate",
            "-nextupdate",
            "-dateopt",
            "iso_8601",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    fields = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value.strip()
    issuer = fields.get("issuer", "")
    this_update = fields.get("lastUpdate", "").replace(" ", "T", 1)
    next_update = fields.get("nextUpdate", "").replace(" ", "T", 1)
    if (
        not issuer
        or not RFC3339_SECONDS_RE.fullmatch(this_update)
        or not RFC3339_SECONDS_RE.fullmatch(next_update)
    ):
        raise ValueError("OpenSSL did not return canonical CRL issuer and validity dates")
    return {
        "issuer": issuer,
        "next_update": next_update,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "this_update": this_update,
        "type": crl_type,
    }


def capture_collateral(quote: bytes) -> tuple[dict[str, bytes], dict]:
    manifest = json.loads(NATIVE_MANIFEST.read_text(encoding="utf-8"))
    qvl_artifact = _artifact(manifest, "qvl")
    qvl_path = Path(qvl_artifact["path"]).resolve(strict=True)
    if sha256_file(qvl_path) != qvl_artifact["sha256"]:
        raise ValueError("installed QVL digest does not match release/dcap-native-qvl-v1.json")

    library = ctypes.CDLL(str(qvl_path))
    library.tee_qv_get_collateral.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.tee_qv_get_collateral.restype = ctypes.c_uint32
    library.tee_qv_free_collateral.argtypes = [ctypes.c_void_p]
    library.tee_qv_free_collateral.restype = ctypes.c_uint32

    quote_buffer = (ctypes.c_uint8 * len(quote)).from_buffer_copy(quote)
    collateral_pointer = ctypes.c_void_p()
    collateral_size = ctypes.c_uint32()
    status = library.tee_qv_get_collateral(
        quote_buffer,
        len(quote),
        ctypes.byref(collateral_pointer),
        ctypes.byref(collateral_size),
    )
    if status != 0:
        raise RuntimeError(f"tee_qv_get_collateral failed with quote3_error_t 0x{status:04x}")

    try:
        if collateral_size.value < ctypes.sizeof(_QuoteCollateral):
            raise ValueError("QPL collateral allocation is smaller than its ABI header")
        collateral = ctypes.cast(
            collateral_pointer, ctypes.POINTER(_QuoteCollateral)
        ).contents
        expected = manifest["intel_dcap"]
        if (
            collateral.version.parts.major_version
            != expected["collateral_major_version"]
            or collateral.version.parts.minor_version
            not in (0, 1)
            or collateral.tee_type != 0
        ):
            raise ValueError("QPL collateral ABI/profile does not match the pinned SGX contract")

        raw_text = {
            "pck-crl-issuer-chain.pem": _bytes_at(
                collateral.pck_crl_issuer_chain,
                collateral.pck_crl_issuer_chain_size,
                "PCK CRL issuer chain",
            ),
            "tcb-info-issuer-chain.pem": _bytes_at(
                collateral.tcb_info_issuer_chain,
                collateral.tcb_info_issuer_chain_size,
                "TCB Info issuer chain",
            ),
            "tcb-info.json": _bytes_at(
                collateral.tcb_info, collateral.tcb_info_size, "TCB Info"
            ),
            "qe-identity-issuer-chain.pem": _bytes_at(
                collateral.qe_identity_issuer_chain,
                collateral.qe_identity_issuer_chain_size,
                "QE Identity issuer chain",
            ),
            "qe-identity.json": _bytes_at(
                collateral.qe_identity,
                collateral.qe_identity_size,
                "QE Identity",
            ),
        }
        components = {
            "pck-certificate-chain.pem0": extract_type5_pck_chain(quote),
            "pck.crl.der": _bytes_at(
                collateral.pck_crl, collateral.pck_crl_size, "PCK CRL"
            ),
            "root-ca.crl.der": _bytes_at(
                collateral.root_ca_crl,
                collateral.root_ca_crl_size,
                "root CA CRL",
            ),
        }
        components["pck.crl.der"] = canonical_crl_component(
            components["pck.crl.der"],
            collateral.version.parts.minor_version,
            "PCK CRL",
        )
        components["root-ca.crl.der"] = canonical_crl_component(
            components["root-ca.crl.der"],
            collateral.version.parts.minor_version,
            "root CA CRL",
        )
        components.update(
            {
                name: canonical_text_component(value, name)
                for name, value in raw_text.items()
            }
        )
        qpl_pin = load_host_qpl_pin()
        provenance = {
            "collateral_abi": {
                "major_version": collateral.version.parts.major_version,
                "minor_version": collateral.version.parts.minor_version,
                "tee_type": collateral.tee_type,
                "normalized_minor_version": expected["collateral_minor_version"],
                "allocation_size": collateral_size.value,
            },
            "qvl": _library_provenance(qvl_path, qvl_artifact["package"]),
            "qpl": _library_provenance(
                Path("/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1"),
                qpl_pin["package"],
                qpl_pin["version"],
            ),
            "qcnl": _library_provenance(
                Path("/usr/lib/x86_64-linux-gnu/libsgx_default_qcnl_wrapper.so.1"),
                qpl_pin["package"],
                qpl_pin["version"],
            ),
        }
        return components, provenance
    finally:
        free_status = library.tee_qv_free_collateral(collateral_pointer)
        if free_status != 0:
            raise RuntimeError(
                f"tee_qv_free_collateral failed with quote3_error_t 0x{free_status:04x}"
            )


def write_capture(quote_path: Path, output_dir: Path, expected_pck_ca: str) -> None:
    capture_started_at = int(time.time())
    quote = quote_path.read_bytes()
    components, provenance = capture_collateral(quote)
    output_dir.mkdir(parents=True, exist_ok=False)
    for name, value in components.items():
        (output_dir / name).write_bytes(value)
    provenance["quote"] = {
        "path": quote_path.name,
        "size": len(quote),
        "sha256": sha256_bytes(quote),
    }
    provenance["components"] = {
        name: {"size": len(value), "sha256": sha256_bytes(value)}
        for name, value in sorted(components.items())
    }
    provenance["crls"] = {
        "pck": crl_provenance(output_dir / "pck.crl.der", expected_pck_ca),
        "root": crl_provenance(output_dir / "root-ca.crl.der", "root"),
    }
    provenance["capture"] = {
        "completed_at": int(time.time()),
        "started_at": capture_started_at,
    }
    provenance["openssl_version"] = subprocess.run(
        ["openssl", "version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    (output_dir / "capture-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture exact Intel DCAP collateral for one real SGX quote"
    )
    parser.add_argument("--quote", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--expected-pck-ca", required=True, choices=("processor", "platform")
    )
    arguments = parser.parse_args()
    write_capture(arguments.quote, arguments.output_dir, arguments.expected_pck_ca)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
