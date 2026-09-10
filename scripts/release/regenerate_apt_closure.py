#!/usr/bin/env python3
"""Resolve the pinned APT closure against the frozen Ubuntu snapshot.

The closure digest in ``release/project-toolchain-v1.json`` covers every ``.deb``
apt downloads for the release toolchain image, including the transitive packages
that no version pin names. It is reproducible only because
``release/apt/ubuntu.sources`` freezes the Ubuntu archive at one snapshot
instant, so this script is the way to regenerate it after that timestamp, a
package version or the base image changes.

The probe reads the package set from the pin and the base image from the ELF
build contract, so it introduces no second source of truth for either.

    scripts/release/regenerate_apt_closure.py            # print the values
    scripts/release/regenerate_apt_closure.py --write    # update the pin too
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PIN_PATH = REPO_ROOT / "release/project-toolchain-v1.json"
ELF_CONTRACT_PATH = REPO_ROOT / "release/reproducible-elf-build-v1.json"
APT_SOURCES_PATH = REPO_ROOT / "release/apt/ubuntu.sources"
VERIFIER_PATH = REPO_ROOT / "scripts/release/verify_project_toolchain.py"
PLATFORM = "linux/amd64"

PROBE_RECIPE = """\
FROM {base_image} AS probe

ARG DEBIAN_FRONTEND=noninteractive

COPY ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
COPY verify_project_toolchain.py /opt/outbe/toolchain/verify_project_toolchain.py

RUN apt-get update && \\
    apt-get install --download-only --reinstall -y --no-install-recommends \\
{package_arguments} && \\
    mkdir -p /out && \\
    python3 /opt/outbe/toolchain/verify_project_toolchain.py \\
      --emit-apt-ledger \\
      --deb-dir /var/cache/apt/archives > /out/apt-closure.txt

FROM scratch AS ledger
COPY --from=probe /out/apt-closure.txt /
"""


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def base_image() -> str:
    images = _read_json(ELF_CONTRACT_PATH)["builder"]["base_images"]
    matches = [image for image in images if "gramineproject/gramine:" in image]
    if len(matches) != 1:
        raise SystemExit("ELF build contract must name exactly one Gramine base image")
    return matches[0]


def resolve_closure() -> tuple[str, dict]:
    pin = _read_json(PIN_PATH)
    packages = pin["system_packages"]
    recipe = PROBE_RECIPE.format(
        base_image=base_image(),
        package_arguments=" \\\n".join(
            f"      {name}={version}" for name, version in packages.items()
        ),
    )
    with tempfile.TemporaryDirectory() as directory:
        context = Path(directory)
        (context / "Dockerfile").write_text(recipe, encoding="utf-8")
        shutil.copyfile(APT_SOURCES_PATH, context / "ubuntu.sources")
        shutil.copyfile(VERIFIER_PATH, context / "verify_project_toolchain.py")
        output = context / "out"
        subprocess.run(
            [
                "docker",
                "build",
                "--platform",
                PLATFORM,
                "--no-cache",
                "--target",
                "ledger",
                "--output",
                f"type=local,dest={output}",
                str(context),
            ],
            check=True,
        )
        text = (output / "apt-closure.txt").read_text(encoding="utf-8")
    ledger, _, summary = text.rstrip("\n").rpartition("\n")
    resolved = json.loads(summary)
    recomputed = hashlib.sha256(f"{ledger}\n".encode("ascii")).hexdigest()
    if recomputed != resolved["sha256"]:
        raise SystemExit("probe ledger does not match its own digest")
    return ledger, resolved


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="write the resolved count and digest into the project toolchain pin",
    )
    args = parser.parse_args()

    ledger, resolved = resolve_closure()
    print(ledger)
    print(json.dumps(resolved, indent=2))

    pin = _read_json(PIN_PATH)
    closure = pin["apt_provenance"]["deb_closure"]
    if (closure["count"], closure["sha256"]) == (resolved["count"], resolved["sha256"]):
        print("project APT package closure: already current")
        return
    if not args.write:
        print(
            "project APT package closure drifted from the pin; rerun with --write to update",
            file=sys.stderr,
        )
        raise SystemExit(1)
    closure["count"] = resolved["count"]
    closure["sha256"] = resolved["sha256"]
    PIN_PATH.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")
    print(f"updated {PIN_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
