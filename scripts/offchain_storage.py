"""Generate per-node offchain-storage.toml without overwriting operator settings."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
import tempfile
import tomllib
from typing import Any


def settings(config: dict[str, Any], *, database: str, mongo_uri: str, validator_index: int | None = None) -> dict[str, Any]:
    source = config.get("offchain_storage", {})
    if not isinstance(source, dict):
        raise ValueError("offchain_storage must be a mapping")
    source = dict(source)
    backend = source.get("backend", "rocksdb")
    if source.keys() - {"version", "backend", "start_block", "rocksdb", "mongodb"}:
        raise ValueError("unknown offchain_storage setting")
    if type(source.get("version", 1)) is not int or source.get("version", 1) != 1 or backend not in {"rocksdb", "mongodb"}:
        raise ValueError("unsupported offchain storage version/backend")
    start = source.get("start_block", 1)
    if isinstance(start, bool) or not isinstance(start, int) or not 0 <= start <= 2**64 - 1:
        raise ValueError("storage start_block must be a u64")
    result = {"version": 1, "backend": backend, "start_block": start}
    if backend == "rocksdb":
        if "mongodb" in source:
            raise ValueError("mongodb section conflicts with rocksdb backend")
        section = {"path": "data/offchain", "secondary_path": "ocomp/domain-v1/exporter-v1/rocksdb-secondary"}
    else:
        if "rocksdb" in source:
            raise ValueError("rocksdb section conflicts with mongodb backend")
        section = {"uri": mongo_uri, "database": database}
    overrides = source.get(backend, {})
    if not isinstance(overrides, dict) or overrides.keys() - section.keys():
        raise ValueError("unknown storage backend setting")
    section.update(overrides)
    if any(not isinstance(value, str) or not value.strip() for value in section.values()):
        raise ValueError("storage backend settings must be nonempty strings")
    if backend == "mongodb" and "database" in overrides and validator_index is not None:
        section["database"] += f"_validator_{validator_index}"
    result[backend] = section
    return result


def render(document: dict[str, Any]) -> str:
    # JSON's quoted strings and escaping are valid TOML basic strings.
    backend = document["backend"]
    lines = ["version = 1", f"backend = {json.dumps(backend)}", f"start_block = {document['start_block']}", "", f"[{backend}]"]
    lines.extend(f"{key} = {json.dumps(value, ensure_ascii=False)}" for key, value in document[backend].items())
    return "\n".join(lines) + "\n"


def load(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except tomllib.TOMLDecodeError:
        raise ValueError(f"invalid storage TOML: {path}") from None
    backend = document.get("backend")
    required = {"rocksdb": {"path", "secondary_path"}, "mongodb": {"uri", "database"}}
    if document.get("version") != 1 or backend not in required:
        raise ValueError("storage TOML requires version = 1 and a supported backend")
    section = document.get(backend)
    if not isinstance(section, dict) or section.keys() != required[backend]:
        raise ValueError("storage TOML requires all selected backend fields")
    return settings({"offchain_storage": document}, database="unused", mongo_uri="unused")


def ensure(path: Path, document: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Publish a complete file with private permissions; never replace a restart's config.
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent) as stream:
        stream.write(render(document))
        stream.flush()
        os.fsync(stream.fileno())
        try:
            os.link(stream.name, path)
        except FileExistsError:
            return load(path)
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["ensure", "backend", "matches-mongodb"])
    parser.add_argument("path", type=Path)
    parser.add_argument("--template", type=Path, help="TOML template for a newly created config")
    parser.add_argument("--mongo-uri", help="expected managed MongoDB endpoint")
    args = parser.parse_args()
    if args.action == "ensure":
        document = load(args.template) if args.template else settings({}, database="unused", mongo_uri="unused")
        ensure(args.path, document)
    elif args.action == "backend":
        print(load(args.path)["backend"])
    else:
        document = load(args.path)
        sys.exit(0 if document["backend"] == "mongodb" and document["mongodb"]["uri"] == args.mongo_uri else 1)


if __name__ == "__main__":
    main()
