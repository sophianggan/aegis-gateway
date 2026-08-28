from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def digest(path: Path) -> dict[str, Any]:
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    return {
        "path": path.as_posix(),
        "bytes": path.stat().st_size,
        "sha256": checksum.hexdigest(),
    }


def build_manifest(paths: list[Path], *, revision: str) -> dict[str, Any]:
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"evidence inputs do not exist: {', '.join(missing)}")
    return {
        "schema": "aegis.supply-chain-evidence.v1",
        "revision": revision,
        "generated_at": datetime.now(UTC).isoformat(),
        "artifacts": [digest(path) for path in sorted(paths)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a checksummed release evidence manifest")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", default=os.environ.get("GITHUB_SHA", "local"))
    args = parser.parse_args()
    manifest = build_manifest(args.paths, revision=args.revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
