import hashlib
import json
from pathlib import Path

import pytest

from aegis.evidence import build_manifest


def test_builds_ordered_checksummed_manifest(tmp_path: Path) -> None:
    second = tmp_path / "second.whl"
    first = tmp_path / "first.json"
    second.write_bytes(b"wheel-bytes")
    first.write_text('{"bomFormat":"CycloneDX"}')

    manifest = build_manifest([second, first], revision="abc123")

    assert manifest["schema"] == "aegis.supply-chain-evidence.v1"
    assert manifest["revision"] == "abc123"
    assert [item["path"] for item in manifest["artifacts"]] == sorted(
        [first.as_posix(), second.as_posix()]
    )
    assert manifest["artifacts"][0]["sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    json.dumps(manifest)


def test_refuses_manifest_with_missing_input(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="do not exist"):
        build_manifest([tmp_path / "missing.whl"], revision="abc123")
