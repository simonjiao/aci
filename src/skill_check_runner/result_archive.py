from __future__ import annotations

import json
from typing import BinaryIO, Protocol, cast
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from .models import RunResult


class _JsonModule(Protocol):
    def dumps(
        self,
        document: object,
        *,
        ensure_ascii: bool,
        allow_nan: bool,
        sort_keys: bool,
        separators: tuple[str, str],
    ) -> str: ...


_JSON = cast(_JsonModule, json)


def encode_json(document: object) -> bytes:
    return (
        _JSON.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def write_result_archive(result: RunResult, target: BinaryIO) -> None:
    manifest = {
        "schema_version": "1",
        "conclusion": result.conclusion.value,
        "checks": [
            {
                "check_id": check.check_id,
                "conclusion": check.conclusion.value,
                "artifacts": [artifact.relative_path for artifact in check.artifacts],
            }
            for check in result.checks
        ],
    }
    with ZipFile(target, "w") as archive:
        _write_entry(archive, "manifest.json", encode_json(manifest))
        for artifact in result.artifacts:
            _write_entry(archive, artifact.relative_path, artifact.content)


def _write_entry(archive: ZipFile, path: str, content: bytes) -> None:
    info = ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    archive.writestr(info, content, compress_type=ZIP_DEFLATED, compresslevel=9)
