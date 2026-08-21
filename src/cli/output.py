from __future__ import annotations

import json
from contextlib import suppress
from pathlib import Path
from typing import Protocol, cast
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from skill_check_runner import RunResult


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


class OutputError(Exception):
    pass


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


def write_result_zip(path: Path, result: RunResult) -> None:
    created = False
    succeeded = False
    try:
        if path.exists() or not path.parent.is_dir():
            raise OSError
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
        with path.open("xb") as handle:
            created = True
            with ZipFile(handle, "w") as archive:
                _write_entry(archive, "manifest.json", encode_json(manifest))
                for artifact in result.artifacts:
                    _write_entry(archive, artifact.relative_path, artifact.content)
        succeeded = True
    except Exception:
        pass
    if created and not succeeded:
        with suppress(OSError):
            path.unlink(missing_ok=True)
    if not succeeded:
        raise OutputError("结果 ZIP 写入失败")


def _write_entry(archive: ZipFile, path: str, content: bytes) -> None:
    info = ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    archive.writestr(info, content, compress_type=ZIP_DEFLATED, compresslevel=9)
