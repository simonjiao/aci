from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from skill_check_runner import RunResult, write_result_archive


class OutputError(Exception):
    pass


def write_result_zip(path: Path, result: RunResult) -> None:
    created = False
    succeeded = False
    try:
        if path.exists() or not path.parent.is_dir():
            raise OSError
        with path.open("xb") as handle:
            created = True
            write_result_archive(result, handle)
        succeeded = True
    except Exception:
        pass
    if created and not succeeded:
        with suppress(OSError):
            path.unlink(missing_ok=True)
    if not succeeded:
        raise OutputError("结果 ZIP 写入失败")
