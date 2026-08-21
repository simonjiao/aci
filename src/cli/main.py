from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Never, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from skill_check_runner import (
    CheckRunner,
    InputPackage,
    RunConclusion,
    RunnerError,
    RunnerErrorCode,
    RunRequest,
)

from .config import ConfigError, load_checks
from .output import OutputError, write_result_zip

_NAMESPACE_VALUES = cast(Callable[[object], dict[str, object]], vars)


class _UsageError(Exception):
    pass


class _InputError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> Never:
        raise _UsageError("命令行参数无效")


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    command: Literal["check"]
    config: str
    output: str
    packages: Annotated[list[str], Field(min_length=1)]


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parse_arguments(argv)
        checks = load_checks(Path(arguments.config))
        output_path = Path(arguments.output)
        with ExitStack() as stack:
            request = RunRequest(_open_packages(arguments.packages, stack))
            result = CheckRunner(checks).run(request)
        write_result_zip(output_path, result)
    except (_UsageError, ConfigError, _InputError, OutputError) as error:
        _write_error(str(error))
        return 2
    except RunnerError as error:
        _write_error(f"{error.code.value}: {error.message}")
        return 2 if error.code is RunnerErrorCode.REQUEST_INVALID else 3
    _write_completion(result.conclusion, output_path)
    return 1 if result.conclusion is RunConclusion.REVIEW_REQUIRED else 0


def _parse_arguments(argv: Sequence[str] | None) -> _Arguments:
    parser = _Parser(prog="skillqa")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--config", required=True)
    check.add_argument("--output", required=True)
    check.add_argument("packages", nargs="+")
    try:
        namespace = parser.parse_args(argv)
        return _Arguments.model_validate(_NAMESPACE_VALUES(namespace), strict=True)
    except ValidationError:
        pass
    raise _UsageError("命令行参数无效")


def _open_packages(paths: list[str], stack: ExitStack) -> tuple[InputPackage, ...]:
    packages: list[InputPackage] = []
    failed = False
    for path in _expand_package_paths(paths):
        handle: BinaryIO | None = None
        try:
            handle = stack.enter_context(path.open("rb"))
        except OSError:
            failed = True
        if failed or handle is None:
            break
        packages.append(InputPackage(path.name, handle))
    if failed:
        raise _InputError("输入包无法读取")
    return tuple(packages)


def _expand_package_paths(paths: list[str]) -> tuple[Path, ...]:
    package_paths: list[Path] = []
    failed = False
    for raw_path in paths:
        path = Path(raw_path)
        if not path.is_dir():
            package_paths.append(path)
            continue
        directory_packages: list[Path] | None = None
        try:
            directory_packages = sorted(
                (
                    candidate
                    for candidate in path.iterdir()
                    if candidate.is_file() and candidate.suffix.casefold() == ".zip"
                ),
                key=_path_sort_key,
            )
        except OSError:
            failed = True
        if failed or directory_packages is None:
            break
        if not directory_packages:
            raise _InputError("未找到可扫描的 ZIP 包")
        package_paths.extend(directory_packages)
    if failed:
        raise _InputError("输入目录无法读取")
    if not package_paths:
        raise _InputError("未找到可扫描的 ZIP 包")
    return tuple(package_paths)


def _path_sort_key(path: Path) -> tuple[str, str]:
    return path.name.casefold(), path.name


def _write_error(message: str) -> None:
    sys.stderr.write(message + "\n")


def _write_completion(conclusion: RunConclusion, output_path: Path) -> None:
    review_prompt = "，请人工复核" if conclusion is RunConclusion.REVIEW_REQUIRED else ""
    sys.stdout.write(f"检查完成：{conclusion.value}{review_prompt}。结果 ZIP：{output_path}\n")
