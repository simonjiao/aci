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
        with ExitStack() as stack:
            request = RunRequest(_open_packages(arguments.packages, stack))
            result = CheckRunner(checks).run(request)
        write_result_zip(Path(arguments.output), result)
    except (_UsageError, ConfigError, _InputError, OutputError) as error:
        _write_error(str(error))
        return 2
    except RunnerError as error:
        _write_error(f"{error.code.value}: {error.message}")
        return 2 if error.code is RunnerErrorCode.REQUEST_INVALID else 3
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
    for raw_path in paths:
        path = Path(raw_path)
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


def _write_error(message: str) -> None:
    sys.stderr.write(message + "\n")
