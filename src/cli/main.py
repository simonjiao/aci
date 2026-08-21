from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from typing import Never, cast

from pydantic import ValidationError

from .commands import check

_NAMESPACE_VALUES = cast(Callable[[object], dict[str, object]], vars)


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> Never:
        raise _UsageError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parse_arguments(argv)
    except _UsageError as error:
        sys.stderr.write(str(error) + "\n")
        return 2
    return check.run(arguments)


def _parse_arguments(argv: Sequence[str] | None) -> check.CheckArguments:
    parser = _Parser(prog="skillqa")
    commands = parser.add_subparsers(dest="command", required=True)
    check_parser = commands.add_parser("check")
    check_parser.add_argument("--config", required=True)
    check_parser.add_argument("--output", required=True)
    check_parser.add_argument("packages", nargs="+")
    try:
        namespace = parser.parse_args(argv)
        return check.CheckArguments.model_validate(
            _NAMESPACE_VALUES(namespace),
            strict=True,
        )
    except ValidationError:
        pass
    raise _UsageError("命令行参数无效")
