from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO


class RunConclusion(str, Enum):  # noqa: UP042
    PASS = "PASS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class RunnerErrorCode(str, Enum):  # noqa: UP042
    CHECK_PLAN_INVALID = "CHECK_PLAN_INVALID"
    REQUEST_INVALID = "REQUEST_INVALID"
    CHECK_EXECUTION_FAILED = "CHECK_EXECUTION_FAILED"
    CHECK_RESULT_INVALID = "CHECK_RESULT_INVALID"


class RunnerError(Exception):
    def __init__(
        self,
        code: RunnerErrorCode,
        message: str,
        *,
        check_id: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.check_id = check_id
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class InputPackage:
    display_name: str
    stream: BinaryIO
    source_id: str | None = None


@dataclass(frozen=True, slots=True)
class RunRequest:
    packages: tuple[InputPackage, ...]


@dataclass(frozen=True, slots=True)
class OutputArtifact:
    relative_path: str
    media_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    conclusion: RunConclusion
    artifacts: tuple[OutputArtifact, ...]


@dataclass(frozen=True, slots=True)
class RunResult:
    conclusion: RunConclusion
    checks: tuple[CheckResult, ...]

    @property
    def artifacts(self) -> tuple[OutputArtifact, ...]:
        return tuple(artifact for check in self.checks for artifact in check.artifacts)
