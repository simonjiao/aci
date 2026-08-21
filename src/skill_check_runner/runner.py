from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol, cast

from .models import (
    CheckResult,
    InputPackage,
    OutputArtifact,
    RunConclusion,
    RunnerError,
    RunnerErrorCode,
    RunRequest,
    RunResult,
)


class CheckAdapter(Protocol):
    """One check behind the runner's stable boundary.

    Adapters must not close package streams and must restore each stream's
    original position before returning or raising.
    """

    @property
    def check_id(self) -> str: ...

    def run(self, request: RunRequest) -> CheckResult: ...


@dataclass(frozen=True, slots=True)
class CheckRunner:
    checks: tuple[CheckAdapter, ...]

    def __post_init__(self) -> None:
        if not self.checks:
            raise RunnerError(
                RunnerErrorCode.CHECK_PLAN_INVALID,
                "检查计划不能为空",
            )
        check_ids = tuple(check.check_id for check in self.checks)
        if any(not check_id for check_id in check_ids) or len(check_ids) != len(set(check_ids)):
            raise RunnerError(
                RunnerErrorCode.CHECK_PLAN_INVALID,
                "检查计划字段无效",
            )

    def run(self, request: RunRequest) -> RunResult:
        request = _validate_request(request)
        results = tuple(_run_check(check, request) for check in self.checks)
        artifact_paths = tuple(
            artifact.relative_path for result in results for artifact in result.artifacts
        )
        if len(artifact_paths) != len(set(artifact_paths)):
            raise RunnerError(
                RunnerErrorCode.CHECK_RESULT_INVALID,
                "检查结果字段无效",
            )
        conclusion = (
            RunConclusion.REVIEW_REQUIRED
            if any(result.conclusion is RunConclusion.REVIEW_REQUIRED for result in results)
            else RunConclusion.PASS
        )
        return RunResult(conclusion, results)


def _run_check(check: CheckAdapter, request: RunRequest) -> CheckResult:
    result: object | None = None
    failed = False
    try:
        result = check.run(request)
    except Exception:
        failed = True
    if failed or result is None:
        raise RunnerError(
            RunnerErrorCode.CHECK_EXECUTION_FAILED,
            "检查执行失败",
            check_id=check.check_id,
        )
    return _validate_result(check, result)


def _validate_request(request: object) -> RunRequest:
    if not isinstance(request, RunRequest):
        raise RunnerError(RunnerErrorCode.REQUEST_INVALID, "执行请求字段无效")
    package_value = cast(object, request.packages)
    if type(package_value) is not tuple or not package_value:
        raise RunnerError(RunnerErrorCode.REQUEST_INVALID, "执行请求字段无效")
    packages = cast(tuple[object, ...], package_value)
    if any(not isinstance(package, InputPackage) for package in packages):
        raise RunnerError(RunnerErrorCode.REQUEST_INVALID, "执行请求字段无效")
    typed_packages = tuple(
        package for package in packages if isinstance(package, InputPackage)
    )
    names: tuple[object, ...] = tuple(
        cast(object, package.display_name) for package in typed_packages
    )
    if any(not isinstance(name, str) or not name for name in names):
        raise RunnerError(RunnerErrorCode.REQUEST_INVALID, "执行请求字段无效")
    if len(names) != len(set(names)):
        raise RunnerError(RunnerErrorCode.REQUEST_INVALID, "执行请求字段无效")
    if any(
        source_id is not None and not isinstance(source_id, str)
        for source_id in (
            cast(object, package.source_id) for package in typed_packages
        )
    ):
        raise RunnerError(RunnerErrorCode.REQUEST_INVALID, "执行请求字段无效")
    return request


def _validate_result(check: CheckAdapter, result: object) -> CheckResult:
    if not isinstance(result, CheckResult):
        raise RunnerError(
            RunnerErrorCode.CHECK_RESULT_INVALID,
            "检查结果字段无效",
            check_id=check.check_id,
        )
    result_check_id = cast(object, result.check_id)
    if not isinstance(result_check_id, str) or result_check_id != check.check_id:
        raise RunnerError(
            RunnerErrorCode.CHECK_RESULT_INVALID,
            "检查结果字段无效",
            check_id=check.check_id,
        )
    conclusion = cast(object, result.conclusion)
    if not isinstance(conclusion, RunConclusion):
        raise RunnerError(
            RunnerErrorCode.CHECK_RESULT_INVALID,
            "检查结果字段无效",
            check_id=check.check_id,
        )
    artifact_value = cast(object, result.artifacts)
    if type(artifact_value) is not tuple or not artifact_value:
        raise RunnerError(
            RunnerErrorCode.CHECK_RESULT_INVALID,
            "检查结果字段无效",
            check_id=check.check_id,
        )
    artifacts = cast(tuple[object, ...], artifact_value)
    if any(not _valid_artifact(artifact) for artifact in artifacts):
        raise RunnerError(
            RunnerErrorCode.CHECK_RESULT_INVALID,
            "检查结果字段无效",
            check_id=check.check_id,
        )
    return result


def _valid_artifact(artifact: object) -> bool:
    if not isinstance(artifact, OutputArtifact):
        return False
    if (
        type(artifact.relative_path) is not str
        or not artifact.relative_path
        or type(artifact.media_type) is not str
        or not artifact.media_type
        or type(artifact.content) is not bytes
    ):
        return False
    path = PurePosixPath(artifact.relative_path)
    return (
        not path.is_absolute()
        and ".." not in path.parts
    )
