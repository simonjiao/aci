from __future__ import annotations

import unittest
from dataclasses import dataclass
from io import BytesIO
from typing import cast

from skill_check_runner import (
    CheckAdapter,
    CheckResult,
    CheckRunner,
    InputPackage,
    OutputArtifact,
    RunConclusion,
    RunnerError,
    RunnerErrorCode,
    RunRequest,
)


@dataclass(frozen=True, slots=True)
class FixedCheck:
    check_id: str
    conclusion: RunConclusion

    def run(self, request: RunRequest) -> CheckResult:
        package_names = ",".join(package.display_name for package in request.packages)
        artifact = OutputArtifact(
            f"{self.check_id}.json",
            "application/json",
            package_names.encode(),
        )
        return CheckResult(self.check_id, self.conclusion, (artifact,))


@dataclass(frozen=True, slots=True)
class FailingCheck:
    check_id: str

    def run(self, _request: RunRequest) -> CheckResult:
        raise ValueError("TOKEN_CANARY_SECRET")


@dataclass(frozen=True, slots=True)
class MismatchedResultCheck:
    check_id: str

    def run(self, _request: RunRequest) -> CheckResult:
        artifact = OutputArtifact("result.json", "application/json", b"{}")
        return CheckResult("different", RunConclusion.PASS, (artifact,))


class LeakingPathLike:
    def __fspath__(self) -> str:
        raise ValueError("TOKEN_CANARY_SECRET")


@dataclass(frozen=True, slots=True)
class InvalidArtifactCheck:
    check_id: str

    def run(self, _request: RunRequest) -> CheckResult:
        artifact = OutputArtifact(
            cast(str, LeakingPathLike()),
            "application/json",
            b"{}",
        )
        return CheckResult(self.check_id, RunConclusion.PASS, (artifact,))


class CheckRunnerTests(unittest.TestCase):
    def test_rejects_an_empty_check_plan(self) -> None:
        with self.assertRaises(RunnerError) as raised:
            CheckRunner(())

        self.assertEqual(raised.exception.code, RunnerErrorCode.CHECK_PLAN_INVALID)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_rejects_duplicate_check_ids_and_empty_package_requests(self) -> None:
        duplicate_checks: tuple[CheckAdapter, ...] = (
            FixedCheck("security", RunConclusion.PASS),
            FixedCheck("security", RunConclusion.PASS),
        )
        with self.assertRaises(RunnerError) as duplicate:
            CheckRunner(duplicate_checks)

        checks: tuple[CheckAdapter, ...] = (FixedCheck("security", RunConclusion.PASS),)
        with self.assertRaises(RunnerError) as empty:
            CheckRunner(checks).run(RunRequest(()))

        self.assertEqual(duplicate.exception.code, RunnerErrorCode.CHECK_PLAN_INVALID)
        self.assertEqual(empty.exception.code, RunnerErrorCode.REQUEST_INVALID)

    def test_rejects_the_wrong_request_runtime_type(self) -> None:
        checks: tuple[CheckAdapter, ...] = (FixedCheck("security", RunConclusion.PASS),)

        with self.assertRaises(RunnerError) as raised:
            CheckRunner(checks).run(cast(RunRequest, object()))

        self.assertEqual(raised.exception.code, RunnerErrorCode.REQUEST_INVALID)

    def test_sanitizes_unexpected_check_failures(self) -> None:
        request = RunRequest((InputPackage("demo.zip", BytesIO(b"package")),))
        checks: tuple[CheckAdapter, ...] = (FailingCheck("security"),)

        with self.assertRaises(RunnerError) as raised:
            CheckRunner(checks).run(request)

        self.assertEqual(raised.exception.code, RunnerErrorCode.CHECK_EXECUTION_FAILED)
        self.assertEqual(raised.exception.check_id, "security")
        self.assertNotIn("CANARY_SECRET", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_rejects_a_result_for_a_different_check(self) -> None:
        request = RunRequest((InputPackage("demo.zip", BytesIO(b"package")),))
        checks: tuple[CheckAdapter, ...] = (MismatchedResultCheck("security"),)

        with self.assertRaises(RunnerError) as raised:
            CheckRunner(checks).run(request)

        self.assertEqual(raised.exception.code, RunnerErrorCode.CHECK_RESULT_INVALID)
        self.assertEqual(raised.exception.check_id, "security")

    def test_rejects_invalid_artifact_fields_without_evaluating_them(self) -> None:
        request = RunRequest((InputPackage("demo.zip", BytesIO(b"package")),))
        checks: tuple[CheckAdapter, ...] = (InvalidArtifactCheck("security"),)

        with self.assertRaises(RunnerError) as raised:
            CheckRunner(checks).run(request)

        self.assertEqual(raised.exception.code, RunnerErrorCode.CHECK_RESULT_INVALID)
        self.assertNotIn("CANARY_SECRET", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_runs_checks_in_order_and_aggregates_review_conclusion(self) -> None:
        request = RunRequest((InputPackage("demo.zip", BytesIO(b"package")),))
        checks: tuple[CheckAdapter, ...] = (
            FixedCheck("first", RunConclusion.PASS),
            FixedCheck("second", RunConclusion.REVIEW_REQUIRED),
        )
        runner = CheckRunner(checks)

        result = runner.run(request)

        self.assertEqual(result.conclusion, RunConclusion.REVIEW_REQUIRED)
        self.assertEqual(result.checks[0].check_id, "first")
        self.assertEqual(result.checks[1].check_id, "second")
        self.assertEqual(result.artifacts[0].relative_path, "first.json")
        self.assertEqual(result.artifacts[1].relative_path, "second.json")


if __name__ == "__main__":
    unittest.main()
