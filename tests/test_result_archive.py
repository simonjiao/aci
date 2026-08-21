from __future__ import annotations

import unittest
from io import BytesIO
from zipfile import ZipFile

from skill_check_runner import (
    CheckResult,
    OutputArtifact,
    RunConclusion,
    RunResult,
    write_result_archive,
)


class ResultArchiveTests(unittest.TestCase):
    def test_archive_is_deterministic_and_contains_manifest_and_artifacts(self) -> None:
        result = RunResult(
            RunConclusion.PASS,
            (
                CheckResult(
                    "example",
                    RunConclusion.PASS,
                    (OutputArtifact("report.csv", "text/csv", b"header\r\n"),),
                ),
            ),
        )
        first = BytesIO()
        second = BytesIO()

        write_result_archive(result, first)
        write_result_archive(result, second)

        self.assertEqual(first.getvalue(), second.getvalue())
        with ZipFile(first) as archive:
            expected_names: list[str] = ["manifest.json", "report.csv"]
            self.assertEqual(archive.namelist(), expected_names)
            self.assertEqual(
                archive.read("manifest.json"),
                b'{"checks":[{"artifacts":["report.csv"],"check_id":"example",'
                b'"conclusion":"PASS"}],"conclusion":"PASS","schema_version":"1"}\n',
            )
            self.assertEqual(archive.read("report.csv"), b"header\r\n")


if __name__ == "__main__":
    unittest.main()
