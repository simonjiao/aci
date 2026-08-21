from __future__ import annotations

import csv
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from io import StringIO
from typing import cast

from skill_check_runner import (
    CheckResult,
    InputPackage,
    OutputArtifact,
    RunConclusion,
    RunRequest,
)
from skill_check_runner.result_archive import encode_json
from skill_security import (
    Conclusion,
    PackageInput,
    RuleSet,
    ScanRequest,
    ScanResult,
    SecurityScan,
)

_CSV_HEADERS = (
    "包名称",
    "风险等级",
    "规则 ID",
    "检测项",
    "规则描述",
    "包内路径",
    "行号",
    "列号",
    "证据类型",
    "脱敏证据",
    "修改建议",
    "状态",
    "来源标识",
    "Finding ID",
    "包 SHA-256",
    "证据指纹",
    "规则版本",
    "规则 SHA-256",
)


@dataclass(frozen=True, slots=True)
class SecurityAdapter:
    rules: RuleSet
    scanner: SecurityScan
    check_id: str = "security"

    def run(self, request: RunRequest) -> CheckResult:
        packages = tuple(_security_package(package) for package in request.packages)
        result = self.scanner.scan(ScanRequest(packages, self.rules))
        conclusion = (
            RunConclusion.REVIEW_REQUIRED
            if result.conclusion is Conclusion.REVIEW_REQUIRED
            else RunConclusion.PASS
        )
        findings_artifact = OutputArtifact(
            "security-scan.csv",
            "text/csv; charset=utf-8",
            _encode_findings_csv(result),
        )
        metadata_artifact = OutputArtifact(
            "security-metadata.json",
            "application/json",
            encode_json(_metadata_document(result)),
        )
        return CheckResult(
            self.check_id,
            conclusion,
            (findings_artifact, metadata_artifact),
        )


def _security_package(package: InputPackage) -> PackageInput:
    return PackageInput(package.display_name, package.stream, package.source_id)


def _encode_findings_csv(result: ScanResult) -> bytes:
    buffer = StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    write_row = cast(Callable[[Iterable[object]], object], writer.writerow)
    write_row(_CSV_HEADERS)
    for finding in result.findings:
        row: tuple[str | int, ...] = tuple(
            _csv_cell(value)
            for value in (
                finding.package_name,
                finding.severity,
                finding.rule_id,
                finding.rule_name,
                finding.source_description,
                finding.entry_path,
                finding.line,
                finding.column,
                finding.evidence_type,
                finding.evidence,
                finding.remediation,
                finding.status.value,
                finding.source_id,
                finding.id,
                finding.package_sha256,
                finding.evidence_fingerprint,
                finding.rule_version,
                finding.rule_sha256,
            )
        )
        write_row(row)
    return buffer.getvalue().encode("utf-8-sig")


def _csv_cell(value: str | int | None) -> str | int:
    if value is None:
        return ""
    if isinstance(value, int):
        return value
    if value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return value


def _metadata_document(result: ScanResult) -> dict[str, object]:
    packages: list[object] = [
        {
            "display_name": package.display_name,
            "size_bytes": package.size_bytes,
            "sha256": package.sha256,
            "entry_count": package.entry_count,
            "finding_count": package.finding_count,
        }
        for package in result.packages
    ]
    return {
        "conclusion": result.conclusion.value,
        "packages": packages,
        "coverage": {
            "executed_rule_ids": list(result.coverage.executed_rule_ids),
            "unresolved_rule_ids": list(result.coverage.unresolved_rule_ids),
            "unsupported_rule_ids": list(result.coverage.unsupported_rule_ids),
            "executed_count": result.coverage.executed_count,
            "unresolved_count": result.coverage.unresolved_count,
            "unsupported_count": result.coverage.unsupported_count,
        },
        "rules": {
            "rule_version": result.rules.rule_version,
            "source_version": result.rules.source_version,
            "rule_sha256": result.rules.rule_sha256,
        },
    }
