from __future__ import annotations

import csv
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from skill_check_runner import (
    CheckResult,
    InputPackage,
    OutputArtifact,
    RunConclusion,
    RunRequest,
)
from skill_security import (
    Conclusion,
    PackageInput,
    RuleSet,
    ScanPolicy,
    ScanRequest,
    ScanResult,
    SecurityScan,
    compile_rules,
)

from ..output import encode_json

_JSON_LOADS = cast(Callable[[str], object], json.loads)
_CSV_HEADERS = (
    "Finding ID",
    "包名称",
    "来源标识",
    "包 SHA-256",
    "规则 ID",
    "检测项",
    "规则描述",
    "风险等级",
    "包内路径",
    "行号",
    "列号",
    "证据类型",
    "脱敏证据",
    "证据指纹",
    "状态",
    "修改建议",
    "规则版本",
    "规则 SHA-256",
)


class SecurityPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_package_bytes: Annotated[int, Field(gt=0)]
    max_entries_per_package: Annotated[int, Field(gt=0)]
    max_text_bytes_per_file: Annotated[int, Field(gt=0)]
    max_total_read_bytes: Annotated[int, Field(gt=0)]
    max_findings: Annotated[int, Field(gt=0)]


class SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["skill-security"]
    rules_file: Annotated[str, Field(min_length=1)]
    policy: SecurityPolicyConfig


class SecurityAdapterConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SecurityAdapter:
    rules: RuleSet
    scanner: SecurityScan
    check_id: str = "security"

    @classmethod
    def from_config(cls, config: SecurityConfig, base_directory: Path) -> SecurityAdapter:
        rules_path = Path(config.rules_file)
        if not rules_path.is_absolute():
            rules_path = base_directory / rules_path
        adapter: SecurityAdapter | None = None
        try:
            raw = _JSON_LOADS(rules_path.read_text(encoding="utf-8"))
            document = _string_mapping(raw)
            if document is None:
                raise ValueError
            rules = compile_rules(document)
            policy = ScanPolicy(
                config.policy.max_package_bytes,
                config.policy.max_entries_per_package,
                config.policy.max_text_bytes_per_file,
                config.policy.max_total_read_bytes,
                config.policy.max_findings,
            )
            adapter = cls(rules, SecurityScan(policy))
        except Exception:
            pass
        if adapter is None:
            raise SecurityAdapterConfigError("安全检查配置无效")
        return adapter

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
                finding.id,
                finding.package_name,
                finding.source_id,
                finding.package_sha256,
                finding.rule_id,
                finding.rule_name,
                finding.source_description,
                finding.severity,
                finding.entry_path,
                finding.line,
                finding.column,
                finding.evidence_type,
                finding.evidence,
                finding.evidence_fingerprint,
                finding.status.value,
                finding.remediation,
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


def _string_mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast(Mapping[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return cast(Mapping[str, object], mapping)
