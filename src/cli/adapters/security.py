from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
        artifact = OutputArtifact(
            "security-scan.json",
            "application/json",
            encode_json(_result_document(result)),
        )
        return CheckResult(self.check_id, conclusion, (artifact,))


def _security_package(package: InputPackage) -> PackageInput:
    return PackageInput(package.display_name, package.stream, package.source_id)


def _result_document(result: ScanResult) -> dict[str, object]:
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
    findings: list[object] = [
        {
            "id": finding.id,
            "package_name": finding.package_name,
            "source_id": finding.source_id,
            "package_sha256": finding.package_sha256,
            "rule_version": finding.rule_version,
            "rule_sha256": finding.rule_sha256,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "source_description": finding.source_description,
            "severity": finding.severity,
            "entry_path": finding.entry_path,
            "line": finding.line,
            "column": finding.column,
            "evidence_type": finding.evidence_type,
            "evidence": finding.evidence,
            "evidence_fingerprint": finding.evidence_fingerprint,
            "status": finding.status.value,
            "remediation": finding.remediation,
        }
        for finding in result.findings
    ]
    return {
        "conclusion": result.conclusion.value,
        "packages": packages,
        "findings": findings,
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
