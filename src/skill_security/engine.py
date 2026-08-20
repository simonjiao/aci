from __future__ import annotations

from dataclasses import dataclass

from .archive import PackageContent, read_package
from .detectors import Match, detect
from .evidence import finding_id, process_evidence
from .facts import build_fact_index
from .limits import ReadBudget
from .models import (
    CompiledRule,
    Conclusion,
    Coverage,
    ErrorCode,
    Finding,
    FindingStatus,
    PackageSummary,
    RuleInfo,
    RuleStatus,
    ScanError,
    ScanPolicy,
    ScanRequest,
    ScanResult,
)


@dataclass(frozen=True, slots=True)
class _PendingFinding:
    package_index: int
    finding: Finding


class Engine:
    def __init__(self, policy: ScanPolicy) -> None:
        self._policy = policy

    def scan(self, request: ScanRequest) -> ScanResult:
        budget = ReadBudget(self._policy.max_total_read_bytes)
        pending: dict[tuple[int, str], _PendingFinding] = {}
        summaries: list[PackageSummary] = []
        for package_index, package_input in enumerate(request.packages):
            package = read_package(package_input, request.rules, self._policy, budget)
            facts = build_fact_index(package.text_entries)
            package_finding_count = 0
            for rule in request.rules.execution_plan:
                for match in detect(rule, facts, package, request.rules):
                    item = _PendingFinding(
                        package_index,
                        _finding(package, rule, match, request),
                    )
                    key = (package_index, item.finding.id)
                    if key in pending:
                        continue
                    pending[key] = item
                    package_finding_count += 1
                    if len(pending) > self._policy.max_findings:
                        raise _finding_limit(package.display_name, match.entry_path)
            summaries.append(
                PackageSummary(
                    package.display_name,
                    package.size_bytes,
                    package.sha256,
                    package.entry_count,
                    package_finding_count,
                )
            )

        ordered = tuple(
            item.finding
            for item in sorted(
                pending.values(),
                key=_pending_sort_key,
            )
        )
        coverage = Coverage(
            tuple(
                sorted(
                    rule.id for rule in request.rules.rules if rule.status is RuleStatus.APPROVED
                )
            ),
            tuple(
                sorted(
                    rule.id for rule in request.rules.rules if rule.status is RuleStatus.UNRESOLVED
                )
            ),
            tuple(
                sorted(
                    rule.id for rule in request.rules.rules if rule.status is RuleStatus.UNSUPPORTED
                )
            ),
        )
        return ScanResult(
            Conclusion.REVIEW_REQUIRED if ordered else Conclusion.PASS,
            tuple(summaries),
            ordered,
            coverage,
            RuleInfo(
                request.rules.rule_version,
                request.rules.source_version,
                request.rules.sha256,
            ),
        )


def _finding(
    package: PackageContent,
    rule: CompiledRule,
    match: Match,
    request: ScanRequest,
) -> Finding:
    processed = process_evidence(
        rule,
        match.raw_evidence,
        match.line,
        match.column,
        match.details,
    )
    return Finding(
        id=finding_id(
            package.sha256,
            rule.id,
            match.entry_path,
            match.line,
            match.column,
            processed.fingerprint,
        ),
        package_name=package.display_name,
        source_id=package.source_id,
        package_sha256=package.sha256,
        rule_version=request.rules.rule_version,
        rule_sha256=request.rules.sha256,
        rule_id=rule.id,
        rule_name=rule.name,
        source_description=rule.source_description,
        severity=rule.severity,
        entry_path=match.entry_path,
        line=match.line,
        column=match.column,
        evidence_type=rule.evidence.type,
        evidence=processed.display,
        evidence_fingerprint=processed.fingerprint,
        status=FindingStatus.REVIEW_REQUIRED,
        remediation=rule.remediation,
    )


def _finding_limit(package_name: str, entry_path: str) -> ScanError:
    return ScanError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "finding 数量超过限制",
        package_name=package_name,
        entry_path=entry_path,
    )


def _pending_sort_key(item: _PendingFinding) -> tuple[int, str, int, int, str]:
    return (
        item.package_index,
        item.finding.entry_path,
        item.finding.line,
        item.finding.column,
        item.finding.rule_id,
    )
