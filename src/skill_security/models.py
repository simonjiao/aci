from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import BinaryIO, cast


class ErrorCode(str, Enum):  # noqa: UP042
    REQUEST_INVALID = "REQUEST_INVALID"
    POLICY_INVALID = "POLICY_INVALID"
    RULESET_INVALID = "RULESET_INVALID"
    PACKAGE_SOURCE_INVALID = "PACKAGE_SOURCE_INVALID"
    ZIP_OPEN_FAILED = "ZIP_OPEN_FAILED"
    ZIP_ENTRY_READ_FAILED = "ZIP_ENTRY_READ_FAILED"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"


class RuleStatus(str, Enum):  # noqa: UP042
    APPROVED = "APPROVED"
    UNRESOLVED = "UNRESOLVED"
    UNSUPPORTED = "UNSUPPORTED"


class Conclusion(str, Enum):  # noqa: UP042
    PASS = "PASS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class FindingStatus(str, Enum):  # noqa: UP042
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class ScanError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        package_name: str | None = None,
        entry_path: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.package_name = package_name
        self.entry_path = entry_path
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    type: str
    prefix_length: int


@dataclass(frozen=True, slots=True)
class MatchDetails:
    classification: str | None = None
    length: int | None = None
    entropy: float | None = None
    threshold: float | None = None
    code_point: str | None = None

    def values(self) -> dict[str, str | int | float]:
        result: dict[str, str | int | float] = {}
        if self.classification is not None:
            result["classification"] = self.classification
        if self.length is not None:
            result["length"] = self.length
        if self.entropy is not None:
            result["entropy"] = self.entropy
        if self.threshold is not None:
            result["threshold"] = self.threshold
        if self.code_point is not None:
            result["code_point"] = self.code_point
        return result


@dataclass(frozen=True, slots=True)
class CompiledRule:
    id: str
    detector: str
    name: str
    source_description: str
    severity: str
    status: RuleStatus
    scope: str
    match_type: str
    parameters: Mapping[str, object]
    evidence: EvidencePolicy
    remediation: str | None
    source_limitations: tuple[str, ...]
    skip_extensions: tuple[str, ...] = ()
    only_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PackageInput:
    display_name: str
    stream: BinaryIO
    source_id: str | None = None


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    max_package_bytes: int
    max_entries_per_package: int
    max_text_bytes_per_file: int
    max_total_read_bytes: int
    max_findings: int


@dataclass(frozen=True, slots=True)
class ScanRequest:
    packages: tuple[PackageInput, ...]
    rules: RuleSet


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    package_name: str
    source_id: str | None
    package_sha256: str
    rule_version: str
    rule_sha256: str
    rule_id: str
    rule_name: str
    source_description: str
    severity: str
    entry_path: str
    line: int
    column: int
    evidence_type: str
    evidence: str
    evidence_fingerprint: str
    status: FindingStatus
    remediation: str | None


@dataclass(frozen=True, slots=True)
class PackageSummary:
    display_name: str
    size_bytes: int
    sha256: str
    entry_count: int
    finding_count: int


@dataclass(frozen=True, slots=True)
class Coverage:
    executed_rule_ids: tuple[str, ...]
    unresolved_rule_ids: tuple[str, ...]
    unsupported_rule_ids: tuple[str, ...]

    @property
    def executed_count(self) -> int:
        return len(self.executed_rule_ids)

    @property
    def unresolved_count(self) -> int:
        return len(self.unresolved_rule_ids)

    @property
    def unsupported_count(self) -> int:
        return len(self.unsupported_rule_ids)


@dataclass(frozen=True, slots=True)
class RuleInfo:
    rule_version: str
    source_version: str
    rule_sha256: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    conclusion: Conclusion
    packages: tuple[PackageSummary, ...]
    findings: tuple[Finding, ...]
    coverage: Coverage
    rules: RuleInfo


_RULESET_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class RuleSet:
    schema_version: str
    rule_version: str
    source_version: str
    sha256: str
    default_skip_directories: tuple[str, ...]
    text_extensions: tuple[str, ...]
    vocabularies: Mapping[str, tuple[str, ...]]
    rules: tuple[CompiledRule, ...]
    execution_plan: tuple[CompiledRule, ...]

    def __init__(
        self,
        *,
        schema_version: str,
        rule_version: str,
        source_version: str,
        sha256: str,
        default_skip_directories: tuple[str, ...],
        text_extensions: tuple[str, ...],
        vocabularies: Mapping[str, tuple[str, ...]],
        rules: tuple[CompiledRule, ...],
        execution_plan: tuple[CompiledRule, ...],
        _seal: object,
    ) -> None:
        if _seal is not _RULESET_SEAL:
            raise TypeError("RuleSet can only be created by compile_rules()")
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "rule_version", rule_version)
        object.__setattr__(self, "source_version", source_version)
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "default_skip_directories", default_skip_directories)
        object.__setattr__(self, "text_extensions", text_extensions)
        frozen_vocabularies: Mapping[str, tuple[str, ...]] = MappingProxyType(dict(vocabularies))
        object.__setattr__(self, "vocabularies", frozen_vocabularies)
        object.__setattr__(self, "rules", rules)
        object.__setattr__(self, "execution_plan", execution_plan)


def _new_rule_set(
    *,
    schema_version: str,
    rule_version: str,
    source_version: str,
    sha256: str,
    default_skip_directories: tuple[str, ...],
    text_extensions: tuple[str, ...],
    vocabularies: Mapping[str, tuple[str, ...]],
    rules: tuple[CompiledRule, ...],
    execution_plan: tuple[CompiledRule, ...],
) -> RuleSet:
    return RuleSet(
        schema_version=schema_version,
        rule_version=rule_version,
        source_version=source_version,
        sha256=sha256,
        default_skip_directories=default_skip_directories,
        text_extensions=text_extensions,
        vocabularies=vocabularies,
        rules=rules,
        execution_plan=execution_plan,
        _seal=_RULESET_SEAL,
    )


def freeze_mapping(values: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: _freeze_value(value) for key, value in values.items()})


def _freeze_value(value: object) -> object:
    if isinstance(value, list):
        list_items = cast(list[object], value)
        return tuple(_freeze_value(item) for item in list_items)
    if isinstance(value, Mapping):
        mapping_items = cast(Mapping[str, object], value)
        frozen: dict[str, object] = {
            key: _freeze_value(item) for key, item in mapping_items.items()
        }
        return MappingProxyType(frozen)
    return value
