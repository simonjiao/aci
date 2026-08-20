from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from skill_security import (
    Conclusion,
    FindingStatus,
    PackageInput,
    RuleStatus,
    ScanPolicy,
    ScanRequest,
    SecurityScan,
    compile_rules,
)


def minimal_rule_document() -> dict[str, object]:
    return {
        "schemaVersion": "1.0",
        "ruleVersion": "2026.08.20-test",
        "sourceVersion": "test-source",
        "defaultSkipDirectories": [".git"],
        "textExtensions": ["md", "py"],
        "vocabularies": {"terms": ["danger"]},
        "rules": [
            {
                "id": "SEC-TEST-01",
                "detector": "TestDetector",
                "name": "测试规则",
                "sourceDescription": "匹配 danger",
                "severity": "HIGH",
                "status": "APPROVED",
                "scope": "line",
                "match": {"type": "literal_any", "vocabulary": "terms"},
                "evidence": {"type": "command", "prefixLength": 0},
                "remediation": None,
                "sourceLimitations": [],
            },
            {
                "id": "SEC-TEST-02",
                "detector": "TestDetector",
                "name": "外部能力",
                "sourceDescription": "需要外部数据",
                "severity": "CRITICAL",
                "status": "UNSUPPORTED",
                "scope": "line",
                "match": {"type": "external_intelligence"},
                "evidence": {"type": "indicator", "prefixLength": 0},
                "remediation": None,
                "sourceLimitations": ["未提供数据源"],
            },
        ],
    }


class RuleCompilationTests(unittest.TestCase):
    def test_compiles_immutable_execution_plan(self) -> None:
        rules = compile_rules(minimal_rule_document())
        execution_ids: tuple[str, ...] = tuple(rule.id for rule in rules.execution_plan)

        self.assertEqual(rules.schema_version, "1.0")
        self.assertEqual(rules.rule_version, "2026.08.20-test")
        self.assertEqual(execution_ids, ("SEC-TEST-01",))
        self.assertEqual(rules.rules[1].status, RuleStatus.UNSUPPORTED)
        self.assertEqual(len(rules.sha256), 64)
        with self.assertRaises(FrozenInstanceError):
            rules.__setattr__("rule_version", "changed")


def zip_bytes(entries: dict[str, str]) -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return stream.getvalue()


def policy() -> ScanPolicy:
    return ScanPolicy(
        max_package_bytes=1024 * 1024,
        max_entries_per_package=100,
        max_text_bytes_per_file=64 * 1024,
        max_total_read_bytes=1024 * 1024,
        max_findings=100,
    )


class ScanningTests(unittest.TestCase):
    def test_scans_package_and_restores_stream_position(self) -> None:
        rules = compile_rules(minimal_rule_document())
        stream = BytesIO(zip_bytes({"SKILL.md": "safe\ndanger command\n"}))
        stream.seek(2)

        result = SecurityScan(policy()).scan(
            ScanRequest((PackageInput("demo.zip", stream, "upload-7"),), rules)
        )

        self.assertEqual(result.conclusion, Conclusion.REVIEW_REQUIRED)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "SEC-TEST-01")
        self.assertEqual(finding.status, FindingStatus.REVIEW_REQUIRED)
        self.assertEqual((finding.entry_path, finding.line, finding.column), ("SKILL.md", 2, 1))
        self.assertEqual(finding.evidence, "danger command")
        self.assertEqual(result.packages[0].finding_count, 1)
        self.assertEqual(result.coverage.executed_rule_ids, ("SEC-TEST-01",))
        self.assertEqual(result.coverage.unsupported_rule_ids, ("SEC-TEST-02",))
        self.assertEqual(stream.tell(), 2)


if __name__ == "__main__":
    unittest.main()
