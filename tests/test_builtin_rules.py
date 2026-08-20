from __future__ import annotations

import copy
import json
import unittest
from io import BytesIO
from pathlib import Path
from typing import ClassVar
from zipfile import ZIP_DEFLATED, ZipFile

from skill_security import (
    PackageInput,
    RuleSet,
    ScanPolicy,
    ScanRequest,
    ScanResult,
    SecurityScan,
    compile_rules,
)

ROOT = Path(__file__).resolve().parents[1]
RULE_DOCUMENT = json.loads((ROOT / "config/security-rules.json").read_text(encoding="utf-8"))
RULE_SCHEMA = json.loads((ROOT / "config/security-rules.schema.json").read_text(encoding="utf-8"))
RULE_CASES = json.loads(
    (ROOT / "tests/fixtures/security-rule-cases.json").read_text(encoding="utf-8")
)
POLICY = ScanPolicy(2 * 1024 * 1024, 100, 64 * 1024, 2 * 1024 * 1024, 100)


def compile_one(rule_id: str) -> RuleSet:
    document = copy.deepcopy(RULE_DOCUMENT)
    document["rules"] = [item for item in document["rules"] if item["id"] == rule_id]
    return compile_rules(document)


def scan(entries: dict[str, str], rules: RuleSet) -> ScanResult:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return SecurityScan(POLICY).scan(
        ScanRequest((PackageInput("case.zip", BytesIO(stream.getvalue())),), rules)
    )


class BuiltinRuleTests(unittest.TestCase):
    rules: ClassVar[RuleSet]

    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = compile_rules(RULE_DOCUMENT)

    def test_rule_inventory_and_capability_coverage_are_complete(self) -> None:
        approved = {rule.id for rule in self.rules.execution_plan}

        self.assertEqual(len(self.rules.rules), 98)
        self.assertEqual(len(approved), 96)
        self.assertEqual(set(RULE_CASES), approved)
        self.assertEqual(
            {rule.id for rule in self.rules.rules if rule.status.value == "UNSUPPORTED"},
            {"SEC-IOC-06", "SEC-IOC-07"},
        )

    def test_every_approved_rule_has_positive_and_negative_behavior(self) -> None:
        for rule_id, case in RULE_CASES.items():
            with self.subTest(rule_id=rule_id, sample="positive"):
                positive = scan(case["positive"], compile_one(rule_id))
                self.assertTrue(positive.findings)
                self.assertEqual({finding.rule_id for finding in positive.findings}, {rule_id})
            with self.subTest(rule_id=rule_id, sample="negative"):
                negative = scan(case["negative"], compile_one(rule_id))
                self.assertEqual(negative.findings, ())

    def test_unsupported_ioc_rules_are_coverage_not_findings(self) -> None:
        result = scan({"sample.txt": "25.37.80.151 https://example.test"}, self.rules)

        self.assertNotIn("SEC-IOC-06", {finding.rule_id for finding in result.findings})
        self.assertNotIn("SEC-IOC-07", {finding.rule_id for finding in result.findings})
        self.assertEqual(
            result.coverage.unsupported_rule_ids,
            ("SEC-IOC-06", "SEC-IOC-07"),
        )

    def test_external_rule_document_matches_published_match_schema(self) -> None:
        match_schema = RULE_SCHEMA["properties"]["rules"]["items"]["properties"]["match"]
        variants = {item["properties"]["type"]["const"]: item for item in match_schema["oneOf"]}

        for rule in RULE_DOCUMENT["rules"]:
            with self.subTest(rule_id=rule["id"]):
                variant = variants[rule["match"]["type"]]
                self.assertLessEqual(set(variant["required"]), set(rule["match"]))
                self.assertLessEqual(set(rule["match"]), set(variant["properties"]))

        compatibility = {
            item["if"]["properties"]["evidence"]["properties"]["type"]["const"]: item["then"][
                "properties"
            ]["match"]["properties"]["type"]["const"]
            for item in RULE_SCHEMA["properties"]["rules"]["items"]["allOf"]
        }
        self.assertEqual(
            compatibility,
            {
                "base64": "base64_class",
                "entropy": "entropy",
                "hidden": "hidden_characters",
            },
        )

    def test_known_source_limitations_are_not_silently_exempted_or_broadened(self) -> None:
        domain = scan({"sample.txt": "df.info()"}, compile_one("SEC-IOC-05"))
        username = scan(
            {"SKILL.md": "| username | string | required |"},
            compile_one("SEC-SECRET-09"),
        )
        password_call = scan(
            {"sample.py": 'writer.encrypt("userpassword", "ownerpassword")'},
            compile_one("SEC-SECRET-08"),
        )

        self.assertEqual({finding.rule_id for finding in domain.findings}, {"SEC-IOC-05"})
        self.assertEqual(
            {finding.rule_id for finding in username.findings},
            {"SEC-SECRET-09"},
        )
        self.assertEqual(password_call.findings, ())


if __name__ == "__main__":
    unittest.main()
