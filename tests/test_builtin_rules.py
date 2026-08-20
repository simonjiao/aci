from __future__ import annotations

import copy
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
from tests.support import (
    dict_field,
    list_field,
    load_json_object,
    object_dict,
    string_field,
    string_list,
    string_mapping,
)

ROOT = Path(__file__).resolve().parents[1]
RULE_DOCUMENT = load_json_object(ROOT / "config/security-rules.json")
RULE_SCHEMA = load_json_object(ROOT / "config/security-rules.schema.json")
RULE_CASES = load_json_object(ROOT / "tests/fixtures/security-rule-cases.json")
POLICY = ScanPolicy(2 * 1024 * 1024, 100, 64 * 1024, 2 * 1024 * 1024, 100)


def compile_one(rule_id: str) -> RuleSet:
    document = copy.deepcopy(RULE_DOCUMENT)
    selected: list[object] = []
    for item in list_field(document, "rules"):
        rule = object_dict(item)
        if string_field(rule, "id") == rule_id:
            selected.append(rule)
    document["rules"] = selected
    return compile_rules(document)


def rule_schema() -> dict[str, object]:
    properties = dict_field(RULE_SCHEMA, "properties")
    rules = dict_field(properties, "rules")
    return dict_field(rules, "items")


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
        case_ids: set[str] = set(RULE_CASES)
        unsupported: set[str] = {
            rule.id for rule in self.rules.rules if rule.status.value == "UNSUPPORTED"
        }
        expected_unsupported: set[str] = {"SEC-IOC-06", "SEC-IOC-07"}
        self.assertEqual(case_ids, approved)
        self.assertEqual(unsupported, expected_unsupported)

    def test_every_approved_rule_has_positive_and_negative_behavior(self) -> None:
        for rule_id, raw_case in RULE_CASES.items():
            case = object_dict(raw_case)
            with self.subTest(rule_id=rule_id, sample="positive"):
                positive = scan(string_mapping(case["positive"]), compile_one(rule_id))
                self.assertTrue(positive.findings)
                positive_ids: set[str] = {finding.rule_id for finding in positive.findings}
                expected_ids: set[str] = {rule_id}
                self.assertEqual(positive_ids, expected_ids)
            with self.subTest(rule_id=rule_id, sample="negative"):
                negative = scan(string_mapping(case["negative"]), compile_one(rule_id))
                self.assertEqual(negative.findings, ())

    def test_unsupported_ioc_rules_are_coverage_not_findings(self) -> None:
        result = scan({"sample.txt": "25.37.80.151 https://example.test"}, self.rules)

        finding_ids: set[str] = {finding.rule_id for finding in result.findings}
        self.assertNotIn("SEC-IOC-06", finding_ids)
        self.assertNotIn("SEC-IOC-07", finding_ids)
        self.assertEqual(
            result.coverage.unsupported_rule_ids,
            ("SEC-IOC-06", "SEC-IOC-07"),
        )

    def test_external_rule_document_matches_published_match_schema(self) -> None:
        item_schema = rule_schema()
        match_schema = dict_field(dict_field(item_schema, "properties"), "match")
        variants: dict[str, dict[str, object]] = {}
        for raw_variant in list_field(match_schema, "oneOf"):
            variant = object_dict(raw_variant)
            type_schema = dict_field(dict_field(variant, "properties"), "type")
            variants[string_field(type_schema, "const")] = variant

        for raw_rule in list_field(RULE_DOCUMENT, "rules"):
            rule = object_dict(raw_rule)
            match = dict_field(rule, "match")
            with self.subTest(rule_id=string_field(rule, "id")):
                variant = variants[string_field(match, "type")]
                required = set(string_list(variant["required"]))
                allowed = set(dict_field(variant, "properties"))
                self.assertLessEqual(required, set(match))
                self.assertLessEqual(set(match), allowed)

        compatibility: dict[str, str] = {}
        for raw_item in list_field(item_schema, "allOf"):
            item = object_dict(raw_item)
            condition_properties = dict_field(dict_field(item, "if"), "properties")
            evidence = dict_field(condition_properties, "evidence")
            evidence_type = dict_field(dict_field(evidence, "properties"), "type")
            result_properties = dict_field(dict_field(item, "then"), "properties")
            match = dict_field(result_properties, "match")
            match_type = dict_field(dict_field(match, "properties"), "type")
            compatibility[string_field(evidence_type, "const")] = string_field(match_type, "const")
        expected_compatibility: dict[str, str] = {
            "base64": "base64_class",
            "entropy": "entropy",
            "hidden": "hidden_characters",
        }
        self.assertEqual(compatibility, expected_compatibility)

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

        domain_ids: set[str] = {finding.rule_id for finding in domain.findings}
        username_ids: set[str] = {finding.rule_id for finding in username.findings}
        expected_domain_ids: set[str] = {"SEC-IOC-05"}
        expected_username_ids: set[str] = {"SEC-SECRET-09"}
        self.assertEqual(domain_ids, expected_domain_ids)
        self.assertEqual(username_ids, expected_username_ids)
        self.assertEqual(password_call.findings, ())


if __name__ == "__main__":
    unittest.main()
