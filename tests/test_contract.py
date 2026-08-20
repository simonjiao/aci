from __future__ import annotations

import copy
import json
import math
import unittest
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from types import MappingProxyType
from zipfile import ZIP_DEFLATED, ZipFile

from skill_security import (
    Conclusion,
    ErrorCode,
    PackageInput,
    ScanError,
    ScanPolicy,
    ScanRequest,
    SecurityScan,
    compile_rules,
)

ROOT = Path(__file__).resolve().parents[1]


def document() -> dict[str, object]:
    return {
        "schemaVersion": "1.0",
        "ruleVersion": "test",
        "sourceVersion": "test",
        "defaultSkipDirectories": [".git"],
        "textExtensions": ["txt"],
        "vocabularies": {},
        "rules": [
            {
                "id": "SEC-TEST-01",
                "detector": "TestDetector",
                "name": "danger",
                "sourceDescription": "danger",
                "severity": "HIGH",
                "status": "APPROVED",
                "scope": "line",
                "match": {"type": "literal_any", "terms": ["danger", "dangerous"]},
                "evidence": {"type": "command", "prefixLength": 0},
                "remediation": None,
                "sourceLimitations": [],
            },
            {
                "id": "SEC-TEST-02",
                "detector": "TestDetector",
                "name": "alert",
                "sourceDescription": "alert",
                "severity": "MEDIUM",
                "status": "APPROVED",
                "scope": "line",
                "match": {"type": "literal_any", "terms": ["alert"]},
                "evidence": {"type": "command", "prefixLength": 0},
                "remediation": None,
                "sourceLimitations": [],
            },
        ],
    }


def archive_bytes(entries: dict[str, str]) -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return stream.getvalue()


def policy(**changes: int) -> ScanPolicy:
    values = {
        "max_package_bytes": 1024 * 1024,
        "max_entries_per_package": 100,
        "max_text_bytes_per_file": 64 * 1024,
        "max_total_read_bytes": 1024 * 1024,
        "max_findings": 100,
    }
    values.update(changes)
    return ScanPolicy(**values)


class RuleContractTests(unittest.TestCase):
    def test_canonical_hash_ignores_object_key_order_but_keeps_array_order(self) -> None:
        original = document()
        reordered = dict(reversed(tuple(original.items())))
        reversed_rules = copy.deepcopy(original)
        rule_items = reversed_rules["rules"]
        self.assertIsInstance(rule_items, list)
        assert isinstance(rule_items, list)
        rule_items.reverse()

        self.assertEqual(compile_rules(original).sha256, compile_rules(reordered).sha256)
        self.assertNotEqual(
            compile_rules(original).sha256,
            compile_rules(reversed_rules).sha256,
        )

    def test_compiled_rules_are_deeply_immutable(self) -> None:
        rules = compile_rules(document())

        self.assertIsInstance(rules.rules[0].parameters, MappingProxyType)
        with self.assertRaises(TypeError):
            rules.rules[0].parameters["terms"] = ("changed",)  # type: ignore[index]

    def test_invalid_parameters_are_rejected_without_echoing_value(self) -> None:
        unknown = document()
        secret_key = "password=do-not-echo"
        unknown["rules"][0]["match"][secret_key] = "value"  # type: ignore[index]
        non_finite = document()
        non_finite["rules"][0]["match"]["threshold"] = math.inf  # type: ignore[index]

        for invalid in (unknown, non_finite):
            with self.subTest(document=json.dumps(invalid, default=str)[:30]):
                with self.assertRaises(ScanError) as raised:
                    compile_rules(invalid)
                self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)
                self.assertNotIn("do-not-echo", raised.exception.message)

    def test_parameters_that_cannot_execute_deterministically_are_rejected(self) -> None:
        invalid_documents = []

        invalid_id = document()
        invalid_id["rules"][0]["id"] = "SEC-test"  # type: ignore[index]
        invalid_documents.append(invalid_id)

        non_normal_extension = document()
        non_normal_extension["textExtensions"] = ["TXT"]
        invalid_documents.append(non_normal_extension)

        impossible_token_length = document()
        impossible_token_length["rules"][0]["match"] = {  # type: ignore[index]
            "type": "prefixed_token",
            "prefixes": ["github_pat_"],
            "minimumLength": 1,
            "maximumLength": 5,
            "alphabet": "token",
        }
        invalid_documents.append(impossible_token_length)

        invalid_code_point = document()
        invalid_code_point["rules"][0]["match"] = {  # type: ignore[index]
            "type": "hidden_characters",
            "codePoints": ["0041"],
        }
        invalid_documents.append(invalid_code_point)

        ignored_field_alphabet = document()
        ignored_field_alphabet["rules"][0]["match"] = {  # type: ignore[index]
            "type": "field_value",
            "fields": ["password"],
            "separators": ["="],
            "minimumValueLength": 8,
            "alphabet": "upper_alnum",
        }
        invalid_documents.append(ignored_field_alphabet)

        invalid_scope = document()
        invalid_scope["rules"][0]["scope"] = "package"  # type: ignore[index]
        invalid_documents.append(invalid_scope)

        unsupported_base64_threshold = document()
        unsupported_base64_threshold["vocabularies"] = {"bad": ["exec"]}
        unsupported_base64_threshold["rules"][0]["match"] = {  # type: ignore[index]
            "type": "base64_class",
            "classification": "suspicious_text",
            "minimumLength": 49,
            "maliciousVocabulary": "bad",
            "skipLinePrefixes": [],
            "skipBasenames": [],
            "skipFieldNames": [],
        }
        invalid_documents.append(unsupported_base64_threshold)

        invalid_condition_type = document()
        invalid_condition_type["rules"][0]["match"] = {  # type: ignore[index]
            "type": "url_ioc",
            "condition": [],
            "requireExecutable": False,
            "tldVocabulary": "tlds",
            "keywordVocabulary": "keywords",
            "executableVocabulary": "executables",
        }
        invalid_condition_type["vocabularies"] = {
            "tlds": [".xyz"],
            "keywords": ["evil"],
            "executables": [".exe"],
        }
        invalid_documents.append(invalid_condition_type)

        incompatible_evidence = document()
        incompatible_evidence["rules"][0]["evidence"] = {  # type: ignore[index]
            "type": "base64",
            "prefixLength": 0,
        }
        invalid_documents.append(incompatible_evidence)

        excessive_evidence_prefix = document()
        excessive_evidence_prefix["rules"][0]["evidence"]["prefixLength"] = 9  # type: ignore[index]
        invalid_documents.append(excessive_evidence_prefix)

        for invalid in invalid_documents:
            with self.subTest(match=invalid["rules"][0]["match"]):  # type: ignore[index]
                with self.assertRaises(ScanError) as raised:
                    compile_rules(invalid)
                self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)


class PublicContractTests(unittest.TestCase):
    def test_policy_and_request_validation_use_structured_errors(self) -> None:
        rules = compile_rules(document())
        valid_package = PackageInput("sample.zip", BytesIO(archive_bytes({"a.txt": "safe"})))
        invalid_policy = ScanPolicy(
            "POLICY_CANARY_SECRET",  # type: ignore[arg-type]
            100,
            64 * 1024,
            1024 * 1024,
            100,
        )
        invalid_package = PackageInput(
            b"REQUEST_CANARY_SECRET",  # type: ignore[arg-type]
            BytesIO(archive_bytes({"a.txt": "safe"})),
        )

        invalid_calls: list[tuple[Callable[[], object], ErrorCode]] = [
            (lambda: SecurityScan(None), ErrorCode.POLICY_INVALID),  # type: ignore[arg-type]
            (lambda: SecurityScan(invalid_policy), ErrorCode.POLICY_INVALID),
            (
                lambda: SecurityScan(policy(max_entries_per_package=1001)),
                ErrorCode.POLICY_INVALID,
            ),
            (
                lambda: SecurityScan(policy()).scan(ScanRequest((), rules)),
                ErrorCode.REQUEST_INVALID,
            ),
            (
                lambda: SecurityScan(policy()).scan(
                    ScanRequest((valid_package, valid_package), rules)
                ),
                ErrorCode.REQUEST_INVALID,
            ),
            (
                lambda: SecurityScan(policy()).scan(ScanRequest((invalid_package,), rules)),
                ErrorCode.REQUEST_INVALID,
            ),
        ]
        for call, expected in invalid_calls:
            with self.subTest(expected=expected):
                with self.assertRaises(ScanError) as raised:
                    call()
                self.assertEqual(raised.exception.code, expected)
                self.assertIsNone(raised.exception.__context__)
                self.assertIsNone(raised.exception.__cause__)
                self.assertNotIn("CANARY_SECRET", str(raised.exception))

    def test_public_string_enums_keep_original_string_behavior(self) -> None:
        self.assertEqual(str(Conclusion.PASS), "Conclusion.PASS")
        self.assertEqual(format(ErrorCode.REQUEST_INVALID), "ErrorCode.REQUEST_INVALID")

    def test_result_is_deterministic_deduplicated_and_sorted(self) -> None:
        rules = compile_rules(document())
        content = archive_bytes({"z.txt": "alert", "a.txt": "dangerous"})
        scanner = SecurityScan(policy())

        first = scanner.scan(
            ScanRequest((PackageInput("sample.zip", BytesIO(content), "source-1"),), rules)
        )
        second = scanner.scan(
            ScanRequest((PackageInput("sample.zip", BytesIO(content), "source-1"),), rules)
        )

        self.assertEqual(first, second)
        self.assertEqual(first.conclusion, Conclusion.REVIEW_REQUIRED)
        self.assertEqual(
            [(finding.entry_path, finding.rule_id) for finding in first.findings],
            [("a.txt", "SEC-TEST-01"), ("z.txt", "SEC-TEST-02")],
        )
        self.assertEqual(len({finding.id for finding in first.findings}), 2)
        self.assertTrue(all(len(finding.id) == 64 for finding in first.findings))


if __name__ == "__main__":
    unittest.main()
