from __future__ import annotations

import copy
import json
import math
import unittest
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from io import BytesIO
from pathlib import Path
from types import MappingProxyType
from typing import cast
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
from tests.support import dict_field, list_field, object_dict

ROOT = Path(__file__).resolve().parents[1]


class TokenCanarySecretDocument(Mapping[str, object]):
    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = values

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


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


def first_rule(values: dict[str, object]) -> dict[str, object]:
    return object_dict(list_field(values, "rules")[0])


class RuleContractTests(unittest.TestCase):
    def test_canonical_hash_ignores_object_key_order_but_keeps_array_order(self) -> None:
        original = document()
        reordered = dict(reversed(tuple(original.items())))
        reversed_rules = copy.deepcopy(original)
        rule_items = list_field(reversed_rules, "rules")
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
            mutable = cast(MutableMapping[str, object], rules.rules[0].parameters)
            mutable["terms"] = ("changed",)

    def test_invalid_parameters_are_rejected_without_echoing_value(self) -> None:
        unknown = document()
        secret_key = "password=do-not-echo"
        dict_field(first_rule(unknown), "match")[secret_key] = "value"
        non_finite = document()
        dict_field(first_rule(non_finite), "match")["threshold"] = math.inf

        for invalid in (unknown, non_finite):
            with self.subTest(document=json.dumps(invalid, default=str)[:30]):
                with self.assertRaises(ScanError) as raised:
                    compile_rules(invalid)
                self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)
                self.assertNotIn("do-not-echo", raised.exception.message)

    def test_invalid_rule_value_does_not_escape_through_exception_chain(self) -> None:
        invalid = document()
        first_rule(invalid)["status"] = "TOKEN_CANARY_SECRET"

        with self.assertRaises(ScanError) as raised:
            compile_rules(invalid)

        self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)
        self.assertNotIn("CANARY_SECRET", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_invalid_rule_document_does_not_escape_through_exception_chain(self) -> None:
        invalid = TokenCanarySecretDocument(document())

        with self.assertRaises(ScanError) as raised:
            compile_rules(invalid)

        self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)
        self.assertNotIn("CanarySecret", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_non_utf8_rule_value_does_not_escape_raw_encoding_error(self) -> None:
        invalid = document()
        invalid["ruleVersion"] = "TOKEN_CANARY_SECRET\ud800"

        with self.assertRaises(ScanError) as raised:
            compile_rules(invalid)

        self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)
        self.assertNotIn("CANARY_SECRET", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_parameters_that_cannot_execute_deterministically_are_rejected(self) -> None:
        invalid_documents: list[dict[str, object]] = []

        invalid_id = document()
        first_rule(invalid_id)["id"] = "SEC-test"
        invalid_documents.append(invalid_id)

        non_normal_extension = document()
        non_normal_extension["textExtensions"] = ["TXT"]
        invalid_documents.append(non_normal_extension)

        impossible_token_length = document()
        first_rule(impossible_token_length)["match"] = {
            "type": "prefixed_token",
            "prefixes": ["github_pat_"],
            "minimumLength": 1,
            "maximumLength": 5,
            "alphabet": "token",
        }
        invalid_documents.append(impossible_token_length)

        invalid_code_point = document()
        first_rule(invalid_code_point)["match"] = {
            "type": "hidden_characters",
            "codePoints": ["0041"],
        }
        invalid_documents.append(invalid_code_point)

        ignored_field_alphabet = document()
        first_rule(ignored_field_alphabet)["match"] = {
            "type": "field_value",
            "fields": ["password"],
            "separators": ["="],
            "minimumValueLength": 8,
            "alphabet": "upper_alnum",
        }
        invalid_documents.append(ignored_field_alphabet)

        invalid_scope = document()
        first_rule(invalid_scope)["scope"] = "package"
        invalid_documents.append(invalid_scope)

        unsupported_base64_threshold = document()
        unsupported_base64_threshold["vocabularies"] = {"bad": ["exec"]}
        first_rule(unsupported_base64_threshold)["match"] = {
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
        first_rule(invalid_condition_type)["match"] = {
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
        first_rule(incompatible_evidence)["evidence"] = {
            "type": "base64",
            "prefixLength": 0,
        }
        invalid_documents.append(incompatible_evidence)

        excessive_evidence_prefix = document()
        dict_field(first_rule(excessive_evidence_prefix), "evidence")["prefixLength"] = 9
        invalid_documents.append(excessive_evidence_prefix)

        for invalid in invalid_documents:
            with self.subTest(match=dict_field(first_rule(invalid), "match")):
                with self.assertRaises(ScanError) as raised:
                    compile_rules(invalid)
                self.assertEqual(raised.exception.code, ErrorCode.RULESET_INVALID)


class PublicContractTests(unittest.TestCase):
    def test_policy_and_request_validation_use_structured_errors(self) -> None:
        rules = compile_rules(document())
        valid_package = PackageInput("sample.zip", BytesIO(archive_bytes({"a.txt": "safe"})))
        invalid_policy = ScanPolicy(
            cast(int, "POLICY_CANARY_SECRET"),
            100,
            64 * 1024,
            1024 * 1024,
            100,
        )
        invalid_package = PackageInput(
            cast(str, b"REQUEST_CANARY_SECRET"),
            BytesIO(archive_bytes({"a.txt": "safe"})),
        )

        invalid_calls: list[tuple[Callable[[], object], ErrorCode]] = [
            (lambda: SecurityScan(cast(ScanPolicy, None)), ErrorCode.POLICY_INVALID),
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
        actual_order: list[tuple[str, str]] = [
            (finding.entry_path, finding.rule_id) for finding in first.findings
        ]
        expected_order: list[tuple[str, str]] = [
            ("a.txt", "SEC-TEST-01"),
            ("z.txt", "SEC-TEST-02"),
        ]
        self.assertEqual(actual_order, expected_order)
        self.assertEqual(len({finding.id for finding in first.findings}), 2)
        self.assertTrue(all(len(finding.id) == 64 for finding in first.findings))


if __name__ == "__main__":
    unittest.main()
