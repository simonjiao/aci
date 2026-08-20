from __future__ import annotations

import base64
import math
import unittest
from collections import Counter
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from skill_security import PackageInput, ScanPolicy, ScanRequest, SecurityScan, compile_rules


def rule(rule_id: str, match: dict[str, object], evidence_type: str) -> dict[str, object]:
    return {
        "id": rule_id,
        "detector": "TestDetector",
        "name": rule_id,
        "sourceDescription": rule_id,
        "severity": "HIGH",
        "status": "APPROVED",
        "scope": "line",
        "match": match,
        "evidence": {"type": evidence_type, "prefixLength": 3},
        "remediation": None,
        "sourceLimitations": [],
    }


def rules_for(item: dict[str, object], vocabularies: dict[str, list[str]] | None = None):
    return compile_rules(
        {
            "schemaVersion": "1.0",
            "ruleVersion": "test",
            "sourceVersion": "test",
            "defaultSkipDirectories": [".git"],
            "textExtensions": ["md", "py", "txt"],
            "vocabularies": vocabularies or {},
            "rules": [item],
        }
    )


def scan_text(text: str, compiled) -> tuple:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        archive.writestr("sample.py", text)
    policy = ScanPolicy(1024 * 1024, 20, 64 * 1024, 1024 * 1024, 100)
    result = SecurityScan(policy).scan(
        ScanRequest((PackageInput("sample.zip", BytesIO(stream.getvalue())),), compiled)
    )
    return result.findings


class ContentDetectionTests(unittest.TestCase):
    def test_prefixed_secret_is_redacted(self) -> None:
        compiled = rules_for(
            rule(
                "SEC-TEST-01",
                {
                    "type": "prefixed_token",
                    "prefixes": ["sk-"],
                    "minimumLength": 20,
                    "alphabet": "token",
                },
                "secret",
            )
        )

        findings = scan_text("token = sk-abcdefghijklmnopq", compiled)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, "sk-… [REDACTED; length=20]")
        self.assertNotIn("abcdefghijklmnopq", findings[0].evidence)

    def test_redaction_never_returns_an_entire_short_token(self) -> None:
        item = rule(
            "SEC-TEST-01",
            {
                "type": "prefixed_token",
                "prefixes": ["t-"],
                "minimumLength": 3,
                "alphabet": "token",
            },
            "token",
        )
        item["evidence"]["prefixLength"] = 8  # type: ignore[index]

        finding = scan_text("token=t-x", rules_for(item))[0]

        self.assertNotIn("t-x", finding.evidence)
        self.assertEqual(finding.evidence, "t-… [REDACTED; length=3]")

    def test_nonliteral_call_ignores_literal_argument(self) -> None:
        compiled = rules_for(
            rule(
                "SEC-TEST-01",
                {"type": "nonliteral_call", "functions": ["eval"]},
                "command",
            )
        )

        self.assertEqual(scan_text('eval("1 + 1")', compiled), ())
        self.assertEqual(len(scan_text("eval(user_input)", compiled)), 1)

    def test_base64_classification_uses_decoded_content(self) -> None:
        encoded = base64.b64encode(b"import os; os.system('id')" * 3).decode()
        compiled = rules_for(
            rule(
                "SEC-TEST-01",
                {
                    "type": "base64_class",
                    "classification": "suspicious_text",
                    "minimumLength": 50,
                    "maliciousVocabulary": "malicious",
                    "skipLinePrefixes": ["data:image/"],
                    "skipBasenames": [],
                    "skipFieldNames": [],
                },
                "base64",
            ),
            {"malicious": ["import", "os.system"]},
        )

        finding = scan_text(encoded, compiled)[0]

        self.assertIn("classification=suspicious_text", finding.evidence)
        self.assertNotIn(encoded, finding.evidence)

    def test_entropy_match_reports_source_measurement(self) -> None:
        text = "".join(chr(33 + index) for index in range(90)) * 2
        expected = -sum(
            count / len(text) * math.log2(count / len(text)) for count in Counter(text).values()
        )
        compiled = rules_for(
            rule(
                "SEC-TEST-01",
                {
                    "type": "entropy",
                    "minimumLength": 100,
                    "threshold": 5.5,
                    "elevatedThreshold": 6.5,
                    "elevatedExtensions": ["md"],
                    "commentPrefixes": ["//", "#", "/*", "*"],
                    "dataPrefix": "data:",
                    "skipBasenames": [],
                },
                "entropy",
            )
        )

        finding = scan_text(text, compiled)[0]

        self.assertIn(f"entropy={expected:.3f}", finding.evidence)
        self.assertIn("threshold=5.500", finding.evidence)

    def test_command_evidence_masks_incidental_credentials(self) -> None:
        compiled = rules_for(
            rule(
                "SEC-TEST-01",
                {"type": "literal_any", "terms": ["curl"]},
                "command",
            )
        )
        secret = "ghp_abcdefghijklmnopqrstuvwxyz"
        generic = "CANARY-DO-NOT-RETURN"
        option = "SECOND-CANARY"

        finding = scan_text(
            (
                f'curl https://example.test -H "Authorization: Bearer {secret}" '
                f"# token={generic} --client-secret {option}"
            ),
            compiled,
        )[0]

        self.assertNotIn(secret, finding.evidence)
        self.assertNotIn(generic, finding.evidence)
        self.assertNotIn(option, finding.evidence)
        self.assertIn("[REDACTED]", finding.evidence)


if __name__ == "__main__":
    unittest.main()
