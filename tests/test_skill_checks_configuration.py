from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from skill_checks import (
    SecurityAdapterBuildError,
    SecurityAdapterSettings,
    build_security_adapter,
)

ROOT = Path(__file__).resolve().parents[1]


def _settings(rules_path: Path) -> SecurityAdapterSettings:
    return SecurityAdapterSettings(
        rules_path=rules_path,
        max_package_bytes=1024 * 1024,
        max_entries_per_package=100,
        max_text_bytes_per_file=64 * 1024,
        max_total_read_bytes=1024 * 1024,
        max_findings=100,
    )


class SecurityAdapterConfigurationTests(unittest.TestCase):
    def test_builds_adapter_from_rules_and_policy_settings(self) -> None:
        adapter = build_security_adapter(
            _settings(ROOT / "config/security-rules.json")
        )

        self.assertEqual(adapter.check_id, "security")

    def test_invalid_rules_do_not_escape_the_sanitized_error_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rules_path = Path(directory) / "rules.json"
            rules_path.write_text("TOKEN_CANARY_SECRET", encoding="utf-8")

            with self.assertRaises(SecurityAdapterBuildError) as raised:
                build_security_adapter(_settings(rules_path))

            self.assertEqual(str(raised.exception), "安全检查配置无效")
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)


if __name__ == "__main__":
    unittest.main()
