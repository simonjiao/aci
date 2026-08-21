from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_server.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parents[1]


def _write_config(path: Path, max_request_body_bytes: int = 2 * 1024 * 1024) -> None:
    path.write_text(
        f'''schema_version = "1"

[http]
host = "127.0.0.1"
port = 8765
path = "/mcp"
max_request_body_bytes = {max_request_body_bytes}
allowed_hosts = ["127.0.0.1:*", "localhost:*"]
allowed_origins = ["http://127.0.0.1:*", "http://localhost:*"]

[tools.scan_skill_security]
type = "skill-security"
rules_file = "security-rules.json"

[tools.scan_skill_security.policy]
max_package_bytes = 1048576
max_entries_per_package = 100
max_text_bytes_per_file = 65536
max_total_read_bytes = 1048576
max_findings = 100
''',
        encoding="utf-8",
    )


class McpConfigTests(unittest.TestCase):
    def test_repository_mcp_config_is_loadable(self) -> None:
        loaded = load_config(ROOT / "config/mcp.toml")

        self.assertEqual(loaded.http.path, "/mcp")
        self.assertEqual(loaded.security_adapter.check_id, "security")

    def test_loads_http_and_security_tool_config_from_its_own_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            _write_config(config)

            loaded = load_config(config)

            self.assertEqual(loaded.http.host, "127.0.0.1")
            self.assertEqual(loaded.http.port, 8765)
            self.assertEqual(loaded.http.path, "/mcp")
            self.assertEqual(loaded.http.max_request_body_bytes, 2 * 1024 * 1024)
            self.assertEqual(loaded.http.allowed_hosts, ("127.0.0.1:*", "localhost:*"))
            self.assertEqual(
                loaded.http.allowed_origins,
                ("http://127.0.0.1:*", "http://localhost:*"),
            )
            self.assertEqual(loaded.max_package_bytes, 1024 * 1024)
            self.assertEqual(loaded.security_adapter.check_id, "security")

    def test_rejects_a_body_limit_that_cannot_hold_the_configured_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            _write_config(config, max_request_body_bytes=1024 * 1024)

            with self.assertRaises(ConfigError) as raised:
                load_config(config)

            self.assertEqual(str(raised.exception), "MCP 配置无效")
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)

    def test_invalid_config_does_not_retain_sensitive_validation_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "mcp.toml"
            config.write_text(
                'schema_version = "TOKEN_CANARY_SECRET"\n',
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError) as raised:
                load_config(config)

            self.assertNotIn("CANARY_SECRET", str(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)


if __name__ == "__main__":
    unittest.main()
