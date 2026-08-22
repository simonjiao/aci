from __future__ import annotations

import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from os import environ
from pathlib import Path

from mcp_server.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def _environment(name: str, value: str) -> Iterator[None]:
    previous = environ.get(name)
    environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            environ.pop(name, None)
        else:
            environ[name] = previous


@contextmanager
def _without_environment(name: str) -> Iterator[None]:
    previous = environ.pop(name, None)
    try:
        yield
    finally:
        if previous is not None:
            environ[name] = previous


def _write_config(path: Path, max_request_body_bytes: int = 2 * 1024 * 1024) -> None:
    artifact_root = (path.parent / "artifacts").as_posix()
    scratch_root = (path.parent / "scratch").as_posix()
    path.write_text(
        f'''schema_version = "2"

[http]
host = "127.0.0.1"
port = 8765
path = "/mcp"
max_request_body_bytes = {max_request_body_bytes}
public_base_url = "http://127.0.0.1:8765"
allowed_hosts = ["127.0.0.1:*", "localhost:*"]
allowed_origins = ["http://127.0.0.1:*", "http://localhost:*"]

[auth]
type = "static_bearer"
key_env = "SKILLQA_TEST_API_KEY"

[storage]
max_result_bytes = 1048576
scratch_directory = "{scratch_root}"

[storage.backend]
type = "filesystem"
root = "{artifact_root}"

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
        with _environment("SKILLQA_API_KEY", "test-static-key-0123456789abcdef"):
            loaded = load_config(ROOT / "config/mcp.toml")

        self.assertEqual(loaded.http.path, "/mcp")
        self.assertEqual(loaded.http.public_base_url, "http://127.0.0.1:8000")
        self.assertEqual(loaded.security_adapter.check_id, "security")

    def test_loads_http_and_security_tool_config_from_its_own_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            _write_config(config)

            with _environment(
                "SKILLQA_TEST_API_KEY",
                "test-static-key-0123456789abcdef",
            ):
                loaded = load_config(config)

            self.assertEqual(loaded.http.host, "127.0.0.1")
            self.assertEqual(loaded.http.port, 8765)
            self.assertEqual(loaded.http.path, "/mcp")
            self.assertEqual(loaded.http.max_request_body_bytes, 2 * 1024 * 1024)
            self.assertEqual(loaded.http.public_base_url, "http://127.0.0.1:8765")
            self.assertEqual(loaded.http.allowed_hosts, ("127.0.0.1:*", "localhost:*"))
            self.assertEqual(
                loaded.http.allowed_origins,
                ("http://127.0.0.1:*", "http://localhost:*"),
            )
            self.assertEqual(loaded.max_package_bytes, 1024 * 1024)
            self.assertEqual(loaded.max_result_bytes, 1024 * 1024)
            self.assertEqual(loaded.security_adapter.check_id, "security")
            self.assertNotIn("test-static-key-0123456789abcdef", repr(loaded))

    def test_rejects_a_missing_static_bearer_key_without_leaking_its_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            _write_config(config)

            with (
                _without_environment("SKILLQA_TEST_API_KEY"),
                self.assertRaises(ConfigError) as raised,
            ):
                load_config(config)

        self.assertEqual(str(raised.exception), "MCP 配置无效")
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_rejects_a_body_limit_that_cannot_hold_the_configured_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            _write_config(config, max_request_body_bytes=1024 * 1024)

            with (
                _environment(
                    "SKILLQA_TEST_API_KEY",
                    "test-static-key-0123456789abcdef",
                ),
                self.assertRaises(ConfigError) as raised,
            ):
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
