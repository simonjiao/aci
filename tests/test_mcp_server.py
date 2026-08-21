from __future__ import annotations

import base64
import unittest
from io import BytesIO
from pathlib import Path
from typing import cast
from zipfile import ZIP_DEFLATED, ZipFile

from mcp.types import BlobResourceContents, EmbeddedResource

from mcp_server import create_server
from skill_checks import SecurityAdapter
from skill_security import ScanPolicy, SecurityScan, compile_rules
from tests.mcp_support import mcp_client, protocol_version, tool_list, tool_result
from tests.support import load_json_object, object_dict, string_list

ROOT = Path(__file__).resolve().parents[1]


def _skill_zip(content: str) -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        archive.writestr("SKILL.md", content)
    return stream.getvalue()


def _security_adapter() -> SecurityAdapter:
    rules = compile_rules(load_json_object(ROOT / "config/security-rules.json"))
    policy = ScanPolicy(
        max_package_bytes=1024 * 1024,
        max_entries_per_package=100,
        max_text_bytes_per_file=64 * 1024,
        max_total_read_bytes=1024 * 1024,
        max_findings=100,
    )
    return SecurityAdapter(rules, SecurityScan(policy))


class McpServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_security_tool_returns_only_the_result_zip_resource(self) -> None:
        server = create_server(_security_adapter(), max_package_bytes=1024 * 1024)
        arguments: dict[str, object] = {
            "package_name": "demo.zip",
            "package_base64": base64.b64encode(_skill_zip("# Safe Skill\n")).decode("ascii"),
            "source_id": "test-source",
        }

        async with mcp_client(server, raise_exceptions=True) as client:
            listed = tool_list(await client.list_tools())
            result = tool_result(await client.call_tool("scan_skill_security", arguments))
            negotiated_version = protocol_version(client.protocol_version)

        self.assertEqual(negotiated_version, "2026-07-28")
        tool_names: list[str] = [tool.name for tool in listed.tools]
        expected_tool_names: list[str] = ["scan_skill_security"]
        self.assertEqual(tool_names, expected_tool_names)
        input_schema = object_dict(listed.tools[0].input_schema)
        expected_required: list[str] = ["package_name", "package_base64"]
        self.assertEqual(
            string_list(input_schema["required"]),
            expected_required,
        )
        self.assertFalse(result.is_error)
        self.assertIsNone(result.structured_content)
        self.assertEqual(len(result.content), 1)
        resource_block = result.content[0]
        if not isinstance(resource_block, EmbeddedResource):
            raise AssertionError("expected embedded resource")
        resource = resource_block.resource
        if not isinstance(resource, BlobResourceContents):
            raise AssertionError("expected binary resource")
        self.assertEqual(resource.uri, "skill-security://result/skill-security-result.zip")
        self.assertEqual(resource.mime_type, "application/zip")
        archive_bytes = base64.b64decode(resource.blob, validate=True)
        with ZipFile(BytesIO(archive_bytes)) as archive:
            expected_names: list[str] = [
                "manifest.json",
                "security-scan.csv",
                "security-metadata.json",
            ]
            self.assertEqual(archive.namelist(), expected_names)
            self.assertEqual(archive.testzip(), None)

    async def test_invalid_tool_input_does_not_echo_sensitive_values(self) -> None:
        server = create_server(_security_adapter(), max_package_bytes=1024 * 1024)
        canary = "TOKEN_CANARY_SECRET" * 20

        async with mcp_client(server, raise_exceptions=False) as client:
            cases: tuple[dict[str, object], ...] = (
                {
                    "package_name": canary + ".zip",
                    "package_base64": {"value": canary},
                },
                {"package_name": "demo.zip", "package_base64": canary},
                {"package_base64": canary},
                {"package_name": canary + ".zip"},
                {"unexpected": canary},
            )
            for arguments in cases:
                result = tool_result(await client.call_tool("scan_skill_security", arguments))
                self.assertTrue(result.is_error)
                error_content = cast(object, result.content)
                self.assertNotIn("CANARY_SECRET", str(error_content))
            empty_arguments: dict[str, object] = {}
            unknown = tool_result(
                await client.call_tool("TOKEN_CANARY_SECRET", empty_arguments)
            )

        self.assertTrue(unknown.is_error)
        unknown_content = cast(object, unknown.content)
        self.assertNotIn("CANARY_SECRET", str(unknown_content))


if __name__ == "__main__":
    unittest.main()
