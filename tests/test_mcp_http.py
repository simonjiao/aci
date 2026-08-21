from __future__ import annotations

import asyncio
import base64
import http.client
import os
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from mcp.types import BlobResourceContents, EmbeddedResource

from tests.mcp_support import mcp_client, protocol_version, tool_result

ROOT = Path(__file__).resolve().parents[1]


def _available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        address = listener.getsockname()
    if not isinstance(address, tuple) or not isinstance(address[1], int):
        raise AssertionError("expected TCP address")
    return address[1]


def _write_config(path: Path, port: int) -> None:
    path.write_text(
        f'''schema_version = "1"

[http]
host = "127.0.0.1"
port = {port}
path = "/mcp"
max_request_body_bytes = 2097152
allowed_hosts = ["127.0.0.1:*"]
allowed_origins = ["http://127.0.0.1:*"]

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


def _skill_zip() -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        archive.writestr("SKILL.md", "# Safe Skill\n")
    return stream.getvalue()


async def _wait_until_listening(port: int, process: subprocess.Popen[str]) -> None:
    for _attempt in range(100):
        if process.poll() is not None:
            raise AssertionError("MCP server exited before accepting connections")
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        await writer.wait_closed()
        return
    raise AssertionError("MCP server did not accept connections")


def _request_with_spoofed_host(port: int) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/mcp",
            body=b"{}",
            headers={"Content-Type": "application/json", "Host": "untrusted.example"},
        )
        return connection.getresponse().status
    finally:
        connection.close()


class McpHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_serves_the_security_tool_over_streamable_http(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            port = _available_port()
            _write_config(config, port)
            process = subprocess.Popen(
                (
                    sys.executable,
                    "-m",
                    "mcp_server.main",
                    "--config",
                    str(config),
                ),
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            shutdown_stderr = ""
            try:
                await _wait_until_listening(port, process)
                spoofed_host_status = _request_with_spoofed_host(port)
                arguments: dict[str, object] = {
                    "package_name": "demo.zip",
                    "package_base64": base64.b64encode(_skill_zip()).decode("ascii"),
                }
                async with mcp_client(
                    f"http://127.0.0.1:{port}/mcp",
                    raise_exceptions=True,
                ) as client:
                    result = tool_result(
                        await client.call_tool("scan_skill_security", arguments)
                    )
                    negotiated_version = protocol_version(client.protocol_version)
                if os.name == "posix":
                    process.send_signal(signal.SIGINT)
                    _shutdown_stdout, shutdown_stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5)

        self.assertEqual(negotiated_version, "2026-07-28")
        self.assertEqual(spoofed_host_status, 421)
        if os.name == "posix":
            self.assertEqual(process.returncode, 0)
            self.assertNotIn("Traceback", shutdown_stderr)
        self.assertFalse(result.is_error)
        self.assertIsNone(result.structured_content)
        self.assertEqual(len(result.content), 1)
        resource_block = result.content[0]
        if not isinstance(resource_block, EmbeddedResource):
            raise AssertionError("expected embedded resource")
        resource = resource_block.resource
        if not isinstance(resource, BlobResourceContents):
            raise AssertionError("expected binary resource")
        self.assertEqual(resource.mime_type, "application/zip")


if __name__ == "__main__":
    unittest.main()
