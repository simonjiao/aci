from __future__ import annotations

import asyncio
import base64
import hashlib
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
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

from mcp.client.session_group import ClientSessionGroup
from mcp.types import ResourceLink

from tests.mcp_support import authenticated_streamable_http_parameters, tool_result
from tests.support import object_dict

ROOT = Path(__file__).resolve().parents[1]


def _available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        address = listener.getsockname()
    if not isinstance(address, tuple) or not isinstance(address[1], int):
        raise AssertionError("expected TCP address")
    return address[1]


def _write_config(path: Path, port: int) -> None:
    artifact_root = (path.parent / "artifacts").as_posix()
    scratch_root = (path.parent / "scratch").as_posix()
    path.write_text(
        f'''schema_version = "2"

[http]
host = "127.0.0.1"
port = {port}
path = "/mcp"
max_request_body_bytes = 2097152
public_base_url = "http://127.0.0.1:{port}"
allowed_hosts = ["127.0.0.1:*"]
allowed_origins = ["http://127.0.0.1:*"]

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


def _request_mcp_without_authentication(port: int) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/mcp",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        return connection.getresponse().status
    finally:
        connection.close()


def _download(
    uri: str,
    key: str | None,
    *,
    origin: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urlsplit(uri)
    if parsed.hostname is None or parsed.port is None:
        raise AssertionError("expected an absolute result URL")
    headers = {"Authorization": f"Bearer {key}"} if key is not None else {}
    if origin is not None:
        headers["Origin"] = origin
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request("GET", parsed.path, headers=headers)
        response = connection.getresponse()
        response_headers = {name.casefold(): value for name, value in response.getheaders()}
        return response.status, response_headers, response.read()
    finally:
        connection.close()


class McpHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_result_resource_link_downloads_a_protected_zip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mcp.toml"
            (root / "security-rules.json").write_bytes(
                (ROOT / "config/security-rules.json").read_bytes()
            )
            port = _available_port()
            _write_config(config, port)
            api_key = "test-static-bearer-key-0123456789"
            process_environment = os.environ.copy()
            process_environment["SKILLQA_TEST_API_KEY"] = api_key
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
                env=process_environment,
            )
            shutdown_stderr = ""
            try:
                await _wait_until_listening(port, process)
                spoofed_host_status = _request_with_spoofed_host(port)
                unauthenticated_mcp_status = _request_mcp_without_authentication(port)
                arguments: dict[str, object] = {
                    "package_name": "demo.zip",
                    "package_base64": base64.b64encode(_skill_zip()).decode("ascii"),
                }
                async with ClientSessionGroup() as client:
                    await client.connect_to_server(
                        authenticated_streamable_http_parameters(
                            f"http://127.0.0.1:{port}/mcp",
                            api_key,
                        )
                    )
                    result = tool_result(
                        await client.call_tool("scan_skill_security", arguments)
                    )
                resource = result.content[0]
                if not isinstance(resource, ResourceLink):
                    raise AssertionError("expected result resource link")
                unauthorized_status, unauthorized_headers, _unauthorized_body = _download(
                    resource.uri, None
                )
                download_status, download_headers, archive_bytes = _download(
                    resource.uri, api_key
                )
                wrong_key_status, _wrong_key_headers, _wrong_key_body = _download(
                    resource.uri,
                    "wrong-static-bearer-key-0123456789",
                )
                missing_status, _missing_headers, _missing_body = _download(
                    f"http://127.0.0.1:{port}/artifacts/res_{'0' * 32}",
                    api_key,
                )
                malformed_status, _malformed_headers, _malformed_body = _download(
                    f"http://127.0.0.1:{port}/artifacts/not-a-reference",
                    api_key,
                )
                rejected_origin_status, _origin_headers, _origin_body = _download(
                    resource.uri,
                    api_key,
                    origin="https://untrusted.example",
                )
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

        self.assertEqual(spoofed_host_status, 421)
        self.assertEqual(unauthenticated_mcp_status, 401)
        if os.name == "posix":
            self.assertEqual(process.returncode, 0)
            self.assertNotIn("Traceback", shutdown_stderr)
        self.assertFalse(result.is_error)
        self.assertEqual(len(result.content), 1)
        self.assertEqual(unauthorized_status, 401)
        self.assertEqual(unauthorized_headers["www-authenticate"], "Bearer")
        self.assertEqual(wrong_key_status, 401)
        self.assertEqual(missing_status, 404)
        self.assertEqual(malformed_status, 404)
        self.assertEqual(rejected_origin_status, 403)
        self.assertEqual(download_status, 200)
        self.assertEqual(download_headers["content-type"], "application/zip")
        self.assertEqual(
            download_headers["content-disposition"],
            'attachment; filename="skill-security-result.zip"',
        )
        self.assertEqual(int(download_headers["content-length"]), len(archive_bytes))
        structured = object_dict(result.structured_content)
        self.assertEqual(structured["result_size_bytes"], len(archive_bytes))
        self.assertEqual(structured["result_sha256"], hashlib.sha256(archive_bytes).hexdigest())
        with ZipFile(BytesIO(archive_bytes)) as archive:
            self.assertEqual(archive.testzip(), None)


if __name__ == "__main__":
    unittest.main()
