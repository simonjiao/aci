from __future__ import annotations

import base64
import binascii
from contextlib import suppress
from io import BytesIO
from typing import Annotated, Protocol, cast

from mcp.server import MCPServer
from mcp.types import (
    CallToolResult,
    ResourceLink,
    ToolAnnotations,
)
from pydantic import Field

from artifact_storage import ArtifactStorageFailure
from skill_check_runner import CheckRunner, InputPackage, RunnerError, RunRequest, RunResult
from skill_checks import SecurityAdapter

from ..error_boundary import safe_tool_error
from ..result_artifacts import ResultArtifactError, ResultArtifactPublisher

_PackageNameInput = Annotated[str, Field(min_length=5, max_length=255)]
_PackageContentInput = Annotated[str, Field(min_length=1)]
_SourceIdInput = Annotated[str | None, Field(min_length=1, max_length=256)]


class _ToolInputError(Exception):
    pass


class _ToolExecutionError(Exception):
    pass


class _SecurityTool(Protocol):
    def __call__(
        self,
        package_name: str,
        package_base64: str,
        source_id: str | None = None,
    ) -> object: ...


class _ToolRegistrar(Protocol):
    def add_tool(
        self,
        function: _SecurityTool,
        *,
        name: str,
        title: str,
        description: str,
        annotations: ToolAnnotations,
        structured_output: bool,
    ) -> None: ...


class _ResourceLinkFactory(Protocol):
    def __call__(
        self,
        *,
        name: str,
        uri: str,
        description: str,
        mime_type: str,
        size: int,
    ) -> object: ...


class _ToolResultFactory(Protocol):
    def __call__(
        self,
        *,
        content: list[object],
        structured_content: dict[str, object],
    ) -> object: ...


_RESOURCE_LINK = cast(_ResourceLinkFactory, ResourceLink)
_TOOL_RESULT = cast(_ToolResultFactory, CallToolResult)


def register_security_scan(
    server: MCPServer[None],
    security_adapter: SecurityAdapter,
    result_publisher: ResultArtifactPublisher,
    *,
    max_package_bytes: int,
) -> None:
    runner = CheckRunner((security_adapter,))

    def scan_skill_security(
        package_name: _PackageNameInput,
        package_base64: _PackageContentInput,
        source_id: _SourceIdInput = None,
    ) -> object:
        validated_name, package_bytes, validated_source = _decode_package(
            package_name,
            package_base64,
            source_id,
            max_package_bytes,
        )
        run_result = _run_security_check(
            runner,
            validated_name,
            package_bytes,
            validated_source,
        )
        try:
            published = result_publisher.publish(run_result)
        except ArtifactStorageFailure:
            return safe_tool_error("STORAGE_UNAVAILABLE: 结果存储不可用")
        except ResultArtifactError:
            return safe_tool_error("CHECK_RESULT_WRITE_FAILED: 结果文件生成失败")
        return _TOOL_RESULT(
            content=[
                _RESOURCE_LINK(
                    name="skill-security-result.zip",
                    uri=published.uri,
                    description="使用与 MCP 相同的 Bearer Key 下载",
                    mime_type="application/zip",
                    size=published.size_bytes,
                )
            ],
            structured_content={
                "result_ref": published.reference,
                "result_size_bytes": published.size_bytes,
                "result_sha256": published.sha256,
            },
        )

    registrar = cast(_ToolRegistrar, server)
    registrar.add_tool(
        scan_skill_security,
        name="scan_skill_security",
        title="检查 Skill 安全规则",
        description="检查一个 Skill ZIP，返回结果摘要和受保护的结果 ZIP 下载链接。",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
        structured_output=False,
    )


def _decode_package(
    package_name: object,
    content: object,
    source_id: object,
    max_package_bytes: int,
) -> tuple[str, bytes, str | None]:
    max_encoded_characters = 4 * ((max_package_bytes + 2) // 3)
    if (
        not isinstance(package_name, str)
        or not isinstance(content, str)
        or (source_id is not None and not isinstance(source_id, str))
        or not 5 <= len(package_name) <= 255
        or not package_name.casefold().endswith(".zip")
        or "/" in package_name
        or "\\" in package_name
        or "\x00" in package_name
        or not content
        or len(content) > max_encoded_characters
        or (isinstance(source_id, str) and not 1 <= len(source_id) <= 256)
    ):
        raise _ToolInputError("MCP_INPUT_INVALID: 工具输入无效")
    package_bytes: bytes | None = None
    with suppress(binascii.Error, UnicodeError, ValueError):
        package_bytes = base64.b64decode(content, validate=True)
    if package_bytes is None or len(package_bytes) > max_package_bytes:
        raise _ToolInputError("MCP_INPUT_INVALID: 工具输入无效")
    return package_name, package_bytes, source_id


def _run_security_check(
    runner: CheckRunner,
    package_name: str,
    package_bytes: bytes,
    source_id: str | None,
) -> RunResult:
    run_result: RunResult | None = None
    with suppress(RunnerError):
        run_result = runner.run(
            RunRequest((InputPackage(package_name, BytesIO(package_bytes), source_id),))
        )
    if run_result is None:
        raise _ToolExecutionError("CHECK_EXECUTION_FAILED: 检查执行失败")
    return run_result
