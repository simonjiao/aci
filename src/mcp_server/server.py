from __future__ import annotations

from pathlib import Path

from mcp.server import MCPServer

from artifact_storage import ArtifactStorage
from skill_checks import SecurityAdapter

from .error_boundary import tool_error_middleware
from .registry import register_tools
from .result_artifacts import ResultArtifactPublisher
from .routes import register_artifact_download


def create_server(
    security_adapter: SecurityAdapter,
    artifact_storage: ArtifactStorage,
    *,
    max_package_bytes: int,
    scratch_directory: Path,
    max_result_bytes: int,
    public_base_url: str,
) -> MCPServer[None]:
    if (
        type(max_package_bytes) is not int
        or max_package_bytes <= 0
        or type(max_result_bytes) is not int
        or max_result_bytes <= 0
    ):
        raise ValueError("MCP Server 参数无效")
    server: MCPServer[None] = MCPServer(
        name="skillqa",
        description="Skill 质量检查工具",
        version="0.1.0",
        middleware=tool_error_middleware(),
    )
    result_publisher = ResultArtifactPublisher(
        artifact_storage,
        scratch_directory=scratch_directory,
        max_result_bytes=max_result_bytes,
        public_base_url=public_base_url,
    )
    register_tools(
        server,
        security_adapter,
        result_publisher,
        max_package_bytes=max_package_bytes,
    )
    register_artifact_download(server, artifact_storage)
    return server
