from __future__ import annotations

from mcp.server import MCPServer

from skill_checks import SecurityAdapter

from .error_boundary import tool_error_middleware
from .registry import register_tools


def create_server(
    security_adapter: SecurityAdapter,
    *,
    max_package_bytes: int,
) -> MCPServer[None]:
    if type(max_package_bytes) is not int or max_package_bytes <= 0:
        raise ValueError("MCP Server 参数无效")
    server: MCPServer[None] = MCPServer(
        name="skillqa",
        description="Skill 质量检查工具",
        version="0.1.0",
        middleware=tool_error_middleware(),
    )
    register_tools(server, security_adapter, max_package_bytes=max_package_bytes)
    return server
