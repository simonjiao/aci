from __future__ import annotations

from mcp.server import MCPServer

from skill_checks import SecurityAdapter

from .tools.security_scan import register_security_scan


def register_tools(
    server: MCPServer[None],
    security_adapter: SecurityAdapter,
    *,
    max_package_bytes: int,
) -> None:
    register_security_scan(
        server,
        security_adapter,
        max_package_bytes=max_package_bytes,
    )
