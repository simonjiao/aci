from __future__ import annotations

from types import TracebackType
from typing import Protocol, cast

from mcp import Client
from mcp.server import MCPServer


class ToolView(Protocol):
    name: str
    input_schema: object


class ToolListView(Protocol):
    tools: list[ToolView]


class ToolResultView(Protocol):
    is_error: bool
    structured_content: object
    content: list[object]


class ClientSessionView(Protocol):
    protocol_version: object

    async def list_tools(self) -> object: ...

    async def call_tool(self, name: str, arguments: dict[str, object]) -> object: ...


class ClientContextView(Protocol):
    async def __aenter__(self) -> ClientSessionView: ...

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...


class _ClientFactory(Protocol):
    def __call__(
        self,
        server: MCPServer[None] | str,
        *,
        raise_exceptions: bool,
    ) -> object: ...


_CLIENT = cast(_ClientFactory, Client)


def mcp_client(
    server: MCPServer[None] | str,
    *,
    raise_exceptions: bool,
) -> ClientContextView:
    return cast(ClientContextView, _CLIENT(server, raise_exceptions=raise_exceptions))


def tool_list(value: object) -> ToolListView:
    return cast(ToolListView, value)


def tool_result(value: object) -> ToolResultView:
    return cast(ToolResultView, value)


def protocol_version(value: object) -> str:
    if not isinstance(value, str):
        raise AssertionError("expected negotiated protocol version")
    return value
