from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from mcp.server.context import (
    CallNext,
    HandlerResult,
    ServerMiddleware,
    ServerRequestContext,
)
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError


class _ToolErrorBoundary:
    async def __call__(
        self,
        context: ServerRequestContext[None, object],
        call_next: CallNext,
    ) -> HandlerResult:
        result: HandlerResult = None
        invalid_parameters = False
        try:
            result = await call_next(context)
        except ValidationError:
            if context.method != "tools/call":
                raise
            invalid_parameters = True
        if invalid_parameters:
            return _safe_tool_error()
        if context.method == "tools/call" and _is_tool_error(result):
            return _safe_tool_error()
        return result


def tool_error_middleware() -> Sequence[ServerMiddleware[None]]:
    value: object = (_ToolErrorBoundary(),)
    return cast(Sequence[ServerMiddleware[None]], value)


def _is_tool_error(result: HandlerResult) -> bool:
    if not isinstance(result, Mapping):
        return False
    values = cast(Mapping[object, object], result)
    return values.get("isError") is True


def _safe_tool_error() -> CallToolResult:
    return CallToolResult(
        content=[TextContent(text="MCP_TOOL_FAILED: 工具输入或执行失败")],
        is_error=True,
    )
