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

_GENERIC_TOOL_ERROR = "MCP_TOOL_FAILED: 工具输入或执行失败"
_SAFE_TOOL_ERRORS = frozenset(
    {
        "CHECK_RESULT_WRITE_FAILED: 结果文件生成失败",
        "STORAGE_UNAVAILABLE: 结果存储不可用",
    }
)


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
            return _tool_error(_GENERIC_TOOL_ERROR)
        if context.method == "tools/call" and _is_tool_error(result):
            return _tool_error(_safe_error_message(result) or _GENERIC_TOOL_ERROR)
        return result


def tool_error_middleware() -> Sequence[ServerMiddleware[None]]:
    value: object = (_ToolErrorBoundary(),)
    return cast(Sequence[ServerMiddleware[None]], value)


def _is_tool_error(result: HandlerResult) -> bool:
    if not isinstance(result, Mapping):
        return False
    values = cast(Mapping[object, object], result)
    return values.get("isError") is True


def safe_tool_error(message: str) -> CallToolResult:
    if message not in _SAFE_TOOL_ERRORS:
        raise ValueError("Tool 错误消息无效")
    return _tool_error(message)


def _tool_error(message: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(text=message)],
        is_error=True,
    )


def _safe_error_message(result: HandlerResult) -> str | None:
    if not isinstance(result, Mapping):
        return None
    values = cast(Mapping[object, object], result)
    content = values.get("content")
    if not isinstance(content, list) or len(content) != 1:
        return None
    item = content[0]
    if not isinstance(item, Mapping):
        return None
    item_values = cast(Mapping[object, object], item)
    message = item_values.get("text")
    return message if isinstance(message, str) and message in _SAFE_TOOL_ERRORS else None
