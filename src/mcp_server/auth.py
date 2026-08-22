from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import cast

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send


class StaticBearerAuth:
    def __init__(self, app: ASGIApp, key: str) -> None:
        self._app = app
        self._expected = b"Bearer " + key.encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if _scope_type(scope) != "http" or _authorized(scope, self._expected):
            await self._app(scope, receive, send)
            return
        response = Response(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
        )
        await response(scope, receive, send)


def _authorized(scope: Scope, expected: bytes) -> bool:
    scope_values = cast(Mapping[object, object], cast(object, scope))
    headers_value = scope_values.get("headers")
    if not isinstance(headers_value, list):
        return False
    values: list[bytes] = []
    for header in cast(list[object], headers_value):
        if not isinstance(header, tuple) or len(header) != 2:
            return False
        name, value = cast(tuple[object, object], header)
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            return False
        if name.lower() == b"authorization":
            values.append(value)
    return len(values) == 1 and hmac.compare_digest(values[0], expected)


def _scope_type(scope: Scope) -> object:
    values = cast(Mapping[object, object], cast(object, scope))
    return values.get("type")
