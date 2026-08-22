from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send


class HostOriginGuard:
    def __init__(self, app: ASGIApp, settings: TransportSecuritySettings) -> None:
        self._app = app
        self._security = TransportSecurityMiddleware(settings)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_values = cast(Mapping[object, object], cast(object, scope))
        if scope_values.get("type") == "http":
            rejection = await self._security.validate_request(
                Request(scope, receive=receive),
                is_post=False,
            )
            if rejection is not None:
                await rejection(scope, receive, send)
                return
        await self._app(scope, receive, send)
