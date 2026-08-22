from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Protocol, cast

import anyio.to_thread
from mcp.server import MCPServer
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from artifact_storage import ArtifactStorage, ArtifactStorageFailure, ArtifactUnavailable

_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
_RESULT_FILENAME = "skill-security-result.zip"

_Handler = Callable[[Request], Awaitable[Response]]


class _RouteDecorator(Protocol):
    def __call__(self, handler: _Handler) -> _Handler: ...


class _RouteRegistrar(Protocol):
    def custom_route(
        self,
        path: str,
        methods: list[str],
        name: str | None = None,
        include_in_schema: bool = True,
    ) -> _RouteDecorator: ...


def register_artifact_download(
    server: MCPServer[None],
    storage: ArtifactStorage,
) -> None:
    registrar = cast(_RouteRegistrar, server)

    async def download(request: Request) -> Response:
        path_params = cast(Mapping[object, object], cast(object, request.path_params))
        reference = path_params.get("result_ref")
        if not isinstance(reference, str):
            return _not_found()
        try:
            info = await anyio.to_thread.run_sync(storage.inspect_result, reference)
            content = storage.stream_result(reference, chunk_size=_DOWNLOAD_CHUNK_BYTES)
        except ArtifactUnavailable:
            return _not_found()
        except ArtifactStorageFailure:
            return Response("Artifact storage unavailable", status_code=503)
        return StreamingResponse(
            content,
            media_type="application/zip",
            headers={
                "Content-Length": str(info.size_bytes),
                "Content-Disposition": f'attachment; filename="{_RESULT_FILENAME}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    registrar.custom_route(
        "/artifacts/{result_ref}",
        methods=["GET"],
        name="download-result-artifact",
        include_in_schema=False,
    )(download)


def _not_found() -> Response:
    return Response("Artifact not found", status_code=404)
