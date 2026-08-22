from __future__ import annotations

import unittest
from collections.abc import Iterator, Mapping
from typing import cast

import anyio
from starlette.types import Send

from mcp_server.routes.artifacts import _ArtifactStreamingResponse


class _TrackedStream:
    def __init__(self) -> None:
        self._chunks = iter((b"result",))
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        return next(self._chunks)

    def close(self) -> None:
        self.closed = True


class ArtifactDownloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_closes_the_artifact_stream(self) -> None:
        stream = _TrackedStream()
        response = _ArtifactStreamingResponse(
            stream,
            media_type="application/zip",
            headers={"Content-Length": "6"},
        )
        body_started = anyio.Event()

        async def block_on_body(message: object) -> None:
            values = cast(Mapping[object, object], message)
            if values.get("type") == "http.response.body":
                body_started.set()
                await anyio.sleep_forever()

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(
                response.stream_response,
                cast(Send, block_on_body),
            )
            await body_started.wait()
            tasks.cancel_scope.cancel()

        self.assertTrue(stream.closed)

    async def test_send_failure_closes_the_artifact_stream(self) -> None:
        stream = _TrackedStream()
        response = _ArtifactStreamingResponse(
            stream,
            media_type="application/zip",
            headers={"Content-Length": "6"},
        )

        async def fail_on_body(message: object) -> None:
            values = cast(Mapping[object, object], message)
            if values.get("type") == "http.response.body":
                raise OSError("client disconnected")

        with self.assertRaises(OSError):
            await response.stream_response(cast(Send, fail_on_body))

        self.assertTrue(stream.closed)


if __name__ == "__main__":
    unittest.main()
