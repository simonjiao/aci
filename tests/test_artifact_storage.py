from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import TracebackType

from artifact_storage import (
    ArtifactStorageFailure,
    ArtifactUnavailable,
    FsspecArtifactStorage,
    PreparedArtifact,
)
from artifact_storage.fsspec_storage import _IdempotentClientContext


def _prepared(path: Path, content: bytes) -> PreparedArtifact:
    path.write_bytes(content)
    return PreparedArtifact(path, len(content), hashlib.sha256(content).hexdigest())


class ArtifactStorageTests(unittest.TestCase):
    def test_rejects_a_path_that_resolves_to_the_filesystem_root(self) -> None:
        root_alias = Path(Path.cwd().anchor) / "skillqa-path-must-not-exist" / ".."

        with self.assertRaises(ValueError):
            FsspecArtifactStorage.filesystem(root_alias)

    def test_s3_close_releases_the_backend_and_is_repeatable(self) -> None:
        filesystem = _ClosableS3Filesystem()
        storage = FsspecArtifactStorage(
            filesystem,
            "contract-bucket/prefix",
            protocol="s3",
        )

        storage.close()
        storage.close()

        expected: list[tuple[object, object]] = [
            (filesystem.loop, filesystem.creator),
            (filesystem.loop, filesystem.creator),
        ]
        self.assertEqual(filesystem.calls, expected)

    def test_publishes_and_streams_an_immutable_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            storage = FsspecArtifactStorage.filesystem(root / "artifacts")
            original = _prepared(root / "result.zip", b"first result")

            stored = storage.publish_result(original)
            original.path.write_bytes(b"changed source")
            info = storage.inspect_result(stored.reference)
            downloaded = b"".join(storage.stream_result(stored.reference, chunk_size=3))

        self.assertRegex(stored.reference, r"^res_[0-9a-f]{32}$")
        self.assertEqual(info.size_bytes, len(b"first result"))
        self.assertEqual(downloaded, b"first result")
        self.assertEqual(stored.sha256, hashlib.sha256(b"first result").hexdigest())

    def test_invalid_and_missing_references_have_the_same_public_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            storage = FsspecArtifactStorage.filesystem(Path(directory) / "artifacts")

            with self.assertRaises(ArtifactUnavailable) as invalid:
                storage.inspect_result("../result.zip")
            with self.assertRaises(ArtifactUnavailable) as missing:
                storage.inspect_result("res_00000000000000000000000000000000")
            with self.assertRaises(ArtifactUnavailable) as missing_stream:
                storage.stream_result(
                    "res_00000000000000000000000000000000",
                    chunk_size=1024,
                )

        self.assertEqual(str(invalid.exception), "Artifact 不可用")
        self.assertEqual(str(missing.exception), "Artifact 不可用")
        self.assertEqual(str(missing_stream.exception), "Artifact 不可用")

    def test_rejects_prepared_content_that_does_not_match_its_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            storage = FsspecArtifactStorage.filesystem(root / "artifacts")
            prepared = _prepared(root / "result.zip", b"result")
            invalid = PreparedArtifact(prepared.path, prepared.size_bytes + 1, prepared.sha256)

            with self.assertRaises(ArtifactStorageFailure) as raised:
                storage.publish_result(invalid)

        self.assertEqual(str(raised.exception), "Artifact 发布输入无效")


class _ClosableS3Filesystem:
    def __init__(self) -> None:
        self.loop = object()
        self.creator = object()
        self.calls: list[tuple[object, object]] = []

    @property
    def _s3creator(self) -> object:
        return self.creator

    def close_session(self, loop: object, creator: object) -> None:
        self.calls.append((loop, creator))


class _TrackedAsyncClientContext:
    def __init__(self) -> None:
        self.exits = 0

    async def __aenter__(self) -> object:
        return object()

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> object:
        self.exits += 1
        return None


class S3SessionLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_context_closes_its_delegate_only_once(self) -> None:
        delegate = _TrackedAsyncClientContext()
        context = _IdempotentClientContext(delegate)

        await context.__aenter__()
        await context.__aexit__(None, None, None)
        await context.__aexit__(None, None, None)

        self.assertEqual(delegate.exits, 1)


if __name__ == "__main__":
    unittest.main()
