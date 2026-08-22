from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from artifact_storage import (
    ArtifactStorageFailure,
    ArtifactUnavailable,
    FsspecArtifactStorage,
    PreparedArtifact,
)


def _prepared(path: Path, content: bytes) -> PreparedArtifact:
    path.write_bytes(content)
    return PreparedArtifact(path, len(content), hashlib.sha256(content).hexdigest())


class ArtifactStorageTests(unittest.TestCase):
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

        self.assertEqual(str(invalid.exception), "Artifact 不可用")
        self.assertEqual(str(missing.exception), "Artifact 不可用")

    def test_rejects_prepared_content_that_does_not_match_its_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            storage = FsspecArtifactStorage.filesystem(root / "artifacts")
            prepared = _prepared(root / "result.zip", b"result")
            invalid = PreparedArtifact(prepared.path, prepared.size_bytes + 1, prepared.sha256)

            with self.assertRaises(ArtifactStorageFailure) as raised:
                storage.publish_result(invalid)

        self.assertEqual(str(raised.exception), "Artifact 发布输入无效")


if __name__ == "__main__":
    unittest.main()
