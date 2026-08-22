from __future__ import annotations

import hashlib
import secrets
import tempfile
import unittest
from os import environ
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from artifact_storage import FsspecArtifactStorage, PreparedArtifact

_ENDPOINT = environ.get("SKILLQA_TEST_S3_ENDPOINT")
_BUCKET = environ.get("SKILLQA_TEST_S3_BUCKET")
_ACCESS_KEY = environ.get("SKILLQA_TEST_S3_ACCESS_KEY")
_SECRET_KEY = environ.get("SKILLQA_TEST_S3_SECRET_KEY")
_ENABLED = all((_ENDPOINT, _BUCKET, _ACCESS_KEY, _SECRET_KEY))


class S3ArtifactStorageContractTests(unittest.TestCase):
    def test_result_survives_storage_reconstruction(self) -> None:
        if not _ENABLED:
            self.skipTest("requires a disposable S3-compatible test bucket")
        if _ENDPOINT is None or _BUCKET is None or _ACCESS_KEY is None or _SECRET_KEY is None:
            raise AssertionError("S3 test configuration is incomplete")
        prefix = f"skillqa-contract-{secrets.token_hex(8)}/"
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.zip"
            with ZipFile(result, "w", ZIP_DEFLATED) as archive:
                archive.writestr("security-scan.csv", "rule_id,severity\n")
            prepared = PreparedArtifact.from_file(result)
            storage = self._storage(
                _ENDPOINT,
                _BUCKET,
                prefix,
                _ACCESS_KEY,
                _SECRET_KEY,
            )
            stored = storage.publish_result(prepared)
            storage.close()

            reconstructed = self._storage(
                _ENDPOINT,
                _BUCKET,
                prefix,
                _ACCESS_KEY,
                _SECRET_KEY,
            )
            try:
                info = reconstructed.inspect_result(stored.reference)
                content = b"".join(
                    reconstructed.stream_result(stored.reference, chunk_size=7)
                )
            finally:
                reconstructed.close()
                reconstructed.close()

        self.assertEqual(info.size_bytes, prepared.size_bytes)
        self.assertEqual(len(content), prepared.size_bytes)
        self.assertEqual(hashlib.sha256(content).hexdigest(), prepared.sha256)

    def _storage(
        self,
        endpoint: str,
        bucket: str,
        prefix: str,
        access_key: str,
        secret_key: str,
    ) -> FsspecArtifactStorage:
        return FsspecArtifactStorage.s3(
            endpoint_url=endpoint,
            bucket=bucket,
            region=environ.get("SKILLQA_TEST_S3_REGION", "us-east-1"),
            prefix=prefix,
            path_style=True,
            access_key=access_key,
            secret_key=secret_key,
            session_token=environ.get("SKILLQA_TEST_S3_SESSION_TOKEN"),
        )


if __name__ == "__main__":
    unittest.main()
