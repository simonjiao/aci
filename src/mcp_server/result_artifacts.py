from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO, cast

from artifact_storage import ArtifactStorage, ArtifactStorageFailure, PreparedArtifact
from skill_check_runner import RunResult
from skill_check_runner.result_archive import write_result_archive

from .artifact_urls import result_artifact_uri


class ResultArtifactError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class PublishedResult:
    reference: str
    uri: str
    size_bytes: int
    sha256: str


class ResultArtifactPublisher:
    def __init__(
        self,
        storage: ArtifactStorage,
        *,
        scratch_directory: Path,
        max_result_bytes: int,
        public_base_url: str,
    ) -> None:
        if type(max_result_bytes) is not int or max_result_bytes <= 0:
            raise ValueError("结果发布参数无效")
        self._storage = storage
        self._scratch_directory = scratch_directory
        self._max_result_bytes = max_result_bytes
        self._public_base_url = public_base_url.rstrip("/")

    @property
    def storage(self) -> ArtifactStorage:
        return self._storage

    def publish(self, result: RunResult) -> PublishedResult:
        try:
            with TemporaryDirectory(
                dir=self._scratch_directory,
                prefix="skillqa-result-",
            ) as directory:
                path = Path(directory) / "skill-security-result.zip"
                with path.open("w+b") as output:
                    bounded = _BoundedBinaryWriter(output, self._max_result_bytes)
                    try:
                        write_result_archive(result, cast(BinaryIO, bounded))
                    except _ResultSizeLimitExceeded:
                        raise ResultArtifactError("结果文件大小无效") from None
                prepared = PreparedArtifact.from_file(path)
                if prepared.size_bytes <= 0 or prepared.size_bytes > self._max_result_bytes:
                    raise ResultArtifactError("结果文件大小无效")
                stored = self._storage.publish_result(prepared)
                return PublishedResult(
                    stored.reference,
                    result_artifact_uri(self._public_base_url, stored.reference),
                    stored.size_bytes,
                    stored.sha256,
                )
        except ArtifactStorageFailure:
            raise
        except ResultArtifactError:
            raise
        except Exception:
            raise ResultArtifactError("结果文件生成失败") from None


class _ResultSizeLimitExceeded(Exception):
    pass


class _BoundedBinaryWriter:
    def __init__(self, target: BinaryIO, limit: int) -> None:
        self._target = target
        self._limit = limit

    def write(self, content: bytes) -> int:
        position = self._target.tell()
        if position < 0 or len(content) > self._limit - position:
            raise _ResultSizeLimitExceeded
        return self._target.write(content)

    def tell(self) -> int:
        return self._target.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._target.seek(offset, whence)

    def flush(self) -> None:
        self._target.flush()
