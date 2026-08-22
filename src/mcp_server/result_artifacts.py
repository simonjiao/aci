from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from artifact_storage import ArtifactStorage, PreparedArtifact
from skill_check_runner import RunResult
from skill_check_runner.result_archive import write_result_archive

_HASH_CHUNK_BYTES = 1024 * 1024


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

    def publish(self, result: RunResult) -> PublishedResult:
        published: PublishedResult | None = None
        try:
            with TemporaryDirectory(
                dir=self._scratch_directory,
                prefix="skillqa-result-",
            ) as directory:
                path = Path(directory) / "skill-security-result.zip"
                with path.open("w+b") as output:
                    write_result_archive(result, output)
                size_bytes = path.stat().st_size
                if size_bytes <= 0 or size_bytes > self._max_result_bytes:
                    raise ResultArtifactError("结果文件大小无效")
                sha256 = _sha256(path)
                stored = self._storage.publish_result(
                    PreparedArtifact(path, size_bytes, sha256)
                )
                published = PublishedResult(
                    stored.reference,
                    f"{self._public_base_url}/artifacts/{stored.reference}",
                    stored.size_bytes,
                    stored.sha256,
                )
        except ResultArtifactError:
            pass
        except Exception:
            pass
        if published is None:
            raise ResultArtifactError("结果文件发布失败")
        return published


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()
