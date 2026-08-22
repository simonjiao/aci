from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterator
from contextlib import suppress
from importlib import import_module
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from .models import (
    ArtifactInfo,
    ArtifactStorageFailure,
    ArtifactUnavailable,
    PreparedArtifact,
    StoredArtifact,
    is_result_reference,
)

_COPY_CHUNK_BYTES = 1024 * 1024


class _FsspecModule(Protocol):
    def filesystem(self, protocol: str, **storage_options: object) -> object: ...


class _FileSystem(Protocol):
    def exists(self, path: str) -> object: ...

    def makedirs(self, path: str, exist_ok: bool = False) -> object: ...

    def open(self, path: str, mode: str) -> object: ...

    def rm(self, path: str) -> object: ...

    def size(self, path: str) -> object: ...


_FSSPEC = cast(_FsspecModule, import_module("fsspec"))


class FsspecArtifactStorage:
    def __init__(self, filesystem: object, root: str) -> None:
        if not root or root.endswith("/"):
            raise ValueError("Artifact 存储参数无效")
        self._filesystem = cast(_FileSystem, filesystem)
        self._root = root

    @classmethod
    def filesystem(cls, root: Path) -> FsspecArtifactStorage:
        if (
            not root.is_absolute()
            or root == Path(root.anchor)
            or root.exists()
            and root.is_symlink()
        ):
            raise ValueError("Artifact 存储参数无效")
        root.mkdir(parents=True, exist_ok=True)
        resolved = root.resolve(strict=True)
        filesystem = _create_filesystem("file", {"auto_mkdir": True})
        storage = cls(filesystem, resolved.as_posix())
        storage._ensure_result_root()
        return storage

    @classmethod
    def s3(
        cls,
        *,
        endpoint_url: str,
        bucket: str,
        region: str,
        prefix: str,
        path_style: bool,
        access_key: str | None,
        secret_key: str | None,
        session_token: str | None,
    ) -> FsspecArtifactStorage:
        if (access_key is None) != (secret_key is None) or (
            session_token is not None and access_key is None
        ):
            raise ValueError("Artifact 存储参数无效")
        client_kwargs: dict[str, object] = {
            "endpoint_url": endpoint_url,
            "region_name": region,
        }
        storage_options: dict[str, object] = {"client_kwargs": client_kwargs}
        if path_style:
            storage_options["config_kwargs"] = {"s3": {"addressing_style": "path"}}
        if access_key is not None:
            storage_options["key"] = access_key
            storage_options["secret"] = secret_key
            if session_token is not None:
                storage_options["token"] = session_token
        filesystem = _create_filesystem("s3", storage_options)
        root = bucket if not prefix else f"{bucket}/{prefix.rstrip('/')}"
        storage = cls(filesystem, root)
        storage._require_existing_bucket(bucket)
        return storage

    def publish_result(self, prepared: PreparedArtifact) -> StoredArtifact:
        self._validate_prepared(prepared)
        reference, target = self._new_result_target()
        succeeded = False
        try:
            with prepared.path.open("rb") as source:
                destination = cast(BinaryIO, self._filesystem.open(target, "wb"))
                with destination:
                    while chunk := source.read(_COPY_CHUNK_BYTES):
                        destination.write(chunk)
            info = self.inspect_result(reference)
            if info.size_bytes != prepared.size_bytes:
                raise ArtifactStorageFailure("Artifact 发布失败")
            succeeded = True
            return StoredArtifact(reference, prepared.size_bytes, prepared.sha256)
        except ArtifactStorageFailure:
            raise
        except Exception:
            raise ArtifactStorageFailure("Artifact 发布失败") from None
        finally:
            if not succeeded:
                self._remove_incomplete(target)

    def inspect_result(self, reference: str) -> ArtifactInfo:
        target = self._result_path(reference)
        try:
            exists = self._filesystem.exists(target)
            if type(exists) is not bool or not exists:
                raise ArtifactUnavailable("Artifact 不可用")
            size = self._filesystem.size(target)
            if type(size) is not int or size < 0:
                raise ArtifactStorageFailure("Artifact 检查失败")
            return ArtifactInfo(reference, size)
        except (ArtifactUnavailable, ArtifactStorageFailure):
            raise
        except Exception:
            raise ArtifactStorageFailure("Artifact 检查失败") from None

    def stream_result(self, reference: str, *, chunk_size: int) -> Iterator[bytes]:
        if type(chunk_size) is not int or chunk_size <= 0:
            raise ValueError("Artifact 分块参数无效")
        target = self._result_path(reference)

        def chunks() -> Iterator[bytes]:
            try:
                source = cast(BinaryIO, self._filesystem.open(target, "rb"))
                with source:
                    while chunk := source.read(chunk_size):
                        yield chunk
            except Exception:
                raise ArtifactStorageFailure("Artifact 读取失败") from None

        return chunks()

    def _ensure_result_root(self) -> None:
        try:
            self._filesystem.makedirs(f"{self._root}/results", exist_ok=True)
        except Exception:
            raise ArtifactStorageFailure("Artifact 存储不可用") from None

    def _require_existing_bucket(self, bucket: str) -> None:
        try:
            exists = self._filesystem.exists(bucket)
            if type(exists) is not bool or not exists:
                raise ArtifactStorageFailure("Artifact 存储不可用")
        except ArtifactStorageFailure:
            raise
        except Exception:
            raise ArtifactStorageFailure("Artifact 存储不可用") from None

    def _new_result_target(self) -> tuple[str, str]:
        try:
            for _attempt in range(3):
                reference = f"res_{secrets.token_hex(16)}"
                target = self._result_path(reference)
                exists = self._filesystem.exists(target)
                if type(exists) is not bool:
                    break
                if not exists:
                    return reference, target
        except Exception:
            pass
        raise ArtifactStorageFailure("Artifact 引用生成失败")

    def _result_path(self, reference: object) -> str:
        if not is_result_reference(reference):
            raise ArtifactUnavailable("Artifact 不可用")
        return f"{self._root}/results/{reference[4:]}.zip"

    def _validate_prepared(self, prepared: PreparedArtifact) -> None:
        valid = False
        with suppress(OSError):
            valid = (
                prepared.path.is_file()
                and type(prepared.size_bytes) is int
                and prepared.size_bytes > 0
                and prepared.path.stat().st_size == prepared.size_bytes
                and len(prepared.sha256) == 64
                and prepared.sha256 == _sha256(prepared.path)
            )
        if not valid:
            raise ArtifactStorageFailure("Artifact 发布输入无效")

    def _remove_incomplete(self, target: str) -> None:
        try:
            exists = self._filesystem.exists(target)
            if exists is True:
                self._filesystem.rm(target)
        except Exception:
            pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _create_filesystem(protocol: str, options: dict[str, object]) -> object:
    try:
        return _FSSPEC.filesystem(protocol, **options)
    except Exception:
        raise ArtifactStorageFailure("Artifact 存储不可用") from None
