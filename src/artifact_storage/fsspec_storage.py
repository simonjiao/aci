from __future__ import annotations

import secrets
from contextlib import suppress
from importlib import import_module
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Protocol, cast

from .interface import ArtifactByteStream
from .models import (
    ArtifactInfo,
    ArtifactStorageFailure,
    ArtifactUnavailable,
    PreparedArtifact,
    StoredArtifact,
    is_result_reference,
)

_COPY_CHUNK_BYTES = 1024 * 1024
_S3_BLOCK_BYTES = 8 * 1024 * 1024


class _FsspecModule(Protocol):
    def filesystem(self, protocol: str, **storage_options: object) -> object: ...


class _AsyncClientContext(Protocol):
    async def __aenter__(self) -> object: ...

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> object: ...


class _BotocoreSession(Protocol):
    def unregister(self, event_name: str, handler: object) -> object: ...

    def create_client(self, service_name: str, **kwargs: object) -> object: ...


class _SessionModule(Protocol):
    def get_session(self) -> object: ...


class _HandlersModule(Protocol):
    add_expect_header: object


class _FileSystem(Protocol):
    def exists(self, path: str) -> object: ...

    def makedirs(self, path: str, exist_ok: bool = False) -> object: ...

    def open(self, path: str, mode: str) -> object: ...

    def rm(self, path: str) -> object: ...

    def size(self, path: str) -> object: ...


class _S3FileSystem(Protocol):
    @property
    def loop(self) -> object: ...

    @property
    def _s3creator(self) -> object: ...

    def close_session(self, loop: object, s3: object) -> None: ...


_FSSPEC = cast(_FsspecModule, import_module("fsspec"))


class FsspecArtifactStorage:
    def __init__(self, filesystem: object, root: str, *, protocol: str = "file") -> None:
        if not root or root.endswith("/"):
            raise ValueError("Artifact 存储参数无效")
        self._filesystem = cast(_FileSystem, filesystem)
        self._root = root
        self._protocol = protocol

    @classmethod
    def filesystem(cls, root: Path) -> FsspecArtifactStorage:
        if not root.is_absolute() or root.exists() and root.is_symlink():
            raise ValueError("Artifact 存储参数无效")
        resolved = root.resolve()
        if resolved == Path(resolved.anchor):
            raise ValueError("Artifact 存储参数无效")
        resolved.mkdir(parents=True, exist_ok=True)
        resolved = resolved.resolve(strict=True)
        filesystem = _create_filesystem(
            "file",
            {"auto_mkdir": True, "skip_instance_cache": True},
        )
        storage = cls(filesystem, resolved.as_posix(), protocol="file")
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
        client_kwargs: dict[str, object] = {"region_name": region}
        storage_options: dict[str, object] = {
            "default_block_size": _S3_BLOCK_BYTES,
            "endpoint_url": endpoint_url,
            "client_kwargs": client_kwargs,
            "max_concurrency": 1,
            "session": _new_s3_session(),
            "skip_instance_cache": True,
        }
        if path_style:
            storage_options["config_kwargs"] = {"s3": {"addressing_style": "path"}}
        if access_key is not None:
            storage_options["key"] = access_key
            storage_options["secret"] = secret_key
            if session_token is not None:
                storage_options["token"] = session_token
        filesystem = _create_filesystem("s3", storage_options)
        root = bucket if not prefix else f"{bucket}/{prefix.rstrip('/')}"
        storage = cls(filesystem, root, protocol="s3")
        try:
            storage._verify_s3_access(bucket)
        except Exception:
            storage.close()
            raise
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

    def stream_result(self, reference: str, *, chunk_size: int) -> ArtifactByteStream:
        if type(chunk_size) is not int or chunk_size <= 0:
            raise ValueError("Artifact 分块参数无效")
        target = self._result_path(reference)
        try:
            source = cast(BinaryIO, self._filesystem.open(target, "rb"))
        except Exception:
            self._raise_open_failure(target)
        return _FileByteStream(source, chunk_size)

    def close(self) -> None:
        if self._protocol != "s3":
            return
        filesystem = cast(_S3FileSystem, self._filesystem)
        with suppress(Exception):
            filesystem.close_session(filesystem.loop, filesystem._s3creator)

    def _ensure_result_root(self) -> None:
        try:
            self._filesystem.makedirs(f"{self._root}/results", exist_ok=True)
        except Exception:
            raise ArtifactStorageFailure("Artifact 存储不可用") from None

    def _verify_s3_access(self, bucket: str) -> None:
        probe = f"{self._root}/results/.skillqa-probe-{secrets.token_hex(16)}"
        marker = b"skillqa-storage-probe"
        cleanup_required = False
        try:
            exists = self._filesystem.exists(bucket)
            if type(exists) is not bool or not exists:
                raise ArtifactStorageFailure("Artifact 存储不可用")
            cleanup_required = True
            destination = cast(BinaryIO, self._filesystem.open(probe, "wb"))
            with destination:
                destination.write(marker)
            source = cast(BinaryIO, self._filesystem.open(probe, "rb"))
            with source:
                if source.read(len(marker) + 1) != marker:
                    raise ArtifactStorageFailure("Artifact 存储不可用")
            self._filesystem.rm(probe)
            cleanup_required = False
        except ArtifactStorageFailure:
            raise
        except Exception:
            raise ArtifactStorageFailure("Artifact 存储不可用") from None
        finally:
            if cleanup_required:
                self._remove_incomplete(probe)

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
        if not prepared.matches_file():
            raise ArtifactStorageFailure("Artifact 发布输入无效")

    def _raise_open_failure(self, target: str) -> None:
        try:
            exists = self._filesystem.exists(target)
            if type(exists) is bool and not exists:
                raise ArtifactUnavailable("Artifact 不可用")
        except ArtifactUnavailable:
            raise
        except Exception:
            pass
        raise ArtifactStorageFailure("Artifact 读取失败")

    def _remove_incomplete(self, target: str) -> None:
        try:
            exists = self._filesystem.exists(target)
            if exists is True:
                self._filesystem.rm(target)
        except Exception:
            pass


def _create_filesystem(protocol: str, options: dict[str, object]) -> object:
    try:
        return _FSSPEC.filesystem(protocol, **options)
    except Exception:
        raise ArtifactStorageFailure("Artifact 存储不可用") from None


def _new_s3_session() -> object:
    try:
        session_module = cast(_SessionModule, import_module("aiobotocore.session"))
        handlers_module = cast(_HandlersModule, import_module("botocore.handlers"))
        session = cast(_BotocoreSession, session_module.get_session())
        session.unregister("before-call.s3", handlers_module.add_expect_header)
        return _IdempotentS3Session(session)
    except Exception:
        raise ArtifactStorageFailure("Artifact 存储不可用") from None


class _IdempotentS3Session:
    def __init__(self, session: _BotocoreSession) -> None:
        self._session = session

    def create_client(self, service_name: str, **kwargs: object) -> object:
        context = cast(
            _AsyncClientContext,
            self._session.create_client(service_name, **kwargs),
        )
        return _IdempotentClientContext(context)


class _IdempotentClientContext:
    def __init__(self, context: _AsyncClientContext) -> None:
        self._context = context
        self._closed = False

    async def __aenter__(self) -> object:
        return await self._context.__aenter__()

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> object:
        if self._closed:
            return None
        self._closed = True
        return await self._context.__aexit__(exception_type, exception, traceback)


class _FileByteStream:
    def __init__(self, source: BinaryIO, chunk_size: int) -> None:
        self._source = source
        self._chunk_size = chunk_size
        self._closed = False

    def __iter__(self) -> _FileByteStream:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        try:
            chunk = self._source.read(self._chunk_size)
        except Exception:
            self.close()
            raise ArtifactStorageFailure("Artifact 读取失败") from None
        if not chunk:
            self.close()
            raise StopIteration
        return chunk

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with suppress(Exception):
            self._source.close()
