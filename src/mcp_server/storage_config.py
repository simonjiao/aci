from __future__ import annotations

import re
from os import environ
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from artifact_storage import ArtifactStorage, FsspecArtifactStorage

from .config_validation import is_environment_name, is_root_http_url

_S3_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


class _FilesystemBackendConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["filesystem"]
    root: Annotated[str, Field(min_length=1, max_length=4096)]


class _S3BackendConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["s3"]
    endpoint_url: Annotated[str, Field(min_length=8, max_length=2048)]
    bucket: Annotated[str, Field(min_length=3, max_length=63)]
    region: Annotated[str, Field(min_length=1, max_length=128)]
    prefix: Annotated[str, Field(max_length=1024)]
    path_style: bool
    credential_provider: Literal["static_env", "default_chain"]
    access_key_env: Annotated[str | None, Field(max_length=128)] = None
    secret_key_env: Annotated[str | None, Field(max_length=128)] = None
    session_token_env: Annotated[str | None, Field(max_length=128)] = None


_BackendConfig = Annotated[
    _FilesystemBackendConfig | _S3BackendConfig,
    Field(discriminator="type"),
]


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_result_bytes: Annotated[int, Field(gt=0)]
    scratch_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    backend: _BackendConfig


def build_artifact_storage(config: StorageConfig) -> tuple[ArtifactStorage, Path]:
    resolved_scratch = _resolved_directory(Path(config.scratch_directory))
    backend = config.backend
    if isinstance(backend, _FilesystemBackendConfig):
        resolved_root = _resolved_directory(Path(backend.root))
        if _paths_overlap(resolved_root, resolved_scratch):
            raise ValueError
        storage: ArtifactStorage = FsspecArtifactStorage.filesystem(resolved_root)
    else:
        _validate_s3(backend)
        access_key, secret_key, session_token = _s3_credentials(backend)
        storage = FsspecArtifactStorage.s3(
            endpoint_url=backend.endpoint_url,
            bucket=backend.bucket,
            region=backend.region,
            prefix=backend.prefix,
            path_style=backend.path_style,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
        )
    try:
        resolved_scratch.mkdir(parents=True, exist_ok=True)
        resolved_scratch = resolved_scratch.resolve(strict=True)
    except OSError:
        storage.close()
        raise
    return storage, resolved_scratch


def _validate_s3(config: _S3BackendConfig) -> None:
    environment_names = (
        config.access_key_env,
        config.secret_key_env,
        config.session_token_env,
    )
    static_names_present = config.access_key_env is not None and config.secret_key_env is not None
    if (
        not is_root_http_url(config.endpoint_url)
        or _S3_BUCKET.fullmatch(config.bucket) is None
        or config.prefix.startswith("/")
        or ".." in config.prefix.split("/")
        or config.prefix and not config.prefix.endswith("/")
        or any(name is not None and not is_environment_name(name) for name in environment_names)
        or config.credential_provider == "static_env" and not static_names_present
        or config.credential_provider == "default_chain" and any(environment_names)
    ):
        raise ValueError


def _s3_credentials(config: _S3BackendConfig) -> tuple[str | None, str | None, str | None]:
    if config.credential_provider == "default_chain":
        return None, None, None
    if config.access_key_env is None or config.secret_key_env is None:
        raise ValueError
    access_key = environ.get(config.access_key_env)
    secret_key = environ.get(config.secret_key_env)
    session_token = environ.get(config.session_token_env) if config.session_token_env else None
    if not access_key or not secret_key:
        raise ValueError
    return access_key, secret_key, session_token


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _resolved_directory(path: Path) -> Path:
    if not path.is_absolute() or path.exists() and path.is_symlink():
        raise ValueError
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError
    return resolved
