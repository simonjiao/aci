from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from os import environ
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from artifact_storage import ArtifactStorage, ArtifactStorageFailure
from skill_checks import (
    SecurityAdapter,
    SecurityAdapterBuildError,
    SecurityAdapterSettings,
    build_security_adapter,
)

from .config_validation import is_environment_name, is_root_http_url
from .storage_config import StorageConfig, build_artifact_storage

_MAX_CONFIG_BYTES = 1024 * 1024
_REQUEST_OVERHEAD_BYTES = 4096
_HTTP_PATH = re.compile(r"/[A-Za-z0-9/_-]*")


class _TomlModule(Protocol):
    def load(self, handle: BinaryIO) -> object: ...


_TOML = cast(_TomlModule, tomllib)


class ConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class HttpSettings:
    host: str
    port: int
    path: str
    max_request_body_bytes: int
    public_base_url: str
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServerConfig:
    http: HttpSettings
    security_adapter: SecurityAdapter
    max_package_bytes: int
    artifact_storage: ArtifactStorage
    scratch_directory: Path
    max_result_bytes: int
    bearer_key: str = field(repr=False)


_NetworkValue = Annotated[str, Field(min_length=1, max_length=512)]


class _HttpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(gt=0, le=65535)]
    path: Annotated[str, Field(min_length=1, max_length=256)]
    max_request_body_bytes: Annotated[int, Field(gt=0)]
    public_base_url: Annotated[str, Field(min_length=8, max_length=2048)]
    allowed_hosts: Annotated[list[_NetworkValue], Field(min_length=1, max_length=64)]
    allowed_origins: Annotated[list[_NetworkValue], Field(min_length=1, max_length=64)]


class _SecurityPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_package_bytes: Annotated[int, Field(gt=0)]
    max_entries_per_package: Annotated[int, Field(gt=0)]
    max_text_bytes_per_file: Annotated[int, Field(gt=0)]
    max_total_read_bytes: Annotated[int, Field(gt=0)]
    max_findings: Annotated[int, Field(gt=0)]


class _SecurityToolConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["skill-security"]
    rules_file: Annotated[str, Field(min_length=1, max_length=4096)]
    policy: _SecurityPolicyConfig


class _AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["static_bearer"]
    key_env: Annotated[str, Field(min_length=1, max_length=128)]


class _ToolsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scan_skill_security: _SecurityToolConfig


class _Document(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["2"]
    http: _HttpConfig
    auth: _AuthConfig
    storage: StorageConfig
    tools: _ToolsConfig


def load_config(path: Path) -> ServerConfig:
    loaded: ServerConfig | None = None
    artifact_storage: ArtifactStorage | None = None
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            raise ValueError
        with path.open("rb") as handle:
            raw = _TOML.load(handle)
        document = _Document.model_validate(raw, strict=True)
        _validate_http(document.http, document.tools.scan_skill_security.policy)
        bearer_key = _bearer_key(document.auth)
        security_adapter = _security_adapter(
            document.tools.scan_skill_security,
            path.parent,
        )
        http_settings = HttpSettings(
            host=document.http.host,
            port=document.http.port,
            path=document.http.path,
            max_request_body_bytes=document.http.max_request_body_bytes,
            public_base_url=_public_base_url(document.http.public_base_url),
            allowed_hosts=tuple(document.http.allowed_hosts),
            allowed_origins=tuple(document.http.allowed_origins),
        )
        artifact_storage, scratch_directory = build_artifact_storage(document.storage)
        loaded = ServerConfig(
            http_settings,
            security_adapter,
            document.tools.scan_skill_security.policy.max_package_bytes,
            artifact_storage,
            scratch_directory,
            document.storage.max_result_bytes,
            bearer_key,
        )
    except (
        OSError,
        ValidationError,
        SecurityAdapterBuildError,
        ArtifactStorageFailure,
        ValueError,
        TypeError,
    ):
        if artifact_storage is not None:
            artifact_storage.close()
    if loaded is None:
        raise ConfigError("MCP 配置无效")
    return loaded


def _validate_http(http: _HttpConfig, policy: _SecurityPolicyConfig) -> None:
    minimum_body_bytes = 4 * ((policy.max_package_bytes + 2) // 3) + _REQUEST_OVERHEAD_BYTES
    network_values = (*http.allowed_hosts, *http.allowed_origins)
    if (
        _HTTP_PATH.fullmatch(http.path) is None
        or http.path.endswith("/")
        or any(value != value.strip() or "\x00" in value for value in network_values)
        or http.host != http.host.strip()
        or "\x00" in http.host
        or len(set(http.allowed_hosts)) != len(http.allowed_hosts)
        or len(set(http.allowed_origins)) != len(http.allowed_origins)
        or http.max_request_body_bytes < minimum_body_bytes
    ):
        raise ValueError


def _public_base_url(value: str) -> str:
    if not is_root_http_url(value):
        raise ValueError
    return value.rstrip("/")


def _bearer_key(config: _AuthConfig) -> str:
    if not is_environment_name(config.key_env):
        raise ValueError
    value = environ.get(config.key_env)
    if (
        value is None
        or not 32 <= len(value) <= 512
        or any(character.isspace() or not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError
    return value


def _security_adapter(
    config: _SecurityToolConfig,
    base_directory: Path,
) -> SecurityAdapter:
    rules_path = Path(config.rules_file)
    if not rules_path.is_absolute():
        rules_path = base_directory / rules_path
    return build_security_adapter(
        SecurityAdapterSettings(
            rules_path=rules_path,
            max_package_bytes=config.policy.max_package_bytes,
            max_entries_per_package=config.policy.max_entries_per_package,
            max_text_bytes_per_file=config.policy.max_text_bytes_per_file,
            max_total_read_bytes=config.policy.max_total_read_bytes,
            max_findings=config.policy.max_findings,
        )
    )
