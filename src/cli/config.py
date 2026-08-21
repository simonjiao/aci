from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from skill_check_runner import CheckAdapter

from .adapters.security import SecurityAdapter, SecurityAdapterConfigError, SecurityConfig

_MAX_CONFIG_BYTES = 1024 * 1024


class _TomlModule(Protocol):
    def load(self, handle: BinaryIO) -> object: ...


_TOML = cast(_TomlModule, tomllib)


class ConfigError(Exception):
    pass


class _ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    security: SecurityConfig


class _CliConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1"]
    checks: Annotated[list[Literal["security"]], Field(min_length=1, max_length=1)]
    modules: _ModulesConfig


def load_checks(path: Path) -> tuple[CheckAdapter, ...]:
    checks: tuple[CheckAdapter, ...] | None = None
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            raise ValueError
        with path.open("rb") as handle:
            raw = _TOML.load(handle)
        config = _CliConfig.model_validate(raw, strict=True)
        if config.checks != ["security"]:
            raise ValueError
        checks = (SecurityAdapter.from_config(config.modules.security, path.parent),)
    except (OSError, ValidationError, SecurityAdapterConfigError, ValueError, TypeError):
        pass
    if checks is None:
        raise ConfigError("CLI 配置无效")
    return checks
