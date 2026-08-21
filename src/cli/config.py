from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from skill_check_runner import CheckAdapter
from skill_checks import (
    SecurityAdapterBuildError,
    SecurityAdapterSettings,
    build_security_adapter,
)

_MAX_CONFIG_BYTES = 1024 * 1024


class _TomlModule(Protocol):
    def load(self, handle: BinaryIO) -> object: ...


_TOML = cast(_TomlModule, tomllib)


class ConfigError(Exception):
    pass


class _SecurityPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_package_bytes: Annotated[int, Field(gt=0)]
    max_entries_per_package: Annotated[int, Field(gt=0)]
    max_text_bytes_per_file: Annotated[int, Field(gt=0)]
    max_total_read_bytes: Annotated[int, Field(gt=0)]
    max_findings: Annotated[int, Field(gt=0)]


class _SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["skill-security"]
    rules_file: Annotated[str, Field(min_length=1)]
    policy: _SecurityPolicyConfig


class _ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    security: _SecurityConfig


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
        checks = (_security_adapter(config.modules.security, path.parent),)
    except (OSError, ValidationError, SecurityAdapterBuildError, ValueError, TypeError):
        pass
    if checks is None:
        raise ConfigError("CLI 配置无效")
    return checks


def _security_adapter(
    config: _SecurityConfig,
    base_directory: Path,
) -> CheckAdapter:
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
