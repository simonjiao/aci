from __future__ import annotations

import json
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from skill_check_runner import CheckAdapter
from skill_checks import SecurityAdapter
from skill_security import ScanPolicy, SecurityScan, compile_rules

_MAX_CONFIG_BYTES = 1024 * 1024
_JSON_LOADS = cast(Callable[[str], object], json.loads)


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


class _SecurityConfigError(Exception):
    pass


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
        checks = (_build_security_adapter(config.modules.security, path.parent),)
    except (OSError, ValidationError, _SecurityConfigError, ValueError, TypeError):
        pass
    if checks is None:
        raise ConfigError("CLI 配置无效")
    return checks


def _build_security_adapter(
    config: _SecurityConfig,
    base_directory: Path,
) -> SecurityAdapter:
    rules_path = Path(config.rules_file)
    if not rules_path.is_absolute():
        rules_path = base_directory / rules_path
    adapter: SecurityAdapter | None = None
    try:
        raw = _JSON_LOADS(rules_path.read_text(encoding="utf-8"))
        document = _string_mapping(raw)
        if document is None:
            raise ValueError
        rules = compile_rules(document)
        policy = ScanPolicy(
            config.policy.max_package_bytes,
            config.policy.max_entries_per_package,
            config.policy.max_text_bytes_per_file,
            config.policy.max_total_read_bytes,
            config.policy.max_findings,
        )
        adapter = SecurityAdapter(rules, SecurityScan(policy))
    except Exception:
        pass
    if adapter is None:
        raise _SecurityConfigError("安全检查配置无效")
    return adapter


def _string_mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast(Mapping[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return cast(Mapping[str, object], mapping)
