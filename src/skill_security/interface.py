from __future__ import annotations

from typing import Annotated, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .engine import Engine
from .limits import validate_policy
from .models import (
    ErrorCode,
    PackageInput,
    RuleSet,
    ScanError,
    ScanPolicy,
    ScanRequest,
    ScanResult,
)


class _PackageContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    display_name: Annotated[str, Field(min_length=1)]
    source_id: str | None


class _RequestContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    packages: Annotated[tuple[_PackageContract, ...], Field(min_length=1)]


class SecurityScan:
    def __init__(self, policy: ScanPolicy) -> None:
        self._policy = validate_policy(policy)

    def scan(self, request: ScanRequest) -> ScanResult:
        _validate_request(request)
        return Engine(self._policy).scan(request)


def _validate_request(value: object) -> None:
    if not isinstance(value, ScanRequest):
        raise ScanError(ErrorCode.REQUEST_INVALID, "请求必须是 ScanRequest")
    request = value
    _require_rule_set(request.rules)
    packages = _require_packages(request.packages)
    try:
        contract = _RequestContract(
            packages=tuple(
                _PackageContract(
                    display_name=package.display_name,
                    source_id=package.source_id,
                )
                for package in packages
            )
        )
    except ValidationError:
        pass
    else:
        names = tuple(package.display_name for package in contract.packages)
        if len(names) != len(set(names)):
            raise ScanError(ErrorCode.REQUEST_INVALID, "扫描请求字段无效")
        return
    raise ScanError(ErrorCode.REQUEST_INVALID, "扫描请求字段无效")


def _require_rule_set(value: object) -> RuleSet:
    if not isinstance(value, RuleSet):
        raise ScanError(ErrorCode.REQUEST_INVALID, "请求必须使用 compile_rules() 生成的 RuleSet")
    return value


def _require_packages(value: object) -> tuple[PackageInput, ...]:
    if not isinstance(value, tuple):
        raise ScanError(ErrorCode.REQUEST_INVALID, "packages 必须是 tuple")
    packages: list[PackageInput] = []
    for item in cast(tuple[object, ...], value):
        if not isinstance(item, PackageInput):
            raise ScanError(ErrorCode.REQUEST_INVALID, "packages 必须只包含 PackageInput")
        packages.append(item)
    return tuple(packages)
