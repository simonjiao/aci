from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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

    display_name: str = Field(min_length=1)
    source_id: str | None


class _RequestContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    packages: tuple[_PackageContract, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def display_names_are_unique(self) -> Self:
        names = tuple(package.display_name for package in self.packages)
        if len(names) != len(set(names)):
            raise ValueError("package display names must be unique")
        return self


class SecurityScan:
    def __init__(self, policy: ScanPolicy) -> None:
        self._policy = validate_policy(policy)

    def scan(self, request: ScanRequest) -> ScanResult:
        _validate_request(request)
        return Engine(self._policy).scan(request)


def _validate_request(request: ScanRequest) -> None:
    if not isinstance(request, ScanRequest):
        raise ScanError(ErrorCode.REQUEST_INVALID, "请求必须是 ScanRequest")
    if not isinstance(request.rules, RuleSet):
        raise ScanError(ErrorCode.REQUEST_INVALID, "请求必须使用 compile_rules() 生成的 RuleSet")
    if not isinstance(request.packages, tuple):
        raise ScanError(ErrorCode.REQUEST_INVALID, "packages 必须是 tuple")
    for package in request.packages:
        if not isinstance(package, PackageInput):
            raise ScanError(ErrorCode.REQUEST_INVALID, "packages 必须只包含 PackageInput")
    try:
        _RequestContract.model_validate(
            {
                "packages": tuple(
                    {
                        "display_name": package.display_name,
                        "source_id": package.source_id,
                    }
                    for package in request.packages
                )
            }
        )
    except ValidationError:
        pass
    else:
        return
    raise ScanError(ErrorCode.REQUEST_INVALID, "扫描请求字段无效")
