from __future__ import annotations

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
    if not isinstance(request.packages, tuple) or not request.packages:
        raise ScanError(ErrorCode.REQUEST_INVALID, "包列表不得为空")
    names: set[str] = set()
    for package in request.packages:
        if not isinstance(package, PackageInput):
            raise ScanError(ErrorCode.REQUEST_INVALID, "packages 必须只包含 PackageInput")
        if not isinstance(package.display_name, str) or not package.display_name:
            raise ScanError(ErrorCode.REQUEST_INVALID, "包显示名称必须是非空字符串")
        if package.display_name in names:
            raise ScanError(ErrorCode.REQUEST_INVALID, "同一请求中的包显示名称必须唯一")
        if package.source_id is not None and not isinstance(package.source_id, str):
            raise ScanError(ErrorCode.REQUEST_INVALID, "包来源标识必须是字符串或 null")
        names.add(package.display_name)
