from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from skill_security import ScanPolicy, SecurityScan, compile_rules

from .security import SecurityAdapter

_JSON_LOADS = cast(Callable[[str], object], json.loads)


class SecurityAdapterBuildError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SecurityAdapterSettings:
    rules_path: Path
    max_package_bytes: int
    max_entries_per_package: int
    max_text_bytes_per_file: int
    max_total_read_bytes: int
    max_findings: int


def build_security_adapter(settings: SecurityAdapterSettings) -> SecurityAdapter:
    adapter: SecurityAdapter | None = None
    try:
        raw = _JSON_LOADS(settings.rules_path.read_text(encoding="utf-8"))
        document = _string_mapping(raw)
        if document is None:
            raise ValueError
        rules = compile_rules(document)
        policy = ScanPolicy(
            settings.max_package_bytes,
            settings.max_entries_per_package,
            settings.max_text_bytes_per_file,
            settings.max_total_read_bytes,
            settings.max_findings,
        )
        adapter = SecurityAdapter(rules, SecurityScan(policy))
    except Exception:
        pass
    if adapter is None:
        raise SecurityAdapterBuildError("安全检查配置无效")
    return adapter


def _string_mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast(Mapping[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return cast(Mapping[str, object], mapping)
