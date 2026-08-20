from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import ErrorCode, ScanError, ScanPolicy

HARD_MAX_PACKAGE_BYTES = 512 * 1024 * 1024
HARD_MAX_ENTRIES_PER_PACKAGE = 1000
HARD_MAX_TEXT_BYTES_PER_FILE = 64 * 1024
HARD_MAX_TOTAL_READ_BYTES = 64 * 1024 * 1024
HARD_MAX_FINDINGS = 10_000


class _PolicyContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_package_bytes: Annotated[int, Field(gt=0, le=HARD_MAX_PACKAGE_BYTES)]
    max_entries_per_package: Annotated[int, Field(gt=0, le=HARD_MAX_ENTRIES_PER_PACKAGE)]
    max_text_bytes_per_file: Annotated[int, Field(gt=0, le=HARD_MAX_TEXT_BYTES_PER_FILE)]
    max_total_read_bytes: Annotated[int, Field(gt=0, le=HARD_MAX_TOTAL_READ_BYTES)]
    max_findings: Annotated[int, Field(gt=0, le=HARD_MAX_FINDINGS)]


def validate_policy(policy: ScanPolicy | None) -> ScanPolicy:
    if not isinstance(policy, ScanPolicy):
        raise ScanError(ErrorCode.POLICY_INVALID, "必须提供 ScanPolicy")
    try:
        _PolicyContract(
            max_package_bytes=policy.max_package_bytes,
            max_entries_per_package=policy.max_entries_per_package,
            max_text_bytes_per_file=policy.max_text_bytes_per_file,
            max_total_read_bytes=policy.max_total_read_bytes,
            max_findings=policy.max_findings,
        )
    except ValidationError:
        pass
    else:
        return policy
    raise ScanError(
        ErrorCode.POLICY_INVALID,
        "ScanPolicy 取值无效或超过 Module 硬上限",
    )


@dataclass(slots=True)
class ReadBudget:
    maximum: int
    consumed: int = 0

    def consume(self, amount: int, *, package_name: str, entry_path: str) -> None:
        if self.consumed + amount > self.maximum:
            raise ScanError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "累计文本读取量超过限制",
                package_name=package_name,
                entry_path=entry_path,
            )
        self.consumed += amount
