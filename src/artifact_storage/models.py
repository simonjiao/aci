from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

_RESULT_REFERENCE = re.compile(r"res_[0-9a-f]{32}")


class ArtifactUnavailable(Exception):
    pass


class ArtifactStorageFailure(Exception):
    pass


@dataclass(frozen=True, slots=True)
class PreparedArtifact:
    path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    reference: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ArtifactInfo:
    reference: str
    size_bytes: int


def is_result_reference(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _RESULT_REFERENCE.fullmatch(value) is not None
