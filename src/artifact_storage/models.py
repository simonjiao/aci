from __future__ import annotations

import hashlib
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

_RESULT_REFERENCE = re.compile(r"res_[0-9a-f]{32}")
_HASH_CHUNK_BYTES = 1024 * 1024


class ArtifactUnavailable(Exception):
    pass


class ArtifactStorageFailure(Exception):
    pass


@dataclass(frozen=True, slots=True)
class PreparedArtifact:
    path: Path
    size_bytes: int
    sha256: str

    @classmethod
    def from_file(cls, path: Path) -> PreparedArtifact:
        return cls(path, path.stat().st_size, _sha256(path))

    def matches_file(self) -> bool:
        matches = False
        with suppress(OSError):
            matches = (
                self.path.is_file()
                and type(self.size_bytes) is int
                and self.size_bytes > 0
                and self.path.stat().st_size == self.size_bytes
                and len(self.sha256) == 64
                and self.sha256 == _sha256(self.path)
            )
        return matches


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()
