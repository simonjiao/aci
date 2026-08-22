from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from .models import ArtifactInfo, PreparedArtifact, StoredArtifact


class ArtifactStorage(Protocol):
    def publish_result(self, prepared: PreparedArtifact) -> StoredArtifact: ...

    def inspect_result(self, reference: str) -> ArtifactInfo: ...

    def stream_result(self, reference: str, *, chunk_size: int) -> Iterator[bytes]: ...
