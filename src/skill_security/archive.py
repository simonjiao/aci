from __future__ import annotations

import codecs
import hashlib
import stat
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO, Protocol, cast
from zipfile import ZipFile, ZipInfo

from .facts import TextEntry
from .limits import ReadBudget
from .models import ErrorCode, PackageInput, RuleSet, ScanError, ScanPolicy


@dataclass(frozen=True, slots=True)
class PackageContent:
    display_name: str
    source_id: str | None
    size_bytes: int
    sha256: str
    entry_count: int
    text_entries: tuple[TextEntry, ...]
    filenames: tuple[str, ...]


class _ZipEntryReader(Protocol):
    def open(self, name: ZipInfo, mode: str = "r") -> BinaryIO: ...


def read_package(
    package: PackageInput,
    rules: RuleSet,
    policy: ScanPolicy,
    budget: ReadBudget,
) -> PackageContent:
    stream = package.stream
    original_position = _validate_stream(package)
    try:
        size, digest = _measure_and_hash(package, policy)
        stream.seek(0)
        try:
            with ZipFile(stream, "r", allowZip64=True) as archive:
                infos = archive.infolist()
                if len(infos) > policy.max_entries_per_package:
                    raise ScanError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        "ZIP 条目数超过限制",
                        package_name=package.display_name,
                    )
                text_entries: list[TextEntry] = []
                filenames: list[str] = []
                for info in infos:
                    path = info.filename
                    if info.flag_bits & 0x1:
                        raise ScanError(
                            ErrorCode.ZIP_ENTRY_READ_FAILED,
                            "ZIP 条目已加密",
                            package_name=package.display_name,
                            entry_path=path,
                        )
                    skipped = _is_skipped(path, rules.default_skip_directories)
                    if not info.is_dir() and not skipped:
                        filenames.append(path)
                    if info.is_dir() or _is_link(info.external_attr):
                        continue
                    if skipped:
                        continue
                    if _extension(path) not in rules.text_extensions:
                        continue
                    text_entries.append(_read_text(archive, info, package, policy, budget))
        except ScanError:
            raise
        except Exception as exc:
            raise ScanError(
                ErrorCode.ZIP_OPEN_FAILED,
                "ZIP 内容无法打开",
                package_name=package.display_name,
            ) from exc
        return PackageContent(
            display_name=package.display_name,
            source_id=package.source_id,
            size_bytes=size,
            sha256=digest,
            entry_count=len(infos),
            text_entries=tuple(text_entries),
            filenames=tuple(filenames),
        )
    finally:
        try:
            stream.seek(original_position)
        except Exception as exc:
            raise ScanError(
                ErrorCode.PACKAGE_SOURCE_INVALID,
                "扫描后无法恢复包内容流的位置",
                package_name=package.display_name,
            ) from exc


def _validate_stream(package: PackageInput) -> int:
    stream = package.stream
    try:
        position = stream.tell()
        stream.seek(position)
    except Exception as exc:
        raise ScanError(
            ErrorCode.PACKAGE_SOURCE_INVALID,
            "包内容必须是可读、可定位的二进制流",
            package_name=package.display_name,
        ) from exc
    return position


def _measure_and_hash(package: PackageInput, policy: ScanPolicy) -> tuple[int, str]:
    stream = package.stream
    try:
        stream.seek(0, 2)
        size = stream.tell()
        if not isinstance(size, int) or size < 0:
            raise TypeError
        if size > policy.max_package_bytes:
            raise ScanError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "ZIP 内容大小超过限制",
                package_name=package.display_name,
            )
        stream.seek(0)
        digest = hashlib.sha256()
        while chunk := _require_bytes(stream.read(1024 * 1024)):
            digest.update(chunk)
        return size, digest.hexdigest()
    except ScanError:
        raise
    except Exception as exc:
        raise ScanError(
            ErrorCode.PACKAGE_SOURCE_INVALID,
            "包内容必须是可读、可定位的二进制流",
            package_name=package.display_name,
        ) from exc


def _require_bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError
    return value


def _read_text(
    archive: ZipFile,
    info: ZipInfo,
    package: PackageInput,
    policy: ScanPolicy,
    budget: ReadBudget,
) -> TextEntry:
    path = info.filename
    amount = min(info.file_size, policy.max_text_bytes_per_file)
    try:
        budget.consume(info.file_size, package_name=package.display_name, entry_path=path)
        content = bytearray()
        validator = codecs.getincrementaldecoder("utf-8")("strict")
        opened = cast(_ZipEntryReader, archive).open(info, "r")
        with opened as entry:
            while chunk := entry.read(64 * 1024):
                validator.decode(chunk, final=False)
                # Detection retains only the per-file sample. The remaining stream is
                # consumed solely for CRC/UTF-8 integrity under the total-read budget.
                if len(content) < amount:
                    content.extend(chunk[: amount - len(content)])
        validator.decode(b"", final=True)
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        text = decoder.decode(bytes(content), final=info.file_size <= amount)
    except ScanError:
        raise
    except Exception as exc:
        raise ScanError(
            ErrorCode.ZIP_ENTRY_READ_FAILED,
            "ZIP 文本条目读取失败",
            package_name=package.display_name,
            entry_path=path,
        ) from exc
    return TextEntry(path, text, info.file_size, len(content))


def _extension(path: str) -> str:
    return PurePosixPath(path).suffix.lower().removeprefix(".")


def _is_skipped(path: str, skipped: tuple[str, ...]) -> bool:
    return any(segment in skipped for segment in PurePosixPath(path).parts)


def _is_link(external_attr: int) -> bool:
    mode = external_attr >> 16
    return bool(mode and stat.S_ISLNK(mode))
