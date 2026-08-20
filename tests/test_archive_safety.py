from __future__ import annotations

import stat
import struct
import unittest
from io import BytesIO, StringIO
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from skill_security import (
    ErrorCode,
    PackageInput,
    ScanError,
    ScanPolicy,
    ScanRequest,
    SecurityScan,
    compile_rules,
)


def document() -> dict[str, object]:
    return {
        "schemaVersion": "1.0",
        "ruleVersion": "test",
        "sourceVersion": "test",
        "defaultSkipDirectories": [".git"],
        "textExtensions": ["txt"],
        "vocabularies": {},
        "rules": [
            {
                "id": "SEC-TEST-01",
                "detector": "TestDetector",
                "name": "danger",
                "sourceDescription": "danger",
                "severity": "HIGH",
                "status": "APPROVED",
                "scope": "line",
                "match": {"type": "literal_any", "terms": ["danger", "dangerous"]},
                "evidence": {"type": "command", "prefixLength": 0},
                "remediation": None,
                "sourceLimitations": [],
            }
        ],
    }


def archive_bytes(entries: dict[str, str | bytes]) -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_STORED) as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return stream.getvalue()


def policy(**changes: int) -> ScanPolicy:
    values = {
        "max_package_bytes": 1024 * 1024,
        "max_entries_per_package": 100,
        "max_text_bytes_per_file": 64 * 1024,
        "max_total_read_bytes": 1024 * 1024,
        "max_findings": 100,
    }
    values.update(changes)
    return ScanPolicy(**values)


def encrypted_flag(content: bytes) -> bytes:
    data = bytearray(content)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = 0
        while (position := data.find(signature, position)) >= 0:
            flags = struct.unpack_from("<H", data, position + flag_offset)[0]
            struct.pack_into("<H", data, position + flag_offset, flags | 1)
            position += 4
    return bytes(data)


def corrupt_first_entry(content: bytes, offset: int = 0) -> bytes:
    data = bytearray(content)
    position = data.index(b"PK\x03\x04")
    name_length, extra_length = struct.unpack_from("<HH", data, position + 26)
    content_start = position + 30 + name_length + extra_length
    data[content_start + offset] ^= 1
    return bytes(data)


def unsupported_compression(content: bytes) -> bytes:
    data = bytearray(content)
    for signature, method_offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        position = data.index(signature)
        struct.pack_into("<H", data, position + method_offset, 99)
    return bytes(data)


class ArchiveSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = compile_rules(document())

    def scan(self, packages: tuple[PackageInput, ...], scan_policy: ScanPolicy | None = None):
        return SecurityScan(scan_policy or policy()).scan(ScanRequest(packages, self.rules))

    def assert_scan_error(
        self,
        code: ErrorCode,
        package: PackageInput,
        scan_policy: ScanPolicy | None = None,
    ) -> ScanError:
        with self.assertRaises(ScanError) as raised:
            self.scan((package,), scan_policy)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_invalid_zip_restores_stream_and_does_not_close_it(self) -> None:
        stream = BytesIO(b"not a zip")
        stream.seek(3)

        self.assert_scan_error(ErrorCode.ZIP_OPEN_FAILED, PackageInput("bad.zip", stream))

        self.assertEqual(stream.tell(), 3)
        self.assertFalse(stream.closed)

    def test_encrypted_entry_fails_without_returning_partial_result(self) -> None:
        stream = BytesIO(encrypted_flag(archive_bytes({"sample.txt": "safe"})))

        error = self.assert_scan_error(
            ErrorCode.ZIP_ENTRY_READ_FAILED,
            PackageInput("encrypted.zip", stream),
        )

        self.assertEqual(error.entry_path, "sample.txt")

    def test_crc_failure_and_invalid_utf8_are_read_errors(self) -> None:
        corrupt = PackageInput(
            "corrupt.zip",
            BytesIO(corrupt_first_entry(archive_bytes({"sample.txt": "safe"}))),
        )
        invalid_utf8 = PackageInput(
            "utf8.zip",
            BytesIO(archive_bytes({"sample.txt": b"\xff\xfe"})),
        )
        unsupported = PackageInput(
            "compression.zip",
            BytesIO(unsupported_compression(archive_bytes({"sample.txt": "safe"}))),
        )

        self.assert_scan_error(ErrorCode.ZIP_ENTRY_READ_FAILED, corrupt)
        self.assert_scan_error(ErrorCode.ZIP_ENTRY_READ_FAILED, invalid_utf8)
        self.assert_scan_error(ErrorCode.ZIP_ENTRY_READ_FAILED, unsupported)

    def test_read_failures_after_text_sample_are_still_errors(self) -> None:
        content = b"a" * 100_000
        corrupt = PackageInput(
            "late-corrupt.zip",
            BytesIO(corrupt_first_entry(archive_bytes({"sample.txt": content}), 90_000)),
        )

        self.assert_scan_error(
            ErrorCode.ZIP_ENTRY_READ_FAILED,
            corrupt,
            policy(max_text_bytes_per_file=8),
        )

        invalid_utf8 = PackageInput(
            "late-utf8.zip",
            BytesIO(archive_bytes({"sample.txt": b"a" * 100_000 + b"\xff"})),
        )
        self.assert_scan_error(
            ErrorCode.ZIP_ENTRY_READ_FAILED,
            invalid_utf8,
            policy(max_text_bytes_per_file=8),
        )

    def test_non_binary_or_non_seekable_source_is_rejected(self) -> None:
        source = PackageInput("text.zip", StringIO("not binary"))  # type: ignore[arg-type]

        self.assert_scan_error(ErrorCode.PACKAGE_SOURCE_INVALID, source)

    def test_entry_package_total_read_and_finding_limits_are_hard_failures(self) -> None:
        two_entries = PackageInput(
            "entries.zip",
            BytesIO(archive_bytes({"a.txt": "a", "b.txt": "b"})),
        )
        package_too_large = PackageInput(
            "large.zip",
            BytesIO(archive_bytes({"a.txt": "a"})),
        )
        read_too_large = PackageInput(
            "read.zip",
            BytesIO(archive_bytes({"a.txt": "abcdef"})),
        )
        findings = PackageInput(
            "findings.zip",
            BytesIO(archive_bytes({"a.txt": "danger danger"})),
        )

        self.assert_scan_error(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            two_entries,
            policy(max_entries_per_package=1),
        )
        self.assert_scan_error(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            package_too_large,
            policy(max_package_bytes=10),
        )
        self.assert_scan_error(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            read_too_large,
            policy(max_total_read_bytes=5),
        )
        self.assert_scan_error(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            findings,
            policy(max_findings=1),
        )

    def test_text_after_per_file_sample_limit_is_not_scanned(self) -> None:
        package = PackageInput(
            "prefix.zip",
            BytesIO(archive_bytes({"sample.txt": "safe----danger"})),
        )

        result = self.scan((package,), policy(max_text_bytes_per_file=8))

        self.assertEqual(result.findings, ())

    def test_crc_verification_counts_toward_total_read_limit(self) -> None:
        package = PackageInput(
            "large-text.zip",
            BytesIO(archive_bytes({"sample.txt": "safe" * 100})),
        )

        self.assert_scan_error(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            package,
            policy(max_text_bytes_per_file=8, max_total_read_bytes=100),
        )

    def test_finding_limit_is_applied_after_stable_deduplication(self) -> None:
        package = PackageInput(
            "dedupe.zip",
            BytesIO(archive_bytes({"sample.txt": "dangerous"})),
        )

        result = self.scan((package,), policy(max_findings=1))

        self.assertEqual(len(result.findings), 1)

    def test_later_package_failure_restores_every_stream_and_returns_no_result(self) -> None:
        first = BytesIO(archive_bytes({"sample.txt": "danger"}))
        second = BytesIO(b"invalid")
        first.seek(2)
        second.seek(1)

        with self.assertRaises(ScanError) as raised:
            self.scan((PackageInput("first.zip", first), PackageInput("second.zip", second)))

        self.assertEqual(raised.exception.code, ErrorCode.ZIP_OPEN_FAILED)
        self.assertEqual((first.tell(), second.tell()), (2, 1))
        self.assertFalse(first.closed)
        self.assertFalse(second.closed)

    def test_nested_zip_and_link_content_are_not_followed(self) -> None:
        inner = archive_bytes({"payload.txt": "danger"})
        stream = BytesIO()
        with ZipFile(stream, "w", ZIP_STORED) as archive:
            archive.writestr("nested.zip", inner)
            link = ZipInfo("link.txt")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "danger")

        result = self.scan((PackageInput("containers.zip", BytesIO(stream.getvalue())),))

        self.assertEqual(result.findings, ())


if __name__ == "__main__":
    unittest.main()
