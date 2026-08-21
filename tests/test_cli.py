from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from typing import cast
from zipfile import ZIP_DEFLATED, ZipFile

from cli.main import main
from tests.support import list_field

ROOT = Path(__file__).resolve().parents[1]
_JSON_LOADS = cast(Callable[[str], object], json.loads)


def write_skill(path: Path, content: str) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("SKILL.md", content)


def write_config(path: Path) -> None:
    rules = (ROOT / "config/security-rules.json").as_posix()
    path.write_text(
        f'''schema_version = "1"
checks = ["security"]

[modules.security]
type = "skill-security"
rules_file = "{rules}"

[modules.security.policy]
max_package_bytes = 1048576
max_entries_per_package = 100
max_text_bytes_per_file = 65536
max_total_read_bytes = 1048576
max_findings = 100
''',
        encoding="utf-8",
    )


def json_object(raw: bytes) -> Mapping[str, object]:
    value = _JSON_LOADS(raw.decode())
    if not isinstance(value, Mapping):
        raise AssertionError("expected JSON object")
    mapping = cast(Mapping[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise AssertionError("expected string keys")
    return cast(Mapping[str, object], mapping)


class CliTests(unittest.TestCase):
    def test_check_writes_a_result_zip_without_modifying_the_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "safe.zip"
            config = root / "skillqa.toml"
            output = root / "result.zip"
            second_output = root / "result-2.zip"
            write_skill(package, "# Safe Skill\n")
            write_config(config)
            before = hashlib.sha256(package.read_bytes()).hexdigest()

            exit_code = main(
                (
                    "check",
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                    str(package),
                )
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(hashlib.sha256(package.read_bytes()).hexdigest(), before)
            expected_names: list[str] = ["manifest.json", "security-scan.json"]
            with ZipFile(output) as archive:
                self.assertEqual(archive.namelist(), expected_names)
                manifest = json_object(archive.read("manifest.json"))
                security = json_object(archive.read("security-scan.json"))
            self.assertEqual(manifest["conclusion"], "PASS")
            self.assertEqual(security["conclusion"], "PASS")

            second_exit = main(
                (
                    "check",
                    "--config",
                    str(config),
                    "--output",
                    str(second_output),
                    str(package),
                )
            )
            self.assertEqual(second_exit, 0)
            self.assertEqual(output.read_bytes(), second_output.read_bytes())

    def test_review_findings_are_written_and_return_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "review.zip"
            config = root / "skillqa.toml"
            output = root / "result.zip"
            write_skill(package, "eval(user_input)\n")
            write_config(config)

            exit_code = main(
                ("check", "--config", str(config), "--output", str(output), str(package))
            )

            self.assertEqual(exit_code, 1)
            with ZipFile(output) as archive:
                security = json_object(archive.read("security-scan.json"))
            self.assertEqual(security["conclusion"], "REVIEW_REQUIRED")
            self.assertTrue(list_field(security, "findings"))

    def test_invalid_zip_fails_without_output_or_sensitive_error_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "invalid.zip"
            config = root / "skillqa.toml"
            output = root / "result.zip"
            package.write_bytes(b"PASSWORD_CANARY_SECRET")
            write_config(config)
            stderr = StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    ("check", "--config", str(config), "--output", str(output), str(package))
                )

            self.assertEqual(exit_code, 3)
            self.assertFalse(output.exists())
            self.assertNotIn("CANARY_SECRET", stderr.getvalue())

    def test_invalid_config_and_existing_output_are_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "safe.zip"
            invalid_config = root / "invalid.toml"
            valid_config = root / "valid.toml"
            output = root / "result.zip"
            write_skill(package, "# Safe Skill\n")
            invalid_config.write_text('schema_version = "TOKEN_CANARY_SECRET"\n', encoding="utf-8")
            write_config(valid_config)
            stderr = StringIO()

            with redirect_stderr(stderr):
                invalid_exit = main(
                    (
                        "check",
                        "--config",
                        str(invalid_config),
                        "--output",
                        str(output),
                        str(package),
                    )
                )
            output.write_bytes(b"preserve")
            with redirect_stderr(StringIO()):
                existing_exit = main(
                    (
                        "check",
                        "--config",
                        str(valid_config),
                        "--output",
                        str(output),
                        str(package),
                    )
                )

            self.assertEqual(invalid_exit, 2)
            self.assertNotIn("CANARY_SECRET", stderr.getvalue())
            self.assertEqual(existing_exit, 2)
            self.assertEqual(output.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
