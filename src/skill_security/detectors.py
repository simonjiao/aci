from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

from .archive import PackageContent
from .facts import FactIndex, FileFacts, LineFact
from .models import CompiledRule, RuleSet


@dataclass(frozen=True, slots=True)
class Match:
    entry_path: str
    line: int
    column: int
    raw_evidence: str
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


Matcher = Callable[[CompiledRule, FactIndex, PackageContent, RuleSet], tuple[Match, ...]]


def detect(
    rule: CompiledRule,
    facts: FactIndex,
    package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    matcher = _MATCHERS.get(rule.match_type)
    if matcher is None:
        return ()
    return matcher(rule, facts, package, rules)


def _literal_any(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    return _line_term_matches(rule, facts, _terms(rule, rules))


def _prefixed_token(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    prefixes = rule.parameters["prefixes"]
    minimum = rule.parameters["minimumLength"]
    maximum = rule.parameters.get("maximumLength")
    alphabet = rule.parameters["alphabet"]
    tail = "[0-9A-Z]" if alphabet == "upper_alnum" else "[A-Za-z0-9_.-]"
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for prefix in prefixes:
                remaining = max(1, minimum - len(prefix))
                upper = "" if maximum is None else str(maximum - len(prefix))
                pattern = re.compile(re.escape(prefix) + tail + f"{{{remaining},{upper}}}")
                for found in pattern.finditer(line.text):
                    matches.append(_match(file, line, found.start(), found.group(0)))
    return tuple(matches)


def _field_value(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    fields = "|".join(re.escape(item) for item in rule.parameters["fields"])
    separators = "|".join(re.escape(item) for item in rule.parameters["separators"])
    minimum = rule.parameters["minimumValueLength"]
    value = rf"[^\s,;#]{{{minimum},}}"
    pattern = re.compile(rf"(?<![A-Za-z0-9_])(?:{fields})\s*(?:{separators})\s*(['\"]?)({value})")
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for found in pattern.finditer(line.text):
                raw = found.group(2).rstrip("'\"")
                quote = found.group(1)
                dynamic_syntax = not quote and any(character in raw for character in "()[]{}")
                if len(raw) >= minimum and not dynamic_syntax:
                    matches.append(_match(file, line, found.start(2), raw))
    return tuple(matches)


def _private_key_header(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    headers = tuple(
        f"-----BEGIN {key_type + ' ' if key_type != 'GENERIC' else ''}PRIVATE KEY-----"
        for key_type in rule.parameters["keyTypes"]
    )
    return _line_term_matches(rule, facts, headers)


def _nonliteral_call(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for function in rule.parameters["functions"]:
                pattern = re.compile(rf"(?<![A-Za-z0-9_.]){re.escape(function)}\s*\(([^)]*)\)")
                for found in pattern.finditer(line.text):
                    argument = found.group(1).lstrip()
                    if argument and not _starts_literal_string(argument):
                        matches.append(_match(file, line, found.start(), found.group(0)))
    return tuple(matches)


def _function_call(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for function in rule.parameters["functions"]:
                boundary = (
                    r"(?<![A-Za-z0-9_.])"
                    if rule.parameters.get("bareOnly")
                    else r"(?<![A-Za-z0-9_])"
                )
                pattern = re.compile(boundary + re.escape(function) + r"\s*\(")
                for found in pattern.finditer(line.text):
                    matches.append(_match(file, line, found.start(), line.text))
    return tuple(matches)


def _subprocess_shell_true(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    pattern = re.compile(
        r"subprocess\.(?:run|Popen|call|check_call|check_output)\s*" r"\([^)]*\bshell\s*=\s*True"
    )
    return _pattern_matches(rule, facts, pattern)


def _base64_class(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    expected = rule.parameters["classification"]
    malicious = rules.vocabularies[rule.parameters["maliciousVocabulary"]]
    minimum = rule.parameters["minimumLength"]
    skip_prefixes = rule.parameters["skipLinePrefixes"]
    skip_basenames = rule.parameters["skipBasenames"]
    skip_fields = rule.parameters["skipFieldNames"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        if PurePosixPath(file.entry.path).name in skip_basenames:
            continue
        for line in file.lines:
            stripped = line.text.lstrip()
            if any(stripped.startswith(prefix) for prefix in skip_prefixes):
                continue
            if any(field in line.text for field in skip_fields):
                continue
            for candidate in line.base64:
                if len(candidate.raw) < minimum:
                    continue
                if candidate.decoded_text is None:
                    classification = "binary"
                elif any(term in candidate.decoded_text for term in malicious):
                    classification = "suspicious_text"
                else:
                    classification = "plain_text"
                if classification == expected:
                    matches.append(
                        _match(
                            file,
                            line,
                            candidate.column - 1,
                            candidate.raw,
                            classification=classification,
                        )
                    )
    return tuple(matches)


def _hex_escape_run(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    count = rule.parameters["minimumCount"]
    return _pattern_matches(rule, facts, re.compile(rf"(?:\\x[0-9A-Fa-f]{{2}}){{{count},}}"))


def _chr_chain(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    minimum = rule.parameters["minimumCount"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            calls = tuple(re.finditer(r"\bchr\s*\([^)]*\)", line.text))
            for start in range(0, len(calls) - minimum + 1):
                selected = calls[start : start + minimum]
                span = line.text[selected[0].start() : selected[-1].end()]
                if span.count("+") >= minimum - 1:
                    matches.append(_match(file, line, selected[0].start(), span))
                    break
    return tuple(matches)


def _slice_reverse(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    return _pattern_matches(rule, facts, re.compile(r"\[\s*::\s*-1\s*\]"))


def _js_reverse(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    pattern = re.compile(r"\.split\s*\([^)]*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\([^)]*\)")
    return _pattern_matches(rule, facts, pattern)


def _from_char_code(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    minimum = rule.parameters["minimumArguments"]
    matches: list[Match] = []
    pattern = re.compile(r"String\.fromCharCode\s*\(([^)]*)\)")
    for file in _files(rule, facts):
        for line in file.lines:
            for found in pattern.finditer(line.text):
                arguments = [item for item in found.group(1).split(",") if item.strip()]
                if len(arguments) >= minimum:
                    matches.append(_match(file, line, found.start(), found.group(0)))
    return tuple(matches)


def _atob_long(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    minimum = rule.parameters["minimumLength"]
    pattern = re.compile(r"\batob\s*\(\s*(['\"])([A-Za-z0-9+/=]+)\1\s*\)")
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for found in pattern.finditer(line.text):
                if len(found.group(2)) >= minimum:
                    matches.append(_match(file, line, found.start(), found.group(0)))
    return tuple(matches)


def _hidden_characters(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    characters = {chr(int(value, 16)) for value in rule.parameters["codePoints"]}
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for hidden in line.hidden:
                if hidden.character in characters:
                    matches.append(
                        _match(
                            file,
                            line,
                            hidden.column - 1,
                            hidden.character,
                            code_point=f"U+{ord(hidden.character):04X}",
                        )
                    )
    return tuple(matches)


def _unicode_escape(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    return _line_term_matches(rule, facts, rule.parameters["escapes"])


def _entropy(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    minimum = rule.parameters["minimumLength"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        path = PurePosixPath(file.entry.path)
        if path.name in rule.parameters["skipBasenames"]:
            continue
        elevated = path.suffix.removeprefix(".") in rule.parameters["elevatedExtensions"]
        for line in file.lines:
            stripped = line.text.lstrip()
            if len(line.text) < minimum:
                continue
            if stripped.startswith(rule.parameters["dataPrefix"]):
                continue
            if any(stripped.startswith(prefix) for prefix in rule.parameters["commentPrefixes"]):
                continue
            threshold = (
                rule.parameters["elevatedThreshold"]
                if elevated or line.has_cjk
                else rule.parameters["threshold"]
            )
            if line.entropy > threshold:
                matches.append(
                    _match(
                        file,
                        line,
                        0,
                        line.text,
                        length=len(line.text),
                        entropy=round(line.entropy, 6),
                        threshold=float(threshold),
                    )
                )
    return tuple(matches)


def _line_sequence(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    segments = rule.parameters["segments"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            cursor = 0
            first = -1
            for segment in segments:
                index = line.text.find(segment, cursor)
                if index < 0:
                    break
                if first < 0:
                    first = index
                cursor = index + len(segment)
            else:
                matches.append(_match(file, line, first, line.text))
    return tuple(matches)


def _line_groups(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    groups = rule.parameters["groups"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            positions = [_first_term(line.text, group) for group in groups]
            if all(position >= 0 for position in positions):
                matches.append(_match(file, line, positions[-1], line.text))
    return tuple(matches)


def _file_groups(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    groups = rule.parameters["groups"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        if not all(_file_has_group(file, group) for group in groups[:-1]):
            continue
        matches.extend(_group_anchors(file, groups[-1]))
    return tuple(matches)


def _package_groups(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    files = _files(rule, facts)
    groups = rule.parameters["groups"]
    if not all(any(_file_has_group(file, group) for file in files) for group in groups[:-1]):
        return ()
    return tuple(match for file in files for match in _group_anchors(file, groups[-1]))


def _command_token(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    terms = "|".join(re.escape(term) for term in rule.parameters["terms"])
    pattern = re.compile(rf"(?<![A-Za-z0-9_-])(?:{terms})(?=\s|$|[;&|])")
    return _pattern_matches(rule, facts, pattern)


def _filename_double_extension(
    rule: CompiledRule,
    _facts: FactIndex,
    package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    executables = {
        value.lower() for value in rules.vocabularies[rule.parameters["executableVocabulary"]]
    }
    matches: list[Match] = []
    for path in package.filenames:
        suffixes = PurePosixPath(path).suffixes
        if len(suffixes) >= 2 and suffixes[-1].lower() in executables:
            matches.append(Match(path, 0, path.rfind(suffixes[-2]) + 1, path))
    return tuple(matches)


def _filename_keywords(
    rule: CompiledRule,
    _facts: FactIndex,
    package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for path in package.filenames:
        name = PurePosixPath(path).name
        for term in rule.parameters["terms"]:
            if (index := name.find(term)) >= 0:
                matches.append(Match(path, 0, index + 1, name))
    return tuple(matches)


def _url_keywords(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for url in line.urls:
                if any(term in url.raw for term in rule.parameters["terms"]):
                    matches.append(Match(file.entry.path, line.number, url.column, url.raw))
    return tuple(matches)


def _support_content(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    matches = list(_line_term_matches(rule, facts, rule.parameters["terms"]))
    if rule.parameters["phonePattern"]:
        phone = re.compile(r"\bcall\s+1-\d{3}-\d{3}-\d{4}\b")
        matches.extend(_pattern_matches(rule, facts, phone))
    return tuple(matches)


def _chmod_suid_mode(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    return _pattern_matches(rule, facts, re.compile(r"\bchmod\s+[42][0-7]{3}\b"))


def _package_command_keyword(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    command = rule.parameters["command"]
    actions = "|".join(re.escape(action) for action in rule.parameters["actions"])
    keywords = rules.vocabularies[rule.parameters["keywordVocabulary"]]
    pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(command)}\s+(?:{actions})\s+([^;&|]+)")
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for found in pattern.finditer(line.text):
                try:
                    arguments = shlex.split(found.group(1), posix=True)
                except ValueError:
                    arguments = found.group(1).split()
                candidates = _package_arguments(command, arguments)
                for candidate in candidates:
                    if any(keyword in candidate for keyword in keywords):
                        column = line.text.find(candidate, found.start(1))
                        matches.append(_match(file, line, column, line.text))
    if rule.parameters["includePackageJsonName"]:
        for file in _files(rule, facts):
            if PurePosixPath(file.entry.path).name != "package.json":
                continue
            parsed = _json_object(file.entry.text)
            name = parsed.get("name") if parsed is not None else None
            if isinstance(name, str) and any(keyword in name for keyword in keywords):
                matches.append(_match_from_text(file, name, name))
    return tuple(matches)


def _package_arguments(command: str, arguments: list[str]) -> list[str]:
    value_options = {
        "docker": {"--platform"},
        "gem": {"--install-dir", "--source", "--version", "-i", "-v"},
        "npm": {
            "--cache",
            "--prefix",
            "--registry",
            "--tag",
            "--userconfig",
            "--workspace",
            "-w",
        },
        "pip": {
            "--abi",
            "--constraint",
            "--extra-index-url",
            "--find-links",
            "--implementation",
            "--index-url",
            "--platform",
            "--prefix",
            "--proxy",
            "--python-version",
            "--requirement",
            "--root",
            "--src",
            "--target",
            "--trusted-host",
            "-c",
            "-f",
            "-i",
            "-r",
            "-t",
        },
    }.get(command, set())
    packages: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            packages.extend(arguments[index + 1 :])
            break
        option = argument.split("=", 1)[0]
        if argument.startswith("-"):
            index += 2 if option in value_options and "=" not in argument else 1
            continue
        packages.append(argument)
        index += 1
    return packages


def _docker_nonofficial(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    pattern = re.compile(r"(?<![A-Za-z0-9_-])docker\s+pull\s+([^\s;&|]+)")
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for found in pattern.finditer(line.text):
                image = found.group(1)
                first = image.split("/", 1)[0].lower()
                is_registry = "/" in image and (
                    "." in first or ":" in first or first == "localhost"
                )
                if is_registry and first not in {"docker.io", "index.docker.io"}:
                    matches.append(_match(file, line, found.start(1), line.text))
    return tuple(matches)


def _pip_index(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    pattern = re.compile(
        r"(?<![A-Za-z0-9_-])pip\s+install\b[^\n]*" r"(?:--extra-index-url|--index-url)\b"
    )
    return _pattern_matches(rule, facts, pattern)


def _package_json_hooks(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    hooks = rules.vocabularies[rule.parameters["hooksVocabulary"]]
    suspicious = rules.vocabularies[rule.parameters["suspiciousVocabulary"]]
    mode = rule.parameters["mode"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        if PurePosixPath(file.entry.path).name != "package.json":
            continue
        parsed = _json_object(file.entry.text)
        scripts = parsed.get("scripts") if parsed is not None else None
        if not isinstance(scripts, dict):
            continue
        for hook in hooks:
            value = scripts.get(hook)
            if not isinstance(value, str):
                continue
            if mode == "hook_presence" or any(term in value for term in suspicious):
                matches.append(_match_from_text(file, hook, value))
    return tuple(matches)


def _setup_cmdclass(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    _rules: RuleSet,
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for file in _files(rule, facts):
        if PurePosixPath(file.entry.path).name == "setup.py":
            matches.extend(_line_term_matches(rule, FactIndex((file,)), ("cmdclass",)))
    return tuple(matches)


def _url_ioc(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    tlds = tuple(item.lower() for item in rules.vocabularies[rule.parameters["tldVocabulary"]])
    keywords = rules.vocabularies[rule.parameters["keywordVocabulary"]]
    executables = tuple(
        item.lower() for item in rules.vocabularies[rule.parameters["executableVocabulary"]]
    )
    condition = rule.parameters["condition"]
    require_executable = rule.parameters["requireExecutable"]
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for url in line.urls:
                condition_met = (
                    url.hostname.endswith(tlds)
                    if condition == "suspicious_tld"
                    else any(keyword in url.hostname for keyword in keywords)
                )
                executable = url.path.lower().endswith(executables)
                if condition_met and (executable or not require_executable):
                    matches.append(Match(file.entry.path, line.number, url.column, url.raw))
    return tuple(matches)


def _standalone_domain_tld(
    rule: CompiledRule,
    facts: FactIndex,
    _package: PackageContent,
    rules: RuleSet,
) -> tuple[Match, ...]:
    endings = [
        re.escape(item.removeprefix("."))
        for item in rules.vocabularies[rule.parameters["tldVocabulary"]]
    ]
    pattern = re.compile(
        rf"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+(?:{'|'.join(endings)})\b",
        re.IGNORECASE,
    )
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            url_spans = [(url.column - 1, url.column - 1 + len(url.raw)) for url in line.urls]
            for found in pattern.finditer(line.text):
                if any(found.start() < end and found.end() > start for start, end in url_spans):
                    continue
                matches.append(_match(file, line, found.start(), found.group(0)))
    return tuple(matches)


def _json_object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _match_from_text(file: FileFacts, needle: str, raw: str) -> Match:
    offset = file.entry.text.find(needle)
    if offset < 0:
        return Match(file.entry.path, 1, 1, raw)
    before = file.entry.text[:offset]
    return Match(
        file.entry.path,
        before.count("\n") + 1,
        offset - before.rfind("\n"),
        raw,
    )


def _first_term(text: str, terms: tuple[str, ...]) -> int:
    positions = [index for term in terms if (index := text.find(term)) >= 0]
    return min(positions, default=-1)


def _file_has_group(file: FileFacts, terms: tuple[str, ...]) -> bool:
    return any(_first_term(line.text, terms) >= 0 for line in file.lines)


def _group_anchors(file: FileFacts, terms: tuple[str, ...]) -> tuple[Match, ...]:
    anchors: list[Match] = []
    for line in file.lines:
        if (index := _first_term(line.text, terms)) >= 0:
            anchors.append(_match(file, line, index, line.text))
    return tuple(anchors)


def _pattern_matches(
    rule: CompiledRule,
    facts: FactIndex,
    pattern: re.Pattern[str],
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for found in pattern.finditer(line.text):
                matches.append(_match(file, line, found.start(), line.text))
    return tuple(matches)


def _line_term_matches(
    rule: CompiledRule,
    facts: FactIndex,
    terms: tuple[str, ...],
) -> tuple[Match, ...]:
    matches: list[Match] = []
    for file in _files(rule, facts):
        for line in file.lines:
            for term in terms:
                start = 0
                while (index := line.text.find(term, start)) >= 0:
                    matches.append(_match(file, line, index, line.text))
                    start = index + max(1, len(term))
    return tuple(matches)


def _terms(rule: CompiledRule, rules: RuleSet) -> tuple[str, ...]:
    vocabulary = rule.parameters.get("vocabulary")
    if vocabulary is not None:
        return rules.vocabularies[vocabulary]
    return rule.parameters["terms"]


def _files(rule: CompiledRule, facts: FactIndex) -> tuple[FileFacts, ...]:
    return tuple(file for file in facts.files if _applies(rule, file.entry.path))


def _applies(rule: CompiledRule, path: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in rule.skip_extensions:
        return False
    return not rule.only_paths or path in rule.only_paths


def _match(
    file: FileFacts,
    line: LineFact,
    zero_based_column: int,
    raw: str,
    **details: Any,
) -> Match:
    return Match(
        file.entry.path,
        line.number,
        zero_based_column + 1,
        raw,
        MappingProxyType(details),
    )


def _starts_literal_string(argument: str) -> bool:
    return bool(re.match(r"(?i:(?:r|u|b|br|rb)?)(?:'|\")", argument))


_MATCHERS: dict[str, Matcher] = {
    "literal_any": _literal_any,
    "prefixed_token": _prefixed_token,
    "field_value": _field_value,
    "private_key_header": _private_key_header,
    "nonliteral_call": _nonliteral_call,
    "function_call": _function_call,
    "subprocess_shell_true": _subprocess_shell_true,
    "base64_class": _base64_class,
    "hex_escape_run": _hex_escape_run,
    "chr_chain": _chr_chain,
    "slice_reverse": _slice_reverse,
    "js_reverse": _js_reverse,
    "from_char_code": _from_char_code,
    "atob_long": _atob_long,
    "hidden_characters": _hidden_characters,
    "unicode_escape": _unicode_escape,
    "entropy": _entropy,
    "line_sequence": _line_sequence,
    "file_groups": _file_groups,
    "package_groups": _package_groups,
    "line_groups": _line_groups,
    "command_token": _command_token,
    "filename_double_extension": _filename_double_extension,
    "filename_keywords": _filename_keywords,
    "url_keywords": _url_keywords,
    "support_content": _support_content,
    "package_command_keyword": _package_command_keyword,
    "docker_nonofficial": _docker_nonofficial,
    "pip_index": _pip_index,
    "package_json_hooks": _package_json_hooks,
    "setup_cmdclass": _setup_cmdclass,
    "url_ioc": _url_ioc,
    "standalone_domain_tld": _standalone_domain_tld,
    "chmod_suid_mode": _chmod_suid_mode,
}
