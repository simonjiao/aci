from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"'`]+")
_BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{50,}={0,2}(?![A-Za-z0-9+/=])")
_TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_URL_TRAILING = ".,;:!?)]}"


@dataclass(frozen=True, slots=True)
class TextEntry:
    path: str
    text: str
    declared_size: int
    sampled_size: int


@dataclass(frozen=True, slots=True)
class UrlFact:
    raw: str
    column: int
    hostname: str
    path: str


@dataclass(frozen=True, slots=True)
class Base64Fact:
    raw: str
    column: int
    decoded_text: str | None


@dataclass(frozen=True, slots=True)
class HiddenFact:
    character: str
    column: int


@dataclass(frozen=True, slots=True)
class LineFact:
    number: int
    text: str
    tokens: tuple[str, ...]
    urls: tuple[UrlFact, ...]
    base64: tuple[Base64Fact, ...]
    entropy: float
    has_cjk: bool
    hidden: tuple[HiddenFact, ...]


@dataclass(frozen=True, slots=True)
class FileFacts:
    entry: TextEntry
    lines: tuple[LineFact, ...]


@dataclass(frozen=True, slots=True)
class FactIndex:
    files: tuple[FileFacts, ...]


def build_fact_index(entries: tuple[TextEntry, ...]) -> FactIndex:
    return FactIndex(tuple(FileFacts(entry, _lines(entry.text)) for entry in entries))


def _lines(text: str) -> tuple[LineFact, ...]:
    return tuple(_line(index, value) for index, value in enumerate(text.splitlines(), 1))


def _line(number: int, text: str) -> LineFact:
    return LineFact(
        number=number,
        text=text,
        tokens=tuple(match.group(0) for match in _TOKEN_PATTERN.finditer(text)),
        urls=_urls(text),
        base64=_base64_candidates(text),
        entropy=shannon_entropy(text),
        has_cjk=any("\u4e00" <= character <= "\u9fff" for character in text),
        hidden=tuple(
            HiddenFact(character, index)
            for index, character in enumerate(text, 1)
            if character in _ALL_HIDDEN_CHARACTERS
        ),
    )


def _urls(text: str) -> tuple[UrlFact, ...]:
    facts: list[UrlFact] = []
    for match in _URL_PATTERN.finditer(text):
        raw = match.group(0).rstrip(_URL_TRAILING)
        try:
            parsed = urlsplit(raw)
            hostname = parsed.hostname or ""
        except ValueError:
            hostname = ""
            parsed = urlsplit("")
        facts.append(UrlFact(raw, match.start() + 1, hostname.lower(), parsed.path))
    return tuple(facts)


def _base64_candidates(text: str) -> tuple[Base64Fact, ...]:
    facts: list[Base64Fact] = []
    for match in _BASE64_PATTERN.finditer(text):
        raw = match.group(0)
        padded = raw + "=" * (-len(raw) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = None
        facts.append(Base64Fact(raw, match.start() + 1, decoded_text))
    return tuple(facts)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    return -sum(count / length * math.log2(count / length) for count in Counter(text).values())


SUPPORTED_HIDDEN_CODE_POINTS = frozenset(
    {
        "00AD",
        "200B",
        "200C",
        "200D",
        "200E",
        "200F",
        "202A",
        "202B",
        "202C",
        "202D",
        "202E",
        "2060",
        "2063",
        "2066",
        "2067",
        "2068",
        "2069",
        "FEFF",
    }
)
_ALL_HIDDEN_CHARACTERS = frozenset(
    chr(int(code_point, 16)) for code_point in SUPPORTED_HIDDEN_CODE_POINTS
)
