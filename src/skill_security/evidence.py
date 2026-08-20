from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import CompiledRule, MatchDetails

_MAX_EVIDENCE_LENGTH = 160
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"(?P<prefix>(?P<quote>['\"]?)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P=quote)\s*[:=]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
)
_OPTION_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"
    r"(?P<prefix>--?(?P<key>[A-Za-z][A-Za-z0-9_-]*)(?:\s+|=))"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&|]+)"
)


@dataclass(frozen=True, slots=True)
class ProcessedEvidence:
    display: str
    fingerprint: str


def process_evidence(
    rule: CompiledRule,
    raw: str,
    line: int,
    column: int,
    details: MatchDetails,
) -> ProcessedEvidence:
    cleaned = _display(rule, raw, details)
    structure = {
        "category": rule.evidence.type,
        "column": column,
        "details": details.values(),
        "length": len(raw),
        "line": line,
    }
    encoded = json.dumps(structure, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return ProcessedEvidence(cleaned, hashlib.sha256(encoded).hexdigest())


def _display(rule: CompiledRule, raw: str, details: MatchDetails) -> str:
    evidence_type = rule.evidence.type
    if evidence_type in {"secret", "private_key", "token"}:
        visible_length = min(rule.evidence.prefix_length, max(0, len(raw) - 1))
        prefix = raw[:visible_length]
        shown = f"{prefix}… " if prefix else ""
        return f"{shown}[REDACTED; length={len(raw)}]"
    if evidence_type == "username":
        visible_length = min(rule.evidence.prefix_length, max(0, len(raw) - 1))
        prefix = raw[:visible_length]
        return f"{prefix}*** [length={len(raw)}]"
    if evidence_type == "base64":
        if details.classification is None:
            raise ValueError("base64 evidence details are incomplete")
        return f"Base64 [length={len(raw)}; classification={details.classification}]"
    if evidence_type == "entropy":
        length = details.length
        entropy = details.entropy
        threshold = details.threshold
        if length is None or entropy is None or threshold is None:
            raise ValueError("entropy evidence details are incomplete")
        return (
            f"high-entropy text [length={length}; entropy={entropy:.3f}; threshold={threshold:.3f}]"
        )
    if evidence_type == "hidden":
        if details.code_point is None:
            raise ValueError("hidden-character evidence details are incomplete")
        return f"hidden character [{details.code_point}]"
    if evidence_type == "url":
        return _redact_url(raw)[:_MAX_EVIDENCE_LENGTH]
    cleaned = raw.replace("\r", " ").replace("\n", " ")
    return _redact_inline_secrets(cleaned)[:_MAX_EVIDENCE_LENGTH]


def _redact_url(raw: str) -> str:
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        userinfo = "[REDACTED]@" if parsed.username or parsed.password else ""
        netloc = f"{userinfo}{hostname}{port}"
        query = urlencode(
            [
                (key, "[REDACTED]" if _sensitive_parameter(key) else value)
                for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        fragment_pairs = parse_qsl(parsed.fragment, keep_blank_values=True)
        fragment = (
            urlencode(
                [
                    (key, "[REDACTED]" if _sensitive_parameter(key) else value)
                    for key, value in fragment_pairs
                ]
            )
            if fragment_pairs
            else parsed.fragment
        )
        return _redact_inline_secrets(
            urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment)),
            redact_assignments=False,
        )
    except ValueError:
        return "[URL REDACTED]"


def _sensitive_parameter(name: str) -> bool:
    normalized = name.lower().replace("-", "_").replace(".", "_")
    exact = {
        "api_key",
        "auth",
        "credential",
        "key",
        "pass",
        "password",
        "passwd",
        "secret",
        "session",
        "sessionid",
        "sig",
        "signature",
        "token",
    }
    suffixes = (
        "_auth",
        "_credential",
        "_key",
        "_pass",
        "_passwd",
        "_password",
        "_secret",
        "_session",
        "_sessionid",
        "_sig",
        "_signature",
        "_token",
    )
    return normalized in exact or normalized.endswith(suffixes)


def _redact_inline_secrets(text: str, *, redact_assignments: bool = True) -> str:
    value = re.sub(
        r"(?i)(\bAuthorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        text,
    )
    value = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA…[REDACTED]", value)
    value = re.sub(r"sk-[A-Za-z0-9._-]+", "sk-…[REDACTED]", value)
    value = re.sub(
        r"(?:ghp_|gho_|github_pat_)[A-Za-z0-9._-]+",
        "github-token…[REDACTED]",
        value,
    )
    value = re.sub(r"xox[baprs]-[A-Za-z0-9._-]+", "slack-token…[REDACTED]", value)
    if not redact_assignments:
        return value
    value = _ASSIGNMENT_PATTERN.sub(_mask_sensitive_assignment, value)
    return _OPTION_PATTERN.sub(_mask_sensitive_assignment, value)


def _mask_sensitive_assignment(match: re.Match[str]) -> str:
    if not _sensitive_parameter(match.group("key")):
        return match.group(0)
    return f"{match.group('prefix')}[REDACTED]"


def finding_id(
    package_sha256: str,
    rule_id: str,
    entry_path: str,
    line: int,
    column: int,
    evidence_fingerprint: str,
) -> str:
    values = [package_sha256, rule_id, entry_path, line, column, evidence_fingerprint]
    encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
