from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any

from .facts import SUPPORTED_HIDDEN_CODE_POINTS
from .models import (
    CompiledRule,
    ErrorCode,
    EvidencePolicy,
    RuleSet,
    RuleStatus,
    ScanError,
    _new_rule_set,
    freeze_json,
)

_DOCUMENT_KEYS = {
    "schemaVersion",
    "ruleVersion",
    "sourceVersion",
    "defaultSkipDirectories",
    "textExtensions",
    "vocabularies",
    "rules",
}
_RULE_KEYS = {
    "id",
    "detector",
    "name",
    "sourceDescription",
    "severity",
    "status",
    "scope",
    "match",
    "evidence",
    "remediation",
    "sourceLimitations",
    "skipExtensions",
    "onlyPaths",
}
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "HIGH/CRITICAL", "MEDIUM/HIGH"}
_SCOPES = {"filename", "line", "file", "package"}
_MATCH_TYPES = {
    "atob_long",
    "base64_class",
    "chmod_suid_mode",
    "chr_chain",
    "command_token",
    "docker_nonofficial",
    "entropy",
    "external_intelligence",
    "field_value",
    "file_groups",
    "filename_double_extension",
    "filename_keywords",
    "from_char_code",
    "function_call",
    "hex_escape_run",
    "hidden_characters",
    "js_reverse",
    "line_groups",
    "line_sequence",
    "literal_any",
    "nonliteral_call",
    "package_command_keyword",
    "package_groups",
    "package_json_hooks",
    "pip_index",
    "prefixed_token",
    "private_key_header",
    "setup_cmdclass",
    "slice_reverse",
    "standalone_domain_tld",
    "subprocess_shell_true",
    "support_content",
    "unicode_escape",
    "url_ioc",
    "url_keywords",
}
_MATCH_FIELDS: dict[str, tuple[set[str], set[str]]] = {
    "literal_any": (set(), {"terms", "vocabulary"}),
    "prefixed_token": (
        {"prefixes", "minimumLength", "alphabet"},
        {"maximumLength"},
    ),
    "field_value": (
        {"fields", "separators", "minimumValueLength", "alphabet"},
        set(),
    ),
    "private_key_header": ({"keyTypes"}, set()),
    "nonliteral_call": ({"functions"}, set()),
    "function_call": ({"functions"}, {"bareOnly"}),
    "subprocess_shell_true": (set(), set()),
    "base64_class": (
        {
            "classification",
            "minimumLength",
            "maliciousVocabulary",
            "skipLinePrefixes",
            "skipBasenames",
            "skipFieldNames",
        },
        set(),
    ),
    "hex_escape_run": ({"minimumCount"}, set()),
    "chr_chain": ({"minimumCount"}, set()),
    "slice_reverse": (set(), set()),
    "js_reverse": (set(), set()),
    "from_char_code": ({"minimumArguments"}, set()),
    "atob_long": ({"minimumLength"}, set()),
    "hidden_characters": ({"codePoints"}, set()),
    "unicode_escape": ({"escapes"}, set()),
    "entropy": (
        {
            "minimumLength",
            "threshold",
            "elevatedThreshold",
            "elevatedExtensions",
            "commentPrefixes",
            "dataPrefix",
            "skipBasenames",
        },
        set(),
    ),
    "line_sequence": ({"segments"}, set()),
    "file_groups": ({"groups"}, set()),
    "package_groups": ({"groups"}, set()),
    "line_groups": ({"groups"}, set()),
    "command_token": ({"terms"}, set()),
    "filename_double_extension": ({"executableVocabulary"}, set()),
    "filename_keywords": ({"terms"}, set()),
    "url_keywords": ({"terms"}, set()),
    "support_content": ({"terms", "phonePattern"}, set()),
    "package_command_keyword": (
        {"command", "actions", "keywordVocabulary", "includePackageJsonName"},
        set(),
    ),
    "docker_nonofficial": (set(), set()),
    "pip_index": (set(), set()),
    "package_json_hooks": (
        {"hooksVocabulary", "suspiciousVocabulary", "mode"},
        set(),
    ),
    "setup_cmdclass": (set(), set()),
    "url_ioc": (
        {
            "condition",
            "requireExecutable",
            "tldVocabulary",
            "keywordVocabulary",
            "executableVocabulary",
        },
        set(),
    ),
    "standalone_domain_tld": ({"tldVocabulary"}, set()),
    "chmod_suid_mode": (set(), set()),
    "external_intelligence": (set(), set()),
}
_LIST_PARAMETERS = {
    "actions",
    "codePoints",
    "commentPrefixes",
    "elevatedExtensions",
    "escapes",
    "fields",
    "functions",
    "keyTypes",
    "prefixes",
    "segments",
    "separators",
    "skipBasenames",
    "skipFieldNames",
    "skipLinePrefixes",
    "terms",
}
_EMPTY_LIST_PARAMETERS = {
    "commentPrefixes",
    "elevatedExtensions",
    "skipBasenames",
    "skipFieldNames",
    "skipLinePrefixes",
}
_INTEGER_PARAMETERS = {
    "maximumLength",
    "minimumArguments",
    "minimumCount",
    "minimumLength",
    "minimumValueLength",
}
_NUMBER_PARAMETERS = {"threshold", "elevatedThreshold"}
_BOOLEAN_PARAMETERS = {
    "bareOnly",
    "includePackageJsonName",
    "phonePattern",
    "requireExecutable",
}
_STRING_PARAMETERS = {
    "alphabet",
    "classification",
    "command",
    "condition",
    "dataPrefix",
    "executableVocabulary",
    "hooksVocabulary",
    "keywordVocabulary",
    "maliciousVocabulary",
    "mode",
    "suspiciousVocabulary",
    "tldVocabulary",
    "vocabulary",
}
_EVIDENCE_TYPES = {
    "base64",
    "command",
    "entropy",
    "filename",
    "hidden",
    "indicator",
    "private_key",
    "secret",
    "token",
    "url",
    "username",
}


def canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    _validate_json_value(document, "$", seen=set())
    try:
        text = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise _invalid("规则文档不是有效的 JSON 兼容对象") from exc
    return text.encode("utf-8")


def compile_rules(document: Mapping[str, Any]) -> RuleSet:
    if not isinstance(document, Mapping):
        raise _invalid("规则文档必须是对象")
    digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    _require_exact_keys(document, _DOCUMENT_KEYS, "规则文档")

    schema_version = _required_text(document, "schemaVersion", "规则文档")
    if schema_version != "1.0":
        raise _invalid("不支持的 schemaVersion")
    rule_version = _required_text(document, "ruleVersion", "规则文档")
    source_version = _required_text(document, "sourceVersion", "规则文档")
    skip_dirs = _text_list(document.get("defaultSkipDirectories"), "defaultSkipDirectories")
    text_extensions = _text_list(
        document.get("textExtensions"), "textExtensions", allow_empty=False
    )
    if any(value.startswith(".") for value in text_extensions):
        raise _invalid("textExtensions 中的扩展名不得包含点号")
    if any(
        value != value.lower() or not re.fullmatch(r"[a-z0-9]+", value) for value in text_extensions
    ):
        raise _invalid("textExtensions 必须使用小写字母或数字")

    raw_vocabularies = document.get("vocabularies")
    if not isinstance(raw_vocabularies, Mapping):
        raise _invalid("vocabularies 必须是对象")
    vocabularies: dict[str, tuple[str, ...]] = {}
    for name, values in raw_vocabularies.items():
        if not isinstance(name, str) or not name:
            raise _invalid("vocabularies 的名称必须是非空字符串")
        vocabularies[name] = _text_list(values, f"vocabularies.{name}", allow_empty=False)

    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise _invalid("rules 必须是非空数组")
    rules: list[CompiledRule] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule = _compile_rule(raw_rule, index, vocabularies)
        if rule.id in seen_ids:
            raise _invalid(f"规则 ID 重复：{rule.id}")
        seen_ids.add(rule.id)
        rules.append(rule)

    compiled = tuple(rules)
    return _new_rule_set(
        schema_version=schema_version,
        rule_version=rule_version,
        source_version=source_version,
        sha256=digest,
        default_skip_directories=skip_dirs,
        text_extensions=text_extensions,
        vocabularies=vocabularies,
        rules=compiled,
        execution_plan=tuple(rule for rule in compiled if rule.status is RuleStatus.APPROVED),
    )


def _compile_rule(
    raw_rule: Any,
    index: int,
    vocabularies: Mapping[str, tuple[str, ...]],
) -> CompiledRule:
    label = f"rules[{index}]"
    if not isinstance(raw_rule, Mapping):
        raise _invalid(f"{label} 必须是对象")
    required = _RULE_KEYS - {"skipExtensions", "onlyPaths"}
    actual = set(raw_rule)
    missing = required - actual
    extra = actual - _RULE_KEYS
    if missing or extra:
        raise _invalid(_key_error(label, missing, extra))

    rule_id = _required_text(raw_rule, "id", label)
    if not re.fullmatch(r"SEC-[A-Z0-9]+-[0-9]{2}", rule_id):
        raise _invalid(f"{label}.id 格式无效")
    severity = _required_text(raw_rule, "severity", label)
    if severity not in _SEVERITIES:
        raise _invalid(f"{label}.severity 无效")
    try:
        status = RuleStatus(_required_text(raw_rule, "status", label))
    except ValueError as exc:
        raise _invalid(f"{label}.status 无效") from exc
    scope = _required_text(raw_rule, "scope", label)
    if scope not in _SCOPES:
        raise _invalid(f"{label}.scope 无效")

    raw_match = raw_rule.get("match")
    if not isinstance(raw_match, Mapping):
        raise _invalid(f"{label}.match 必须是对象")
    match_type = _required_text(raw_match, "type", f"{label}.match")
    if match_type not in _MATCH_TYPES:
        raise _invalid(f"{label}.match.type 不受支持")
    if status is RuleStatus.APPROVED and match_type == "external_intelligence":
        raise _invalid(f"{label} 缺少可执行的本地检测能力")
    _validate_match(raw_match, match_type, scope, label)
    vocabulary_keys = (
        "vocabulary",
        "maliciousVocabulary",
        "keywordVocabulary",
        "hooksVocabulary",
        "suspiciousVocabulary",
        "executableVocabulary",
        "tldVocabulary",
    )
    for key in vocabulary_keys:
        vocabulary = raw_match.get(key)
        if vocabulary is not None and vocabulary not in vocabularies:
            raise _invalid(f"{label}.match.{key} 引用了不存在的公共词汇表")

    raw_evidence = raw_rule.get("evidence")
    if not isinstance(raw_evidence, Mapping):
        raise _invalid(f"{label}.evidence 必须是对象")
    _require_exact_keys(raw_evidence, {"type", "prefixLength"}, f"{label}.evidence")
    prefix_length = raw_evidence.get("prefixLength")
    if isinstance(prefix_length, bool) or not isinstance(prefix_length, int) or prefix_length < 0:
        raise _invalid(f"{label}.evidence.prefixLength 必须是非负整数")
    if prefix_length > 8:
        raise _invalid(f"{label}.evidence.prefixLength 不得超过 8")

    remediation = raw_rule.get("remediation")
    if remediation is not None and not isinstance(remediation, str):
        raise _invalid(f"{label}.remediation 必须是字符串或 null")

    evidence_type = _required_text(raw_evidence, "type", f"{label}.evidence")
    if evidence_type not in _EVIDENCE_TYPES:
        raise _invalid(f"{label}.evidence.type 无效")
    detailed_evidence_match = {
        "base64": "base64_class",
        "entropy": "entropy",
        "hidden": "hidden_characters",
    }.get(evidence_type)
    if detailed_evidence_match is not None and match_type != detailed_evidence_match:
        raise _invalid(f"{label}.evidence.type 与 match.type 不兼容")

    parameters = {key: value for key, value in raw_match.items() if key != "type"}
    return CompiledRule(
        id=rule_id,
        detector=_required_text(raw_rule, "detector", label),
        name=_required_text(raw_rule, "name", label),
        source_description=_required_text(raw_rule, "sourceDescription", label),
        severity=severity,
        status=status,
        scope=scope,
        match_type=match_type,
        parameters=freeze_json(parameters),
        evidence=EvidencePolicy(
            type=evidence_type,
            prefix_length=prefix_length,
        ),
        remediation=remediation,
        source_limitations=_text_list(
            raw_rule.get("sourceLimitations"), f"{label}.sourceLimitations"
        ),
        skip_extensions=_text_list(raw_rule.get("skipExtensions", []), f"{label}.skipExtensions"),
        only_paths=_text_list(raw_rule.get("onlyPaths", []), f"{label}.onlyPaths"),
    )


def _validate_json_value(value: Any, path: str, seen: set[int]) -> None:
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _invalid(f"{path} 包含非有限数值")
        return
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in seen:
            raise _invalid(f"{path} 包含循环引用")
        seen.add(marker)
        for key, item in value.items():
            if not isinstance(key, str):
                raise _invalid(f"{path} 的对象键必须是字符串")
            _validate_json_value(item, f"{path}.{key}", seen)
        seen.remove(marker)
        return
    if isinstance(value, list):
        marker = id(value)
        if marker in seen:
            raise _invalid(f"{path} 包含循环引用")
        seen.add(marker)
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]", seen)
        seen.remove(marker)
        return
    raise _invalid(f"{path} 包含非 JSON 类型")


def _required_text(values: Mapping[str, Any], key: str, label: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise _invalid(f"{label}.{key} 必须是非空字符串")
    return value


def _text_list(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _invalid(f"{label} 必须是字符串数组")
    if not allow_empty and not value:
        raise _invalid(f"{label} 不得为空")
    if any(not isinstance(item, str) or not item for item in value):
        raise _invalid(f"{label} 必须只包含非空字符串")
    if len(value) != len(set(value)):
        raise _invalid(f"{label} 不得包含重复值")
    return tuple(value)


def _validate_match(
    raw_match: Mapping[str, Any],
    match_type: str,
    scope: str,
    label: str,
) -> None:
    required, optional = _MATCH_FIELDS[match_type]
    actual = set(raw_match) - {"type"}
    missing = required - actual
    extra = actual - required - optional
    if missing or extra:
        raise _invalid(_key_error(f"{label}.match", missing, extra))
    if match_type == "literal_any" and ("terms" in actual) == ("vocabulary" in actual):
        raise _invalid(f"{label}.match 必须且只能提供 terms 或 vocabulary")

    for key in actual & _LIST_PARAMETERS:
        _text_list(
            raw_match[key],
            f"{label}.match.{key}",
            allow_empty=key in _EMPTY_LIST_PARAMETERS,
        )
    if "groups" in actual:
        groups = raw_match["groups"]
        if not isinstance(groups, list) or len(groups) < 2:
            raise _invalid(f"{label}.match.groups 必须至少包含两个字符串数组")
        for index, group in enumerate(groups):
            _text_list(group, f"{label}.match.groups[{index}]", allow_empty=False)
    for key in actual & _INTEGER_PARAMETERS:
        value = raw_match[key]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise _invalid(f"{label}.match.{key} 必须是正整数")
    for key in actual & _NUMBER_PARAMETERS:
        value = raw_match[key]
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise _invalid(f"{label}.match.{key} 必须是非负有限数值")
        if not math.isfinite(value) or value < 0:
            raise _invalid(f"{label}.match.{key} 必须是非负有限数值")
    for key in actual & _BOOLEAN_PARAMETERS:
        if not isinstance(raw_match[key], bool):
            raise _invalid(f"{label}.match.{key} 必须是布尔值")
    for key in actual & _STRING_PARAMETERS:
        if not isinstance(raw_match[key], str) or not raw_match[key]:
            raise _invalid(f"{label}.match.{key} 必须是非空字符串")

    if raw_match.get("alphabet") not in {None, "token", "upper_alnum"}:
        raise _invalid(f"{label}.match.alphabet 无效")
    if match_type == "field_value" and raw_match["alphabet"] != "token":
        raise _invalid(f"{label}.match.alphabet 无效")
    if raw_match.get("classification") not in {
        None,
        "suspicious_text",
        "plain_text",
        "binary",
    }:
        raise _invalid(f"{label}.match.classification 无效")
    if raw_match.get("mode") not in {None, "hook_presence", "suspicious_command"}:
        raise _invalid(f"{label}.match.mode 无效")
    if raw_match.get("condition") not in {None, "suspicious_tld", "malicious_keyword"}:
        raise _invalid(f"{label}.match.condition 无效")
    if "maximumLength" in raw_match:
        if raw_match["maximumLength"] < raw_match.get("minimumLength", 1):
            raise _invalid(f"{label}.match.maximumLength 不得小于 minimumLength")
        if any(
            raw_match["maximumLength"] <= len(prefix) for prefix in raw_match.get("prefixes", [])
        ):
            raise _invalid(f"{label}.match.maximumLength 必须容纳前缀后的 Token 内容")
    if match_type == "base64_class" and raw_match["minimumLength"] < 50:
        raise _invalid(f"{label}.match.minimumLength 不得小于 50")
    if match_type == "hidden_characters" and any(
        not re.fullmatch(r"[0-9A-Fa-f]{4,6}", item)
        or item != item.upper()
        or int(item, 16) > 0x10FFFF
        or 0xD800 <= int(item, 16) <= 0xDFFF
        or item.upper() not in SUPPORTED_HIDDEN_CODE_POINTS
        for item in raw_match["codePoints"]
    ):
        raise _invalid(f"{label}.match.codePoints 包含不受支持的 Unicode 码点")

    expected_scope = {
        "file_groups": "file",
        "filename_double_extension": "filename",
        "filename_keywords": "filename",
        "package_groups": "package",
        "package_json_hooks": "file",
        "setup_cmdclass": "file",
    }.get(match_type, "line")
    if scope != expected_scope:
        raise _invalid(f"{label}.scope 与 {match_type} 不一致")


def _require_exact_keys(values: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(values)
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        raise _invalid(_key_error(label, missing, extra))


def _key_error(label: str, missing: set[str], extra: set[str]) -> str:
    parts = []
    if missing:
        parts.append("缺少 " + ", ".join(sorted(missing)))
    if extra:
        parts.append(f"包含 {len(extra)} 个未知字段")
    return f"{label} 字段无效：" + "；".join(parts)


def _invalid(message: str) -> ScanError:
    return ScanError(ErrorCode.RULESET_INVALID, message)
