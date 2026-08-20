from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

_JSON_LOADS = cast(Callable[[str], object], json.loads)


def load_json_object(path: Path) -> dict[str, object]:
    return object_dict(_JSON_LOADS(path.read_text(encoding="utf-8")))


def object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("expected object")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise TypeError("expected string object keys")
    return cast(dict[str, object], raw)


def dict_field(values: Mapping[str, object], key: str) -> dict[str, object]:
    return object_dict(values[key])


def object_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError("expected array")
    return cast(list[object], value)


def list_field(values: Mapping[str, object], key: str) -> list[object]:
    return object_list(values[key])


def string_field(values: Mapping[str, object], key: str) -> str:
    value = values[key]
    if not isinstance(value, str):
        raise TypeError("expected string")
    return value


def string_list(value: object) -> list[str]:
    items = object_list(value)
    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise TypeError("expected string array")
        result.append(item)
    return result


def string_mapping(value: object) -> dict[str, str]:
    values = object_dict(value)
    result: dict[str, str] = {}
    for key, item in values.items():
        if not isinstance(item, str):
            raise TypeError("expected string values")
        result[key] = item
    return result
