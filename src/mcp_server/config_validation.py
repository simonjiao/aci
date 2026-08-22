from __future__ import annotations

import re
from urllib.parse import urlsplit

_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}")


def is_environment_name(value: str) -> bool:
    return _ENVIRONMENT_NAME.fullmatch(value) is not None


def is_root_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path in {"", "/"}
        and (port is None or port > 0)
    )
