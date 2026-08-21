from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal, Never, Protocol, cast

from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, ValidationError

from .config import ConfigError, HttpSettings, ServerConfig, load_config
from .server import create_server

_NAMESPACE_VALUES = cast(Callable[[object], dict[str, object]], vars)


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> Never:
        raise _UsageError("MCP 启动参数无效")


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    config: str


class _HttpServer(Protocol):
    def run(
        self,
        transport: Literal["streamable-http"],
        *,
        host: str,
        port: int,
        streamable_http_path: str,
        json_response: bool,
        stateless_http: bool,
        max_request_body_size: int,
        transport_security: TransportSecuritySettings,
    ) -> None: ...


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parse_arguments(argv)
    except _UsageError as error:
        _write_error(str(error))
        return 2
    try:
        config = load_config(Path(arguments.config))
    except ConfigError as error:
        _write_error(str(error))
        return 2
    succeeded = False
    try:
        _serve(config)
        succeeded = True
    except KeyboardInterrupt:
        return 0
    except Exception:
        pass
    if not succeeded:
        _write_error("MCP 服务启动失败")
        return 3
    return 0


def _parse_arguments(argv: Sequence[str] | None) -> _Arguments:
    parser = _Parser(prog="skillqa-mcp")
    parser.add_argument("--config", required=True)
    try:
        namespace = parser.parse_args(argv)
        return _Arguments.model_validate(_NAMESPACE_VALUES(namespace), strict=True)
    except ValidationError:
        pass
    raise _UsageError("MCP 启动参数无效")


def _serve(config: ServerConfig) -> None:
    server = create_server(
        config.security_adapter,
        max_package_bytes=config.max_package_bytes,
    )
    settings = config.http
    runnable = cast(_HttpServer, server)
    runnable.run(
        "streamable-http",
        host=settings.host,
        port=settings.port,
        streamable_http_path=settings.path,
        json_response=True,
        stateless_http=True,
        max_request_body_size=settings.max_request_body_bytes,
        transport_security=_transport_security(settings),
    )


def _transport_security(settings: HttpSettings) -> TransportSecuritySettings:
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(settings.allowed_hosts),
        allowed_origins=list(settings.allowed_origins),
    )


def _write_error(message: str) -> None:
    sys.stderr.write(message + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
