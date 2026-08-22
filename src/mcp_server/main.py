from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from importlib import import_module
from pathlib import Path
from typing import Never, Protocol, cast

from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.types import ASGIApp

from .auth import StaticBearerAuth
from .config import ConfigError, HttpSettings, ServerConfig, load_config
from .http_security import HostOriginGuard
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


class _UvicornModule(Protocol):
    def run(
        self,
        app: ASGIApp,
        *,
        host: str,
        port: int,
        log_level: str,
    ) -> None: ...


_UVICORN = cast(_UvicornModule, import_module("uvicorn"))


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
        config.artifact_storage,
        max_package_bytes=config.max_package_bytes,
        scratch_directory=config.scratch_directory,
        max_result_bytes=config.max_result_bytes,
        public_base_url=config.http.public_base_url,
    )
    settings = config.http
    transport_security = _transport_security(settings)
    app = server.streamable_http_app(
        streamable_http_path=settings.path,
        json_response=True,
        stateless_http=True,
        max_request_body_size=settings.max_request_body_bytes,
        transport_security=transport_security,
        host=settings.host,
    )
    secured_app = HostOriginGuard(
        StaticBearerAuth(app, config.bearer_key),
        transport_security,
    )
    _UVICORN.run(
        secured_app,
        host=settings.host,
        port=settings.port,
        log_level="info",
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
