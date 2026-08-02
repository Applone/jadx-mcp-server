"""OAuth configuration for the public MCP resource and the internal JADX plugin bridge.

The public FastMCP endpoint and the Java plugin are separate OAuth protected resources.
This module deliberately obtains a second, plugin-audience token for Java API calls
instead of forwarding the access token presented by an MCP client.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote_plus, urlparse

import httpx
from fastmcp.server.auth import JWTVerifier, OAuthProxy, RemoteAuthProvider, TokenVerifier
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier
from pydantic import AnyHttpUrl


READ_SCOPE = "jadx:read"
WRITE_SCOPE = "jadx:write"
DEBUG_SCOPE = "jadx:debug"
SUPPORTED_SCOPES = (READ_SCOPE, WRITE_SCOPE, DEBUG_SCOPE)
MCP_PATH = "/mcp"


class OAuthConfigurationError(ValueError):
    """Raised for unsafe or incomplete OAuth configuration."""


class PluginTokenError(RuntimeError):
    """Raised when the MCP server cannot obtain a plugin-audience access token."""


def _trimmed(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _required(env: Mapping[str, str], name: str) -> str:
    value = _trimmed(env.get(name))
    if value is None:
        raise OAuthConfigurationError(f"{name} is required for the selected OAuth mode")
    return value


def _boolean(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    value = _trimmed(env.get(name))
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise OAuthConfigurationError(f"{name} must be true or false")


def _csv(value: str | None, default: Sequence[str] = ()) -> tuple[str, ...]:
    if _trimmed(value) is None:
        return tuple(default)
    values = tuple(item.strip() for item in value.split(",") if item.strip())
    if not values:
        raise OAuthConfigurationError("OAuth scope and URL lists must not be empty")
    return values


def _validate_url(value: str, setting: str, allow_insecure_loopback: bool) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password:
        raise OAuthConfigurationError(f"{setting} must be an absolute HTTP(S) URL without user info")
    if parsed.query or parsed.fragment:
        raise OAuthConfigurationError(f"{setting} must not contain a query or fragment")
    if parsed.scheme == "https":
        return value
    if allow_insecure_loopback and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return value
    raise OAuthConfigurationError(f"{setting} must use HTTPS outside explicit loopback development")


def _parse_json_object(env: Mapping[str, str], name: str) -> dict[str, str] | None:
    raw = _trimmed(env.get(name))
    if raw is None:
        return None
    import json

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OAuthConfigurationError(f"{name} must be a JSON object") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()):
        raise OAuthConfigurationError(f"{name} must contain string keys and string values")
    return value


@dataclass(frozen=True)
class PublicOAuthSettings:
    """Settings for public FastMCP OAuth authentication."""

    mode: str = "disabled"
    base_url: str | None = None
    issuer: str | None = None
    authorization_servers: tuple[str, ...] = ()
    validation_mode: str = "jwt"
    jwks_uri: str | None = None
    audience: str | None = None
    jwt_algorithm: str = "RS256"
    introspection_url: str | None = None
    introspection_client_id: str | None = None
    introspection_client_secret: str | None = None
    introspection_client_auth_method: str = "client_secret_basic"
    upstream_authorization_endpoint: str | None = None
    upstream_token_endpoint: str | None = None
    upstream_revocation_endpoint: str | None = None
    upstream_client_id: str | None = None
    upstream_client_secret: str | None = None
    upstream_audience: str | None = None
    proxy_jwt_signing_key: str | None = None
    allowed_client_redirect_uris: tuple[str, ...] = ("http://localhost:*", "http://127.0.0.1:*")
    extra_authorize_params: dict[str, str] | None = None
    extra_token_params: dict[str, str] | None = None
    allow_insecure_loopback: bool = False

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "PublicOAuthSettings":
        env = os.environ if environ is None else environ
        mode = (_trimmed(env.get("JADX_MCP_OAUTH_MODE")) or "disabled").lower()
        if mode == "disabled":
            return cls()
        if mode not in {"remote", "proxy"}:
            raise OAuthConfigurationError("JADX_MCP_OAUTH_MODE must be disabled, remote, or proxy")

        allow_insecure_loopback = _boolean(env, "JADX_MCP_OAUTH_ALLOW_INSECURE_LOOPBACK", False)
        base_url = _validate_url(_required(env, "JADX_MCP_OAUTH_PUBLIC_BASE_URL"), "JADX_MCP_OAUTH_PUBLIC_BASE_URL", allow_insecure_loopback).rstrip("/")
        issuer = _validate_url(_required(env, "JADX_MCP_OAUTH_UPSTREAM_ISSUER"), "JADX_MCP_OAUTH_UPSTREAM_ISSUER", allow_insecure_loopback)
        validation_mode = (_trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_TOKEN_VALIDATION")) or "jwt").lower()
        if validation_mode not in {"jwt", "introspection"}:
            raise OAuthConfigurationError("JADX_MCP_OAUTH_PUBLIC_TOKEN_VALIDATION must be jwt or introspection")

        audience = _trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_AUDIENCE")) or f"{base_url}{MCP_PATH}"
        jwks_uri = _trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_JWKS_URI"))
        introspection_url = _trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_URL"))
        introspection_client_id = _trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_CLIENT_ID"))
        introspection_client_secret = _trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_CLIENT_SECRET"))
        if validation_mode == "jwt":
            jwks_uri = _validate_url(_required(env, "JADX_MCP_OAUTH_PUBLIC_JWKS_URI"), "JADX_MCP_OAUTH_PUBLIC_JWKS_URI", allow_insecure_loopback)
        else:
            introspection_url = _validate_url(_required(env, "JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_URL"), "JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_URL", allow_insecure_loopback)
            if introspection_client_id is None or introspection_client_secret is None:
                raise OAuthConfigurationError("public opaque-token validation requires introspection client credentials")

        authorization_servers = _csv(env.get("JADX_MCP_OAUTH_AUTHORIZATION_SERVERS"), (issuer,))
        authorization_servers = tuple(
            _validate_url(server, "JADX_MCP_OAUTH_AUTHORIZATION_SERVERS", allow_insecure_loopback)
            for server in authorization_servers
        )

        settings = cls(
            mode=mode,
            base_url=base_url,
            issuer=issuer,
            authorization_servers=authorization_servers,
            validation_mode=validation_mode,
            jwks_uri=jwks_uri,
            audience=audience,
            jwt_algorithm=_trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_JWT_ALGORITHM")) or "RS256",
            introspection_url=introspection_url,
            introspection_client_id=introspection_client_id,
            introspection_client_secret=introspection_client_secret,
            introspection_client_auth_method=_trimmed(env.get("JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_CLIENT_AUTH_METHOD")) or "client_secret_basic",
            upstream_authorization_endpoint=_trimmed(env.get("JADX_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT")),
            upstream_token_endpoint=_trimmed(env.get("JADX_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT")),
            upstream_revocation_endpoint=_trimmed(env.get("JADX_MCP_OAUTH_UPSTREAM_REVOCATION_ENDPOINT")),
            upstream_client_id=_trimmed(env.get("JADX_MCP_OAUTH_UPSTREAM_CLIENT_ID")),
            upstream_client_secret=_trimmed(env.get("JADX_MCP_OAUTH_UPSTREAM_CLIENT_SECRET")),
            upstream_audience=_trimmed(env.get("JADX_MCP_OAUTH_UPSTREAM_AUDIENCE")),
            proxy_jwt_signing_key=_trimmed(env.get("JADX_MCP_OAUTH_PROXY_JWT_SIGNING_KEY")),
            allowed_client_redirect_uris=_csv(env.get("JADX_MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS"), ("http://localhost:*", "http://127.0.0.1:*")),
            extra_authorize_params=_parse_json_object(env, "JADX_MCP_OAUTH_UPSTREAM_EXTRA_AUTHORIZE_PARAMS"),
            extra_token_params=_parse_json_object(env, "JADX_MCP_OAUTH_UPSTREAM_EXTRA_TOKEN_PARAMS"),
            allow_insecure_loopback=allow_insecure_loopback,
        )
        if mode == "proxy":
            required_proxy_settings = {
                "JADX_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT": settings.upstream_authorization_endpoint,
                "JADX_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT": settings.upstream_token_endpoint,
                "JADX_MCP_OAUTH_UPSTREAM_CLIENT_ID": settings.upstream_client_id,
                "JADX_MCP_OAUTH_UPSTREAM_CLIENT_SECRET": settings.upstream_client_secret,
                "JADX_MCP_OAUTH_UPSTREAM_AUDIENCE": settings.upstream_audience,
                "JADX_MCP_OAUTH_PROXY_JWT_SIGNING_KEY": settings.proxy_jwt_signing_key,
            }
            missing = [name for name, value in required_proxy_settings.items() if value is None]
            if missing:
                raise OAuthConfigurationError("OAuth proxy mode requires " + ", ".join(missing))
            _validate_url(settings.upstream_authorization_endpoint, "JADX_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT", allow_insecure_loopback)
            _validate_url(settings.upstream_token_endpoint, "JADX_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT", allow_insecure_loopback)
            if settings.upstream_revocation_endpoint:
                _validate_url(settings.upstream_revocation_endpoint, "JADX_MCP_OAUTH_UPSTREAM_REVOCATION_ENDPOINT", allow_insecure_loopback)
        return settings


@dataclass(frozen=True)
class PluginTokenSettings:
    """OAuth client-credentials configuration for the Python to Java bridge."""

    token_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    resource: str | None = None
    scopes: tuple[str, ...] = SUPPORTED_SCOPES
    client_auth_method: str = "client_secret_basic"
    send_resource_parameter: bool = True
    extra_token_params: dict[str, str] | None = None
    timeout_seconds: float = 10.0
    allow_insecure_loopback: bool = False

    @property
    def enabled(self) -> bool:
        return self.token_url is not None

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "PluginTokenSettings":
        env = os.environ if environ is None else environ
        token_url = _trimmed(env.get("JADX_PLUGIN_OAUTH_TOKEN_URL"))
        if token_url is None:
            return cls()
        allow_insecure_loopback = _boolean(env, "JADX_PLUGIN_OAUTH_ALLOW_INSECURE_LOOPBACK", False)
        token_url = _validate_url(token_url, "JADX_PLUGIN_OAUTH_TOKEN_URL", allow_insecure_loopback)
        client_id = _required(env, "JADX_PLUGIN_OAUTH_CLIENT_ID")
        client_secret = _required(env, "JADX_PLUGIN_OAUTH_CLIENT_SECRET")
        resource = _validate_url(_required(env, "JADX_PLUGIN_OAUTH_RESOURCE"), "JADX_PLUGIN_OAUTH_RESOURCE", allow_insecure_loopback)
        client_auth_method = _trimmed(env.get("JADX_PLUGIN_OAUTH_CLIENT_AUTH_METHOD")) or "client_secret_basic"
        if client_auth_method not in {"client_secret_basic", "client_secret_post"}:
            raise OAuthConfigurationError("JADX_PLUGIN_OAUTH_CLIENT_AUTH_METHOD must be client_secret_basic or client_secret_post")
        try:
            timeout_seconds = float(_trimmed(env.get("JADX_PLUGIN_OAUTH_TIMEOUT_SECONDS")) or "10")
        except ValueError as exc:
            raise OAuthConfigurationError("JADX_PLUGIN_OAUTH_TIMEOUT_SECONDS must be numeric") from exc
        if not 1 <= timeout_seconds <= 60:
            raise OAuthConfigurationError("JADX_PLUGIN_OAUTH_TIMEOUT_SECONDS must be between 1 and 60")
        return cls(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            resource=resource,
            scopes=_csv(env.get("JADX_PLUGIN_OAUTH_SCOPES"), SUPPORTED_SCOPES),
            client_auth_method=client_auth_method,
            send_resource_parameter=_boolean(env, "JADX_PLUGIN_OAUTH_SEND_RESOURCE_PARAMETER", True),
            extra_token_params=_parse_plugin_extra_token_params(env),
            timeout_seconds=timeout_seconds,
            allow_insecure_loopback=allow_insecure_loopback,
        )


def _parse_plugin_extra_token_params(env: Mapping[str, str]) -> dict[str, str] | None:
    params = _parse_json_object(env, "JADX_PLUGIN_OAUTH_EXTRA_TOKEN_PARAMS")
    if params is None:
        return None
    reserved = {"grant_type", "scope", "resource", "client_id", "client_secret"}
    conflicts = reserved.intersection(params)
    if conflicts:
        raise OAuthConfigurationError(
            "JADX_PLUGIN_OAUTH_EXTRA_TOKEN_PARAMS must not override " + ", ".join(sorted(conflicts))
        )
    return params


class PluginAccessTokenClient:
    """Caches a short-lived client-credentials token for the plugin resource."""

    def __init__(
        self,
        settings: PluginTokenSettings,
        http_client_factory: Callable[..., httpx.AsyncClient] = httpx.AsyncClient,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._http_client_factory = http_client_factory
        self._monotonic = monotonic
        self._lock = asyncio.Lock()
        self._access_token: str | None = None
        self._expires_at = 0.0

    @property
    def enabled(self) -> bool:
        return self._settings.enabled

    async def authorization_headers(self) -> dict[str, str]:
        if not self._settings.enabled:
            return {}
        async with self._lock:
            if self._access_token is None or self._monotonic() >= self._expires_at:
                await self._refresh()
            return {"Authorization": f"Bearer {self._access_token}"}

    async def _refresh(self) -> None:
        assert self._settings.token_url is not None
        assert self._settings.client_id is not None
        assert self._settings.client_secret is not None
        assert self._settings.resource is not None

        form: dict[str, str] = {
            "grant_type": "client_credentials",
            "scope": " ".join(self._settings.scopes),
        }
        if self._settings.send_resource_parameter:
            form["resource"] = self._settings.resource
        form.update(self._settings.extra_token_params or {})

        headers = {"Accept": "application/json"}
        if self._settings.client_auth_method == "client_secret_basic":
            credentials = f"{quote_plus(self._settings.client_id)}:{quote_plus(self._settings.client_secret)}"
            headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        else:
            form["client_id"] = self._settings.client_id
            form["client_secret"] = self._settings.client_secret

        try:
            async with self._http_client_factory(
                timeout=self._settings.timeout_seconds,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = await client.post(self._settings.token_url, data=form, headers=headers)
        except httpx.HTTPError as exc:
            raise PluginTokenError("Unable to reach the plugin authorization server") from exc

        if response.status_code < 200 or response.status_code > 299:
            raise PluginTokenError("Plugin authorization server rejected the client-credentials request")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PluginTokenError("Plugin authorization server returned an invalid token response") from exc
        if not isinstance(payload, dict):
            raise PluginTokenError("Plugin authorization server returned a non-object token response")

        token = payload.get("access_token")
        token_type = payload.get("token_type", "Bearer")
        if not isinstance(token, str) or not token or not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise PluginTokenError("Plugin authorization server did not return a bearer access token")
        expires_in = payload.get("expires_in", 60)
        if not isinstance(expires_in, (int, float)) or expires_in <= 0:
            raise PluginTokenError("Plugin authorization server returned an invalid token lifetime")

        self._access_token = token
        self._expires_at = self._monotonic() + max(0.0, float(expires_in) - 30.0)


class AudienceBoundIntrospectionVerifier(IntrospectionTokenVerifier):
    """Adds issuer and audience checks that generic RFC 7662 responses may omit."""

    def __init__(self, *, expected_issuer: str, expected_audience: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience

    async def verify_token(self, token: str):
        access_token = await super().verify_token(token)
        if access_token is None:
            return None
        claims = access_token.claims
        if claims.get("iss") != self._expected_issuer:
            return None
        audience = claims.get("aud")
        if isinstance(audience, str):
            audiences = {audience}
        elif isinstance(audience, list):
            audiences = {value for value in audience if isinstance(value, str)}
        else:
            return None
        return access_token if self._expected_audience in audiences else None


def build_public_auth(settings: PublicOAuthSettings):
    """Build the FastMCP auth provider selected by environment configuration."""
    if settings.mode == "disabled":
        return None
    verifier = _build_token_verifier(settings)
    assert settings.base_url is not None
    if settings.mode == "remote":
        return RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[AnyHttpUrl(server) for server in settings.authorization_servers],
            base_url=settings.base_url,
            scopes_supported=list(SUPPORTED_SCOPES),
            resource_name="JADX MCP Server",
        )
    if settings.mode == "proxy":
        assert settings.upstream_authorization_endpoint is not None
        assert settings.upstream_token_endpoint is not None
        assert settings.upstream_client_id is not None
        assert settings.upstream_client_secret is not None
        assert settings.upstream_audience is not None
        authorize_params = dict(settings.extra_authorize_params or {})
        token_params = dict(settings.extra_token_params or {})
        # RFC 8707 resource indicators preserve the upstream token audience. Providers
        # with non-standard names such as Auth0 audience can override this through the
        # explicit JSON parameter settings.
        authorize_params.setdefault("resource", settings.upstream_audience)
        token_params.setdefault("resource", settings.upstream_audience)
        return OAuthProxy(
            upstream_authorization_endpoint=settings.upstream_authorization_endpoint,
            upstream_token_endpoint=settings.upstream_token_endpoint,
            upstream_client_id=settings.upstream_client_id,
            upstream_client_secret=settings.upstream_client_secret,
            upstream_revocation_endpoint=settings.upstream_revocation_endpoint,
            token_verifier=verifier,
            base_url=settings.base_url,
            allowed_client_redirect_uris=list(settings.allowed_client_redirect_uris),
            valid_scopes=list(SUPPORTED_SCOPES),
            forward_pkce=True,
            jwt_signing_key=settings.proxy_jwt_signing_key,
            extra_authorize_params=authorize_params,
            extra_token_params=token_params,
        )
    raise OAuthConfigurationError("Unsupported OAuth mode")


def _build_token_verifier(settings: PublicOAuthSettings) -> TokenVerifier:
    required_scopes: list[str] | None = None
    if settings.validation_mode == "jwt":
        assert settings.jwks_uri is not None
        audience = settings.upstream_audience if settings.mode == "proxy" else settings.audience
        if audience is None:
            raise OAuthConfigurationError("JWT validation requires an audience")
        return JWTVerifier(
            jwks_uri=settings.jwks_uri,
            issuer=settings.issuer,
            audience=audience,
            algorithm=settings.jwt_algorithm,
            required_scopes=required_scopes,
            base_url=settings.base_url,
            ssrf_safe=not settings.allow_insecure_loopback,
        )
    assert settings.introspection_url is not None
    assert settings.introspection_client_id is not None
    assert settings.introspection_client_secret is not None
    audience = settings.upstream_audience if settings.mode == "proxy" else settings.audience
    if audience is None or settings.issuer is None:
        raise OAuthConfigurationError("introspection validation requires an issuer and audience")
    return AudienceBoundIntrospectionVerifier(
        expected_issuer=settings.issuer,
        expected_audience=audience,
        introspection_url=settings.introspection_url,
        client_id=settings.introspection_client_id,
        client_secret=settings.introspection_client_secret,
        client_auth_method=settings.introspection_client_auth_method,
        required_scopes=required_scopes,
        base_url=settings.base_url,
    )
