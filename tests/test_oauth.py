import base64
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx
from fastmcp.server.auth import AccessToken, AuthContext, OAuthProxy, RemoteAuthProvider

from src.server.oauth import (
    OAuthConfigurationError,
    PluginAccessTokenClient,
    PluginTokenSettings,
    PublicOAuthSettings,
    build_public_auth,
)


class PublicOAuthSettingsTests(unittest.TestCase):
    def remote_environment(self) -> dict[str, str]:
        return {
            "JADX_MCP_OAUTH_MODE": "remote",
            "JADX_MCP_OAUTH_ALLOW_INSECURE_LOOPBACK": "true",
            "JADX_MCP_OAUTH_PUBLIC_BASE_URL": "http://127.0.0.1:8651",
            "JADX_MCP_OAUTH_UPSTREAM_ISSUER": "http://127.0.0.1:9000",
            "JADX_MCP_OAUTH_PUBLIC_JWKS_URI": "http://127.0.0.1:9000/jwks",
        }

    def test_remote_mode_builds_metadata_aware_provider(self) -> None:
        settings = PublicOAuthSettings.from_environment(self.remote_environment())
        provider = build_public_auth(settings)

        self.assertIsInstance(provider, RemoteAuthProvider)
        self.assertEqual("http://127.0.0.1:8651/mcp", settings.audience)
        self.assertEqual(("http://127.0.0.1:9000",), settings.authorization_servers)

    def test_proxy_mode_requires_a_stable_signing_key(self) -> None:
        environment = self.remote_environment() | {
            "JADX_MCP_OAUTH_MODE": "proxy",
            "JADX_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT": "http://127.0.0.1:9000/authorize",
            "JADX_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT": "http://127.0.0.1:9000/token",
            "JADX_MCP_OAUTH_UPSTREAM_CLIENT_ID": "mcp-client",
            "JADX_MCP_OAUTH_UPSTREAM_CLIENT_SECRET": "mcp-secret",
            "JADX_MCP_OAUTH_UPSTREAM_AUDIENCE": "http://127.0.0.1:8651/mcp",
        }

        with self.assertRaises(OAuthConfigurationError):
            PublicOAuthSettings.from_environment(environment)

        environment["JADX_MCP_OAUTH_PROXY_JWT_SIGNING_KEY"] = "stable-test-signing-key"
        settings = PublicOAuthSettings.from_environment(environment)
        self.assertIsInstance(build_public_auth(settings), OAuthProxy)


class PublicToolAuthorizationTests(unittest.TestCase):
    def test_public_tools_require_distinct_read_write_and_debug_scopes(self) -> None:
        environment = PublicOAuthSettingsTests().remote_environment()
        module_name = "scoped_jadx_mcp_server_for_test"
        source_path = Path(__file__).resolve().parents[1] / "jadx_mcp_server.py"
        spec = importlib.util.spec_from_file_location(module_name, source_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)

        with patch.dict(os.environ, environment, clear=False):
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        try:
            tools = {
                component.name: component
                for component in module.mcp._local_provider._components.values()
                if hasattr(component, "auth")
            }
            read_token = AccessToken(token="read", client_id="client", scopes=["jadx:read"], expires_at=None)
            read_context = AuthContext(token=read_token, component=tools["get_class_source"])
            write_context = AuthContext(token=read_token, component=tools["rename_class"])
            debug_context = AuthContext(token=read_token, component=tools["debug_get_threads"])

            self.assertTrue(tools["get_class_source"].auth(read_context))
            self.assertFalse(tools["rename_class"].auth(write_context))
            self.assertFalse(tools["debug_get_threads"].auth(debug_context))
        finally:
            sys.modules.pop(module_name, None)


class PluginAccessTokenClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_requests_and_caches_a_resource_bound_service_token(self) -> None:
        calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            self.assertEqual("POST", request.method)
            self.assertEqual("https://auth.example.test/token", str(request.url))
            basic = request.headers["Authorization"]
            self.assertTrue(basic.startswith("Basic "))
            decoded = base64.b64decode(basic[len("Basic "):]).decode("utf-8")
            self.assertEqual("bridge-client:bridge-secret", decoded)
            payload = parse_qs(request.content.decode("utf-8"))
            self.assertEqual(["client_credentials"], payload["grant_type"])
            self.assertEqual(["https://plugin.example.test/"], payload["resource"])
            self.assertEqual(["jadx:read jadx:write jadx:debug"], payload["scope"])
            return httpx.Response(200, json={"access_token": "plugin-token", "token_type": "Bearer", "expires_in": 120})

        def client_factory(**kwargs):
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

        settings = PluginTokenSettings(
            token_url="https://auth.example.test/token",
            client_id="bridge-client",
            client_secret="bridge-secret",
            resource="https://plugin.example.test/",
        )
        token_client = PluginAccessTokenClient(settings, http_client_factory=client_factory)

        self.assertEqual({"Authorization": "Bearer plugin-token"}, await token_client.authorization_headers())
        self.assertEqual({"Authorization": "Bearer plugin-token"}, await token_client.authorization_headers())
        self.assertEqual(1, calls)

    async def test_rejects_non_bearer_token_responses(self) -> None:
        async def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"access_token": "wrong-type", "token_type": "MAC", "expires_in": 120})

        def client_factory(**kwargs):
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

        settings = PluginTokenSettings(
            token_url="https://auth.example.test/token",
            client_id="bridge-client",
            client_secret="bridge-secret",
            resource="https://plugin.example.test/",
        )
        token_client = PluginAccessTokenClient(settings, http_client_factory=client_factory)

        with self.assertRaisesRegex(Exception, "bearer access token"):
            await token_client.authorization_headers()


if __name__ == "__main__":
    unittest.main()


class ScopeConfigurationTests(unittest.TestCase):
    def remote_environment(self, **overrides: str) -> dict[str, str]:
        env = {
            "JADX_MCP_OAUTH_MODE": "remote",
            "JADX_MCP_OAUTH_ALLOW_INSECURE_LOOPBACK": "true",
            "JADX_MCP_OAUTH_PUBLIC_BASE_URL": "http://127.0.0.1:8651",
            "JADX_MCP_OAUTH_UPSTREAM_ISSUER": "http://127.0.0.1:9000",
            "JADX_MCP_OAUTH_PUBLIC_JWKS_URI": "http://127.0.0.1:9000/jwks",
        }
        env.update(overrides)
        return env

    def proxy_environment(self, **overrides: str) -> dict[str, str]:
        env = self.remote_environment(
            JADX_MCP_OAUTH_MODE="proxy",
            JADX_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT="http://127.0.0.1:9000/authorize",
            JADX_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT="http://127.0.0.1:9000/token",
            JADX_MCP_OAUTH_UPSTREAM_CLIENT_ID="jadx-mcp",
            JADX_MCP_OAUTH_UPSTREAM_CLIENT_SECRET="secret",
            JADX_MCP_OAUTH_UPSTREAM_AUDIENCE="http://127.0.0.1:8651/mcp",
            JADX_MCP_OAUTH_PROXY_JWT_SIGNING_KEY="a" * 43,
        )
        env.update(overrides)
        return env

    def test_defaults_preserve_the_jadx_scope_vocabulary(self) -> None:
        settings = PublicOAuthSettings.from_environment(self.remote_environment())

        self.assertEqual(("jadx:read", "jadx:write", "jadx:debug"), settings.scopes_supported)
        self.assertEqual((), settings.required_scopes)
        self.assertEqual("jadx:read", settings.read_scope)

    def test_extra_scopes_append_to_the_defaults(self) -> None:
        settings = PublicOAuthSettings.from_environment(
            self.remote_environment(JADX_MCP_OAUTH_EXTRA_SCOPES="openid, profile, email")
        )

        self.assertEqual(
            ("jadx:read", "jadx:write", "jadx:debug", "openid", "profile", "email"),
            settings.scopes_supported,
        )

    def test_extra_scopes_do_not_duplicate_existing_entries(self) -> None:
        settings = PublicOAuthSettings.from_environment(
            self.remote_environment(JADX_MCP_OAUTH_EXTRA_SCOPES="openid,jadx:read,openid")
        )

        self.assertEqual(
            ("jadx:read", "jadx:write", "jadx:debug", "openid"),
            settings.scopes_supported,
        )

    def test_supported_scopes_can_be_replaced_wholesale(self) -> None:
        settings = PublicOAuthSettings.from_environment(
            self.remote_environment(
                JADX_MCP_OAUTH_SCOPES_SUPPORTED="openid,profile,re:read,re:write,re:debug",
                JADX_MCP_OAUTH_READ_SCOPE="re:read",
                JADX_MCP_OAUTH_WRITE_SCOPE="re:write",
                JADX_MCP_OAUTH_DEBUG_SCOPE="re:debug",
            )
        )

        self.assertEqual("re:read", settings.read_scope)
        self.assertEqual("re:write", settings.write_scope)
        self.assertEqual("re:debug", settings.debug_scope)
        self.assertNotIn("jadx:read", settings.scopes_supported)

    def test_renamed_tool_scope_must_be_advertised(self) -> None:
        with self.assertRaises(OAuthConfigurationError) as caught:
            PublicOAuthSettings.from_environment(
                self.remote_environment(JADX_MCP_OAUTH_READ_SCOPE="re:read")
            )

        self.assertIn("JADX_MCP_OAUTH_READ_SCOPE=re:read", str(caught.exception))

    def test_required_scopes_must_be_advertised(self) -> None:
        with self.assertRaises(OAuthConfigurationError) as caught:
            PublicOAuthSettings.from_environment(
                self.remote_environment(JADX_MCP_OAUTH_REQUIRED_SCOPES="openid")
            )

        self.assertIn("not advertised", str(caught.exception))

    def test_remote_provider_advertises_the_configured_scopes(self) -> None:
        settings = PublicOAuthSettings.from_environment(
            self.remote_environment(JADX_MCP_OAUTH_EXTRA_SCOPES="openid,profile,email")
        )
        provider = build_public_auth(settings)

        self.assertIsInstance(provider, RemoteAuthProvider)
        # _scopes_supported is what the provider publishes in its
        # protected-resource metadata document.
        self.assertIn("openid", provider._scopes_supported)
        self.assertIn("jadx:read", provider._scopes_supported)

    def test_no_required_scopes_leaves_the_verifier_unconstrained(self) -> None:
        settings = PublicOAuthSettings.from_environment(self.remote_environment())
        provider = build_public_auth(settings)

        # FastMCP normalises an unset required_scopes to an empty list, which
        # imposes no constraint on presented tokens.
        self.assertEqual([], provider.token_verifier.required_scopes)

    def test_required_scopes_reach_the_token_verifier(self) -> None:
        settings = PublicOAuthSettings.from_environment(
            self.remote_environment(
                JADX_MCP_OAUTH_EXTRA_SCOPES="openid,profile,email",
                JADX_MCP_OAUTH_REQUIRED_SCOPES="openid,jadx:read",
            )
        )
        provider = build_public_auth(settings)

        self.assertEqual(["openid", "jadx:read"], provider.token_verifier.required_scopes)

    def test_proxy_requests_required_scopes_from_the_upstream_provider(self) -> None:
        """An Authelia-style provider needs `openid` in the authorization request.

        OAuthProxy derives the scope string it registers clients with from the
        verifier's required_scopes, so this is the knob that puts openid on the
        wire when a client registers without naming scopes itself.
        """
        settings = PublicOAuthSettings.from_environment(
            self.proxy_environment(
                JADX_MCP_OAUTH_EXTRA_SCOPES="openid,profile,email,groups",
                JADX_MCP_OAUTH_REQUIRED_SCOPES="openid,profile,email",
            )
        )
        provider = build_public_auth(settings)

        self.assertIsInstance(provider, OAuthProxy)
        self.assertEqual("openid profile email", provider._default_scope_str)
        self.assertIn("groups", provider.client_registration_options.valid_scopes)


class RenamedToolScopeTests(unittest.TestCase):
    """A provider that cannot mint `jadx:read` should still be able to gate tools."""

    def test_tool_tiers_honour_renamed_scopes(self) -> None:
        environment = {
            "JADX_MCP_OAUTH_MODE": "remote",
            "JADX_MCP_OAUTH_ALLOW_INSECURE_LOOPBACK": "true",
            "JADX_MCP_OAUTH_PUBLIC_BASE_URL": "http://127.0.0.1:8651",
            "JADX_MCP_OAUTH_UPSTREAM_ISSUER": "http://127.0.0.1:9091",
            "JADX_MCP_OAUTH_PUBLIC_JWKS_URI": "http://127.0.0.1:9091/jwks.json",
            "JADX_MCP_OAUTH_SCOPES_SUPPORTED": "openid,profile,jadx_read,jadx_write,jadx_debug",
            "JADX_MCP_OAUTH_READ_SCOPE": "jadx_read",
            "JADX_MCP_OAUTH_WRITE_SCOPE": "jadx_write",
            "JADX_MCP_OAUTH_DEBUG_SCOPE": "jadx_debug",
        }
        module_name = "renamed_scope_jadx_mcp_server_for_test"
        source_path = Path(__file__).resolve().parents[1] / "jadx_mcp_server.py"
        spec = importlib.util.spec_from_file_location(module_name, source_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)

        with patch.dict(os.environ, environment, clear=False):
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        try:
            tools = {
                component.name: component
                for component in module.mcp._local_provider._components.values()
                if hasattr(component, "auth")
            }
            token = AccessToken(token="read", client_id="client", scopes=["jadx_read"], expires_at=None)

            self.assertTrue(
                tools["get_class_source"].auth(AuthContext(token=token, component=tools["get_class_source"]))
            )
            self.assertFalse(
                tools["rename_class"].auth(AuthContext(token=token, component=tools["rename_class"]))
            )
            # The old vocabulary must no longer open anything.
            stale = AccessToken(token="stale", client_id="client", scopes=["jadx:read"], expires_at=None)
            self.assertFalse(
                tools["get_class_source"].auth(AuthContext(token=stale, component=tools["get_class_source"]))
            )
        finally:
            sys.modules.pop(module_name, None)


class AudienceBoundIntrospectionVerifierTests(unittest.IsolatedAsyncioTestCase):
    """The introspection verifier must work against RFC 7662 responses that omit `iss`."""

    ISSUER = "https://auth.example.com"
    AUDIENCE = "https://mcp.example.com/mcp"

    def build_verifier(self):
        from src.server.oauth import AudienceBoundIntrospectionVerifier

        return AudienceBoundIntrospectionVerifier(
            expected_issuer=self.ISSUER,
            expected_audience=self.AUDIENCE,
            introspection_url="https://auth.example.com/api/oidc/introspection",
            client_id="client",
            client_secret="secret",
        )

    async def verify_with_claims(self, claims: dict):
        from unittest.mock import AsyncMock, patch
        from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier

        token = AccessToken(
            token="opaque", client_id="client", scopes=["jadx:read"], expires_at=None, claims=claims
        )
        with patch.object(IntrospectionTokenVerifier, "verify_token", AsyncMock(return_value=token)):
            return await self.build_verifier().verify_token("opaque")

    async def test_accepts_authelia_shaped_response_without_an_issuer_claim(self) -> None:
        """Authelia's plain JSON introspection response has no `iss` — this must still pass."""
        result = await self.verify_with_claims(
            {"active": True, "aud": [self.AUDIENCE], "scope": "jadx:read", "client_id": "client"}
        )
        self.assertIsNotNone(result)

    async def test_accepts_a_matching_issuer_when_present(self) -> None:
        result = await self.verify_with_claims({"iss": self.ISSUER, "aud": [self.AUDIENCE]})
        self.assertIsNotNone(result)

    async def test_rejects_a_mismatched_issuer(self) -> None:
        result = await self.verify_with_claims(
            {"iss": "https://evil.example.com", "aud": [self.AUDIENCE]}
        )
        self.assertIsNone(result)

    async def test_rejects_a_missing_audience(self) -> None:
        result = await self.verify_with_claims({"active": True, "scope": "jadx:read"})
        self.assertIsNone(result)

    async def test_rejects_a_foreign_audience(self) -> None:
        result = await self.verify_with_claims({"aud": ["https://other.example.com/mcp"]})
        self.assertIsNone(result)

    async def test_accepts_a_string_audience(self) -> None:
        result = await self.verify_with_claims({"aud": self.AUDIENCE})
        self.assertIsNotNone(result)
