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
