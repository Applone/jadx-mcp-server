# End-to-end OAuth deployment

The Python `jadx-mcp-server` and the Java `jadx-ai-mcp` plugin are **two different OAuth protected resources**:

```text
MCP client -- user token for public MCP resource --> Python FastMCP server
Python FastMCP server -- service token for plugin resource --> Java JADX plugin
```

The Python server never forwards an MCP client's bearer token to the Java plugin. It obtains a short-lived client-credentials token for the plugin resource, validates that token's target in the Java plugin, and sends it only in the HTTP `Authorization` header. This preserves OAuth audience boundaries and follows MCP token-passthrough guidance.

## Public MCP OAuth modes

Set `JADX_MCP_OAUTH_MODE` before starting the server with `--http`.

| Mode | Use when | FastMCP component |
|---|---|---|
| `remote` | The upstream identity provider supports Dynamic Client Registration | `RemoteAuthProvider` |
| `proxy` | The upstream provider uses a fixed, pre-registered OAuth client | `OAuthProxy` |
| `disabled` | Local development or stdio only | No HTTP OAuth provider |

The Streamable HTTP MCP endpoint is fixed at `/mcp`. In every HTTP mode, configure the public base URL as the external URL without `/mcp`; the default public audience is then that URL plus `/mcp`.

### Remote DCR mode

```bash
export JADX_MCP_OAUTH_MODE=remote
export JADX_MCP_OAUTH_PUBLIC_BASE_URL=https://mcp.example.com
export JADX_MCP_OAUTH_UPSTREAM_ISSUER=https://id.example.com
export JADX_MCP_OAUTH_PUBLIC_JWKS_URI=https://id.example.com/.well-known/jwks.json
# Optional when the IdP needs an explicit public resource value
export JADX_MCP_OAUTH_PUBLIC_AUDIENCE=https://mcp.example.com/mcp
uv run jadx_mcp_server.py --http --host 127.0.0.1 --port 8651
```

The provider must support Dynamic Client Registration and issue tokens with the configured public audience. In production, terminate TLS in a gateway or load balancer and make `JADX_MCP_OAUTH_PUBLIC_BASE_URL` the client-visible HTTPS URL.

### Fixed-client proxy mode

```bash
export JADX_MCP_OAUTH_MODE=proxy
export JADX_MCP_OAUTH_PUBLIC_BASE_URL=https://mcp.example.com
export JADX_MCP_OAUTH_UPSTREAM_ISSUER=https://id.example.com
export JADX_MCP_OAUTH_PUBLIC_JWKS_URI=https://id.example.com/.well-known/jwks.json
export JADX_MCP_OAUTH_UPSTREAM_AUTHORIZATION_ENDPOINT=https://id.example.com/authorize
export JADX_MCP_OAUTH_UPSTREAM_TOKEN_ENDPOINT=https://id.example.com/token
export JADX_MCP_OAUTH_UPSTREAM_CLIENT_ID=jadx-mcp-public
export JADX_MCP_OAUTH_UPSTREAM_CLIENT_SECRET=secret-from-a-secret-manager
export JADX_MCP_OAUTH_UPSTREAM_AUDIENCE=https://id.example.com/public-mcp-api
export JADX_MCP_OAUTH_PROXY_JWT_SIGNING_KEY=stable-secret-from-a-secret-manager
uv run jadx_mcp_server.py --http --host 127.0.0.1 --port 8651
```

`OAuthProxy` provides MCP-compatible dynamic registration, PKCE, callback forwarding, and its own public-MCP token audience while the upstream provider continues to use its fixed client registration. It forwards the configured upstream audience as an RFC 8707 `resource` parameter in upstream authorization and token requests. Providers with a non-standard parameter such as Auth0's `audience` can use `JADX_MCP_OAUTH_UPSTREAM_EXTRA_AUTHORIZE_PARAMS` and `JADX_MCP_OAUTH_UPSTREAM_EXTRA_TOKEN_PARAMS` JSON objects to supply it. Keep `JADX_MCP_OAUTH_PROXY_JWT_SIGNING_KEY` stable across restarts and use shared persistent client storage before running multiple replicas.

### Public scopes

| MCP tool category | Required public scope |
|---|---|
| Decompiled code, resources, search, xrefs, cache stats | `jadx:read` |
| Cache clear and all renaming or refactoring tools | `jadx:write` |
| Debugger tools | `jadx:debug` |

The FastMCP server validates public JWTs through the configured issuer and JWKS, or can use `JADX_MCP_OAUTH_PUBLIC_TOKEN_VALIDATION=introspection` with `JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_URL`, `JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_CLIENT_ID`, and `JADX_MCP_OAUTH_PUBLIC_INTROSPECTION_CLIENT_SECRET`. Both paths enforce the configured issuer and expected audience before scopes are evaluated.

## Java plugin bridge token

If Java plugin OAuth is enabled, configure a second OAuth client in the Python server. Its token must have the Java plugin resource as its audience and carry the operation scopes listed above.

```bash
export JADX_PLUGIN_OAUTH_TOKEN_URL=https://id.example.com/oauth/token
export JADX_PLUGIN_OAUTH_CLIENT_ID=jadx-python-bridge
export JADX_PLUGIN_OAUTH_CLIENT_SECRET=secret-from-a-secret-manager
export JADX_PLUGIN_OAUTH_RESOURCE=https://jadx-plugin.internal.example.com/
export JADX_PLUGIN_OAUTH_SCOPES=jadx:read,jadx:write,jadx:debug
export JADX_PLUGIN_OAUTH_CLIENT_AUTH_METHOD=client_secret_basic
```

The bridge sends an OAuth 2.0 client-credentials request with the configured scopes and an RFC 8707 `resource` parameter, caches each bearer token until shortly before expiration, and rejects malformed or non-Bearer token responses. Set `JADX_PLUGIN_OAUTH_SEND_RESOURCE_PARAMETER=false` only for an authorization server that rejects RFC 8707 parameters and is configured by another mechanism to issue the correct plugin audience. Providers that require a non-standard parameter such as Auth0's `audience` can use `JADX_PLUGIN_OAUTH_EXTRA_TOKEN_PARAMS` with a JSON object such as `{"audience":"https://jadx-plugin.internal.example.com/"}`.

## Matching Java configuration

The Java plugin needs compatible resource-server settings:

```text
-Djadx.oauth.enabled=true
-Djadx.oauth.issuer=https://id.example.com
-Djadx.oauth.resource=https://jadx-plugin.internal.example.com/
-Djadx.oauth.jwks-uri=https://id.example.com/.well-known/jwks.json
-Djadx.oauth.required-client-id=jadx-python-bridge
-Djadx.oauth.token-validation=jwt
```

The following values must match exactly:

| Python setting | Java setting | Purpose |
|---|---|---|
| `JADX_PLUGIN_OAUTH_RESOURCE` | `jadx.oauth.resource` | Access-token audience accepted by the Java plugin |
| `JADX_PLUGIN_OAUTH_CLIENT_ID` | `jadx.oauth.required-client-id` | Authorized bridge client identity |
| token issuer and JWKS issuer | `jadx.oauth.issuer` and `jadx.oauth.jwks-uri` | Trusted signing authority |
| `JADX_PLUGIN_OAUTH_SCOPES` | Plugin route scope requirements | Least-privilege operation access |

The Java plugin remains bound to loopback. Do not expose its port directly; use a local deployment, an SSH tunnel, or a controlled gateway.

## Security requirements

- Use HTTPS for all public endpoints. HTTP is accepted only with the explicit loopback-development flags.
- Keep all secrets in environment variables or a secret manager; never put them in source code, tool arguments, or logs.
- Use a distinct public MCP resource and internal plugin resource.
- Configure exact allowed client redirect URI patterns rather than broad wildcards when your MCP clients are known.
- Do not use HTTP OAuth with stdio. Stdio relies on local process security and the server rejects a configured public OAuth mode without `--http`.
- Rotate signing keys and service credentials regularly.

## Standards

- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OAuth 2.0 Protected Resource Metadata, RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)
- [OAuth 2.0 Bearer Token Usage, RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)
- [Resource Indicators for OAuth 2.0, RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
- [PKCE, RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)
