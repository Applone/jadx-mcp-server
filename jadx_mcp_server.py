#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [ "fastmcp>=3.0.2", "httpx" ]
# ///

"""
Copyright (c) 2025 jadx mcp server developer(s) (https://github.com/zinja-coder/jadx-ai-mcp)
See the file 'LICENSE' for copying permission
"""

import argparse
import logging
import os
import sys

# ---------------------------------------------------------------------------
# Sanitise proxy-related environment variables BEFORE any library reads them.
#
# Problem (GitHub issue #99): if no_proxy (or any *_PROXY var) contains
# non-printable characters such as trailing newlines — common when set via
# .env files or proxy managers — httpx raises InvalidURL on the first request.
# Our own httpx calls use trust_env=False, but third-party code (e.g.
# fastmcp's version check) may not, so we clean the environment globally.
# ---------------------------------------------------------------------------
_PROXY_VARS = (
    "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy",
    "ALL_PROXY", "all_proxy",
    "NO_PROXY", "no_proxy",
)
for _var in _PROXY_VARS:
    _val = os.environ.get(_var)
    if _val is not None:
        _clean = _val.strip()
        if _clean != _val:
            os.environ[_var] = _clean
        if not _clean:
            del os.environ[_var]
from fastmcp import FastMCP, Context
from fastmcp.server.auth import require_scopes
from src.banner import jadx_mcp_server_banner
from src.server import config, tools
from src.server.oauth import (
    MCP_PATH,
    DEBUG_SCOPE,
    READ_SCOPE,
    WRITE_SCOPE,
    PublicOAuthSettings,
    build_public_auth,
)

# The public MCP endpoint and the internal Java plugin are distinct resources.
# Public OAuth is selected at startup by JADX_MCP_OAUTH_MODE.
public_oauth_settings = PublicOAuthSettings.from_environment()
public_oauth = build_public_auth(public_oauth_settings)

# The three tool tiers are gated on scope names the operator can rename (some
# providers cannot mint `jadx:read`). Rebinding the imported defaults here means
# every @mcp.tool decorator below picks up the configured vocabulary without
# each one having to reach into settings.
READ_SCOPE = public_oauth_settings.read_scope
WRITE_SCOPE = public_oauth_settings.write_scope
DEBUG_SCOPE = public_oauth_settings.debug_scope


def _tool_auth(scope: str):
    """Keep existing stdio workflows open while enforcing scopes for HTTP OAuth mode."""
    return require_scopes(scope) if public_oauth is not None else None


# Initialize MCP Server
mcp = FastMCP("JADX-AI-MCP Plugin Reverse Engineering Server", auth=public_oauth)

# Bootstrap logger — always writes to stderr to keep stdout clean for stdio transport
logger = logging.getLogger("jadx-mcp-server.bootstrap")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

# Import and register ALL tools using correct FastMCP pattern
from src.server.tools.class_tools import (
    fetch_current_class, get_selected_text, get_class_source,
    get_all_classes, get_methods_of_class, get_fields_of_class, get_smali_of_class,
    get_main_application_classes_names, get_main_application_classes_code, get_main_activity_class,
    get_package_tree, get_cache_stats, clear_cache
)
from src.server.tools.search_tools import (
    get_method_by_name, search_method_by_name, search_classes_by_keyword
)
from src.server.tools.resource_tools import (
    get_manifest_component, get_android_manifest, get_strings, get_all_resource_file_names,
    get_resource_file
)
from src.server.tools.refactor_tools import (
    rename_class, rename_method, rename_field, rename_package, rename_variable
)
from src.server.tools.debug_tools import (
    debug_get_stack_frames, debug_get_threads, debug_get_variables
)
from src.server.tools.xrefs_tools import (
    get_xrefs_to_class, get_xrefs_to_method, get_xrefs_to_field
)


# CORRECT REGISTRATION PATTERN for FastMCP
@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def fetch_current_class() -> dict:
    """Fetch the currently selected class and its code from the JADX-GUI plugin."""
    return await tools.class_tools.fetch_current_class()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_selected_text() -> dict:
    """Returns the currently selected text in the decompiled code view."""
    return await tools.class_tools.get_selected_text()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_method_by_name(class_name: str, method_name: str, method_signature: str = None) -> dict:
    """Fetch the source code of a method from a specific class."""
    return await tools.search_tools.get_method_by_name(class_name, method_name, method_signature)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_all_classes(offset: int = 0, count: int = 0) -> dict:
    """Returns a list of all classes in the project with pagination support."""
    return await tools.class_tools.get_all_classes(offset, count)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_class_source(class_name: str) -> dict:
    """Fetch the Java source of a specific class."""
    return await tools.class_tools.get_class_source(class_name)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def search_method_by_name(method_name: str, ctx: Context = None) -> dict:
    """Search for a method name across all classes."""
    report_progress = ctx.report_progress if ctx else None
    return await tools.search_tools.search_method_by_name(method_name, report_progress=report_progress)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_methods_of_class(class_name: str) -> dict:
    """List all method names in a class."""
    return await tools.class_tools.get_methods_of_class(class_name)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def search_classes_by_keyword(
    search_term: str,
    package: str = "",
    search_in: str = "code",
    offset: int = 0,
    count: int = 20,
    ctx: Context = None,
) -> dict:
    """Search for classes containing a specific keyword with flexible filtering options.

    This tool performs a comprehensive search across decompiled Android code, allowing you to:
    1. Search within specific packages by providing a package name
    2. Target specific search scopes (class names, method names, fields, code content, comments)
    3. Combine multiple search scopes for precise results

    Args:
        search_term: The keyword or string to search for. This is the main search query.

        package (optional): Package name to limit the search scope.
            - If empty string (default), searches across all packages in the APK
            - If provided, only searches within classes belonging to the specified package
            - Example: "com.example.app" to search only in that package

        search_in (optional): Comma-separated list of search scopes to target.
            Valid values:
            - "class": Search in class names only
            - "method": Search in method names only
            - "field": Search in field names only
            - "code": Search in code content (method bodies, statements, etc.)
            - "comment": Search in comments

            You can specify one or multiple scopes:
            - Single scope: "class" (only class names)
            - Multiple scopes: "class,method" (class names OR method names)
            - Combined: "class,method,code" (searches in all three scopes)

            Default: "code" (searches in code content)

        offset (optional): Starting index for pagination. Default: 0
        count (optional): Maximum number of results to return. Default: 20

    Returns:
        dict: Paginated list of classes containing the search term, with metadata about matches

    MCP Tool: search_classes_by_keyword
    Description: Advanced search tool that finds classes matching a keyword with package filtering
                 and scope targeting capabilities. Use this when you need to find specific code
                 patterns, class names, method names, or other identifiers across the decompiled APK."""
    report_progress = ctx.report_progress if ctx else None
    return await tools.search_tools.search_classes_by_keyword(
        search_term, package, search_in, offset, count, report_progress=report_progress
    )


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_fields_of_class(class_name: str) -> dict:
    """List all field names in a class."""
    return await tools.class_tools.get_fields_of_class(class_name)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_smali_of_class(class_name: str) -> dict:
    """Fetch the smali representation of a class."""
    return await tools.class_tools.get_smali_of_class(class_name)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_manifest_component(component_type: str, only_exported: bool = False) -> dict:
    """Retrieve specified component data from AndroidManifest.xml, support filter exported components.
    Support standard Android components: activity, provider, service, receiver."""
    return await tools.resource_tools.get_manifest_component(component_type, only_exported)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_android_manifest() -> dict:
    """Retrieve and return the AndroidManifest.xml content."""
    return await tools.resource_tools.get_android_manifest()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_strings(offset: int = 0, count: int = 0) -> dict:
    """Retrieve contents of strings.xml files."""
    return await tools.resource_tools.get_strings(offset, count)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_all_resource_file_names(offset: int = 0, count: int = 0) -> dict:
    """Retrieve all resource files names."""
    return await tools.resource_tools.get_all_resource_file_names(offset, count)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_resource_file(resource_name: str) -> dict:
    """Retrieve resource file content."""
    return await tools.resource_tools.get_resource_file(resource_name)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_main_application_classes_names() -> dict:
    """Fetch main application classes' names from Manifest package."""
    return await tools.class_tools.get_main_application_classes_names()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_main_application_classes_code(offset: int = 0, count: int = 0) -> dict:
    """Fetch main application classes' code with pagination."""
    return await tools.class_tools.get_main_application_classes_code(offset, count)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_main_activity_class() -> dict:
    """Fetch the main activity class from AndroidManifest.xml."""
    return await tools.class_tools.get_main_activity_class()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_package_tree() -> dict:
    """Get all packages in the APK sorted by class count. Shows total_classes, total_packages, and per-package name, class_count, is_likely_library. Use this first to understand the APK structure before searching."""
    return await tools.class_tools.get_package_tree()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_cache_stats() -> dict:
    """Get decompilation cache statistics: hits, misses, hit_rate, cached_classes, compressed_mb, compression_ratio."""
    return await tools.class_tools.get_cache_stats()


@mcp.tool(auth=_tool_auth(WRITE_SCOPE))
async def clear_cache() -> dict:
    """Clear the decompilation source cache and reset counters. Use when switching APKs or to free memory."""
    return await tools.class_tools.clear_cache()


@mcp.tool(auth=_tool_auth(WRITE_SCOPE))
async def rename_class(class_name: str, new_name: str) -> dict:
    """Renames a specific class."""
    return await tools.refactor_tools.rename_class(class_name, new_name)


@mcp.tool(auth=_tool_auth(WRITE_SCOPE))
async def rename_method(method_name: str, new_name: str, method_signature: str = None) -> dict:
    """Renames a specific method."""
    return await tools.refactor_tools.rename_method(method_name, new_name, method_signature)


@mcp.tool(auth=_tool_auth(WRITE_SCOPE))
async def rename_field(class_name: str, field_name: str, new_name: str) -> dict:
    """Renames a specific field."""
    return await tools.refactor_tools.rename_field(class_name, field_name, new_name)


@mcp.tool(auth=_tool_auth(WRITE_SCOPE))
async def rename_package(old_package_name: str, new_package_name: str) -> dict:
    """Renames a package and all its classes."""
    return await tools.refactor_tools.rename_package(old_package_name, new_package_name)


@mcp.tool(auth=_tool_auth(WRITE_SCOPE))
async def rename_variable(class_name: str, method_name: str, variable_name: str, new_name: str, reg: str = None, ssa: str = None) -> dict:
    """Renames a specific variable in a method."""
    return await tools.refactor_tools.rename_variable(class_name, method_name, variable_name, new_name, reg, ssa)


@mcp.tool(auth=_tool_auth(DEBUG_SCOPE))
async def debug_get_stack_frames() -> dict:
    """Get current stack frames (call stack)."""
    return await tools.debug_tools.debug_get_stack_frames()


@mcp.tool(auth=_tool_auth(DEBUG_SCOPE))
async def debug_get_threads() -> dict:
    """Get all threads in the debugged process."""
    return await tools.debug_tools.debug_get_threads()


@mcp.tool(auth=_tool_auth(DEBUG_SCOPE))
async def debug_get_variables() -> dict:
    """Get current variables when process is suspended."""
    return await tools.debug_tools.debug_get_variables()


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_xrefs_to_class(class_name: str, offset: int = 0, count: int = 20) -> dict:
    """Find all references to a class."""
    return await tools.xrefs_tools.get_xrefs_to_class(class_name, offset, count)


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_xrefs_to_method(
    class_name: str, method_name: str, offset: int = 0, count: int = 20
) -> dict:
    """Find all references to a method."""
    return await tools.xrefs_tools.get_xrefs_to_method(
        class_name, method_name, offset, count
    )


@mcp.tool(auth=_tool_auth(READ_SCOPE))
async def get_xrefs_to_field(
    class_name: str, field_name: str, offset: int = 0, count: int = 20
) -> dict:
    """Find all references to a field."""
    return await tools.xrefs_tools.get_xrefs_to_field(
        class_name, field_name, offset, count
    )


def main():
    parser = argparse.ArgumentParser("MCP Server for Jadx")
    parser.add_argument(
        "--http",
        help="Serve MCP Server over HTTP stream.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--host",
        help="Host address to bind for --http (default: 127.0.0.1). Public non-loopback deployments require an OAuth mode and HTTPS public URL configuration.",
        default="127.0.0.1",
        type=str
    )
    parser.add_argument(
        "--port", help="Port for --http (default:8651)", default=8651, type=int
    )
    parser.add_argument(
        "--jadx-port",
        help="JADX AI MCP Plugin port (default:8650)",
        default=8650,
        type=int,
    )
    parser.add_argument(
        "--jadx-host",
        help="JADX AI MCP Plugin host (default:127.0.0.1). "
             "Security: non-localhost may expose plugin to network; use trusted network/firewall.",
        default="127.0.0.1",
        type=str,
    )
    args = parser.parse_args()

    if not args.http and public_oauth is not None:
        parser.error("JADX_MCP_OAUTH_MODE requires --http because OAuth is an HTTP transport feature")

    # Configure the loopback Java plugin bridge.
    config.set_jadx_host(args.jadx_host)
    config.set_jadx_port(args.jadx_port)
    config.configure_plugin_oauth()

    # A non-loopback MCP listener must never silently run without authorization.
    if args.host not in ("127.0.0.1", "localhost", "::1") and public_oauth is None:
        parser.error("non-loopback --host requires JADX_MCP_OAUTH_MODE=remote or proxy")
    if public_oauth is not None:
        logger.info(
            "Public MCP OAuth is enabled in %s mode for %s",
            public_oauth_settings.mode,
            public_oauth_settings.base_url,
        )
        logger.info(
            "Advertised scopes: %s | required on every token: %s",
            ", ".join(public_oauth_settings.scopes_supported),
            ", ".join(public_oauth_settings.required_scopes) or "none",
        )
        logger.info(
            "Tool scopes: read=%s write=%s debug=%s",
            public_oauth_settings.read_scope,
            public_oauth_settings.write_scope,
            public_oauth_settings.debug_scope,
        )
    if config.plugin_oauth_enabled():
        logger.info("Java plugin calls use a separate client-credentials token for the configured plugin resource")

    # Banner & Health Check — always logs to stderr to keep stdout clean for stdio transport
    try:
        logger.info(jadx_mcp_server_banner())
    except Exception:
        logger.info(
            "[JADX AI MCP Server] v3.3.5 | MCP Port: %s | JADX Host: %s | JADX Port: %s",
            args.port,
            args.jadx_host,
            args.jadx_port,
        )

    logger.info("Testing JADX AI MCP Plugin connectivity...")
    result = config.health_ping()
    logger.info("Health check result: %s", result)

    # Run Server
    if args.http:
        mcp.run(transport="streamable-http", host=args.host, port=args.port, path=MCP_PATH)
    else:
        # StdIO transport must keep stdout reserved for MCP frames.
        mcp.run()


if __name__ == "__main__":
    main()
