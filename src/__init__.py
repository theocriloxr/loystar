"""Loystar MCP Server package.

The clean production path intentionally has no import-time OAuth side effects.
Legacy compatibility modules remain in the repository for reference while the
new core is validated, but importing ``src`` no longer mutates OAuthStore or
Starlette response classes globally.
"""

__version__ = "2.0.0-clean"
__author__ = "Loystar Team"
__description__ = "Platform-agnostic MCP bridge for merchant-scoped Loystar data"
