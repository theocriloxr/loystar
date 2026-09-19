"""Command-line entry point for the Loystar MCP server.

Production Railway deployments use the repository-level ``main:app`` wrapper.
This CLI is for local/package execution and installs the same MCP compatibility
routes before starting Uvicorn.
"""
from __future__ import annotations

import uvicorn

import src.main_clean as clean_core
from src.claude_compat import install as install_claude_compat
from src.config import settings


def main() -> None:
    """Run the clean MCP application from the installed console script."""
    install_claude_compat(clean_core.app, clean_core)
    uvicorn.run(
        clean_core.app,
        host=settings.server_host,
        port=settings.server_port,
        log_level=settings.log_level.lower(),
    )


__all__ = ["main"]
