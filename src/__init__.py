"""
Loystar MCP Server
Customer Loyalty Manager AI Agent
"""

__version__ = "1.0.0"
__author__ = "Loystar Team"
__description__ = "Platform-agnostic MCP-driven customer loyalty management system"

from src.oauth_cimd import install as _install_oauth_cimd
from src.oauth_client_compat import install as _install_oauth_client_compat

_install_oauth_cimd()
_install_oauth_client_compat()
