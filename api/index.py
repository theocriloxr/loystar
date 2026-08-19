"""Vercel serverless entry point for the Loystar MCP Server.

Vercel expects a module-level `app` variable that it can call as an ASGI handler.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main import app  # noqa: E402, F401 — Vercel discovers `app`
