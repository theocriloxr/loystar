"""Repository-level regression tests for deploy and plugin packaging."""
from __future__ import annotations

import json
from pathlib import Path

from src.cli import main as cli_main


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_ORIGIN = "https://loystar-production.up.railway.app"


def _json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_console_entrypoint_is_callable():
    assert callable(cli_main)


def test_railway_runs_tests_before_startup_not_inside_start_command():
    railway = _json("railway.json")
    deploy = railway["deploy"]
    start = deploy["startCommand"]
    predeploy = deploy["preDeployCommand"]

    assert "pytest" not in start
    assert "uvicorn main:app" in start
    assert predeploy == ["python scripts/run_clean_predeploy.py"]
    assert deploy["healthcheckPath"] == "/health"


def test_portable_plugin_targets_production_mcp():
    plugin = _json("plugin.json")
    mcp = _json("mcp.json")

    assert plugin["$schema"] == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
    assert plugin["name"] == "loystar-mcp"
    assert plugin["extensions"]["com.openai"]["interface"]["capabilities"] == ["Read"]

    server = mcp["mcpServers"]["loystar"]
    assert mcp["$schema"] == "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
    assert server == {
        "type": "streamable-http",
        "url": f"{PRODUCTION_ORIGIN}/mcp",
    }


def test_readme_contains_no_nul_bytes():
    assert "\x00" not in (ROOT / "README.md").read_text(encoding="utf-8")
