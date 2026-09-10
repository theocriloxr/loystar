"""Run the clean-core deploy gate without inheriting production infrastructure.

Railway executes pre-deploy commands inside the production service environment.
This wrapper launches compilation/tests in a sanitized child environment so
unit tests cannot mutate production Postgres/Redis and always exercise HTTPS +
a trusted deterministic host.
"""
from __future__ import annotations

import os
import subprocess
import sys


BUILD_SHA = (
    os.getenv("RAILWAY_GIT_COMMIT_SHA")
    or os.getenv("GIT_COMMIT_SHA")
    or os.getenv("SOURCE_COMMIT")
    or "unknown"
)

TEST_ENV = os.environ.copy()
TEST_ENV.update(
    {
        "ENVIRONMENT": "development",
        "MCP_SERVER_BASE_URL": "https://testserver",
        "OAUTH_ISSUER": "https://testserver",
        "ALLOWED_HOSTS": "testserver,localhost,127.0.0.1",
        "ALLOWED_ORIGINS": "https://testserver",
        "DATABASE_URL": "",
        "REDIS_URL": "",
        "OAUTH_ENCRYPTION_KEY": "",
        "ADMIN_API_KEY": "",
        "OAUTH_DCR_INITIAL_ACCESS_TOKEN": "",
        "OAUTH_ENABLE_CIMD": "true",
        "OAUTH_ALLOW_DYNAMIC_REGISTRATION": "true",
        "ALLOW_ENVIRONMENT_CREDENTIALS": "false",
        "LOYSTAR_ACCESS_TOKEN": "",
        "LOYSTAR_CLIENT": "",
        "LOYSTAR_UID": "",
        "LOYSTAR_EXPIRY": "",
        "ENABLE_DEMO_ROUTES": "false",
        "ENABLE_LEGACY_ROUTES": "false",
        "ENABLE_PROTOTYPE_ROUTES": "false",
        "ENABLE_PROTOTYPE_TOOLS": "false",
        "ENABLE_BILLING_ROUTES": "false",
    }
)

COMPILE_TARGETS = [
    "src/oauth_cimd_clean.py",
    "src/oauth_store_clean.py",
    "src/loystar_client_clean.py",
    "src/main_clean.py",
    "main.py",
]


def run(command: list[str]) -> None:
    print("PREDEPLOY_RUN:", " ".join(command), flush=True)
    subprocess.run(command, env=TEST_ENV, check=True)


def main() -> int:
    print(f"PREDEPLOY_BUILD_SHA={BUILD_SHA}", flush=True)
    run([sys.executable, "-m", "py_compile", *COMPILE_TARGETS])
    run([sys.executable, "-m", "pytest", "-q", "tests/unit/test_clean_core.py"])
    print("PREDEPLOY_STATUS=PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
