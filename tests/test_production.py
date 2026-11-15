"""Production-mode checks. Settings are read once at import, so each check runs the app
in a fresh interpreter with APP_ENV=production."""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROBE = textwrap.dedent(
    """
    import json, re
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app, base_url="https://notes.example", follow_redirects=False) as c:
        login = c.get("/login")
        result = {
            "docs": c.get("/docs").status_code,
            "openapi": c.get("/openapi.json").status_code,
            "health": c.get("/healthz").status_code,
            "hsts": login.headers.get("strict-transport-security", ""),
            "cookie": login.headers.get("set-cookie", ""),
            "stylesheet": re.search(r'rel="stylesheet" href="([^"]+)"', login.text).group(1),
        }
    print(json.dumps(result))
    """
)


def run_production(extra_env: dict[str, str]) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("SECRET_KEY", "DATABASE_URL")}
    env.update(APP_ENV="production", PYTHONPATH=str(ROOT), **extra_env)
    return subprocess.run([sys.executable, "-c", PROBE], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)


def production_probe() -> dict:
    db = Path(tempfile.mkdtemp()) / "prod.db"
    proc = run_production({"SECRET_KEY": "a" * 43, "DATABASE_URL": f"sqlite:///{db}"})
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_production_refuses_to_start_without_secret_key():
    proc = run_production({})
    assert proc.returncode != 0
    assert "SECRET_KEY must be set in production" in proc.stderr


def test_production_hardening():
    r = production_probe()
    assert r["docs"] == 404 and r["openapi"] == 404, "API docs must be off in production"
    assert r["health"] == 200
    assert "max-age=" in r["hsts"]
    cookie = r["cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    # Relative, so it stays https behind the TLS proxy (no mixed content).
    assert r["stylesheet"] == "/static/style.css"
