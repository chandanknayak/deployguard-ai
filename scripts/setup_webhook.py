"""
scripts/setup_webhook.py — Interactive webhook + environment setup assistant.

Guides the user through the complete local-to-GitHub webhook setup:
  1. Validates required environment variables in .env
  2. Checks if ngrok is installed; prints the tunnel command
  3. Prints exact GitHub webhook registration instructions
  4. Runs a connectivity test against the FastAPI server

Usage:
    python scripts/setup_webhook.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

def ok(msg: str) -> None:
    print(f"  {_GREEN}✓{_RESET} {msg}")

def warn(msg: str) -> None:
    print(f"  {_YELLOW}⚠{_RESET}  {msg}")

def err(msg: str) -> None:
    print(f"  {_RED}✗{_RESET} {msg}")

def header(msg: str) -> None:
    print(f"\n{_BOLD}{_BLUE}{'─'*60}{_RESET}")
    print(f"{_BOLD}  {msg}{_RESET}")
    print(f"{_BOLD}{_BLUE}{'─'*60}{_RESET}")


def load_env() -> dict[str, str]:
    """Load .env file if present."""
    env_path = ROOT / ".env"
    env: dict[str, str] = {}
    if not env_path.exists():
        return env
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def check_env_vars(env: dict[str, str]) -> bool:
    """Check required and optional environment variables."""
    header("Step 1 — Environment Variables (.env)")
    required = {
        "GITHUB_WEBHOOK_SECRET": "Secret for HMAC signature verification",
        "GITHUB_API_TOKEN": "GitHub PAT with repo + statuses + pull_requests scopes",
        "MONGODB_URI": "MongoDB Atlas connection string (mongodb+srv://...)",
    }
    optional = {
        "OPENAI_API_KEY": "Optional OpenAI API key (deterministic AST engine works without it)",
        "JWT_SECRET_KEY": "Strong HMAC secret for workspace JWT auth",
    }
    all_ok = True
    for key, desc in required.items():
        val = env.get(key, os.environ.get(key, ""))
        if val and not val.startswith("<") and "xxxx" not in val:
            ok(f"{key} — set ✓")
        else:
            err(f"{key} — MISSING or placeholder  ({desc})")
            all_ok = False
    for key, desc in optional.items():
        val = env.get(key, os.environ.get(key, ""))
        if val and not val.startswith("<") and "xxxx" not in val and "replace-with" not in val:
            ok(f"{key} — set ✓")
        else:
            warn(f"{key} — not set ({desc})")
    return all_ok


def check_dependencies() -> None:
    """Check Python package dependencies."""
    header("Step 2 — Python Dependencies")
    packages = {
        "fastapi": "FastAPI web framework",
        "uvicorn": "ASGI server",
        "motor": "Async MongoDB driver",
        "openai": "OpenAI SDK (optional enrichment)",
        "httpx": "Async HTTP client",
    }
    for pkg, desc in packages.items():
        try:
            __import__(pkg)
            ok(f"{pkg} — installed")
        except ImportError:
            err(f"{pkg} — NOT INSTALLED  ({desc})  →  pip install {pkg}")


def check_ngrok() -> str | None:
    """Check if ngrok is installed and return the tunnel command."""
    header("Step 3 — Tunnel Setup (ngrok)")
    ngrok_path = shutil.which("ngrok")
    if ngrok_path:
        ok(f"ngrok found at {ngrok_path}")
        print()
        print(f"  Run this command in a NEW terminal to create a public tunnel:")
        print(f"\n    {_BOLD}ngrok http 8080{_RESET}\n")
        print(f"  Copy the https://xxxx.ngrok-free.app URL for the next step.")
        return ngrok_path
    else:
        warn("ngrok not found. Install from: https://ngrok.com/download")
        print()
        print("  Alternatives for tunneling:")
        print("    - cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/")
        print("    - localtunnel: npx localtunnel --port 8080")
        print("    - Deploy to Railway / Render / Fly.io for a permanent public URL")
        return None


def print_github_instructions(env: dict[str, str]) -> None:
    """Print step-by-step GitHub webhook registration instructions."""
    header("Step 4 — Register GitHub Webhook")
    secret = env.get("GITHUB_WEBHOOK_SECRET", "<your-secret>")
    print("""
  1. Go to your GitHub repo → Settings → Webhooks → Add webhook

  2. Fill in the fields:
     ┌─────────────────────────────────────────────────────┐
     │ Payload URL   │ https://xxxx.ngrok-free.app/webhook/github  │
     │ Content type  │ application/json                            │
     │ Secret        │ (same as GITHUB_WEBHOOK_SECRET in .env)     │
     │ Events        │ ✅ Pull requests  (or "Send me everything") │
     └─────────────────────────────────────────────────────┘
""")
    print(f"  Your GITHUB_WEBHOOK_SECRET: {_BOLD}{secret[:6]}{'*'*max(0,len(secret)-6)}{_RESET}")
    print()
    print("  3. Click 'Add webhook' — GitHub will send a ping event immediately.")
    print("     Check the webhook delivery tab to verify the 200 response.")


def check_server() -> None:
    """Check if the FastAPI server is running."""
    header("Step 5 — Verify API Server")
    import urllib.request
    try:
        with urllib.request.urlopen("http://localhost:8080/healthz", timeout=3) as r:
            data = r.read().decode()
            ok(f"API server is RUNNING at http://localhost:8080  → {data.strip()}")
    except Exception as exc:
        warn(f"API server not reachable at http://localhost:8080  ({exc})")
        print()
        print("  Start the server with:")
        print(f"\n    {_BOLD}python -m uvicorn deployguard.api.main:app --host 0.0.0.0 --port 8080 --reload{_RESET}\n")


def print_summary() -> None:
    """Print the complete quick-start summary."""
    header("Quick-Start Checklist")
    print("""
  Terminal 1 — FastAPI + Built-in Web UI (http://localhost:8080):
    python -m uvicorn deployguard.api.main:app --host 0.0.0.0 --port 8080 --reload

  Terminal 2 — Optional Tunnel (for local GitHub webhooks):
    ngrok http 8080

  GitHub:
    Paste the tunnel/public URL into GitHub Webhooks as:
    https://your-domain.com/webhook/github

  Seed MongoDB (first time only):
    python scripts/seed_graph.py
    python scripts/ingest_incidents.py

  Or simply sign into the Web UI → Tab 1 (Setup & Team) → Create & Seed Real GitHub Repo!
""")


def main() -> None:
    print(f"\n{_BOLD}{'='*60}")
    print(f"  🛡️  DeployGuard AI — Webhook Setup Assistant")
    print(f"{'='*60}{_RESET}")

    env_path = ROOT / ".env"
    if not env_path.exists():
        warn(".env file not found — copying from .env.example...")
        example = ROOT / ".env.example"
        if example.exists():
            import shutil as sh
            sh.copy(example, env_path)
            ok("Created .env from .env.example — fill in your values!")
        else:
            err(".env.example not found either. Create .env manually.")
    else:
        ok(".env file found")

    env = load_env()

    env_ok = check_env_vars(env)
    check_dependencies()
    check_ngrok()
    print_github_instructions(env)
    check_server()
    print_summary()

    if not env_ok:
        print(f"\n  {_YELLOW}Action required:{_RESET} Edit .env and fill in the missing values, then re-run this script.\n")
    else:
        print(f"\n  {_GREEN}All environment variables configured!{_RESET} Follow steps 3–5 above.\n")


if __name__ == "__main__":
    main()
