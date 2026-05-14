#!/usr/bin/env python3
"""
LogGuard Interactive Setup Wizard
==================================
Run this script once to configure the key environment variables needed to
start LogGuard for the first time.

Usage:
    python scripts/setup.py

The wizard will write the chosen values to a ``.env`` file in the project
root.  LogGuard reads this file automatically when ``python-dotenv`` is
installed (it is listed in requirements.txt).

You can re-run the wizard at any time – it will offer to update the existing
``.env`` file rather than overwriting it silently.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"


def _c(colour: str, text: str) -> str:
    """Wrap text in an ANSI colour code (stripped on non-TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{colour}{text}{RESET}"


def ask(prompt: str, default: str = "") -> str:
    """Prompt the user for input; return *default* on empty answer."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value or default


def ask_password(prompt: str) -> str:
    """Prompt for a password (hides input when possible)."""
    import getpass
    try:
        value = getpass.getpass(f"  {prompt}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value.strip()


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question."""
    default_str = "Y/n" if default else "y/N"
    answer = ask(f"{prompt} ({default_str})").lower()
    if not answer:
        return default
    return answer.startswith("y")


def _divider(char: str = "─", width: int = 60) -> str:
    return _c(DIM, char * width)


# ---------------------------------------------------------------------------
# Main wizard
# ---------------------------------------------------------------------------

def main() -> None:
    root = Path(__file__).resolve().parent.parent
    env_path = root / ".env"

    print()
    print(_c(CYAN, _divider("═")))
    print(_c(BOLD, "  🛡  LogGuard — Interactive Setup Wizard"))
    print(_c(CYAN, _divider("═")))
    print()
    print("  This wizard will guide you through the initial configuration.")
    print("  Values are saved to " + _c(BOLD, str(env_path)))
    print()

    existing: dict[str, str] = {}
    if env_path.exists():
        print(_c(YELLOW, "  ⚠  A .env file already exists at the project root."))
        if not ask_yes_no("  Overwrite / update it?", default=True):
            print()
            print(_c(GREEN, "  Nothing changed. Exiting."))
            print()
            return
        # Parse the existing file so we can use current values as defaults
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip().strip('"').strip("'")
        print()

    config: dict[str, str] = {}

    # ── Admin credentials ─────────────────────────────────────────────────
    print(_c(BOLD, "  [ 1 / 4 ]  Admin Account"))
    print(_c(DIM,  "  The first user created will have the admin role."))
    print()
    config["LOGGUARD_ADMIN_USERNAME"] = ask(
        "Admin username", existing.get("LOGGUARD_ADMIN_USERNAME", "admin")
    )
    while True:
        password = ask_password("Admin password (min 8 chars)")
        if len(password) >= 8:
            break
        print(_c(RED, "  Password must be at least 8 characters. Please try again."))
    config["LOGGUARD_ADMIN_PASSWORD"] = password

    # ── Secret key ────────────────────────────────────────────────────────
    print()
    print(_c(BOLD, "  [ 2 / 4 ]  Flask Secret Key"))
    print(_c(DIM,  "  Used to sign session cookies. Use a long random value in production."))
    print()
    generated = secrets.token_hex(32)
    # Use the existing key as the default so it is preserved on re-runs;
    # fall back to a freshly generated key if no existing value is found.
    secret_default = existing.get("LOGGUARD_SECRET_KEY", generated)
    user_secret = ask("Secret key (press Enter to auto-generate)", secret_default)
    config["LOGGUARD_SECRET_KEY"] = user_secret if user_secret else generated

    # ── Optional: SMTP ────────────────────────────────────────────────────
    print()
    print(_c(BOLD, "  [ 3 / 4 ]  Email (SMTP) — optional"))
    print(_c(DIM,  "  Required only if you want to send PDF reports via email."))
    print()
    if ask_yes_no("  Configure SMTP settings?", default=False):
        config["LOGGUARD_SMTP_HOST"]     = ask("SMTP host",     existing.get("LOGGUARD_SMTP_HOST", "smtp.gmail.com"))
        config["LOGGUARD_SMTP_PORT"]     = ask("SMTP port",     existing.get("LOGGUARD_SMTP_PORT", "587"))
        config["LOGGUARD_SMTP_USER"]     = ask("SMTP username", existing.get("LOGGUARD_SMTP_USER", ""))
        config["LOGGUARD_SMTP_PASSWORD"] = ask_password("SMTP password / App Password")
        config["LOGGUARD_SMTP_FROM"]     = ask(
            "From address", existing.get("LOGGUARD_SMTP_FROM", config["LOGGUARD_SMTP_USER"])
        )
    else:
        print(_c(DIM, "  Skipped SMTP configuration."))

    # ── Optional: Slack webhook ────────────────────────────────────────────
    print()
    print(_c(BOLD, "  [ 4 / 4 ]  Slack Webhook — optional"))
    print(_c(DIM,  "  Required only if you want critical-anomaly Slack alerts."))
    print()
    if ask_yes_no("  Configure Slack webhook?", default=False):
        config["LOGGUARD_SLACK_WEBHOOK_URL"] = ask(
            "Slack webhook URL", existing.get("LOGGUARD_SLACK_WEBHOOK_URL", "")
        )
    else:
        print(_c(DIM, "  Skipped Slack configuration."))

    # ── Write .env ─────────────────────────────────────────────────────────
    print()
    print(_c(BOLD, "  Writing configuration…"))
    lines = [
        "# LogGuard environment configuration",
        "# Generated by scripts/setup.py — edit as needed",
        "#",
        "# ⚠  SECURITY: This file contains credentials. Never commit it to",
        "#    version control. It is listed in .gitignore for your protection.",
        "",
    ]
    for key, value in config.items():
        # Use json.dumps to produce a properly escaped double-quoted string
        # whenever the value contains whitespace or shell-special characters.
        if any(c in value for c in (' ', '#', '"', "'", '\\', '$', '`', '\n', '\t')):
            value = json.dumps(value)
        lines.append(f"{key}={value}")
    lines.append("")

    env_path.write_text("\n".join(lines))

    print()
    print(_c(GREEN, "  ✅  Configuration saved to " + str(env_path)))
    print()
    print(_c(YELLOW, "  ⚠  Security reminder: .env contains credentials."))
    print(_c(YELLOW, "     Ensure it is not committed to version control."))
    print()
    print(_c(BOLD, "  Next steps:"))
    print("    1. Start the server:  " + _c(CYAN, "python -m flask --app app/app.py run"))
    print("    2. Open your browser: " + _c(CYAN, "http://localhost:5000"))
    print("    3. Sign in with the admin credentials you just set.")
    print()
    print(_c(CYAN, _divider("═")))
    print()


if __name__ == "__main__":
    main()
