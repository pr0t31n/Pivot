#!/usr/bin/env python3
"""
install.py — Pivot dependency installer
========================================
Installs all Python packages from requirements.txt and required system tools
(iptables / iproute2 / openssl) via apt (Linux) or brew (macOS).

Usage:
    python3 install.py
    python3 install.py --pip-only        # Python packages only
    python3 install.py --system-only     # System packages only
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"

SYSTEM = platform.system()
IS_LINUX = SYSTEM == "Linux"
IS_MACOS = SYSTEM == "Darwin"

# ── Colours ───────────────────────────────────────────────────────────────────
def _c(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def info(msg: str)    -> None: print(_c("36", f"[INFO]  {msg}"))
def ok(msg: str)      -> None: print(_c("32", f"[OK]    {msg}"))
def warn(msg: str)    -> None: print(_c("33", f"[WARN]  {msg}"), file=sys.stderr)
def error(msg: str)   -> None: print(_c("31", f"[ERROR] {msg}"), file=sys.stderr)
def section(msg: str) -> None: print(_c("35", f"\n{'='*60}\n  {msg}\n{'='*60}"))


def run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    info(f"Running: {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        error(f"Command failed (exit {result.returncode}): {' '.join(str(c) for c in cmd)}")
        sys.exit(result.returncode)
    return result


def cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


# ── Python packages ───────────────────────────────────────────────────────────
def install_python_packages() -> None:
    section("Installing Python packages (pip)")

    reqs = Path(__file__).parent / "requirements.txt"
    if not reqs.exists():
        error(f"requirements.txt not found at {reqs}")
        sys.exit(1)

    run([sys.executable, "-m", "pip", "install", "--break-system-packages", "--upgrade", "pip"])
    run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", str(reqs)])

    info("Installing pivot package in editable mode (registers pivot-agent / pivot-client)…")
    setup_py = Path(__file__).parent / "setup.py"
    if setup_py.exists():
        run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-e", str(Path(__file__).parent)])
    ok("Python packages installed.")


# ── System packages ───────────────────────────────────────────────────────────
# Linux: iptables (netfilter project / Harald Welte @laforge — https://www.netfilter.org)
#        iproute2 (Stephen Hemminger — https://github.com/iproute2/iproute2)
#        openssl  (OpenSSL Project — https://github.com/openssl/openssl)

APT_PACKAGES = [
    "iptables",          # NAT/MASQUERADE/FORWARD rules — netfilter.org
    "iproute2",          # ip route add/del on Linux
    "openssl",           # TLS certificate generation via pivot-gen-certs.sh
    "python3-pip",
    "python3-venv",
    "git",
    "curl",
    "ca-certificates",
    "procps",            # sysctl command for ip_forward
]

BREW_PACKAGES = [
    "openssl",           # TLS certificate generation via pivot-gen-certs.sh
    "git",
    "curl",
]


def install_system_linux() -> None:
    section("Installing system packages (apt)")
    if os.geteuid() != 0:
        warn("Not root — apt installs may require sudo. Consider re-running with sudo.")

    run(["apt-get", "update", "-y"])
    run(["apt-get", "install", "-y"] + APT_PACKAGES)
    ok("System packages installed.")

    # Verify iptables is accessible.
    if cmd_exists("iptables"):
        ok("iptables is available.")
    else:
        warn("iptables not found on PATH after installation. The pivot-agent will fail without it.")

    # Verify openssl is accessible.
    if cmd_exists("openssl"):
        ok("openssl is available.")
    else:
        warn("openssl not found. Run tools/pivot-gen-certs.sh manually after installing openssl.")


def install_system_macos() -> None:
    section("Installing system packages (brew)")
    if not cmd_exists("brew"):
        warn("Homebrew not found. Install from https://brew.sh then re-run.")
        return

    _brew_user = os.environ.get("SUDO_USER", "")
    _brew_pfx  = ["sudo", "-u", _brew_user] if _brew_user and _brew_user != "root" else []
    for pkg in BREW_PACKAGES:
        info(f"brew install {pkg}")
        run(_brew_pfx + ["brew", "install", pkg], check=False)

    # macOS does not ship iptables; warn the user.
    warn(
        "pivot-agent requires iptables and is only supported on Linux.\n"
        "       On macOS, only pivot-client is functional (route add via 'route' command)."
    )

    if cmd_exists("openssl"):
        ok("openssl is available (required for tools/pivot-gen-certs.sh).")
    else:
        warn("openssl not found after brew install. Check your PATH.")

    ok("macOS packages installed.")


# ── Post-install hints ────────────────────────────────────────────────────────
def print_post_install() -> None:
    section("Post-install steps")
    print("  1. Generate TLS certificates (relay device only):")
    print("       sudo bash tools/pivot-gen-certs.sh /etc/pivot/certs pivot-agent <relay-ip>")
    print()
    print("  2. Copy example configs:")
    print("       sudo cp config/pivot-agent.yaml.example /etc/pivot/agent_config.yaml")
    print("       sudo cp config/pivot-client.yaml.example /etc/pivot/client_config.yaml")
    print()
    print("  3. Edit configs — set auth_token, interfaces, CIDRs.")
    print()
    print("  4. Start the agent (relay device — Linux + root):")
    print("       sudo pivot-agent --config /etc/pivot/agent_config.yaml")
    print()
    print("  5. Or install as a systemd service:")
    print("       sudo bash tools/pivot-install-service.sh")
    print()
    print("  6. Start the client (scanner machine — Linux or macOS + root):")
    print("       sudo pivot-client --config /etc/pivot/client_config.yaml")


# ── Symlink installation ──────────────────────────────────────────────────────
def _install_symlinks() -> None:
    """Create /usr/local/bin symlinks for all-user access (including root)."""
    from pathlib import Path as _Path
    import stat as _stat
    app_dir = _Path(__file__).parent.resolve()
    bin_dir = _Path("/usr/local/bin")

    # (script_relative_to_app_dir, symlink_name_in_bin_dir)
    LINKS = [
        ("pivot/agent/main.py",  "pivot-agent"),
        ("pivot/client/main.py", "pivot-client"),
    ]

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        warn("Cannot access /usr/local/bin — run as root to install symlinks.")
        return

    for script_rel, link_name in LINKS:
        script = app_dir / script_rel
        link   = bin_dir / link_name
        if not script.exists():
            warn(f"Script not found, skipping symlink: {script}")
            continue
        # Make script executable
        current = script.stat().st_mode
        script.chmod(current | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
        # Ensure shebang
        try:
            text = script.read_text(encoding="utf-8", errors="ignore")
            if not text.startswith("#!"):
                script.write_text("#!/usr/bin/env python3\n" + text, encoding="utf-8")
        except Exception:
            pass
        # Create/replace symlink
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(script)
        ok(f"Symlink installed: {link}  →  {script}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description=f"Pivot installer v{VERSION} — installs Python packages and system tools.",
    )
    parser.add_argument("--pip-only",    action="store_true", help="Python packages only.")
    parser.add_argument("--system-only", action="store_true", help="System packages only.")
    args = parser.parse_args()

    print(_c("36", f"""
╔══════════════════════════════════════════════════════╗
║          Pivot Installer  v{VERSION}                   ║
║   Secure IP-layer relay for multi-hop scanning      ║
║   Platform: {SYSTEM:<43}║
╚══════════════════════════════════════════════════════╝
"""))

    if not args.system_only:
        install_python_packages()

    if not args.pip_only:
        if IS_LINUX:
            install_system_linux()
        elif IS_MACOS:
            install_system_macos()
        else:
            warn(f"Unsupported platform '{SYSTEM}' — skipping system package install.")

    print_post_install()
    _install_symlinks()
    print(_c("32", "\n[DONE]  Pivot installation complete.\n"))


if __name__ == "__main__":
    main()
