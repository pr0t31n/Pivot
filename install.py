#!/usr/bin/env python3
"""
Pivot — Transparent Proxy / Tunnel Tool
Install script for /opt/pr0t31n/Pivot/
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ─── ANSI colours ────────────────────────────────────────────────────────────
R  = "\033[1;31m"
G  = "\033[1;32m"
Y  = "\033[1;33m"
B  = "\033[1;34m"
C  = "\033[1;36m"
W  = "\033[0m"
# ─────────────────────────────────────────────────────────────────────────────

APP_NAME = "Pivot"
APP_DIR  = Path("/opt/pr0t31n/Pivot")
BIN_DIR  = Path("/usr/local/bin")

SYMLINKS = {
    "pivot-agent":  APP_DIR / "pivot" / "agent"  / "main.py",
    "pivot-client": APP_DIR / "pivot" / "client" / "main.py",
}

# system package lists --------------------------------------------------------
APT_PKGS = [
    "iptables", "iproute2", "openssl", "python3-pip", "python3-dev",
    "git", "curl", "ca-certificates", "procps",
]
DNF_PKGS = [
    "iptables", "iproute", "openssl", "python3-pip", "python3-devel",
    "git", "curl", "ca-certificates", "procps-ng",
]
ZYPPER_PKGS = [
    "iptables", "iproute2", "openssl", "python3-pip", "python3-devel",
    "git", "curl", "ca-certificates", "procps",
]
BREW_PKGS = [
    "openssl", "git", "curl",
]

# pip packages ----------------------------------------------------------------
PIP_PKGS = [
    "PyYAML>=6.0",
    "cryptography>=41.0.0",
]

# Verification tools ----------------------------------------------------------
VERIFY_BINS_LINUX = ["iptables", "openssl", "ip", "sysctl"]
VERIFY_BINS_MACOS = ["openssl"]
VERIFY_MODS       = ["yaml", "cryptography"]

# ─── helpers ─────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════╗
║        Pivot — Transparent Proxy/Tunnel      ║
║        Install Script                        ║
╚══════════════════════════════════════════════╝{W}
""")


def info(msg):  print(f"{G}[+]{W} {msg}")
def warn(msg):  print(f"{Y}[!]{W} {msg}")
def err(msg):   print(f"{R}[✗]{W} {msg}")
def step(msg):  print(f"\n{B}━━ {msg} ━━{W}")


def run(cmd, **kwargs):
    print(f"    {C}>{W} {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(str(c) for c in cmd)}")
    return result


def run_ok(cmd, **kwargs):
    try:
        subprocess.run(cmd, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       **kwargs)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def require_root():
    if platform.system() != "Darwin" and os.geteuid() != 0:
        err("This script must be run as root (or with sudo) on Linux.")
        sys.exit(1)


def detect_os():
    system = platform.system()
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    os_release = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    os_release[k] = v.strip('"')
    except FileNotFoundError:
        pass
    dist_id = os_release.get("ID", "").lower()
    id_like  = os_release.get("ID_LIKE", "").lower()
    if dist_id in ("kali", "ubuntu", "debian") or "debian" in id_like:
        return "apt"
    if dist_id in ("rhel", "centos", "rocky", "almalinux", "fedora") or "rhel" in id_like or "fedora" in id_like:
        return "dnf"
    if dist_id in ("sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed") or "suse" in id_like:
        return "zypper"
    return "apt"


def _pip_cmd():
    if shutil.which("pip3"):
        return ["pip3"]
    if shutil.which("pip"):
        return ["pip"]
    return [sys.executable, "-m", "pip"]


def _brew_install(pkgs):
    brew_path = shutil.which("brew")
    if not brew_path:
        warn("Homebrew not found; skipping brew installs.")
        return
    SUDO_USER = os.environ.get("SUDO_USER", "")
    for pkg in pkgs:
        if os.getuid() == 0:
            if not SUDO_USER:
                warn(f"Running as root with no SUDO_USER — cannot brew install {pkg}; skipping.")
                continue
            run(["sudo", "-u", SUDO_USER, brew_path, "install", pkg])
        else:
            run([brew_path, "install", pkg])


# ─── Windows warning ─────────────────────────────────────────────────────────

def windows_warning():
    print(f"""
{R}[WARNING] Windows detected.{W}

  Pivot relies on Linux-specific {Y}iptables{W} for transparent proxy routing and
  the {Y}ip{W} command (iproute2) for network interface management. These are not
  available on Windows.

  Windows support is {R}very limited{W}:
    - The tunnel/encryption components may work on Windows.
    - Transparent proxy (iptables REDIRECT rules) will NOT work on Windows.
      You would need to implement Windows Filtering Platform (WFP) rules
      or a different interception mechanism manually.

  To run Pivot on Windows for non-transparent-proxy use cases:
    1. Install Python 3.10+ from https://python.org/
    2. Install Git from https://git-scm.com/
    3. Install OpenSSL for Windows from https://slproweb.com/products/Win32OpenSSL.html
    4. Run: pip install PyYAML cryptography
    5. Launch agent/client directly: python pivot\\agent\\main.py
                                     python pivot\\client\\main.py
""")


# ─── phase 1: system packages ────────────────────────────────────────────────

def install_system_packages(os_type, args):
    step("Phase 1 — System Packages")
    if args.skip_apt:
        warn("--skip-system set; skipping.")
        return

    if os_type == "windows":
        windows_warning()
        return

    if os_type == "macos":
        warn("iptables and iproute2 are Linux-only; skipping those for macOS.")
        _brew_install(BREW_PKGS)
        return

    if os_type == "apt":
        info("Running apt update + apt upgrade …")
        run(["apt-get", "update", "-y"])
        run(["apt-get", "upgrade", "-y"])
        info("Installing APT packages …")
        run(["apt-get", "install", "-y"] + APT_PKGS)

    elif os_type == "dnf":
        info("Installing DNF packages …")
        run(["dnf", "install", "-y"] + DNF_PKGS)

    elif os_type == "zypper":
        info("Installing zypper packages …")
        run(["zypper", "install", "-y"] + ZYPPER_PKGS)


# ─── phase 2: pip packages ───────────────────────────────────────────────────

def install_pip_packages(args):
    step("Phase 2 — Pip Packages")
    if args.skip_pip:
        warn("--skip-pip set; skipping.")
        return
    pip = _pip_cmd()
    for pkg in PIP_PKGS:
        info(f"pip install {pkg} …")
        try:
            run(pip + ["install", "--break-system-packages", pkg])
        except RuntimeError as exc:
            warn(f"pip install failed for {pkg}: {exc}")


# ─── phase 3: go tools (none for Pivot) ──────────────────────────────────────

def install_go_tools(args):
    step("Phase 3 — Go Tools")
    if args.skip_go:
        warn("--skip-go set; skipping.")
        return
    info("Pivot has no Go tool dependencies — phase skipped.")


# ─── phase 4: git tools (none for Pivot) ─────────────────────────────────────

def install_git_tools(args):
    step("Phase 4 — Git Tools")
    if args.skip_git:
        warn("--skip-git set; skipping.")
        return
    info("Pivot has no git-cloned tool dependencies — phase skipped.")


# ─── symlinks ────────────────────────────────────────────────────────────────

def install_symlinks():
    step("Creating Symlinks")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    for link_name, target in SYMLINKS.items():
        link_path = BIN_DIR / link_name
        if not target.exists():
            warn(f"Target {target} not found; skipping symlink {link_name}.")
            continue
        if link_path.is_symlink() or link_path.exists():
            link_path.unlink()
        # Ensure target script is executable
        target.chmod(target.stat().st_mode | 0o755)
        link_path.symlink_to(target)
        info(f"Symlink: {link_path} → {target}")


# ─── check mode ──────────────────────────────────────────────────────────────

def run_check():
    step("Check Mode — Dependency Status")
    os_type  = detect_os()
    all_ok   = True

    verify_bins = VERIFY_BINS_LINUX if os_type in ("apt", "dnf", "zypper") else VERIFY_BINS_MACOS

    for tool in verify_bins:
        path = shutil.which(tool)
        if path:
            info(f"{tool:22s} {G}OK{W}  ({path})")
        else:
            # iptables missing on macOS is expected
            if tool == "iptables" and os_type == "macos":
                warn(f"{tool:22s} {Y}N/A (macOS){W}")
            else:
                err(f"{tool:22s} {R}MISSING{W}")
                all_ok = False

    for mod in VERIFY_MODS:
        ok = run_ok([sys.executable, "-c", f"import {mod}"])
        marker = f"python:{mod}"
        if ok:
            info(f"{marker:22s} {G}OK{W}")
        else:
            err(f"{marker:22s} {R}MISSING{W}")
            all_ok = False

    for name, target in SYMLINKS.items():
        link = BIN_DIR / name
        ok = link.is_symlink()
        status = f"{G}OK{W}" if ok else f"{Y}MISSING{W}"
        print(f"  {'symlink:'+name:22s} {status}  ({link})")

    print()
    if all_ok:
        info(f"{G}All checks passed.{W}")
    else:
        warn(f"{Y}Some checks failed.{W}")
    return all_ok


# ─── post-install summary ────────────────────────────────────────────────────

def post_install_summary(os_type):
    step("Post-Install Verification Summary")
    results = []

    verify_bins = VERIFY_BINS_LINUX if os_type in ("apt", "dnf", "zypper") else VERIFY_BINS_MACOS
    for tool in verify_bins:
        path = shutil.which(tool)
        if tool == "iptables" and os_type == "macos":
            # Not applicable on macOS — mark as OK to avoid false failure
            results.append((tool, True, "N/A (macOS)"))
        else:
            results.append((tool, bool(path), path or "missing"))

    for mod in VERIFY_MODS:
        ok = run_ok([sys.executable, "-c", f"import {mod}"])
        results.append((f"python:{mod}", ok, "installed" if ok else "missing"))

    for name, target in SYMLINKS.items():
        link = BIN_DIR / name
        ok = link.is_symlink()
        results.append((f"symlink:{name}", ok, str(link) if ok else "missing"))

    pad = max(len(r[0]) for r in results) + 2
    print()
    for label, ok, detail in results:
        status = f"{G}OK{W}" if ok else f"{R}FAIL{W}"
        print(f"  {label:<{pad}} {status}  {detail}")

    failed = [r for r in results if not r[1]]
    print()
    if not failed:
        info(f"{G}Pivot installation complete and verified.{W}")
        info(f"Agent:  {C}pivot-agent{W}  (or  python3 {APP_DIR}/pivot/agent/main.py)")
        info(f"Client: {C}pivot-client{W} (or  python3 {APP_DIR}/pivot/client/main.py)")
        if os_type in ("apt", "dnf", "zypper"):
            info("Transparent proxy requires root + iptables REDIRECT rules.")
    else:
        warn(f"{Y}{len(failed)} item(s) need attention (see above).{W}")


# ─── main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description=f"Installer for {APP_NAME}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--skip-apt",    "--skip-system", dest="skip_apt",
                   action="store_true", help="Skip system package installation")
    p.add_argument("--skip-pip",    action="store_true",
                   help="Skip pip package installation")
    p.add_argument("--skip-go",     action="store_true",
                   help="Skip Go tools phase (no-op for Pivot)")
    p.add_argument("--skip-git",    action="store_true",
                   help="Skip git tools phase (no-op for Pivot)")
    p.add_argument("--check",       action="store_true",
                   help="Check dependencies without installing")
    return p.parse_args()


def main():
    banner()
    args = parse_args()
    os_type = detect_os()
    info(f"Detected OS type: {os_type}")

    if args.check:
        ok = run_check()
        sys.exit(0 if ok else 1)

    if os_type == "windows":
        windows_warning()
        # Still attempt pip install on Windows for partial functionality
        install_pip_packages(args)
        sys.exit(0)

    require_root()

    # Phase 1 — system packages
    install_system_packages(os_type, args)

    # Phase 2 — pip packages
    install_pip_packages(args)

    # Phase 3 — Go tools (no-op)
    install_go_tools(args)

    # Phase 4 — Git tools (no-op)
    install_git_tools(args)

    # Symlinks
    install_symlinks()

    # Summary
    post_install_summary(os_type)


if __name__ == "__main__":
    main()
