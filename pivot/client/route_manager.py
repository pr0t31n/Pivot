"""
pivot/client/route_manager.py

Cross-platform management of temporary host routes on the scanner server.

When the pivot client activates a network profile, it installs a host
route on the local OS so that scan traffic destined for the target CIDR
is forwarded through the relay device's VPN IP.  These routes are removed
on clean shutdown and also via an atexit handler for abrupt termination.

Supported platforms:
  - Linux  (uses `ip route add/del` from iproute2)
  - macOS  (uses `route add/delete`)

All subprocess calls use explicit argument lists (no shell=True) to
prevent command injection.
"""

import atexit
import logging
import os
import platform
import subprocess
import threading
from dataclasses import dataclass, field
from typing import List, Tuple

logger = logging.getLogger(__name__)

_SYSTEM = platform.system()  # "Linux" | "Darwin" | ...


@dataclass
class _Route:
    """Record of an installed route so we can remove it later."""

    cidr: str       # Target network, e.g. "10.0.0.0/24"
    gateway: str    # Relay VPN IP, e.g. "192.168.1.5"


class RouteManager:
    """
    Adds and removes OS routes to direct scan traffic through the relay.

    Thread-safe via a threading.Lock.  Register cleanup on process exit
    via the atexit handler installed in __init__.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._routes: List[_Route] = []
        atexit.register(self._emergency_cleanup)
        logger.debug("RouteManager initialised (platform=%s)", _SYSTEM)

    def add_route(self, cidr: str, gateway: str) -> None:
        """
        Install a host route: *cidr* via *gateway*.

        Args:
            cidr:    Target network in CIDR notation (e.g. "10.0.0.0/24").
            gateway: VPN IP of the relay device (e.g. "192.168.1.5").

        Raises:
            RuntimeError: If the route command fails.
        """
        with self._lock:
            # Avoid duplicate entries.
            for existing in self._routes:
                if existing.cidr == cidr and existing.gateway == gateway:
                    logger.debug("Route already installed: %s via %s", cidr, gateway)
                    return

            cmd = _build_add_command(cidr, gateway)
            _run_command(cmd)
            self._routes.append(_Route(cidr=cidr, gateway=gateway))
            logger.info("Route added: %s via %s", cidr, gateway)

    def remove_route(self, cidr: str, gateway: str) -> None:
        """
        Remove a previously installed host route.

        Args:
            cidr:    Target network in CIDR notation.
            gateway: VPN IP of the relay device.

        Raises:
            RuntimeError: If the route command fails.
        """
        with self._lock:
            cmd = _build_del_command(cidr, gateway)
            try:
                _run_command(cmd)
            except RuntimeError as exc:
                logger.warning("Route removal may have failed: %s", exc)

            self._routes = [
                r for r in self._routes
                if not (r.cidr == cidr and r.gateway == gateway)
            ]
            logger.info("Route removed: %s via %s", cidr, gateway)

    def remove_all_routes(self) -> None:
        """Remove every route installed by this manager."""
        with self._lock:
            routes_to_remove = list(self._routes)
            self._routes = []

        for route in reversed(routes_to_remove):
            cmd = _build_del_command(route.cidr, route.gateway)
            try:
                _run_command(cmd)
                logger.info("Route removed: %s via %s", route.cidr, route.gateway)
            except RuntimeError as exc:
                logger.warning(
                    "Failed to remove route %s via %s: %s",
                    route.cidr, route.gateway, exc,
                )

    # ------------------------------------------------------------------
    # Emergency cleanup
    # ------------------------------------------------------------------

    def _emergency_cleanup(self) -> None:
        """
        Best-effort route cleanup invoked by atexit.

        Errors are logged but not re-raised so atexit handlers continue.
        """
        with self._lock:
            if not self._routes:
                return
            logger.warning(
                "Emergency cleanup: removing %d route(s)", len(self._routes)
            )
            routes = list(self._routes)
            self._routes = []

        for route in reversed(routes):
            cmd = _build_del_command(route.cidr, route.gateway)
            try:
                _run_command(cmd)
                logger.info(
                    "Emergency route removed: %s via %s", route.cidr, route.gateway
                )
            except Exception as exc:
                logger.error(
                    "Emergency route removal failed for %s via %s: %s",
                    route.cidr, route.gateway, exc,
                )


# ---------------------------------------------------------------------------
# Platform-specific command builders
# ---------------------------------------------------------------------------

def _build_add_command(cidr: str, gateway: str) -> List[str]:
    """Build the OS-specific command to add a route."""
    if _SYSTEM == "Linux":
        return ["ip", "route", "add", cidr, "via", gateway]
    elif _SYSTEM == "Darwin":
        # macOS route syntax: route add -net <cidr> <gateway>
        return ["route", "add", "-net", cidr, gateway]
    else:
        raise RuntimeError(
            f"Unsupported platform: {_SYSTEM}. "
            "Route management is supported on Linux and macOS only."
        )


def _build_del_command(cidr: str, gateway: str) -> List[str]:
    """Build the OS-specific command to remove a route."""
    if _SYSTEM == "Linux":
        return ["ip", "route", "del", cidr, "via", gateway]
    elif _SYSTEM == "Darwin":
        return ["route", "delete", "-net", cidr, gateway]
    else:
        raise RuntimeError(
            f"Unsupported platform: {_SYSTEM}. "
            "Route management is supported on Linux and macOS only."
        )


def _run_command(cmd: List[str]) -> str:
    """
    Execute a command and return decoded stdout.

    Args:
        cmd: Argument list (no shell expansion).

    Returns:
        Decoded stdout string.

    Raises:
        RuntimeError: On command not found, timeout, or non-zero exit.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Route command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Route command timed out: {' '.join(cmd)}"
        ) from exc

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"Route command failed (exit {result.returncode}): "
            f"{' '.join(cmd)} – {stderr or stdout}"
        )

    return result.stdout.decode("utf-8", errors="replace")
