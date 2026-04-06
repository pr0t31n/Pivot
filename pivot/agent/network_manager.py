"""
pivot/agent/network_manager.py

Manages the kernel-level networking changes required to route scan traffic
from the VPN interface to the target LAN:

  1. Enables IPv4 packet forwarding (net.ipv4.ip_forward).
  2. Adds iptables FORWARD rules to allow VPN ↔ LAN traffic.
  3. Adds an iptables POSTROUTING MASQUERADE rule so scans appear to
     originate from the relay device's LAN IP.

All rules are tagged with a session-specific iptables comment so they can
be removed precisely without touching unrelated rules.  The original
ip_forward sysctl value is restored on cleanup.

Security notes
--------------
* No shell=True is used anywhere – all subprocess calls use explicit
  argument lists to prevent injection attacks.
* An atexit handler and signal wrappers in main.py guarantee cleanup even
  on abrupt termination.
"""

import asyncio
import atexit
import ipaddress
import logging
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Path to the sysctl key controlling IPv4 packet forwarding.
_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"

# iptables binary locations (searched in order).
_IPTABLES_CANDIDATES = ["/sbin/iptables", "/usr/sbin/iptables", "iptables"]


@dataclass
class _IptablesRule:
    """
    Record of a single iptables rule so we can remove it later.

    Fields mirror the iptables CLI arguments used to add the rule so
    that deletion is straightforward.
    """

    table: str       # e.g. "filter" or "nat"
    chain: str       # e.g. "FORWARD" or "POSTROUTING"
    args: List[str]  # rule specification (everything after -A <chain>)
    comment: str     # the --comment value (used to confirm during deletion)


@dataclass
class _KernelRoute:
    """
    Record of a kernel IP route installed by this manager.

    Used for chained profiles where the relay device itself needs a route
    pointing to the next hop (upstream relay VPN IP).
    """

    cidr: str      # Target network, e.g. "10.1.0.0/24"
    gateway: str   # Next-hop IP, e.g. upstream relay's VPN IP


@dataclass
class _NetworkState:
    """Tracks active rules and routes for a single network profile within a session."""

    session_id: str
    profile_name: str
    rules: List[_IptablesRule] = field(default_factory=list)
    routes: List[_KernelRoute] = field(default_factory=list)  # kernel routes (chained only)


class NetworkManager:
    """
    Thread-safe controller for kernel IP-forwarding and iptables state.

    One NetworkManager instance is shared across all concurrent relay
    sessions.  A threading.Lock serialises all mutation; async callers
    must use run_in_executor when invoking blocking methods.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Maps (session_id, profile_name) → _NetworkState
        self._active: Dict[Tuple[str, str], _NetworkState] = {}
        # Original ip_forward value before we first enabled forwarding.
        self._original_ip_forward: Optional[str] = None
        # Count of sessions that asked us to enable ip_forward.
        self._ip_forward_refcount: int = 0
        # Locate the iptables binary once at construction.
        self._iptables: str = self._find_iptables()

        # Register emergency cleanup in case the process dies unexpectedly.
        atexit.register(self._emergency_cleanup)

    # ------------------------------------------------------------------
    # Public API (called from session_manager.py via run_in_executor)
    # ------------------------------------------------------------------

    def activate_network(
        self,
        session_id: str,
        profile,
        upstream_vpn_ip: Optional[str] = None,
    ) -> str:
        """
        Enable IP forwarding and install iptables rules for *profile*.

        For direct profiles (upstream_vpn_ip is None), iptables rules are
        installed to allow traffic from the VPN interface to the target LAN
        via egress_interface, with MASQUERADE so scans originate from this
        relay's LAN IP.

        For chained profiles (upstream_vpn_ip is set), iptables rules are
        installed to forward traffic from the VPN interface to egress_interface
        (which faces the upstream relay), and a kernel route is added so the
        OS knows to reach the target CIDR via the upstream relay's VPN IP.

        Args:
            session_id:      Unique identifier for the calling relay session.
            profile:         NetworkProfile dataclass from config.
            upstream_vpn_ip: IP of the upstream relay (chained profiles only).
                             This relay will install a kernel route:
                             target_cidr → upstream_vpn_ip.

        Returns:
            The relay device's IP address on its own VPN interface, so the
            scanner (or parent relay) can add a host route through it.

        Raises:
            RuntimeError: If iptables commands fail or the interface IP
                          cannot be determined.
        """
        with self._lock:
            key = (session_id, profile.name)
            if key in self._active:
                logger.warning(
                    "Network profile '%s' already active for session %s",
                    profile.name, session_id,
                )
                return self._get_interface_ip(profile.vpn_interface)

            state = _NetworkState(
                session_id=session_id,
                profile_name=profile.name,
            )

            # Enable ip_forward (idempotent; tracked with a ref-count).
            self._enable_ip_forward(state)

            # Unique comment tags every rule this session creates.
            comment = f"pivot-{session_id[:8]}-{profile.name}"

            if upstream_vpn_ip:
                # ----------------------------------------------------------
                # Chained profile: traffic flows VPN → egress → upstream relay
                # ----------------------------------------------------------
                # Install a kernel route so this device knows where to send
                # packets destined for the target CIDR.
                self._add_kernel_route(state, profile.target_cidr, upstream_vpn_ip)

                # Allow forwarding: VPN interface → egress interface (toward upstream relay)
                self._add_rule(
                    state,
                    table="filter",
                    chain="FORWARD",
                    args=[
                        "-i", profile.vpn_interface,
                        "-o", profile.egress_interface,
                        "-d", profile.target_cidr,
                        "-m", "comment", "--comment", comment,
                        "-j", "ACCEPT",
                    ],
                    comment=comment,
                )

                # Allow established/related return traffic
                self._add_rule(
                    state,
                    table="filter",
                    chain="FORWARD",
                    args=[
                        "-i", profile.egress_interface,
                        "-o", profile.vpn_interface,
                        "-m", "state", "--state", "ESTABLISHED,RELATED",
                        "-m", "comment", "--comment", comment,
                        "-j", "ACCEPT",
                    ],
                    comment=comment,
                )

                # MASQUERADE: rewrite source to this relay's egress IP so
                # the upstream relay sees traffic from a known address.
                self._add_rule(
                    state,
                    table="nat",
                    chain="POSTROUTING",
                    args=[
                        "-o", profile.egress_interface,
                        "-d", profile.target_cidr,
                        "-m", "comment", "--comment", comment,
                        "-j", "MASQUERADE",
                    ],
                    comment=comment,
                )

                logger.info(
                    "Chained network activated | session=%s profile=%s "
                    "cidr=%s upstream_gateway=%s egress=%s",
                    session_id, profile.name, profile.target_cidr,
                    upstream_vpn_ip, profile.egress_interface,
                )

            else:
                # ----------------------------------------------------------
                # Direct profile: traffic flows VPN → egress → target LAN
                # ----------------------------------------------------------
                # Allow forwarding: VPN interface → target LAN interface
                self._add_rule(
                    state,
                    table="filter",
                    chain="FORWARD",
                    args=[
                        "-i", profile.vpn_interface,
                        "-o", profile.egress_interface,
                        "-d", profile.target_cidr,
                        "-m", "comment", "--comment", comment,
                        "-j", "ACCEPT",
                    ],
                    comment=comment,
                )

                # Allow established/related return traffic
                self._add_rule(
                    state,
                    table="filter",
                    chain="FORWARD",
                    args=[
                        "-i", profile.egress_interface,
                        "-o", profile.vpn_interface,
                        "-m", "state", "--state", "ESTABLISHED,RELATED",
                        "-m", "comment", "--comment", comment,
                        "-j", "ACCEPT",
                    ],
                    comment=comment,
                )

                # MASQUERADE: scans appear to originate from this relay's LAN IP
                self._add_rule(
                    state,
                    table="nat",
                    chain="POSTROUTING",
                    args=[
                        "-o", profile.egress_interface,
                        "-d", profile.target_cidr,
                        "-m", "comment", "--comment", comment,
                        "-j", "MASQUERADE",
                    ],
                    comment=comment,
                )

                logger.info(
                    "Direct network activated | session=%s profile=%s "
                    "cidr=%s egress=%s",
                    session_id, profile.name, profile.target_cidr,
                    profile.egress_interface,
                )

            self._active[key] = state
            vpn_ip = self._get_interface_ip(profile.vpn_interface)
            return vpn_ip

    def deactivate_network(self, session_id: str, profile_name: str) -> None:
        """
        Remove iptables rules, kernel routes, and restore ip_forward for one profile.

        Args:
            session_id:   Relay session identifier.
            profile_name: Name of the network profile to deactivate.
        """
        with self._lock:
            key = (session_id, profile_name)
            state = self._active.pop(key, None)
            if state is None:
                logger.debug(
                    "deactivate_network: no active state for session=%s profile=%s",
                    session_id, profile_name,
                )
                return
            self._remove_state(state)
            self._restore_ip_forward()
            logger.info(
                "Network deactivated | session=%s profile=%s",
                session_id, profile_name,
            )

    def deactivate_session(self, session_id: str) -> None:
        """
        Remove all network profiles associated with *session_id*.

        Args:
            session_id: Relay session identifier to clean up.
        """
        with self._lock:
            keys = [k for k in self._active if k[0] == session_id]
            for key in keys:
                state = self._active.pop(key)
                self._remove_state(state)
                self._restore_ip_forward()
                logger.info(
                    "Session deactivated | session=%s profile=%s",
                    session_id, key[1],
                )

    def get_vpn_ip(self, vpn_interface: str) -> str:
        """
        Return the primary IPv4 address of *vpn_interface*.

        Args:
            vpn_interface: Network interface name (e.g. "tun0").

        Returns:
            IPv4 address string.

        Raises:
            RuntimeError: If the address cannot be determined.
        """
        return self._get_interface_ip(vpn_interface)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enable_ip_forward(self, state: _NetworkState) -> None:
        """Enable net.ipv4.ip_forward, saving the original value first."""
        if self._ip_forward_refcount == 0:
            # Save the current value before we change it.
            current = self._read_sysctl(_IP_FORWARD_PATH)
            self._original_ip_forward = current
            if current != "1":
                self._write_sysctl(_IP_FORWARD_PATH, "1")
                logger.info("ip_forward enabled (was '%s')", current)
            else:
                logger.debug("ip_forward already enabled")
        self._ip_forward_refcount += 1

    def _restore_ip_forward(self) -> None:
        """Decrement ref-count; restore original value when it reaches zero."""
        if self._ip_forward_refcount <= 0:
            return
        self._ip_forward_refcount -= 1
        if self._ip_forward_refcount == 0 and self._original_ip_forward is not None:
            try:
                self._write_sysctl(_IP_FORWARD_PATH, self._original_ip_forward)
                logger.info("ip_forward restored to '%s'", self._original_ip_forward)
            except Exception as exc:
                logger.error("Failed to restore ip_forward: %s", exc)

    def _add_kernel_route(
        self, state: _NetworkState, cidr: str, gateway: str
    ) -> None:
        """
        Install a kernel IP route: *cidr* via *gateway* on this relay device.

        Used for chained profiles so the relay's OS knows how to forward
        packets destined for the target network toward the upstream relay.

        Args:
            state:   Network state to record this route for later cleanup.
            cidr:    Target network in CIDR notation, e.g. "10.1.0.0/24".
            gateway: Next-hop IP (upstream relay's VPN IP), e.g. "10.0.0.50".

        Raises:
            RuntimeError: If the 'ip route add' command fails.
        """
        cmd = ["ip", "route", "add", cidr, "via", gateway]
        self._run_command(cmd)
        state.routes.append(_KernelRoute(cidr=cidr, gateway=gateway))
        logger.debug("Kernel route added: %s via %s", cidr, gateway)

    def _remove_kernel_route(self, cidr: str, gateway: str) -> None:
        """
        Remove a kernel IP route.  Errors are logged but do not abort cleanup.

        Args:
            cidr:    Target network in CIDR notation.
            gateway: Next-hop IP.
        """
        cmd = ["ip", "route", "del", cidr, "via", gateway]
        try:
            self._run_command(cmd)
            logger.debug("Kernel route removed: %s via %s", cidr, gateway)
        except Exception as exc:
            logger.error(
                "Failed to remove kernel route %s via %s: %s", cidr, gateway, exc
            )

    def _add_rule(
        self,
        state: _NetworkState,
        table: str,
        chain: str,
        args: List[str],
        comment: str,
    ) -> None:
        """Run 'iptables -t <table> -A <chain> <args>' and record the rule."""
        cmd = [self._iptables, "-t", table, "-A", chain] + args
        self._run_command(cmd)
        rule = _IptablesRule(table=table, chain=chain, args=args, comment=comment)
        state.rules.append(rule)
        logger.debug("iptables rule added: %s", " ".join(cmd))

    def _remove_rules(self, rules: List[_IptablesRule]) -> None:
        """
        Delete iptables rules in LIFO order (reverse of insertion).

        Errors during deletion are logged but do not abort the remaining
        cleanup to ensure we remove as many rules as possible.
        """
        for rule in reversed(rules):
            cmd = [self._iptables, "-t", rule.table, "-D", rule.chain] + rule.args
            try:
                self._run_command(cmd)
                logger.debug("iptables rule removed: %s", " ".join(cmd))
            except Exception as exc:
                logger.error(
                    "Failed to remove iptables rule (table=%s chain=%s): %s",
                    rule.table, rule.chain, exc,
                )

    def _remove_state(self, state: _NetworkState) -> None:
        """
        Remove all iptables rules and kernel routes for *state*.

        Called by deactivate_network, deactivate_session, and emergency_cleanup.
        """
        self._remove_rules(state.rules)
        for route in reversed(state.routes):
            self._remove_kernel_route(route.cidr, route.gateway)

    def _emergency_cleanup(self) -> None:
        """
        Best-effort cleanup called by atexit.

        Acquires the lock and removes all remaining tracked rules and routes.
        Errors are logged but not re-raised.
        """
        with self._lock:
            if not self._active:
                return
            logger.warning(
                "Emergency cleanup: removing %d active network state(s)",
                len(self._active),
            )
            all_states = list(self._active.values())
            self._active.clear()

        for state in all_states:
            try:
                self._remove_state(state)
            except Exception as exc:
                logger.error("Emergency cleanup error for %s: %s", state.profile_name, exc)

        try:
            self._restore_ip_forward()
        except Exception as exc:
            logger.error("Emergency ip_forward restore failed: %s", exc)

    def _get_interface_ip(self, iface: str) -> str:
        """
        Return the first IPv4 address assigned to *iface*.

        Uses `ip addr show` (iproute2) which is available on all
        supported Linux distributions.

        Raises:
            RuntimeError: If the interface has no IPv4 address.
        """
        cmd = ["ip", "-4", "addr", "show", iface]
        try:
            output = self._run_command(cmd)
        except RuntimeError as exc:
            raise RuntimeError(
                f"Cannot query interface {iface}: {exc}"
            ) from exc

        # Parse a line like: "    inet 192.168.1.5/24 brd ..."
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                if len(parts) >= 2:
                    addr_with_prefix = parts[1]
                    addr = addr_with_prefix.split("/")[0]
                    return addr

        raise RuntimeError(
            f"No IPv4 address found on interface '{iface}'. "
            "Is the VPN connected?"
        )

    @staticmethod
    def _read_sysctl(path: str) -> str:
        """Read a sysctl value from the virtual filesystem."""
        try:
            with open(path, "r") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise RuntimeError(f"Cannot read sysctl {path}: {exc}") from exc

    @staticmethod
    def _write_sysctl(path: str, value: str) -> None:
        """Write a sysctl value to the virtual filesystem."""
        try:
            with open(path, "w") as fh:
                fh.write(value + "\n")
        except OSError as exc:
            raise RuntimeError(
                f"Cannot write sysctl {path}={value}: {exc}"
            ) from exc

    @staticmethod
    def _run_command(cmd: List[str]) -> str:
        """
        Execute a command and return its stdout.

        Args:
            cmd: Argument list (no shell expansion).

        Returns:
            Decoded stdout string.

        Raises:
            RuntimeError: On non-zero exit code or OS error.
        """
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"Command not found: {cmd[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Command timed out: {' '.join(cmd)}"
            ) from exc

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"Command failed (exit {result.returncode}): "
                f"{' '.join(cmd)} – {stderr}"
            )

        return result.stdout.decode("utf-8", errors="replace")

    @staticmethod
    def _find_iptables() -> str:
        """Locate the iptables binary or raise RuntimeError."""
        for candidate in _IPTABLES_CANDIDATES:
            try:
                subprocess.run(
                    [candidate, "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                return candidate
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        raise RuntimeError(
            "iptables binary not found. "
            "Install iptables before running the pivot agent."
        )
