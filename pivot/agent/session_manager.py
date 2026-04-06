"""
pivot/agent/session_manager.py

Thread-safe registry for active relay sessions.

Responsibilities:
  - Create and destroy sessions.
  - Coordinate network profile activation/deactivation with NetworkManager.
  - Expire stale sessions when heartbeats stop arriving.
  - Enforce the maximum concurrent session limit from config.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """
    Runtime state for a single authenticated pivot client connection.

    Attributes:
        session_id:       Unique UUID string assigned at creation.
        peer_address:     Remote IP address of the connected client.
        client_id:        Identifier provided by the client during AUTH.
        active_profiles:  Names of network profiles currently activated.
        chain_connectors: Outbound ChainConnector objects keyed by profile name.
                          Active only when chained profiles are in use.
        created_at:       Unix timestamp when the session was created.
        last_heartbeat:   Unix timestamp of the most recent HEARTBEAT.
    """

    session_id: str
    peer_address: str
    client_id: str
    active_profiles: List[str] = field(default_factory=list)
    chain_connectors: Dict[str, object] = field(default_factory=dict)  # profile_name → ChainConnector
    created_at: float = field(default_factory=time.monotonic)
    last_heartbeat: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        """Update the heartbeat timestamp to now."""
        self.last_heartbeat = time.monotonic()

    def is_expired(self, timeout: float) -> bool:
        """
        Return True if no heartbeat has been received within *timeout* seconds.

        Args:
            timeout: Maximum seconds allowed between heartbeats.
        """
        return (time.monotonic() - self.last_heartbeat) > timeout

    def uptime_seconds(self) -> float:
        """Return how many seconds the session has been alive."""
        return time.monotonic() - self.created_at


class SessionManager:
    """
    Manages the lifecycle of relay sessions across concurrent connections.

    All mutating operations are protected by an asyncio.Lock so they are
    safe to call from multiple coroutines on the same event loop.
    """

    def __init__(self, cfg, network_manager) -> None:
        """
        Args:
            cfg:             AgentConfig instance.
            network_manager: NetworkManager instance.
        """
        self._cfg = cfg
        self._nm = network_manager
        self._sessions: Dict[str, Session] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def create_session(self, peer_address: str, client_id: str) -> Optional[Session]:
        """
        Register a new authenticated relay session.

        Args:
            peer_address: IP address of the connecting client.
            client_id:    Human-readable identifier from the AUTH message.

        Returns:
            The new Session, or None if the maximum session limit is reached.
        """
        async with self._lock:
            if len(self._sessions) >= self._cfg.max_sessions:
                logger.warning(
                    "Session limit reached (%d/%d) – rejecting %s",
                    len(self._sessions), self._cfg.max_sessions, peer_address,
                )
                return None

            session_id = str(uuid.uuid4())
            session = Session(
                session_id=session_id,
                peer_address=peer_address,
                client_id=client_id,
            )
            self._sessions[session_id] = session
            logger.info(
                "Session created | id=%s peer=%s client=%s",
                session_id, peer_address, client_id,
            )
            return session

    async def close_session(self, session_id: str) -> None:
        """
        Deactivate all network profiles, disconnect chain connectors, and
        remove the session record.

        Args:
            session_id: Identifier of the session to close.
        """
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                logger.debug("close_session: unknown session %s", session_id)
                return

        # Disconnect all chain connectors outside the lock (they do I/O).
        for profile_name, connector in list(session.chain_connectors.items()):
            try:
                await connector.disconnect()
            except Exception as exc:
                logger.error(
                    "Error disconnecting chain connector for profile '%s' "
                    "[session=%s]: %s",
                    profile_name, session_id, exc,
                )
        session.chain_connectors.clear()

        # Deactivate kernel networking outside the lock.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._nm.deactivate_session, session_id
        )

        logger.info(
            "Session closed | id=%s uptime=%.1fs peer=%s",
            session_id, session.uptime_seconds(), session.peer_address,
        )

    async def activate_networks(
        self, session: Session, network_names: List[str]
    ) -> Tuple[List[dict], List[str]]:
        """
        Activate the requested network profiles for *session*.

        For direct profiles, iptables rules are installed immediately.
        For chained profiles, a ChainConnector is spawned first to
        connect to the upstream relay; the upstream relay's VPN IP is
        then used as the next-hop gateway when installing kernel routes
        and iptables rules on this relay.

        Args:
            session:       The relay session requesting activation.
            network_names: Profile names to activate, or empty list for all.

        Returns:
            A tuple of (activated_networks, errors) where:
              - activated_networks: List of dicts with profile details
                and the relay VPN IP for each activated profile.
              - errors: List of human-readable error strings for profiles
                that could not be activated.
        """
        from pivot.agent.chain_connector import ChainConnector

        # Resolve which profiles to activate.
        available = {p.name: p for p in self._cfg.networks}

        if network_names:
            errors: List[str] = []
            requested = []
            for name in network_names:
                if name in available:
                    requested.append(available[name])
                else:
                    errors.append(f"Unknown network profile: '{name}'")
            if errors:
                return [], errors
        else:
            requested = list(available.values())
            errors = []

        loop = asyncio.get_running_loop()
        activated: List[dict] = []

        for profile in requested:
            if profile.name in session.active_profiles:
                logger.debug(
                    "Profile '%s' already active for session %s",
                    profile.name, session.session_id,
                )
                continue

            upstream_vpn_ip: Optional[str] = None

            # ---- Chained profile: connect to upstream relay first ----
            if profile.is_chained:
                connector = ChainConnector(
                    upstream_cfg=profile.upstream,
                    session_id=session.session_id,
                    profile_name=profile.name,
                )
                try:
                    upstream_networks = await connector.connect()
                except (ConnectionError, PermissionError, RuntimeError) as exc:
                    logger.error(
                        "Chain connector failed for profile '%s' [session=%s]: %s",
                        profile.name, session.session_id, exc,
                    )
                    errors.append(
                        f"Chain connection failed for '{profile.name}': {exc}"
                    )
                    continue

                if not upstream_networks:
                    await connector.disconnect()
                    errors.append(
                        f"Upstream relay returned no active networks for '{profile.name}'"
                    )
                    continue

                # Use the first activated upstream network's relay VPN IP as
                # the next-hop gateway for this relay's kernel route.
                upstream_vpn_ip = upstream_networks[0].get("relay_vpn_ip")
                if not upstream_vpn_ip:
                    await connector.disconnect()
                    errors.append(
                        f"Upstream relay did not return a relay_vpn_ip for '{profile.name}'"
                    )
                    continue

                session.chain_connectors[profile.name] = connector
                logger.info(
                    "Chain connector established for profile '%s' "
                    "[session=%s] upstream_gateway=%s",
                    profile.name, session.session_id, upstream_vpn_ip,
                )

            # ---- Install kernel networking (iptables + optional route) ----
            try:
                vpn_ip = await loop.run_in_executor(
                    None,
                    self._nm.activate_network,
                    session.session_id,
                    profile,
                    upstream_vpn_ip,  # None for direct profiles
                )
                session.active_profiles.append(profile.name)
                activated.append({
                    "name": profile.name,
                    "target_cidr": profile.target_cidr,
                    "relay_vpn_ip": vpn_ip,
                    "chained": profile.is_chained,
                })
            except Exception as exc:
                logger.error(
                    "Failed to activate kernel networking for profile '%s' "
                    "[session=%s]: %s",
                    profile.name, session.session_id, exc,
                )
                # If we spawned a connector, tear it down since networking failed.
                if profile.name in session.chain_connectors:
                    connector = session.chain_connectors.pop(profile.name)
                    try:
                        await connector.disconnect()
                    except Exception:
                        pass
                errors.append(f"Activation failed for '{profile.name}': {exc}")

        return activated, errors

    async def deactivate_networks(self, session: Session) -> None:
        """
        Deactivate all network profiles for *session* without closing it.
        Also disconnects any active chain connectors.

        Args:
            session: The relay session.
        """
        # Disconnect chain connectors first (they hold upstream relay sessions).
        for profile_name, connector in list(session.chain_connectors.items()):
            try:
                await connector.disconnect()
            except Exception as exc:
                logger.error(
                    "Error disconnecting chain connector for profile '%s': %s",
                    profile_name, exc,
                )
        session.chain_connectors.clear()

        loop = asyncio.get_running_loop()
        for profile_name in list(session.active_profiles):
            try:
                await loop.run_in_executor(
                    None,
                    self._nm.deactivate_network,
                    session.session_id,
                    profile_name,
                )
            except Exception as exc:
                logger.error(
                    "Failed to deactivate profile '%s' for session %s: %s",
                    profile_name, session.session_id, exc,
                )
        session.active_profiles.clear()

    async def touch_session(self, session_id: str) -> bool:
        """
        Update the heartbeat timestamp for *session_id*.

        Args:
            session_id: Relay session identifier.

        Returns:
            True if the session exists; False if it was not found.
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.touch()
            return True

    async def get_session(self, session_id: str) -> Optional[Session]:
        """Return the Session for *session_id*, or None if not found."""
        async with self._lock:
            return self._sessions.get(session_id)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    async def expire_stale_sessions(self) -> int:
        """
        Find and close sessions that have missed their heartbeat deadline.

        Returns:
            Number of sessions expired.
        """
        timeout = self._cfg.heartbeat_timeout
        expired_ids: List[str] = []

        async with self._lock:
            for sid, session in self._sessions.items():
                if session.is_expired(timeout):
                    logger.warning(
                        "Session %s expired (no heartbeat for >%ds, peer=%s)",
                        sid, timeout, session.peer_address,
                    )
                    expired_ids.append(sid)

        for sid in expired_ids:
            await self.close_session(sid)

        return len(expired_ids)

    def session_count(self) -> int:
        """Return the current number of active sessions (not thread-safe, informational only)."""
        return len(self._sessions)
