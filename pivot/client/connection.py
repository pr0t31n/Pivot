"""
pivot/client/connection.py

Manages the full lifecycle of a pivot client connection:

  1. Establish TLS connection to the pivot agent.
  2. Authenticate with HMAC-SHA256 token.
  3. Request network profile activation.
  4. Install local OS routes for activated networks.
  5. Maintain a periodic heartbeat loop.
  6. On shutdown: send DEACTIVATE, remove routes, close connection.
"""

import asyncio
import logging
import ssl
import time
from typing import Dict, List, Optional

from pivot.common.crypto import (
    build_client_tls_context,
    build_insecure_tls_context,
    derive_token_hash,
    generate_nonce,
)
from pivot.common.protocol import (
    MsgType,
    receive_message,
    send_message,
)
from pivot.client.config import ClientConfig
from pivot.client.route_manager import RouteManager

logger = logging.getLogger(__name__)


class RelayConnection:
    """
    Manages a single authenticated session with the pivot agent.

    Typical usage::

        conn = RelayConnection(cfg, route_manager)
        networks = await conn.connect()
        # ... scanning runs ...
        await conn.disconnect()
    """

    def __init__(self, cfg: ClientConfig, route_manager: RouteManager) -> None:
        self._cfg = cfg
        self._rm = route_manager
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._session_id: Optional[str] = None
        self._activated: bool = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._activated_networks: List[dict] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def connect(self) -> List[dict]:
        """
        Connect to the pivot agent, authenticate, and activate networks.

        Returns:
            List of activated network dicts (name, target_cidr, relay_vpn_ip).

        Raises:
            ConnectionError:   If the TCP/TLS connection fails.
            PermissionError:   If authentication is rejected.
            RuntimeError:      If network activation fails entirely.
        """
        await self._open_connection()
        await self._authenticate()
        networks = await self._activate_networks()
        self._install_routes(networks)
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(), name="heartbeat"
        )
        self._activated_networks = networks
        return networks

    async def disconnect(self) -> None:
        """
        Gracefully shut down: deactivate networks, remove routes, close TLS.
        """
        # Stop the heartbeat first to avoid racing with DEACTIVATE.
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Send DEACTIVATE and wait for acknowledgement.
        if self._writer and not self._writer.is_closing() and self._activated:
            try:
                await send_message(self._writer, MsgType.DEACTIVATE)
                msg = await asyncio.wait_for(
                    receive_message(self._reader),
                    timeout=self._cfg.operation_timeout,
                )
                if msg.get("type") == MsgType.DEACTIVATE_RESPONSE.value:
                    logger.info(
                        "Deactivation confirmed by agent (session=%s)",
                        self._session_id,
                    )
                else:
                    logger.warning(
                        "Unexpected response to DEACTIVATE: %s", msg.get("type")
                    )
            except Exception as exc:
                logger.warning("Error during DEACTIVATE exchange: %s", exc)

        # Remove OS routes regardless of whether DEACTIVATE succeeded.
        self._remove_routes()

        # Close the connection.
        await self._close_connection()
        logger.info("Relay connection closed")

    @property
    def session_id(self) -> Optional[str]:
        """The session ID assigned by the agent, or None if not connected."""
        return self._session_id

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def _open_connection(self) -> None:
        """Establish the TLS TCP connection to the pivot agent."""
        host = self._cfg.relay_host
        port = self._cfg.relay_port
        ssl_ctx = self._build_ssl_context()

        logger.info(
            "Connecting to pivot agent at %s:%d (TLS=%s)",
            host, port, self._cfg.tls.enabled,
        )

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host,
                    port=port,
                    ssl=ssl_ctx,
                    server_hostname=self._cfg.tls.server_hostname if ssl_ctx else None,
                ),
                timeout=self._cfg.connect_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ConnectionError(
                f"Timed out connecting to {host}:{port} "
                f"after {self._cfg.connect_timeout}s"
            ) from exc
        except (OSError, ssl.SSLError) as exc:
            raise ConnectionError(
                f"Failed to connect to {host}:{port}: {exc}"
            ) from exc

        logger.info("TCP/TLS connection established to %s:%d", host, port)

    async def _close_connection(self) -> None:
        """Close the underlying TCP/TLS connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as exc:
                logger.debug("Error closing connection: %s", exc)
            finally:
                self._writer = None
                self._reader = None

    # ------------------------------------------------------------------
    # Protocol steps
    # ------------------------------------------------------------------

    async def _authenticate(self) -> None:
        """
        Send AUTH message and verify the agent's response.

        Raises:
            PermissionError: If the agent rejects the credentials.
            ConnectionError: If the exchange fails unexpectedly.
        """
        nonce = generate_nonce()
        token_hash = derive_token_hash(self._cfg.auth_token, nonce)

        await send_message(
            self._writer, MsgType.AUTH,
            {
                "nonce": nonce,
                "token_hash": token_hash,
                "client_id": self._cfg.client_id,
            },
        )
        logger.debug("AUTH sent (nonce=%s...)", nonce[:8])

        try:
            msg = await asyncio.wait_for(
                receive_message(self._reader),
                timeout=self._cfg.operation_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ConnectionError("Timed out waiting for AUTH_RESPONSE") from exc

        if msg.get("type") != MsgType.AUTH_RESPONSE.value:
            raise ConnectionError(
                f"Expected AUTH_RESPONSE, received '{msg.get('type')}'"
            )

        if not msg.get("success"):
            reason = msg.get("reason", "no reason provided")
            raise PermissionError(f"Authentication failed: {reason}")

        self._session_id = msg.get("session_id", "unknown")
        logger.info(
            "Authenticated successfully | session=%s server_version=%s",
            self._session_id, msg.get("server_version", "?"),
        )

    async def _activate_networks(self) -> List[dict]:
        """
        Send ACTIVATE and parse the list of activated network profiles.

        Returns:
            List of network info dicts from the agent.

        Raises:
            RuntimeError: If the agent rejects all networks.
        """
        await send_message(
            self._writer, MsgType.ACTIVATE,
            {"networks": self._cfg.activate_networks},
        )
        logger.debug(
            "ACTIVATE sent (requested=%s)",
            self._cfg.activate_networks or "all",
        )

        try:
            msg = await asyncio.wait_for(
                receive_message(self._reader),
                timeout=self._cfg.operation_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ConnectionError("Timed out waiting for ACTIVATE_RESPONSE") from exc

        if msg.get("type") != MsgType.ACTIVATE_RESPONSE.value:
            raise ConnectionError(
                f"Expected ACTIVATE_RESPONSE, received '{msg.get('type')}'"
            )

        if not msg.get("success"):
            reason = msg.get("reason", "unknown error")
            raise RuntimeError(f"Network activation failed: {reason}")

        networks = msg.get("activated_networks", [])
        warnings = msg.get("warnings", [])

        for w in warnings:
            logger.warning("Activation warning: %s", w)

        logger.info(
            "Networks activated: %s",
            [n.get("name") for n in networks],
        )
        self._activated = True
        return networks

    # ------------------------------------------------------------------
    # Route management
    # ------------------------------------------------------------------

    def _install_routes(self, networks: List[dict]) -> None:
        """Add OS routes for each activated network profile."""
        for net in networks:
            cidr = net.get("target_cidr")
            gateway = net.get("relay_vpn_ip")
            name = net.get("name", "unknown")

            if not cidr or not gateway:
                logger.warning(
                    "Network '%s' missing target_cidr or relay_vpn_ip – skipping route",
                    name,
                )
                continue

            try:
                self._rm.add_route(cidr, gateway)
                logger.info(
                    "Route installed: %s via %s  (profile '%s')", cidr, gateway, name
                )
            except RuntimeError as exc:
                logger.error(
                    "Failed to install route for '%s' (%s via %s): %s",
                    name, cidr, gateway, exc,
                )

    def _remove_routes(self) -> None:
        """Remove all routes installed during this connection."""
        try:
            self._rm.remove_all_routes()
        except Exception as exc:
            logger.error("Error removing routes: %s", exc)

    # ------------------------------------------------------------------
    # Heartbeat loop
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """
        Send periodic HEARTBEAT messages to keep the session alive.

        Runs until cancelled or a connection error occurs.
        """
        interval = self._cfg.heartbeat_interval
        logger.debug("Heartbeat loop started (interval=%.0fs)", interval)

        while True:
            try:
                await asyncio.sleep(interval)

                if not self._writer or self._writer.is_closing():
                    logger.warning("Heartbeat: connection closed – stopping loop")
                    break

                await send_message(
                    self._writer, MsgType.HEARTBEAT,
                    {"session_id": self._session_id, "ts": time.time()},
                )

                try:
                    ack = await asyncio.wait_for(
                        receive_message(self._reader), timeout=10.0
                    )
                    if ack.get("type") != MsgType.HEARTBEAT_ACK.value:
                        logger.warning(
                            "Unexpected heartbeat response: %s", ack.get("type")
                        )
                    else:
                        logger.debug(
                            "Heartbeat ACK received (session=%s)", self._session_id
                        )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Heartbeat ACK timed out (session=%s) – "
                        "agent may be unresponsive",
                        self._session_id,
                    )

            except asyncio.CancelledError:
                logger.debug("Heartbeat loop cancelled")
                break
            except ConnectionError as exc:
                logger.error("Heartbeat connection error: %s", exc)
                break
            except Exception as exc:
                logger.error("Heartbeat unexpected error: %s", exc)
                break

    # ------------------------------------------------------------------
    # TLS context
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build the client SSL context based on config."""
        tls = self._cfg.tls
        if not tls.enabled:
            logger.warning(
                "TLS is DISABLED – connection to agent is unencrypted. "
                "Enable TLS for any non-test environment."
            )
            return None

        try:
            return build_client_tls_context(
                cafile=tls.cafile,
                certfile=tls.certfile,
                keyfile=tls.keyfile,
                server_hostname=tls.server_hostname,
                verify_hostname=tls.verify_hostname,
            )
        except (ssl.SSLError, FileNotFoundError, ValueError) as exc:
            raise RuntimeError(f"Failed to build client TLS context: {exc}") from exc
