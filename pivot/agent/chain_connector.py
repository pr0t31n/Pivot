"""
pivot/agent/chain_connector.py

Manages an outbound pivot-client session from this pivot agent to an upstream
pivot agent.  Used when a NetworkProfile has an 'upstream' block configured.

When activated, a ChainConnector:
  1. Opens a TLS connection to the upstream pivot agent.
  2. Authenticates with HMAC-SHA256.
  3. Sends ACTIVATE to bring up the requested network profiles upstream.
  4. Returns the list of activated network dicts (including relay_vpn_ip for
     each), which the NetworkManager uses to install kernel routes and iptables
     rules on this relay device.
  5. Maintains periodic heartbeats to keep the upstream session alive.
  6. On disconnect(): sends DEACTIVATE and closes the connection cleanly.

This class intentionally does NOT install OS routes — that responsibility
stays with NetworkManager, which coordinates all kernel-state changes.

Relationship to pivot-client:
  This is essentially the same protocol as RelayConnection (client/connection.py)
  but purpose-built for use inside the agent process.  It avoids importing
  RouteManager (which would try to modify the scanner's OS routes rather than
  the relay device's routes) and is tightly integrated with the agent's async
  lifecycle.
"""

import asyncio
import logging
import ssl
import time
from typing import Dict, List, Optional

from pivot.common.crypto import (
    build_client_tls_context,
    derive_token_hash,
    generate_nonce,
)
from pivot.common.protocol import (
    MsgType,
    receive_message,
    send_message,
)
from pivot.agent.config import UpstreamRelayConfig

logger = logging.getLogger(__name__)


class ChainConnector:
    """
    An outbound relay connection from this agent to an upstream pivot agent.

    Lifecycle::

        connector = ChainConnector(upstream_cfg, session_id, profile_name)
        networks  = await connector.connect()
        # networks is a list of dicts: [{name, target_cidr, relay_vpn_ip}, ...]
        # ... relay runs ...
        await connector.disconnect()

    The connect() call blocks until the upstream relay has acknowledged the
    ACTIVATE request.  From that point the upstream relay's network profiles
    are active and heartbeats run in the background.
    """

    def __init__(
        self,
        upstream_cfg: UpstreamRelayConfig,
        session_id: str,
        profile_name: str,
    ) -> None:
        """
        Args:
            upstream_cfg: Parsed upstream relay connection parameters.
            session_id:   Parent relay session ID (used in log messages).
            profile_name: Name of the network profile that triggered this chain.
        """
        self._cfg = upstream_cfg
        self._session_id = session_id
        self._profile_name = profile_name

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._upstream_session_id: Optional[str] = None
        self._activated: bool = False
        self._heartbeat_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def connect(self) -> List[dict]:
        """
        Connect to the upstream relay, authenticate, and activate networks.

        Returns:
            List of activated network dicts, each containing:
              - name:          Profile name on the upstream relay.
              - target_cidr:   The reachable CIDR.
              - relay_vpn_ip:  The upstream relay's VPN IP (used by this relay
                               as the next-hop gateway in kernel routes).

        Raises:
            ConnectionError:  TLS/TCP connection failure.
            PermissionError:  Authentication rejected by upstream.
            RuntimeError:     Network activation failed entirely.
        """
        await self._open_connection()
        await self._authenticate()
        networks = await self._activate_networks()
        self._activated = True

        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name=f"chain-heartbeat-{self._profile_name}",
        )

        logger.info(
            "Chain connector active | session=%s profile=%s upstream=%s:%d "
            "networks=%s",
            self._session_id, self._profile_name,
            self._cfg.host, self._cfg.port,
            [n.get("name") for n in networks],
        )
        return networks

    async def disconnect(self) -> None:
        """
        Gracefully shut down: deactivate upstream networks and close TLS.
        """
        # Stop heartbeat first.
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Send DEACTIVATE.
        if self._writer and not self._writer.is_closing() and self._activated:
            try:
                await send_message(self._writer, MsgType.DEACTIVATE)
                msg = await asyncio.wait_for(
                    receive_message(self._reader),
                    timeout=self._cfg.operation_timeout,
                )
                if msg.get("type") == MsgType.DEACTIVATE_RESPONSE.value:
                    logger.info(
                        "Upstream deactivation confirmed | session=%s profile=%s",
                        self._session_id, self._profile_name,
                    )
                else:
                    logger.warning(
                        "Unexpected upstream DEACTIVATE response: %s", msg.get("type")
                    )
            except Exception as exc:
                logger.warning(
                    "Error during upstream DEACTIVATE | session=%s profile=%s: %s",
                    self._session_id, self._profile_name, exc,
                )

        await self._close_connection()
        logger.info(
            "Chain connector closed | session=%s profile=%s",
            self._session_id, self._profile_name,
        )

    @property
    def is_connected(self) -> bool:
        """True if the underlying TLS connection appears to be open."""
        return (
            self._writer is not None
            and not self._writer.is_closing()
        )

    @property
    def upstream_session_id(self) -> Optional[str]:
        """Session ID assigned by the upstream relay, or None if not connected."""
        return self._upstream_session_id

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def _open_connection(self) -> None:
        host = self._cfg.host
        port = self._cfg.port
        ssl_ctx = self._build_ssl_context()

        logger.info(
            "Chain: connecting to upstream relay %s:%d (TLS=%s) "
            "[session=%s profile=%s]",
            host, port, self._cfg.tls.enabled,
            self._session_id, self._profile_name,
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
                f"Chain: timed out connecting to upstream {host}:{port} "
                f"after {self._cfg.connect_timeout}s"
            ) from exc
        except (OSError, ssl.SSLError) as exc:
            raise ConnectionError(
                f"Chain: failed to connect to upstream {host}:{port}: {exc}"
            ) from exc

        logger.debug("Chain: TLS connection established to %s:%d", host, port)

    async def _close_connection(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as exc:
                logger.debug("Chain: error closing upstream connection: %s", exc)
            finally:
                self._writer = None
                self._reader = None

    # ------------------------------------------------------------------
    # Protocol steps
    # ------------------------------------------------------------------

    async def _authenticate(self) -> None:
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

        try:
            msg = await asyncio.wait_for(
                receive_message(self._reader),
                timeout=self._cfg.operation_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ConnectionError(
                "Chain: timed out waiting for upstream AUTH_RESPONSE"
            ) from exc

        if msg.get("type") != MsgType.AUTH_RESPONSE.value:
            raise ConnectionError(
                f"Chain: expected AUTH_RESPONSE from upstream, "
                f"got '{msg.get('type')}'"
            )

        if not msg.get("success"):
            reason = msg.get("reason", "no reason given")
            raise PermissionError(
                f"Chain: upstream rejected authentication: {reason}"
            )

        self._upstream_session_id = msg.get("session_id", "unknown")
        logger.info(
            "Chain: authenticated with upstream | upstream_session=%s "
            "server_version=%s [session=%s profile=%s]",
            self._upstream_session_id,
            msg.get("server_version", "?"),
            self._session_id, self._profile_name,
        )

    async def _activate_networks(self) -> List[dict]:
        await send_message(
            self._writer, MsgType.ACTIVATE,
            {"networks": self._cfg.activate_networks},
        )

        try:
            msg = await asyncio.wait_for(
                receive_message(self._reader),
                timeout=self._cfg.operation_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ConnectionError(
                "Chain: timed out waiting for upstream ACTIVATE_RESPONSE"
            ) from exc

        if msg.get("type") != MsgType.ACTIVATE_RESPONSE.value:
            raise ConnectionError(
                f"Chain: expected ACTIVATE_RESPONSE from upstream, "
                f"got '{msg.get('type')}'"
            )

        if not msg.get("success"):
            reason = msg.get("reason", "unknown error")
            raise RuntimeError(
                f"Chain: upstream network activation failed: {reason}"
            )

        networks = msg.get("activated_networks", [])
        warnings = msg.get("warnings", [])
        for w in warnings:
            logger.warning(
                "Chain: upstream activation warning [session=%s profile=%s]: %s",
                self._session_id, self._profile_name, w,
            )

        logger.debug(
            "Chain: upstream activated %d network(s): %s",
            len(networks), [n.get("name") for n in networks],
        )
        return networks

    # ------------------------------------------------------------------
    # Heartbeat loop
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        interval = self._cfg.heartbeat_interval
        logger.debug(
            "Chain: heartbeat loop started (interval=%.0fs) "
            "[session=%s profile=%s]",
            interval, self._session_id, self._profile_name,
        )

        while True:
            try:
                await asyncio.sleep(interval)

                if not self.is_connected:
                    logger.warning(
                        "Chain: upstream connection lost, heartbeat loop stopping "
                        "[session=%s profile=%s]",
                        self._session_id, self._profile_name,
                    )
                    break

                await send_message(
                    self._writer, MsgType.HEARTBEAT,
                    {
                        "session_id": self._upstream_session_id,
                        "ts": time.time(),
                    },
                )

                try:
                    ack = await asyncio.wait_for(
                        receive_message(self._reader), timeout=15.0
                    )
                    if ack.get("type") != MsgType.HEARTBEAT_ACK.value:
                        logger.warning(
                            "Chain: unexpected upstream heartbeat response: %s "
                            "[session=%s profile=%s]",
                            ack.get("type"), self._session_id, self._profile_name,
                        )
                    else:
                        logger.debug(
                            "Chain: upstream heartbeat ACK [session=%s profile=%s]",
                            self._session_id, self._profile_name,
                        )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Chain: upstream heartbeat ACK timed out – "
                        "upstream may be unresponsive "
                        "[session=%s profile=%s]",
                        self._session_id, self._profile_name,
                    )

            except asyncio.CancelledError:
                logger.debug(
                    "Chain: heartbeat loop cancelled [session=%s profile=%s]",
                    self._session_id, self._profile_name,
                )
                break
            except Exception as exc:
                logger.error(
                    "Chain: heartbeat loop error [session=%s profile=%s]: %s",
                    self._session_id, self._profile_name, exc,
                )
                break

    # ------------------------------------------------------------------
    # TLS context
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        tls = self._cfg.tls
        if not tls.enabled:
            logger.warning(
                "Chain: TLS is DISABLED for upstream %s:%d – "
                "connection is unencrypted. Enable TLS in production.",
                self._cfg.host, self._cfg.port,
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
            raise RuntimeError(
                f"Chain: failed to build TLS context for upstream "
                f"{self._cfg.host}:{self._cfg.port}: {exc}"
            ) from exc
