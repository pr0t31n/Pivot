"""
pivot/agent/server.py

Async TLS TCP server that accepts pivot client connections on port 5200.

Each connection goes through:
  1. Peer IP allowlist check
  2. AUTH exchange (HMAC-SHA256 token + nonce)
  3. Session creation
  4. Message loop (ACTIVATE / DEACTIVATE / HEARTBEAT / STATUS)
  5. Graceful cleanup on disconnect or error

A background coroutine runs every 30 seconds to expire stale sessions.
"""

import asyncio
import ipaddress
import logging
import ssl
import time
from typing import Optional

from pivot.common.crypto import (
    build_server_tls_context,
    build_insecure_tls_context,
    verify_token,
)
from pivot.common.protocol import (
    MsgType,
    make_error,
    receive_message,
    send_message,
)
from pivot.agent.config import AgentConfig
from pivot.agent.network_manager import NetworkManager
from pivot.agent.session_manager import Session, SessionManager

logger = logging.getLogger(__name__)

# How often (seconds) the housekeeping loop checks for expired sessions.
_HOUSEKEEPING_INTERVAL = 30


class RelayServer:
    """
    Manages the asyncio TCP server and all client connection lifecycles.
    """

    def __init__(
        self,
        cfg: AgentConfig,
        network_manager: NetworkManager,
        session_manager: SessionManager,
    ) -> None:
        self._cfg = cfg
        self._nm = network_manager
        self._sm = session_manager
        self._server: Optional[asyncio.AbstractServer] = None
        self._housekeeping_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start listening and begin the background housekeeping loop."""
        ssl_ctx = self._build_ssl_context()

        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self._cfg.bind_address,
            port=self._cfg.port,
            ssl=ssl_ctx,
        )

        addrs = [s.getsockname() for s in self._server.sockets]
        logger.info(
            "Relay agent listening on %s (TLS=%s)",
            addrs,
            self._cfg.tls.enabled,
        )

        self._housekeeping_task = asyncio.create_task(
            self._housekeeping_loop(), name="housekeeping"
        )

    async def stop(self) -> None:
        """Stop the server and cancel background tasks."""
        if self._housekeeping_task and not self._housekeeping_task.done():
            self._housekeeping_task.cancel()
            try:
                await self._housekeeping_task
            except asyncio.CancelledError:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Relay agent server stopped")

    async def serve_forever(self) -> None:
        """Block until the server is stopped."""
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Coroutine invoked by asyncio for each accepted TLS connection.

        Validates the peer, runs the AUTH exchange, then enters the
        message loop until the client disconnects or the session expires.
        """
        peer_addr = writer.get_extra_info("peername", ("unknown", 0))
        peer_ip = peer_addr[0] if peer_addr else "unknown"
        logger.info("Incoming connection from %s", peer_ip)

        # --- Peer allowlist check ---
        if not self._is_peer_allowed(peer_ip):
            logger.warning("Connection from %s rejected (not in allowed_peers)", peer_ip)
            await send_message(
                writer, MsgType.ERROR,
                make_error("Peer not authorised", "PEER_NOT_ALLOWED"),
            )
            writer.close()
            return

        session: Optional[Session] = None
        try:
            # --- Authentication ---
            session = await self._authenticate(reader, writer, peer_ip)
            if session is None:
                return  # Error already sent; connection will be closed below.

            # --- Message loop ---
            await self._message_loop(reader, writer, session)

        except (ConnectionError, asyncio.IncompleteReadError) as exc:
            logger.info("Client %s disconnected: %s", peer_ip, exc)
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for message from %s", peer_ip)
        except Exception as exc:
            logger.exception("Unexpected error handling client %s: %s", peer_ip, exc)
        finally:
            # Always clean up the session on any exit path.
            if session:
                await self._sm.close_session(session.session_id)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("Connection closed for %s", peer_ip)

    async def _authenticate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_ip: str,
    ) -> Optional[Session]:
        """
        Perform the AUTH handshake.

        Returns a Session on success, or None after sending an error.
        """
        try:
            msg = await receive_message(reader, timeout=30.0)
        except Exception as exc:
            logger.warning("Failed to receive AUTH from %s: %s", peer_ip, exc)
            return None

        if msg.get("type") != MsgType.AUTH.value:
            logger.warning(
                "Expected AUTH from %s, got '%s'", peer_ip, msg.get("type")
            )
            await send_message(
                writer, MsgType.ERROR,
                make_error("Expected AUTH message", "PROTOCOL_ERROR"),
            )
            return None

        token_hash = msg.get("token_hash", "")
        nonce = msg.get("nonce", "")
        client_id = str(msg.get("client_id", peer_ip))

        # Validate the HMAC token.
        if not verify_token(self._cfg.auth_token, nonce, token_hash):
            logger.warning("AUTH failed for %s (bad token)", peer_ip)
            await send_message(
                writer, MsgType.AUTH_RESPONSE,
                {"success": False, "reason": "Invalid credentials"},
            )
            return None

        # Create the session.
        session = await self._sm.create_session(peer_ip, client_id)
        if session is None:
            await send_message(
                writer, MsgType.AUTH_RESPONSE,
                {"success": False, "reason": "Server session limit reached"},
            )
            return None

        logger.info(
            "AUTH success | session=%s peer=%s client_id=%s",
            session.session_id, peer_ip, client_id,
        )

        await send_message(
            writer, MsgType.AUTH_RESPONSE,
            {
                "success": True,
                "session_id": session.session_id,
                "server_version": "1.0.0",
            },
        )
        return session

    async def _message_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: Session,
    ) -> None:
        """
        Read and dispatch messages from an authenticated client.

        Runs until the client disconnects, sends DEACTIVATE, or an error
        occurs.
        """
        timeout = float(self._cfg.heartbeat_timeout) * 1.5  # grace window

        while True:
            try:
                msg = await receive_message(reader, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning(
                    "No message from session %s within %.0fs – disconnecting",
                    session.session_id, timeout,
                )
                break

            msg_type = msg.get("type", "")
            logger.debug("Message '%s' from session %s", msg_type, session.session_id)

            if msg_type == MsgType.ACTIVATE.value:
                await self._handle_activate(writer, session, msg)

            elif msg_type == MsgType.HEARTBEAT.value:
                await self._sm.touch_session(session.session_id)
                await send_message(
                    writer, MsgType.HEARTBEAT_ACK,
                    {"session_id": session.session_id, "ts": time.time()},
                )

            elif msg_type == MsgType.STATUS.value:
                await self._handle_status(writer, session)

            elif msg_type == MsgType.DEACTIVATE.value:
                await self._handle_deactivate(writer, session)
                break  # Client is done; exit the loop cleanly.

            else:
                logger.warning(
                    "Unknown message type '%s' from session %s",
                    msg_type, session.session_id,
                )
                await send_message(
                    writer, MsgType.ERROR,
                    make_error(f"Unknown message type: {msg_type}", "UNKNOWN_MSG"),
                )

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------

    async def _handle_activate(
        self,
        writer: asyncio.StreamWriter,
        session: Session,
        msg: dict,
    ) -> None:
        """Process an ACTIVATE request and install iptables rules."""
        network_names = msg.get("networks", [])
        if not isinstance(network_names, list):
            network_names = []

        activated, errors = await self._sm.activate_networks(session, network_names)

        if errors and not activated:
            # All requested profiles failed.
            await send_message(
                writer, MsgType.ACTIVATE_RESPONSE,
                {
                    "success": False,
                    "reason": "; ".join(errors),
                    "activated_networks": [],
                },
            )
        else:
            # At least some profiles activated successfully.
            await send_message(
                writer, MsgType.ACTIVATE_RESPONSE,
                {
                    "success": True,
                    "activated_networks": activated,
                    "warnings": errors,  # Partial failures as warnings.
                },
            )

    async def _handle_deactivate(
        self,
        writer: asyncio.StreamWriter,
        session: Session,
    ) -> None:
        """Remove iptables rules and acknowledge the DEACTIVATE request."""
        await self._sm.deactivate_networks(session)
        await send_message(
            writer, MsgType.DEACTIVATE_RESPONSE,
            {"success": True, "session_id": session.session_id},
        )
        logger.info(
            "DEACTIVATE complete | session=%s uptime=%.1fs",
            session.session_id, session.uptime_seconds(),
        )

    async def _handle_status(
        self,
        writer: asyncio.StreamWriter,
        session: Session,
    ) -> None:
        """Return current session status."""
        await send_message(
            writer, MsgType.STATUS_RESPONSE,
            {
                "success": True,
                "session_id": session.session_id,
                "peer": session.peer_address,
                "active_profiles": session.active_profiles,
                "uptime_seconds": round(session.uptime_seconds(), 1),
                "total_sessions": self._sm.session_count(),
            },
        )

    # ------------------------------------------------------------------
    # Background housekeeping
    # ------------------------------------------------------------------

    async def _housekeeping_loop(self) -> None:
        """
        Periodically expire sessions that have missed their heartbeat deadline.
        """
        logger.debug("Housekeeping loop started (interval=%ds)", _HOUSEKEEPING_INTERVAL)
        while True:
            try:
                await asyncio.sleep(_HOUSEKEEPING_INTERVAL)
                expired = await self._sm.expire_stale_sessions()
                if expired:
                    logger.info("Housekeeping: expired %d stale session(s)", expired)
            except asyncio.CancelledError:
                logger.debug("Housekeeping loop cancelled")
                break
            except Exception as exc:
                logger.error("Housekeeping error: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_peer_allowed(self, peer_ip: str) -> bool:
        """
        Return True if *peer_ip* is in the allowlist, or if the list is empty
        (meaning all authenticated peers are accepted).
        """
        if not self._cfg.allowed_peers:
            return True
        try:
            peer_obj = ipaddress.ip_address(peer_ip)
            return any(
                peer_obj == ipaddress.ip_address(allowed)
                for allowed in self._cfg.allowed_peers
            )
        except ValueError:
            logger.error("Could not parse peer IP '%s'", peer_ip)
            return False

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build and return the server SSL context, or None if TLS is disabled."""
        tls = self._cfg.tls
        if not tls.enabled:
            logger.warning(
                "TLS is DISABLED – connections are unencrypted. "
                "Enable TLS for any non-test environment."
            )
            return None

        try:
            return build_server_tls_context(
                certfile=tls.certfile,
                keyfile=tls.keyfile,
                cafile=tls.cafile,
                require_client_cert=tls.require_client_cert,
            )
        except (ssl.SSLError, FileNotFoundError, ValueError) as exc:
            raise RuntimeError(f"Failed to build TLS context: {exc}") from exc
