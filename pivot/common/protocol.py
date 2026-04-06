"""
pivot/common/protocol.py

Wire protocol for pivot agent <-> client communication.

All messages are JSON objects preceded by a 4-byte big-endian length prefix.
The protocol runs over TLS 1.2+ on port 5200 (configurable).

Message flow:
  Client  -->  AUTH            -->  Agent
  Client  <--  AUTH_RESPONSE   <--  Agent
  Client  -->  ACTIVATE        -->  Agent
  Client  <--  ACTIVATE_RESP   <--  Agent
  Client  -->  HEARTBEAT       -->  Agent   (every N seconds)
  Client  <--  HEARTBEAT_ACK   <--  Agent
  Client  -->  STATUS          -->  Agent
  Client  <--  STATUS_RESP     <--  Agent
  Client  -->  DEACTIVATE      -->  Agent
  Client  <--  DEACTIVATE_RESP <--  Agent
  Agent   <--  ERROR           -->  Either side (on failure)
"""

import asyncio  # stdlib — Python Software Foundation; event-loop concurrency (https://docs.python.org/3/library/asyncio.html)
import json      # stdlib — Python Software Foundation
import struct    # stdlib — Python Software Foundation; 4-byte big-endian length prefix framing
import logging
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Maximum permitted message payload (bytes). Protects against memory exhaustion.
MAX_MESSAGE_SIZE = 1 * 1024 * 1024  # 1 MB

# Header is a single 4-byte unsigned int (big-endian) containing payload length.
HEADER_FORMAT = ">I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 4 bytes


class MsgType(str, Enum):
    """All message types understood by the relay protocol."""

    # Client → Agent
    AUTH = "AUTH"
    ACTIVATE = "ACTIVATE"
    DEACTIVATE = "DEACTIVATE"
    HEARTBEAT = "HEARTBEAT"
    STATUS = "STATUS"

    # Agent → Client
    AUTH_RESPONSE = "AUTH_RESPONSE"
    ACTIVATE_RESPONSE = "ACTIVATE_RESPONSE"
    DEACTIVATE_RESPONSE = "DEACTIVATE_RESPONSE"
    HEARTBEAT_ACK = "HEARTBEAT_ACK"
    STATUS_RESPONSE = "STATUS_RESPONSE"
    ERROR = "ERROR"


def build_message(msg_type: MsgType, payload: Optional[Dict[str, Any]] = None) -> bytes:
    """
    Serialise a protocol message into length-prefixed bytes ready for the wire.

    Args:
        msg_type: One of the MsgType enum values.
        payload:  Optional dictionary of additional fields.

    Returns:
        bytes: 4-byte length header + UTF-8 JSON body.
    """
    envelope: Dict[str, Any] = {"type": msg_type.value}
    if payload:
        envelope.update(payload)

    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    header = struct.pack(HEADER_FORMAT, len(body))
    return header + body


async def send_message(
    writer: asyncio.StreamWriter,
    msg_type: MsgType,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write a protocol message to an async stream.

    Args:
        writer:   asyncio StreamWriter connected to the peer.
        msg_type: Message type enum value.
        payload:  Optional extra fields to include.

    Raises:
        ConnectionError: If the underlying write fails.
    """
    data = build_message(msg_type, payload)
    try:
        writer.write(data)
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        raise ConnectionError(f"Failed to send {msg_type.value}: {exc}") from exc


async def receive_message(
    reader: asyncio.StreamReader,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """
    Read exactly one protocol message from an async stream.

    Args:
        reader:  asyncio StreamReader connected to the peer.
        timeout: Maximum seconds to wait for the full message.

    Returns:
        Parsed JSON envelope as a Python dictionary.

    Raises:
        ConnectionError:   If the connection is closed or broken.
        ValueError:        If the payload is too large or malformed JSON.
        asyncio.TimeoutError: If the read takes longer than *timeout* seconds.
    """
    try:
        # 1. Read the 4-byte length prefix.
        raw_header = await asyncio.wait_for(
            reader.readexactly(HEADER_SIZE), timeout=timeout
        )
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("Connection closed while reading message header") from exc

    payload_length: int = struct.unpack(HEADER_FORMAT, raw_header)[0]

    # Guard against obviously malicious or corrupted length fields.
    if payload_length == 0:
        raise ValueError("Received message with zero-length payload")
    if payload_length > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Message payload too large: {payload_length} bytes "
            f"(max {MAX_MESSAGE_SIZE})"
        )

    # 2. Read the JSON body.
    try:
        raw_body = await asyncio.wait_for(
            reader.readexactly(payload_length), timeout=timeout
        )
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("Connection closed while reading message body") from exc

    # 3. Parse JSON.
    try:
        envelope: Dict[str, Any] = json.loads(raw_body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Malformed message payload: {exc}") from exc

    if "type" not in envelope:
        raise ValueError("Message missing required 'type' field")

    return envelope


def make_error(reason: str, code: str = "GENERIC_ERROR") -> Dict[str, Any]:
    """
    Build an ERROR message payload.

    Args:
        reason: Human-readable error description.
        code:   Machine-readable error identifier (default GENERIC_ERROR).

    Returns:
        Dictionary ready to pass to send_message as payload.
    """
    return {"success": False, "error_code": code, "reason": reason}
