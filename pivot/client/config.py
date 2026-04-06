"""
pivot/client/config.py

Configuration loader and validator for the pivot client (scanner-side).
"""

import logging
import os
import socket
from dataclasses import dataclass, field
from typing import List, Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_PORT = 5200
DEFAULT_HEARTBEAT_INTERVAL = 30  # seconds
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_CONNECT_TIMEOUT = 30.0   # seconds
DEFAULT_OPERATION_TIMEOUT = 60.0 # seconds


@dataclass
class ClientTLSConfig:
    """TLS settings for the client connection."""

    enabled: bool = True
    cafile: Optional[str] = None
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    verify_hostname: bool = True
    server_hostname: Optional[str] = None  # Override for SNI if needed.


@dataclass
class ClientConfig:
    """Complete configuration for the pivot client."""

    # Relay agent endpoint
    relay_host: str = ""
    relay_port: int = DEFAULT_PORT

    # Authentication
    auth_token: str = ""

    # TLS
    tls: ClientTLSConfig = field(default_factory=ClientTLSConfig)

    # Network profiles to activate (empty = all configured on agent)
    activate_networks: List[str] = field(default_factory=list)

    # Timing
    heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    operation_timeout: float = DEFAULT_OPERATION_TIMEOUT

    # Client identity (sent in AUTH for audit logs on the agent)
    client_id: str = ""

    # Logging
    log_level: str = DEFAULT_LOG_LEVEL
    log_file: Optional[str] = None


def load_client_config(path: str) -> ClientConfig:
    """
    Parse *path* as YAML and return a validated ClientConfig.

    Args:
        path: Filesystem path to the client YAML configuration file.

    Returns:
        Populated and validated ClientConfig.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError:        If any required field is missing or invalid.
        yaml.YAMLError:    If the file is malformed YAML.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Client config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError("Config file must contain a YAML mapping at the top level")

    cfg = ClientConfig()

    # ---- relay section ----
    relay_sec = raw.get("relay", {})
    cfg.relay_host = str(relay_sec.get("host", "")).strip()
    if not cfg.relay_host:
        raise ValueError("relay.host must be specified")
    cfg.relay_port = int(relay_sec.get("port", DEFAULT_PORT))
    if not (1 <= cfg.relay_port <= 65535):
        raise ValueError(f"relay.port must be 1–65535, got {cfg.relay_port}")

    # ---- security section ----
    sec = raw.get("security", {})
    cfg.auth_token = str(sec.get("auth_token", "")).strip()
    if not cfg.auth_token:
        raise ValueError("security.auth_token must not be empty")

    # TLS
    tls_sec = sec.get("tls", {})
    cfg.tls = _parse_client_tls(tls_sec, cfg.relay_host)

    # ---- activate_networks ----
    an = raw.get("activate_networks", [])
    cfg.activate_networks = [str(n).strip() for n in an] if an else []

    # ---- timing section ----
    timing = raw.get("timing", {})
    cfg.heartbeat_interval = float(
        timing.get("heartbeat_interval", DEFAULT_HEARTBEAT_INTERVAL)
    )
    cfg.connect_timeout = float(
        timing.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT)
    )
    cfg.operation_timeout = float(
        timing.get("operation_timeout", DEFAULT_OPERATION_TIMEOUT)
    )

    # ---- client identity ----
    cfg.client_id = str(raw.get("client_id", socket.gethostname())).strip()

    # ---- logging section ----
    log_sec = raw.get("logging", {})
    cfg.log_level = log_sec.get("level", DEFAULT_LOG_LEVEL).upper()
    cfg.log_file = log_sec.get("file", None)

    logger.debug(
        "Client config loaded: relay=%s:%d networks=%s",
        cfg.relay_host, cfg.relay_port,
        cfg.activate_networks or "all",
    )
    return cfg


def _parse_client_tls(raw: dict, relay_host: str) -> ClientTLSConfig:
    tls = ClientTLSConfig()
    tls.enabled = bool(raw.get("enabled", True))
    tls.cafile = raw.get("cafile", None)
    tls.certfile = raw.get("certfile", None)
    tls.keyfile = raw.get("keyfile", None)
    tls.verify_hostname = bool(raw.get("verify_hostname", True))
    tls.server_hostname = raw.get("server_hostname", relay_host)

    # Validate mTLS pair completeness.
    has_cert = bool(tls.certfile)
    has_key = bool(tls.keyfile)
    if has_cert != has_key:
        raise ValueError(
            "tls.certfile and tls.keyfile must both be specified (or both omitted)"
        )

    return tls
