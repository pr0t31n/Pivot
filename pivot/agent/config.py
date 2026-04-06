"""
pivot/agent/config.py

Configuration loader and validator for the pivot agent.

Reads a YAML file and returns a typed AgentConfig dataclass.
All validation errors are raised as ValueError with clear messages so
the operator knows exactly what to fix before starting the daemon.
"""

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

import yaml

logger = logging.getLogger(__name__)

# Default values – all may be overridden in the YAML file.
DEFAULT_BIND_ADDRESS = "0.0.0.0"
DEFAULT_PORT = 5200
DEFAULT_HEARTBEAT_TIMEOUT = 90  # seconds
DEFAULT_MAX_SESSIONS = 5
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB

# Chain connector defaults
DEFAULT_CHAIN_CONNECT_TIMEOUT = 30.0
DEFAULT_CHAIN_OPERATION_TIMEOUT = 60.0
DEFAULT_CHAIN_HEARTBEAT_INTERVAL = 30.0


@dataclass
class TLSConfig:
    """TLS settings for the agent listener."""

    enabled: bool = True
    certfile: str = ""
    keyfile: str = ""
    cafile: Optional[str] = None
    require_client_cert: bool = False


@dataclass
class UpstreamTLSConfig:
    """TLS settings for an outbound chain connection to an upstream relay."""

    enabled: bool = True
    cafile: Optional[str] = None
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    server_hostname: Optional[str] = None  # Overrides host for SNI + cert verification
    verify_hostname: bool = True


@dataclass
class UpstreamRelayConfig:
    """
    Connection parameters for the next relay in a chain.

    When a NetworkProfile has a non-None upstream, this relay acts as a
    pivot-client to the upstream relay when activating that profile.

    Attributes:
        host:                IP or hostname of the upstream pivot agent.
        port:                Port the upstream pivot agent listens on.
        auth_token:          Shared secret for the upstream relay.
        tls:                 TLS settings for the outbound connection.
        activate_networks:   Profile names to activate on the upstream relay.
                             Empty list activates all profiles on that relay.
        connect_timeout:     Seconds to wait when opening the TCP connection.
        operation_timeout:   Seconds to wait for individual protocol messages.
        heartbeat_interval:  How often to send heartbeats to the upstream relay.
        client_id:           Identifier sent in AUTH for audit logs upstream.
    """

    host: str = ""
    port: int = DEFAULT_PORT
    auth_token: str = ""
    tls: UpstreamTLSConfig = field(default_factory=UpstreamTLSConfig)
    activate_networks: List[str] = field(default_factory=list)
    connect_timeout: float = DEFAULT_CHAIN_CONNECT_TIMEOUT
    operation_timeout: float = DEFAULT_CHAIN_OPERATION_TIMEOUT
    heartbeat_interval: float = DEFAULT_CHAIN_HEARTBEAT_INTERVAL
    client_id: str = "chain-connector"


@dataclass
class NetworkProfile:
    """
    Represents a single routable target network the agent can expose.

    Attributes:
        name:             Human-readable identifier (used in ACTIVATE messages).
        target_cidr:      IPv4 network to make reachable (e.g. "10.0.0.0/24").
        egress_interface: Interface facing the next hop (target LAN for direct
                          profiles; the network toward the upstream relay for
                          chained profiles).
        vpn_interface:    Interface connected to the VPN (e.g. "tun0").
        upstream:         If set, this is a chained profile.  The agent will
                          act as a pivot-client to the upstream relay to reach
                          the target network.
    """

    name: str
    target_cidr: str
    egress_interface: str
    vpn_interface: str
    upstream: Optional[UpstreamRelayConfig] = None

    @property
    def is_chained(self) -> bool:
        """True if this profile requires an upstream relay connection."""
        return self.upstream is not None


@dataclass
class AgentConfig:
    """Complete configuration for the pivot agent daemon."""

    # Listener
    bind_address: str = DEFAULT_BIND_ADDRESS
    port: int = DEFAULT_PORT

    # Authentication
    auth_token: str = ""

    # TLS
    tls: TLSConfig = field(default_factory=TLSConfig)

    # Peer allowlist – empty list means any authenticated peer is accepted.
    allowed_peers: List[str] = field(default_factory=list)

    # Target network profiles
    networks: List[NetworkProfile] = field(default_factory=list)

    # Session management
    heartbeat_timeout: int = DEFAULT_HEARTBEAT_TIMEOUT
    max_sessions: int = DEFAULT_MAX_SESSIONS

    # Logging
    log_level: str = DEFAULT_LOG_LEVEL
    log_file: Optional[str] = None
    log_max_bytes: int = DEFAULT_LOG_MAX_BYTES


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def load_agent_config(path: str) -> AgentConfig:
    """
    Parse *path* as YAML and return a validated AgentConfig.

    Args:
        path: Filesystem path to the agent YAML configuration file.

    Returns:
        Populated and validated AgentConfig dataclass.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError:        If any required field is missing or invalid.
        yaml.YAMLError:    If the file contains malformed YAML.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Agent config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError("Config file must contain a YAML mapping at the top level")

    cfg = AgentConfig()

    # ---- relay section ----
    relay_sec = raw.get("relay", {})
    cfg.bind_address = relay_sec.get("bind_address", DEFAULT_BIND_ADDRESS)
    cfg.port = int(relay_sec.get("port", DEFAULT_PORT))
    if not (1 <= cfg.port <= 65535):
        raise ValueError(f"relay.port must be 1–65535, got {cfg.port}")

    # ---- security section ----
    sec = raw.get("security", {})
    cfg.auth_token = str(sec.get("auth_token", "")).strip()
    if not cfg.auth_token:
        raise ValueError("security.auth_token must not be empty")
    if len(cfg.auth_token) < 16:
        logger.warning(
            "security.auth_token is shorter than 16 characters – "
            "use a long random value in production"
        )

    # TLS
    tls_sec = sec.get("tls", {})
    cfg.tls = _parse_tls_config(tls_sec)

    # Allowed peers (optional IP allowlist)
    raw_peers = sec.get("allowed_peers", [])
    cfg.allowed_peers = _parse_allowed_peers(raw_peers)

    # ---- networks section ----
    raw_networks = raw.get("networks", [])
    if not raw_networks:
        raise ValueError("At least one network profile must be defined under 'networks'")
    cfg.networks = [_parse_network_profile(n) for n in raw_networks]

    # Check for duplicate profile names.
    names = [n.name for n in cfg.networks]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate network profile names are not allowed")

    # ---- session section ----
    sess = raw.get("session", {})
    cfg.heartbeat_timeout = int(sess.get("heartbeat_timeout", DEFAULT_HEARTBEAT_TIMEOUT))
    cfg.max_sessions = int(sess.get("max_sessions", DEFAULT_MAX_SESSIONS))
    if cfg.heartbeat_timeout < 10:
        raise ValueError("session.heartbeat_timeout must be >= 10 seconds")

    # ---- logging section ----
    log_sec = raw.get("logging", {})
    cfg.log_level = log_sec.get("level", DEFAULT_LOG_LEVEL).upper()
    cfg.log_file = log_sec.get("file", None)
    cfg.log_max_bytes = int(
        log_sec.get("max_bytes", DEFAULT_LOG_MAX_BYTES)
    )

    logger.debug(
        "Agent config loaded: %d network profile(s) from %s", len(cfg.networks), path
    )
    return cfg


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _parse_tls_config(raw: dict) -> TLSConfig:
    tls = TLSConfig()
    tls.enabled = bool(raw.get("enabled", True))

    if tls.enabled:
        tls.certfile = str(raw.get("certfile", "")).strip()
        tls.keyfile = str(raw.get("keyfile", "")).strip()
        if not tls.certfile:
            raise ValueError("tls.certfile must be specified when TLS is enabled")
        if not tls.keyfile:
            raise ValueError("tls.keyfile must be specified when TLS is enabled")

    tls.cafile = raw.get("cafile", None)
    tls.require_client_cert = bool(raw.get("require_client_cert", False))

    if tls.require_client_cert and not tls.cafile:
        raise ValueError(
            "tls.cafile must be specified when tls.require_client_cert is true"
        )

    return tls


def _parse_allowed_peers(raw: list) -> List[str]:
    peers = []
    for entry in raw:
        entry = str(entry).strip()
        try:
            # Validate as an IPv4/IPv6 address.
            ipaddress.ip_address(entry)
            peers.append(entry)
        except ValueError:
            raise ValueError(
                f"security.allowed_peers: '{entry}' is not a valid IP address"
            )
    return peers


def _parse_network_profile(raw: dict) -> NetworkProfile:
    name = str(raw.get("name", "")).strip()
    if not name:
        raise ValueError("Each network profile must have a non-empty 'name'")

    target_cidr = str(raw.get("target_cidr", "")).strip()
    if not target_cidr:
        raise ValueError(f"Network profile '{name}' is missing 'target_cidr'")
    try:
        ipaddress.IPv4Network(target_cidr, strict=False)
    except ValueError as exc:
        raise ValueError(
            f"Network profile '{name}': invalid target_cidr '{target_cidr}': {exc}"
        )

    egress_iface = str(raw.get("egress_interface", "")).strip()
    if not egress_iface:
        raise ValueError(f"Network profile '{name}' is missing 'egress_interface'")

    vpn_iface = str(raw.get("vpn_interface", "")).strip()
    if not vpn_iface:
        raise ValueError(f"Network profile '{name}' is missing 'vpn_interface'")

    upstream: Optional[UpstreamRelayConfig] = None
    if "upstream" in raw and raw["upstream"]:
        upstream = _parse_upstream_config(name, raw["upstream"])

    return NetworkProfile(
        name=name,
        target_cidr=target_cidr,
        egress_interface=egress_iface,
        vpn_interface=vpn_iface,
        upstream=upstream,
    )


def _parse_upstream_config(profile_name: str, raw: dict) -> UpstreamRelayConfig:
    """Parse and validate the upstream relay block inside a network profile."""
    ctx = f"Network profile '{profile_name}' upstream"

    host = str(raw.get("host", "")).strip()
    if not host:
        raise ValueError(f"{ctx}: 'host' must be specified")

    port = int(raw.get("port", DEFAULT_PORT))
    if not (1 <= port <= 65535):
        raise ValueError(f"{ctx}: 'port' must be 1–65535, got {port}")

    auth_token = str(raw.get("auth_token", "")).strip()
    if not auth_token:
        raise ValueError(f"{ctx}: 'auth_token' must be specified")

    tls_raw = raw.get("tls", {})
    tls = UpstreamTLSConfig()
    tls.enabled = bool(tls_raw.get("enabled", True))
    tls.cafile = tls_raw.get("cafile", None)
    tls.certfile = tls_raw.get("certfile", None)
    tls.keyfile = tls_raw.get("keyfile", None)
    tls.server_hostname = tls_raw.get("server_hostname", host)
    tls.verify_hostname = bool(tls_raw.get("verify_hostname", True))

    activate_networks = [
        str(n).strip() for n in raw.get("activate_networks", [])
    ]

    client_id = str(raw.get("client_id", "chain-connector")).strip()

    return UpstreamRelayConfig(
        host=host,
        port=port,
        auth_token=auth_token,
        tls=tls,
        activate_networks=activate_networks,
        connect_timeout=float(raw.get("connect_timeout", DEFAULT_CHAIN_CONNECT_TIMEOUT)),
        operation_timeout=float(raw.get("operation_timeout", DEFAULT_CHAIN_OPERATION_TIMEOUT)),
        heartbeat_interval=float(raw.get("heartbeat_interval", DEFAULT_CHAIN_HEARTBEAT_INTERVAL)),
        client_id=client_id,
    )
