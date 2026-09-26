"""
pivot/agent/main.py

Entry point for the pivot agent daemon.

Usage:
    pivot-agent --config /etc/pivot/agent_config.yaml
    pivot-agent --config /etc/pivot/agent_config.yaml --verbose

Requires root (or CAP_NET_ADMIN + CAP_NET_RAW) to modify iptables
and sysctl values.
"""

import argparse
import asyncio  # stdlib — Python Software Foundation; event-loop server (https://docs.python.org/3/library/asyncio.html)
import logging
import os
import signal   # stdlib — Python Software Foundation; SIGINT/SIGTERM for clean shutdown
import platform
import shutil
import sys

VERSION = __import__("pathlib").Path(__file__).resolve().parents[2].joinpath("VERSION").read_text().strip()

logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pivot-agent",
        description="Pivot agent – enables scanner servers to reach "
                    "target networks through this device.",
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        metavar="FILE",
        help="Path to the agent YAML configuration file.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Override config log level with DEBUG.",
    )
    return parser.parse_args()


async def _async_main(cfg) -> None:
    """
    Async entry point: initialise components, start the server, wait for
    shutdown signal, then clean up.
    """
    # Lazy imports so the top-level entry point stays fast.
    from pivot.agent.network_manager import NetworkManager   # iptables / sysctl — netfilter.org / Harald Welte @laforge
    from pivot.agent.session_manager import SessionManager
    from pivot.agent.server import RelayServer                # asyncio TLS server — Python PSF

    nm = NetworkManager()
    sm = SessionManager(cfg, nm)
    server = RelayServer(cfg, nm, sm)

    # --- Graceful shutdown machinery ---
    shutdown_event = asyncio.Event()

    def _request_shutdown(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s – initiating graceful shutdown", sig_name)
        asyncio.get_event_loop().call_soon_threadsafe(shutdown_event.set)

    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)

    # Start serving.
    try:
        await server.start()
    except Exception as exc:
        logger.critical("Failed to start server: %s", exc)
        sys.exit(1)

    # Log configured network profiles.
    logger.info(
        "Configured network profiles: %s",
        ", ".join(p.name for p in cfg.networks),
    )
    logger.info("Relay agent ready. Waiting for connections on port %d", cfg.port)

    # Block until a shutdown signal is received.
    await shutdown_event.wait()

    logger.info("Shutting down...")
    await server.stop()
    # NetworkManager's atexit handler will clean up any remaining iptables rules.
    logger.info("Relay agent stopped cleanly")


def _check_tools() -> None:
    """Check required Linux networking tools at startup (no-op on macOS/Windows)."""
    if platform.system() != "Linux":
        return
    REQUIRED_LINUX = ["iptables", "ip", "sysctl"]
    missing = [t for t in REQUIRED_LINUX if not shutil.which(t)]
    if missing:
        for t in missing:
            print(f"ERROR: Required tool not found: {t}  "
                  f"(install iproute2 and iptables)", file=__import__('sys').stderr)
        import sys as _sys; _sys.exit(1)


def main() -> None:
    """Synchronous entry point registered in setup.py."""
    args = _parse_args()

    # Check we are running as root (iptables and sysctl need it).
    if os.geteuid() != 0:
        print(
            "ERROR: The pivot agent must run as root (or with CAP_NET_ADMIN).",
            file=sys.stderr,
        )
        sys.exit(1)

    _check_tools()

    # Load configuration first so we can set up logging correctly.
    try:
        from pivot.agent.config import load_agent_config  # PyYAML — Kirill Simonov / yaml/pyyaml (https://github.com/yaml/pyyaml)
        cfg = load_agent_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to load config '{args.config}': {exc}", file=sys.stderr)
        sys.exit(1)

    # Configure logging according to config (overridden by --verbose).
    from pivot.common.logging_setup import configure_logging
    log_level = "DEBUG" if args.verbose else cfg.log_level
    configure_logging(
        level=log_level,
        log_file=cfg.log_file,
        max_bytes=cfg.log_max_bytes,
        component="agent",
    )

    logger.info("=" * 60)
    logger.info("Pivot Agent  v%s  starting", VERSION)
    logger.info("Config: %s", args.config)
    logger.info("=" * 60)

    # Run the async event loop.
    try:
        asyncio.run(_async_main(cfg))
    except KeyboardInterrupt:
        pass  # Already handled by the signal handler above.
    except Exception as exc:
        logger.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
