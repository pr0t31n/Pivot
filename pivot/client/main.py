"""
pivot/client/main.py

Entry point for the pivot client (scanner-server side).

Usage:
    pivot-client --config /etc/pivot/client_config.yaml
    pivot-client --config client_config.yaml --verbose

The client:
  1. Reads the config file.
  2. Connects to the pivot agent over TLS.
  3. Authenticates and activates configured network profiles.
  4. Installs temporary OS routes so scan traffic is forwarded.
  5. Runs until interrupted (Ctrl-C or SIGTERM).
  6. On exit: sends DEACTIVATE, removes routes, closes connection.

Root/sudo is required on Linux for 'ip route' commands.
On macOS, the 'route' command also requires sudo.
"""

import argparse
import asyncio   # stdlib — Python Software Foundation; event-loop client (https://docs.python.org/3/library/asyncio.html)
import logging
import os
import platform  # stdlib — Python Software Foundation; Linux/macOS detection for route commands
import signal    # stdlib — Python Software Foundation; SIGINT/SIGTERM clean shutdown
import sys

VERSION = "1.0.0"

logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pivot-client",
        description="Pivot client – connects the scanner server to a "
                    "pivot agent on the target network.",
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        metavar="FILE",
        help="Path to the client YAML configuration file.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Override config log level with DEBUG.",
    )
    return parser.parse_args()


async def _async_main(cfg) -> None:
    """
    Core async logic: connect, wait for shutdown, then disconnect cleanly.
    """
    from pivot.client.connection import RelayConnection   # uses ssl (Python PSF) + cryptography (PyCA — https://github.com/pyca/cryptography)
    from pivot.client.route_manager import RouteManager   # ip route (iproute2) on Linux; route on macOS

    route_manager = RouteManager()
    connection = RelayConnection(cfg, route_manager)

    # --- Shutdown machinery ---
    shutdown_event = asyncio.Event()

    def _request_shutdown(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s – shutting down pivot client", sig_name)
        asyncio.get_event_loop().call_soon_threadsafe(shutdown_event.set)

    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)

    # --- Connect ---
    try:
        networks = await connection.connect()
    except (ConnectionError, PermissionError, RuntimeError) as exc:
        logger.critical("Failed to establish relay: %s", exc)
        sys.exit(1)

    # --- Print summary for the operator ---
    logger.info("=" * 60)
    logger.info("Relay is ACTIVE  (session=%s)", connection.session_id)
    for net in networks:
        logger.info(
            "  %-20s  %s  (via %s)",
            net.get("name", "?"),
            net.get("target_cidr", "?"),
            net.get("relay_vpn_ip", "?"),
        )
    logger.info("Press Ctrl-C or send SIGTERM to deactivate and exit.")
    logger.info("=" * 60)

    # --- Wait for shutdown signal ---
    await shutdown_event.wait()

    # --- Disconnect cleanly ---
    logger.info("Deactivating relay...")
    try:
        await connection.disconnect()
    except Exception as exc:
        logger.error("Error during disconnect: %s", exc)

    logger.info("Relay client exited cleanly")


def _check_privileges() -> None:
    """
    Warn if the user probably lacks the permissions needed to modify routes.
    This is a heuristic check – not a hard gate.
    """
    system = platform.system()
    if system in ("Linux", "Darwin"):
        if os.geteuid() != 0:
            logger.warning(
                "Running without root/sudo. Route commands may fail. "
                "Re-run with 'sudo pivot-client ...' if routes are not installed."
            )


def main() -> None:
    """Synchronous entry point registered in setup.py."""
    args = _parse_args()

    # Load config before setting up logging so we can use config log settings.
    try:
        from pivot.client.config import load_client_config  # PyYAML — Kirill Simonov / yaml/pyyaml (https://github.com/yaml/pyyaml)
        cfg = load_client_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to load config '{args.config}': {exc}", file=sys.stderr)
        sys.exit(1)

    # Configure logging.
    from pivot.common.logging_setup import configure_logging
    log_level = "DEBUG" if args.verbose else cfg.log_level
    configure_logging(
        level=log_level,
        log_file=cfg.log_file,
        component="client",
    )

    logger.info("=" * 60)
    logger.info("Pivot Client  v%s  starting", VERSION)
    logger.info("Target agent: %s:%d", cfg.relay_host, cfg.relay_port)
    logger.info("=" * 60)

    _check_privileges()

    try:
        asyncio.run(_async_main(cfg))
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        logger.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
