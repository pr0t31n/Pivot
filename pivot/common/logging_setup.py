"""
pivot/common/logging_setup.py

Configures rotating-file + console logging for both agent and client.
Call configure_logging() once at process startup before any other imports
that use logging.
"""

import logging
import logging.handlers
import os
import sys
from typing import Optional


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB per file
    backup_count: int = 5,
    component: str = "relay",
) -> None:
    """
    Set up the root logger with consistent formatting.

    Args:
        level:        Log level string, e.g. "DEBUG", "INFO", "WARNING".
        log_file:     Absolute path to the log file. If None, file logging
                      is disabled and only the console handler is attached.
        max_bytes:    Rotate the log file after this many bytes.
        backup_count: Number of rotated log files to retain.
        component:    Short label appended to the log format (e.g. "agent").
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Build a formatter that includes timestamp, level, component, and source.
    fmt = (
        "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s"
    )
    date_fmt = "%Y-%m-%dT%H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=date_fmt)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove any handlers already attached (e.g. from previous calls).
    root.handlers.clear()

    # --- Console handler (stderr so stdout stays clean) ---
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # --- Rotating file handler (optional) ---
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except OSError as exc:
            # Failing to open the log file is non-fatal; warn on stderr.
            root.warning(
                "Could not open log file %s: %s – file logging disabled",
                log_file,
                exc,
            )

    logging.getLogger("pivot").info(
        "Logging initialised | component=%s level=%s file=%s",
        component,
        level.upper(),
        log_file or "none",
    )
