"""
pivot/common/crypto.py

Security utilities shared by both the pivot agent and client:

  - HMAC-SHA256 token derivation with per-connection nonce
    (prevents replay attacks without a session database).
  - TLS context factories with hardened defaults (TLS 1.2 minimum,
    weak cipher exclusion, optional mutual TLS).

Design notes
------------
* Tokens are never stored as plaintext beyond the config file.
* ``verify_token`` uses ``hmac.compare_digest`` (constant-time comparison)
  to resist timing-based side-channel attacks.
* TLS 1.3 is preferred; TLS 1.2 is the hard floor.
* Hostname verification is always on for the client unless explicitly
  disabled for testing (never disable in production).
"""

import hashlib   # stdlib — Python Software Foundation (https://docs.python.org/3/library/hashlib.html)
import hmac      # stdlib — Python Software Foundation; compare_digest() resists timing attacks
import logging
import os
import ssl       # stdlib — Python Software Foundation; wraps OpenSSL (https://openssl.org) for TLS contexts
from typing import Optional

logger = logging.getLogger(__name__)

# Minimum TLS version enforced on every context we create.
_MIN_TLS = ssl.TLSVersion.TLSv1_2

# Cipher suite exclusion pattern applied to SSLContext objects.
# Removes NULL auth, export-grade, DES, RC4, MD5-based, and anonymous DHE.
_EXCLUDED_CIPHERS = "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!ADH:!3DES"


# ---------------------------------------------------------------------------
# Token authentication
# ---------------------------------------------------------------------------

def derive_token_hash(secret: str, nonce: str) -> str:
    """
    Produce an HMAC-SHA256 hex digest over (nonce) using *secret* as the key.

    The nonce is included in the HMAC input so that each authentication
    message produces a unique digest even when the secret is constant.
    This prevents an eavesdropper from replaying a captured AUTH message.

    Args:
        secret: Shared pre-authentication secret from the config file.
        nonce:  Per-connection random value sent in plaintext in the AUTH
                message (its secrecy is unnecessary; its uniqueness matters).

    Returns:
        Lowercase hexadecimal HMAC digest (64 characters for SHA-256).
    """
    key = secret.encode("utf-8")
    message = nonce.encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    return digest


def verify_token(secret: str, nonce: str, provided_hash: str) -> bool:
    """
    Constant-time verification of a token received from a pivot client.

    Args:
        secret:        Shared secret stored in the agent config.
        nonce:         Nonce from the AUTH message (untrusted input).
        provided_hash: HMAC digest from the AUTH message (untrusted input).

    Returns:
        True if the provided hash matches the expected digest; False otherwise.
    """
    expected = derive_token_hash(secret, nonce)
    # hmac.compare_digest operates in constant time to prevent timing attacks.
    return hmac.compare_digest(expected, provided_hash)


def generate_nonce(length: int = 32) -> str:
    """
    Generate a cryptographically random nonce as a hex string.

    Args:
        length: Number of random bytes (hex output will be 2× this length).

    Returns:
        Lowercase hex string of the requested length.
    """
    return os.urandom(length).hex()


# ---------------------------------------------------------------------------
# TLS context factories
# ---------------------------------------------------------------------------

def build_server_tls_context(
    certfile: str,
    keyfile: str,
    cafile: Optional[str] = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """
    Create a hardened SSLContext for the pivot agent (server side).

    Args:
        certfile:            Path to the agent's PEM certificate.
        keyfile:             Path to the agent's PEM private key.
        cafile:              Path to the CA certificate bundle used to
                             verify client certificates (mTLS). Required
                             when *require_client_cert* is True.
        require_client_cert: Enforce mutual TLS; reject clients that
                             present no certificate or an invalid one.

    Returns:
        An ssl.SSLContext ready to be passed to asyncio.start_server().

    Raises:
        ssl.SSLError: If certificates or keys cannot be loaded.
        FileNotFoundError: If any required file does not exist.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_TLS
    ctx.set_ciphers(_EXCLUDED_CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION  # Disable TLS compression (CRIME)

    # Load the server certificate and private key.
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    logger.debug("Server TLS: loaded cert=%s key=%s", certfile, keyfile)

    # Configure client certificate verification.
    if require_client_cert:
        if not cafile:
            raise ValueError(
                "require_client_cert=True requires cafile to be specified"
            )
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cafile)
        logger.debug("Server TLS: mTLS enabled, CA=%s", cafile)
    elif cafile:
        # Accept client certs if presented, but don't require them.
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.load_verify_locations(cafile=cafile)
        logger.debug("Server TLS: optional client cert, CA=%s", cafile)
    else:
        # No client certificate verification.
        ctx.verify_mode = ssl.CERT_NONE
        logger.debug("Server TLS: no client certificate verification")

    return ctx


def build_client_tls_context(
    cafile: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    server_hostname: Optional[str] = None,
    verify_hostname: bool = True,
) -> ssl.SSLContext:
    """
    Create a hardened SSLContext for the pivot client (outbound connection).

    Args:
        cafile:           Path to the CA certificate to verify the agent's
                          certificate. If None, system CAs are used.
        certfile:         Path to the client's certificate (for mTLS).
        keyfile:          Path to the client's private key (for mTLS).
        server_hostname:  Hostname used for SNI and certificate matching.
        verify_hostname:  If False, hostname verification is skipped.
                          ONLY disable for local testing.

    Returns:
        An ssl.SSLContext ready to be passed to asyncio.open_connection().
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _MIN_TLS
    ctx.set_ciphers(_EXCLUDED_CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION

    if cafile:
        ctx.load_verify_locations(cafile=cafile)
        logger.debug("Client TLS: using custom CA=%s", cafile)
    else:
        ctx.load_default_certs()
        logger.debug("Client TLS: using system CAs")

    ctx.check_hostname = verify_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load client certificate and key for mTLS (optional).
    if certfile and keyfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        logger.debug("Client TLS: mTLS client cert=%s", certfile)
    elif certfile or keyfile:
        logger.warning(
            "Client TLS: both certfile and keyfile must be provided for mTLS; "
            "ignoring incomplete pair"
        )

    return ctx


def build_insecure_tls_context() -> ssl.SSLContext:
    """
    Create a TLS context that does NOT verify the server certificate.

    WARNING: Use ONLY in isolated test environments. This context is
    vulnerable to man-in-the-middle attacks and must never be used in
    production.

    Returns:
        An ssl.SSLContext with certificate verification disabled.
    """
    logger.warning(
        "TLS: INSECURE context requested – certificate verification is DISABLED. "
        "Do not use in production."
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _MIN_TLS
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
