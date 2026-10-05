"""
Retriever plugin for FiestaBoard.

Fetches data from a companion server and exposes it to templates.
"""

import base64
import binascii
import json
import logging
import os
import secrets
import time
import urllib.request
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.plugins.base import PluginBase, PluginResult

logger = logging.getLogger(__name__)

# FiestaBoard abandons a fetch that takes longer than 5 s, and quarantines a
# plugin after three such fetches in a row. Stay inside that.
TIMEOUT_SECONDS = 4

# Wire protocol, version 1; RetrieverServer's Wire.swift is the other half.
# Request and response bodies are each one ChaCha20-Poly1305 message: 12-byte
# nonce, ciphertext, 16-byte tag. The associated data names the version, the
# direction and the path.
PATH = "/retrieve"
REQUEST_CONTEXT = b"retriever/1 request /retrieve"
RESPONSE_CONTEXT = b"retriever/1 response /retrieve"
KEY_BYTES = 32
NONCE_BYTES = 12

# What the server sends for reminders when nothing is due.
NO_REMINDERS: dict[str, Any] = {"error": "", "data": {"count": 0, "text": "", "items": []}}


def decode_key(value: Any) -> bytes | None:
    """Return the 32-byte key that *value* is the base64 of, or None."""
    if not isinstance(value, str):
        return None
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return key if len(key) == KEY_BYTES else None


def seal_request(key: bytes, now: float) -> tuple[bytes, str]:
    """Return a request body and the ID the response must echo."""
    request_id = secrets.token_hex(16)
    plaintext = json.dumps({"ts": int(now), "id": request_id}).encode()
    nonce = os.urandom(NONCE_BYTES)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, REQUEST_CONTEXT), request_id


def open_response(key: bytes, body: bytes, request_id: str) -> dict[str, Any]:
    """Return the values in a response body. Raises unless it is the server's answer to *request_id*."""
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(body[:NONCE_BYTES], body[NONCE_BYTES:], RESPONSE_CONTEXT)
    except (InvalidTag, ValueError):
        raise ValueError("Response was not encrypted with this key") from None
    message = json.loads(plaintext)
    if not isinstance(message, dict) or message.get("id") != request_id:
        raise ValueError("Response does not answer this request")
    if not isinstance(message.get("data"), dict):
        raise ValueError("Response has no values")
    return message["data"]


class RetrieverPlugin(PluginBase):
    """Retriever plugin implementation."""

    @property
    def plugin_id(self) -> str:
        """Return the plugin ID matching manifest.json."""
        return "retriever"

    def fetch_data(self) -> PluginResult:
        """
        Assign the template variables from one fetch. Never raises.

        _fetch tells the truth about the fetch; what the variables become
        when it fails is decided here: ``reminders`` is empty, because
        nothing is known, and ``error`` says why.

        Returns:
            PluginResult with:
            - available: False only if the plugin is not configured
            - data: {<name>: {"error": ..., "data": ...}, ..., "error": ""},
              the server's values unchanged, or, after a failed fetch,
              {"reminders": <no reminders>, "error": <reason>}
            - error: The same reason, for FiestaBoard itself
        """
        errors = self.validate_config(self.config)
        if errors:
            return PluginResult(available=False, error="; ".join(errors))

        server_url = self.config["server_url"].strip().rstrip("/")

        try:
            values = self._fetch(server_url, decode_key(self.config["key"]))
        except Exception as e:
            reason = str(e) or type(e).__name__
            logger.warning(f"Fetch from {server_url} failed: {reason}")
            return PluginResult(available=True, data={"reminders": NO_REMINDERS, "error": reason}, error=reason)

        return PluginResult(available=True, data={**values, "error": ""})

    def _fetch(self, server_url: str, key: bytes) -> dict[str, Any]:
        """
        Retrieve the server's values.

        The only place that talks to the server. Raises on any failure: no
        answer, a non-2xx status, or a response that is not the server's
        answer to this request.
        """
        body, request_id = seal_request(key, time.time())
        # The scheme is restricted to http(s) by validate_config.
        request = urllib.request.Request(  # noqa: S310
            server_url + PATH,
            data=body,
            method="POST",
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return open_response(key, response.read(), request_id)

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """
        Validate plugin configuration.

        This method is called when configuration is updated.
        Note: refresh_seconds validation is handled automatically by
        the base class using the manifest's settings_schema bounds.

        Args:
            config: The configuration dictionary to validate

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        server_url = config.get("server_url")
        if not isinstance(server_url, str) or not server_url.strip():
            errors.append("Server URL is required")
        elif not server_url.strip().lower().startswith(("http://", "https://")):
            errors.append("Server URL must start with http:// or https://")

        if not config.get("key"):
            errors.append("Key is required")
        elif decode_key(config["key"]) is None:
            errors.append("Key must be the base64 of 32 bytes")

        return errors

    def cleanup(self) -> None:
        """
        Cleanup when plugin is disabled.

        Override this to clean up any resources (close connections, etc.)
        """
        logger.info(f"Plugin {self.plugin_id} cleanup")
