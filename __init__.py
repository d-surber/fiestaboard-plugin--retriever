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
import urllib.error
import urllib.request
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.plugins.base import PluginBase, PluginResult

logger = logging.getLogger(__name__)

# FiestaBoard abandons a fetch that takes longer than 5 s, and quarantines a
# plugin after three such fetches in a row. Stay inside that: this is the
# budget for one fetch_data, however many requests it makes.
TIMEOUT_SECONDS = 4

# Wire protocol, version 1; RetrieverServer's Wire.swift is the other half.
# Request and response bodies are each one ChaCha20-Poly1305 message: 12-byte
# nonce, ciphertext, 16-byte tag. The associated data names the version, the
# direction and the path.
RETRIEVE_PATH = "/retrieve"
CONFIG_PATH = "/config"
KEY_BYTES = 32
NONCE_BYTES = 12

CONFIG_PENDING = "config pending"


def request_context(path: str) -> bytes:
    return f"retriever/1 request {path}".encode()


def response_context(path: str) -> bytes:
    return f"retriever/1 response {path}".encode()


def decode_key(value: Any) -> bytes | None:
    """Return the 32-byte key that *value* is the base64 of, or None."""
    if not isinstance(value, str):
        return None
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return key if len(key) == KEY_BYTES else None


def seal_request(key: bytes, now: float, path: str) -> tuple[bytes, str]:
    """Return a request body for *path* and the ID the response must echo."""
    request_id = secrets.token_hex(16)
    plaintext = json.dumps({"ts": int(now), "id": request_id}).encode()
    nonce = os.urandom(NONCE_BYTES)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, request_context(path)), request_id


def open_response(key: bytes, body: bytes, request_id: str, path: str) -> tuple[int, dict[str, Any]]:
    """
    Return the config sequence number and the data in a response body.

    Raises unless the body is the server's answer to *request_id* on *path*.
    """
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(body[:NONCE_BYTES], body[NONCE_BYTES:], response_context(path))
    except (InvalidTag, ValueError):
        raise ValueError("wrong key or corrupt response") from None
    try:
        message = json.loads(plaintext)
    except ValueError:
        raise ValueError("not JSON in response") from None
    if not isinstance(message, dict) or message.get("id") != request_id:
        raise ValueError("wrong ID in response")
    seq = message.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise ValueError("no seq in response")
    if not isinstance(message.get("data"), dict):
        raise ValueError("no data in response")
    return seq, message["data"]


def describe(error: Exception) -> str:
    """A short reason for a failed fetch. What distinguishes it comes first, because a board truncates."""
    if isinstance(error, urllib.error.HTTPError):
        return f"{error.code} {error.reason}"
    if isinstance(error, urllib.error.URLError) and isinstance(error.reason, Exception):
        error = error.reason
    if isinstance(error, TimeoutError):
        return "timed out"
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return str(error) or type(error).__name__


def default_for(schema: Any) -> Any:
    """The value a JSON Schema describes when nothing is known: its ``default``, or else an empty value of its type."""
    if not isinstance(schema, dict):
        return None
    if "default" in schema:
        return schema["default"]
    kind = schema.get("type")
    if kind == "object":
        properties = schema.get("properties")
        return {name: default_for(sub) for name, sub in properties.items()} if isinstance(properties, dict) else {}
    if kind == "array":
        return []
    if kind == "string":
        return ""
    if kind in ("integer", "number"):
        return 0
    if kind == "boolean":
        return False
    return None


class RetrieverPlugin(PluginBase):
    """Retriever plugin implementation."""

    def __init__(self, manifest: dict[str, Any]):
        super().__init__(manifest)
        # What the server said about itself, never built in: its config
        # sequence number and {source: JSON Schema of that source's data}.
        # None until read. One tuple, so a concurrent fetch sees both or neither.
        self._server_config: tuple[int, dict[str, Any]] | None = None

    @property
    def plugin_id(self) -> str:
        """Return the plugin ID matching manifest.json."""
        return "retriever"

    def on_config_change(self, old_config: dict[str, Any], new_config: dict[str, Any]) -> None:
        """Settings were saved: read the server's config again on the next fetch."""
        self._server_config = None

    def fetch_data(self) -> PluginResult:
        """
        Assign the template variables from one fetch. Never raises.

        _fetch tells the truth about each request; what the variables become
        when one fails is decided here.

        Returns:
            PluginResult with:
            - available: False only if the plugin is not configured
            - data: the server's values unchanged, plus ``error``:
              {<source>: {"error": ..., "data": ...}, ..., "error": ""}.
              After a failed retrieve, every source the server's config lists
              has its schema's default as data, and ``error`` is the reason.
              Before the config has been read no source is known, so there
              is only ``error``, ending in "config pending".
            - error: The same reason, for FiestaBoard itself
        """
        errors = self.validate_config(self.config)
        if errors:
            return PluginResult(available=False, error="; ".join(errors))

        server_url = self.config["server_url"].strip().rstrip("/")
        key = decode_key(self.config["key"])
        deadline = time.monotonic() + TIMEOUT_SECONDS

        if self._server_config is None:
            try:
                self._server_config = self._fetch(server_url, CONFIG_PATH, key, deadline)
            except Exception as e:
                return self._failed(server_url, CONFIG_PATH, f"{describe(e)}; {CONFIG_PENDING}", {})

        config_seq, sources = self._server_config
        try:
            seq, values = self._fetch(server_url, RETRIEVE_PATH, key, deadline)
        except Exception as e:
            unknown = {name: {"error": "", "data": default_for(schema)} for name, schema in sources.items()}
            return self._failed(server_url, RETRIEVE_PATH, describe(e), unknown)

        if seq != config_seq:
            # The server's config changed, in either direction. The values
            # just retrieved are good; the config is read again, now or on
            # the next fetch.
            try:
                self._server_config = self._fetch(server_url, CONFIG_PATH, key, deadline)
            except Exception as e:
                return self._failed(server_url, CONFIG_PATH, f"{describe(e)}; {CONFIG_PENDING}", values)

        return PluginResult(available=True, data={**values, "error": ""})

    def _failed(self, server_url: str, path: str, reason: str, values: dict[str, Any]) -> PluginResult:
        """The result of a fetch in which a request failed: *values*, and the reason in ``error``."""
        logger.warning(f"Fetch from {server_url}{path} failed: {reason}")
        return PluginResult(available=True, data={**values, "error": reason}, error=reason)

    def _fetch(self, server_url: str, path: str, key: bytes, deadline: float) -> tuple[int, dict[str, Any]]:
        """
        Make one request to the server; return its config sequence number and data.

        The only place that talks to the server. Raises on any failure: no
        answer by *deadline*, a non-2xx status, or a response that is not the
        server's answer to this request.
        """
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise TimeoutError
        body, request_id = seal_request(key, time.time(), path)
        # The scheme is restricted to http(s) by validate_config.
        request = urllib.request.Request(  # noqa: S310
            server_url + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return open_response(key, response.read(), request_id, path)

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """
        Validate plugin configuration.

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
