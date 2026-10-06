#!/usr/bin/env python3
"""
A test server for the Retriever plugin.

It speaks the same protocol as the real server (POST /server, /config and
/retrieve, each an encrypted request and response) but serves canned data: a
JSON file holding a list. Every retrieve returns the next element of the
list, in order, and after the last it starts again at the first. So a test
decides exactly what the plugin sees, and when.

The list is the data of a single source. The file is read again on every
request, so editing it takes effect at once.

Settings, all from the environment:

  RETRIEVER_TEST_FILE    the JSON file holding the list (required)
  RETRIEVER_TEST_KEY     the key shared with the plugin: base64 of 32 bytes.
                         If unset, one is made and printed at start.
  RETRIEVER_TEST_PORT    the port to listen on (default 42512)
  RETRIEVER_TEST_SOURCE  the name of the source (default "test")

Run it with:

  RETRIEVER_TEST_FILE=example.json python3 retriever_test_server.py

It needs only Python 3 and the `cryptography` package, and runs the same on
macOS and on a Raspberry Pi.
"""

import base64
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NAME = "RetrieverTestServer"
VERSION = "0.1.0"
PROTOCOLS = (1, 1)  # the inclusive range of protocols spoken
MAX_SKEW_SECONDS = 60
MAX_REQUEST_BYTES = 16384
PATHS = ("/server", "/config", "/retrieve")


def request_context(path: str) -> bytes:
    return f"retriever/1 request {path}".encode()


def response_context(path: str) -> bytes:
    return f"retriever/1 response {path}".encode()


def schema_of(value: Any) -> dict[str, Any]:
    """A JSON Schema describing *value*'s shape, taken from the value itself."""
    if isinstance(value, dict):
        return {"type": "object", "properties": {name: schema_of(item) for name, item in value.items()}}
    if isinstance(value, list):
        return {"type": "array", "items": schema_of(value[0])} if value else {"type": "array"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    return {"type": "null"}


def empty_of(value: Any) -> Any:
    """What *value* looks like with nothing in it: the default to show when nothing is known."""
    if isinstance(value, dict):
        return {name: empty_of(item) for name, item in value.items()}
    if isinstance(value, list):
        return []
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return 0
    if isinstance(value, str):
        return ""
    return None


class ListSource:
    """The one source: the elements of the list in the file, one per retrieve, round and round."""

    def __init__(self, path: str, name: str = "test"):
        self.path = path
        self.name = name
        self.position = 0  # the index of the next element to send
        self._lock = threading.Lock()

    def elements(self) -> list[Any]:
        """The list in the file. Raises ValueError saying what is wrong with it."""
        try:
            with open(self.path, encoding="utf-8") as file:
                elements = json.load(file)
        except OSError as error:
            raise ValueError(f"cannot read {self.path}: {error.strerror or error}") from None
        except ValueError:
            raise ValueError(f"{self.path} is not JSON") from None
        if not isinstance(elements, list) or not elements:
            raise ValueError(f"{self.path} does not hold a list with something in it")
        return elements

    def schema(self) -> dict[str, Any]:
        """The shape of the source's data, from the first element."""
        try:
            first = self.elements()[0]
        except ValueError:
            return {"default": None}
        return {**schema_of(first), "default": empty_of(first)}

    def config(self) -> dict[str, Any]:
        return {self.name: self.schema()}

    def seq(self) -> int:
        """Identifies the config: changes when its content does, whatever the key order or layout."""
        canonical = json.dumps(self.config(), sort_keys=True, separators=(",", ":")).encode()
        return int.from_bytes(hashlib.sha256(canonical).digest()[:4], "big")

    def next(self) -> tuple[dict[str, Any], str]:
        """The next entry to send, and a note for the log."""
        with self._lock:
            try:
                elements = self.elements()
            except ValueError as error:
                return {"error": str(error), "data": None}, str(error)
            index = self.position % len(elements)
            self.position = (index + 1) % len(elements)
            return {"error": "", "data": elements[index]}, f"element {index} of {len(elements)}"

    def info(self, port: int) -> dict[str, Any]:
        try:
            count = len(self.elements())
        except ValueError:
            count = 0
        return {
            "name": NAME,
            "version": VERSION,
            "protocol": {"min": PROTOCOLS[0], "max": PROTOCOLS[1]},
            "port": port,
            # Beyond the well-known keys: where the test stands.
            "file": self.path,
            "count": count,
            "next": self.position % count if count else 0,
        }


def make_handler(source: ListSource, key: bytes, port: int, log=print):
    cipher = ChaCha20Poly1305(key)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def say_nothing(self, why: str) -> None:
            """Close the connection without a response: for anything that has not shown the key."""
            log(f"{self.command} {self.path} -> no response ({why})")
            self.close_connection = True

        def refuse(self, status: int, reason: str) -> None:
            log(f"POST {self.path} -> {status} {reason}")
            self.send_response(status, reason)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def do_GET(self) -> None:
            self.say_nothing("not POST")

        do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = do_GET

        def do_POST(self) -> None:
            if self.path not in PATHS:
                return self.say_nothing("unknown path")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self.say_nothing("no length")
            if not 0 <= length <= MAX_REQUEST_BYTES:
                return self.say_nothing("too large")
            body = self.rfile.read(length)
            try:
                plaintext = cipher.decrypt(body[:12], body[12:], request_context(self.path))
            except Exception:
                return self.say_nothing("does not decrypt")

            # The request decrypted, so from here a refusal says why.
            try:
                request = json.loads(plaintext)
                timestamp, request_id = request["ts"], request["id"]
                if not isinstance(timestamp, int) or not isinstance(request_id, str) or not 0 < len(request_id) <= 64:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self.refuse(400, "Bad Request")
            if abs(time.time() - timestamp) > MAX_SKEW_SECONDS:
                return self.refuse(400, "Stale Timestamp")
            protocol = request.get("protocol", 1)
            if not isinstance(protocol, int) or isinstance(protocol, bool):
                return self.refuse(400, "Bad Request")
            if self.path != "/server" and not PROTOCOLS[0] <= protocol <= PROTOCOLS[1]:
                return self.refuse(400, "Unsupported Protocol")

            note = ""
            if self.path == "/server":
                data: Any = source.info(port)
            elif self.path == "/config":
                data = source.config()
            else:
                entry, note = source.next()
                data = {source.name: entry}
            message = json.dumps({"id": request_id, "seq": source.seq(), "data": data}).encode()
            nonce = os.urandom(12)
            sealed = nonce + cipher.encrypt(nonce, message, response_context(self.path))
            log(f"POST {self.path} -> 200" + (f" ({note})" if note else ""))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(sealed)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(sealed)
            self.close_connection = True

        def log_message(self, *args: Any) -> None:
            pass  # one line per request, written above

    return Handler


def serve(path: str, key: bytes, port: int, name: str = "test", log=print) -> ThreadingHTTPServer:
    """A server ready to run with ``serve_forever()``. Port 0 picks a free one."""
    source = ListSource(path, name)
    server = ThreadingHTTPServer(("", port), None)  # type: ignore[arg-type]
    server.RequestHandlerClass = make_handler(source, key, server.server_port, log)
    server.source = source  # type: ignore[attr-defined]
    return server


def main() -> int:
    path = os.environ.get("RETRIEVER_TEST_FILE")
    if not path:
        print("Set RETRIEVER_TEST_FILE to a JSON file holding a list. See the top of this file.", file=sys.stderr)
        return 2
    encoded = os.environ.get("RETRIEVER_TEST_KEY", "").strip()
    made = not encoded
    if made:
        encoded = base64.b64encode(os.urandom(32)).decode()
    try:
        key = base64.b64decode(encoded, validate=True)
        if len(key) != 32:
            raise ValueError
    except ValueError:
        print("RETRIEVER_TEST_KEY must be the base64 of 32 bytes.", file=sys.stderr)
        return 2
    port = int(os.environ.get("RETRIEVER_TEST_PORT", "42512"))
    name = os.environ.get("RETRIEVER_TEST_SOURCE", "test")

    def log(line: str) -> None:
        print(time.strftime("%H:%M:%S"), line, flush=True)

    server = serve(path, key, port, name, log)
    source: ListSource = server.source  # type: ignore[attr-defined]
    log(f"{NAME} {VERSION} on port {server.server_port}, source \"{name}\", file {path}")
    try:
        log(f"{len(source.elements())} elements; the next retrieve sends element 0")
    except ValueError as error:
        log(f"warning: {error}")
    if made:
        log(f"key (enter it in the plugin's settings): {encoded}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
