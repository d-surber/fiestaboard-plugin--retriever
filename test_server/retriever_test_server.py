#!/usr/bin/env python3
"""
A test server for the Retriever plugin.

It speaks the same protocol as the real server (POST /server, /config and
/retrieve, each an encrypted request and response) but serves canned data: a
JSON file holding a list. Every retrieve returns the next element of the
list, in order, and after the last it starts again at the first. So a test
decides exactly what the plugin sees, and when.

The list is the data of a single source. The file is read again on every
request, once, so editing it takes effect at once and every part of one
response comes from the same reading.

Being for tests, it serves what it is given, bad data included: NaN and
Infinity in the file are sent as they are, though neither is JSON, and the
source may be given a name the plugin reserves, such as "error". It answers
a malformed request with an HTTP error where a production server would say
nothing, and it reports the file's full path when the file is at fault.

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
from typing import Any, NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NAME = "RetrieverTestServer"
VERSION = "0.1.0"
PROTOCOLS = (1, 1)  # the inclusive range of protocols spoken
MAX_SKEW_SECONDS = 60
MAX_REQUEST_BYTES = 16384
# How long a connection may go without sending what it owes: a request, or the
# rest of one. Tests break things; a client that stops half-way must not leave
# a thread waiting on it for good.
CLIENT_READ_TIMEOUT_SECONDS = 60
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


class ListFileContents(NamedTuple):
    """
    The list file as it was at one reading.

    Attributes:
        elements: The list, or None if the file cannot be served.
        problem: Why it cannot be served; "" if it can.
    """

    elements: list[Any] | None
    problem: str


class ListSource:
    """
    The one source: the elements of the list in the file, one per retrieve, round and round.

    Each method that depends on the file takes its contents as read for the
    request in hand, so that one response never mixes two versions of the
    file. Given none, it reads the file itself.
    """

    def __init__(self, path: str, name: str = "test"):
        self.path = path
        self.name = name
        self.position = 0  # the index of the next element to send
        self._lock = threading.Lock()

    def elements(self) -> list[Any]:
        """The list in the file. Raises ValueError saying what is wrong with it."""
        try:
            # utf-8-sig: a file saved with a byte-order mark is still JSON.
            with open(self.path, encoding="utf-8-sig") as file:
                elements = json.load(file)
        except OSError as error:
            raise ValueError(f"cannot read {self.path}: {error.strerror or error}") from None
        except RecursionError:
            raise ValueError(f"{self.path} is nested too deeply to read") from None
        except ValueError:
            raise ValueError(f"{self.path} is not JSON") from None
        if not isinstance(elements, list) or not elements:
            raise ValueError(f"{self.path} does not hold a list with something in it")
        return elements

    def read(self) -> ListFileContents:
        """
        Read the file once, for one request.

        The contents are checked for everything a response needs of them: a
        list too deeply nested for Python to describe or to write as JSON is
        reported as a problem here, where it can be, and not left to fail
        half-way through a response. The server sets no limit of its own.
        """
        try:
            elements = self.elements()
            schema_of(elements[0])
            empty_of(elements[0])
            json.dumps(elements)
        except ValueError as error:
            return ListFileContents(None, str(error))
        except RecursionError:
            return ListFileContents(None, f"{self.path} is nested too deeply to serve")
        return ListFileContents(elements, "")

    def schema(self, contents: ListFileContents | None = None) -> dict[str, Any]:
        """The shape of the source's data, from the first element."""
        contents = contents or self.read()
        if contents.elements is None:
            return {"default": None}
        first = contents.elements[0]
        return {**schema_of(first), "default": empty_of(first)}

    def config(self, contents: ListFileContents | None = None) -> dict[str, Any]:
        return {self.name: self.schema(contents or self.read())}

    def seq(self, contents: ListFileContents | None = None) -> int:
        """Identifies the config: changes when its content does, whatever the key order or layout."""
        config = self.config(contents or self.read())
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        return int.from_bytes(hashlib.sha256(canonical).digest()[:4], "big")

    def next(self, contents: ListFileContents | None = None) -> tuple[dict[str, Any], str]:
        """The next entry to send, and a note for the log."""
        contents = contents or self.read()
        with self._lock:
            elements = contents.elements
            if elements is None:
                return {"error": contents.problem, "data": None}, contents.problem
            index = self.position % len(elements)
            self.position = (index + 1) % len(elements)
            return {"error": "", "data": elements[index]}, f"element {index} of {len(elements)}"

    def info(self, port: int, contents: ListFileContents | None = None) -> dict[str, Any]:
        contents = contents or self.read()
        count = len(contents.elements) if contents.elements is not None else 0
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
        timeout = CLIENT_READ_TIMEOUT_SECONDS  # the base class applies it to the connection

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
            try:
                body = self.rfile.read(length)
            except TimeoutError:
                return self.say_nothing("the rest of the request never came")
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

            # One reading of the file for the whole response.
            contents = source.read()
            note = ""
            if self.path == "/server":
                data: Any = source.info(port, contents)
            elif self.path == "/config":
                data = source.config(contents)
            else:
                entry, note = source.next(contents)
                data = {source.name: entry}
            message = json.dumps({"id": request_id, "seq": source.seq(contents), "data": data}).encode()
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
    contents = source.read()
    if contents.elements is None:
        log(f"warning: {contents.problem}")
    else:
        log(f"{len(contents.elements)} elements; the next retrieve sends element 0")
    if made:
        log(f"key (enter it in the plugin's settings): {encoded}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
