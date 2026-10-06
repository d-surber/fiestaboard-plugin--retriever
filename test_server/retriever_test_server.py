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
import contextlib
import hashlib
import json
import os
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SERVER_NAME = "RetrieverTestServer"
SERVER_VERSION = "0.1.0"

# The protocol versions this server speaks, as an inclusive range.
MIN_PROTOCOL_VERSION = 1
MAX_PROTOCOL_VERSION = 1

SERVER_INFO_PATH = "/server"
CONFIG_PATH = "/config"
RETRIEVE_PATH = "/retrieve"
ENDPOINT_PATHS = (SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH)

# The wire format: a request or response body is one ChaCha20-Poly1305
# message, which is a nonce, the ciphertext and a 16-byte tag.
TRANSPORT_KEY_LENGTH_BYTES = 32
NONCE_LENGTH_BYTES = 12

# What a request may be before it is refused.
MAX_REQUEST_LENGTH_BYTES = 16384
MAX_REQUEST_ID_LENGTH = 64
MAX_CLOCK_DIFFERENCE_SECONDS = 60

# How long a connection may go without sending what it owes: a request, or the
# rest of one. Tests break things; a client that stops half-way must not leave
# a thread waiting on it for good.
CLIENT_READ_TIMEOUT_SECONDS = 60

DEFAULT_PORT = 42512
DEFAULT_SOURCE_NAME = "test"


def request_associated_data(endpoint_path: str) -> bytes:
    """
    The associated data a request to an endpoint is encrypted with.

    It differs for every endpoint and from every response's, so a message
    encrypted for one purpose cannot be decrypted as another.
    """
    return f"retriever/1 request {endpoint_path}".encode()


def response_associated_data(endpoint_path: str) -> bytes:
    """The associated data a response from an endpoint is encrypted with; see request_associated_data."""
    return f"retriever/1 response {endpoint_path}".encode()


def shape_of(value: Any) -> dict[str, Any]:
    """Describe the shape of a value in hand as a JSON Schema, taking a list's first element to stand for them all."""
    if isinstance(value, dict):
        return {"type": "object", "properties": {name: shape_of(field) for name, field in value.items()}}
    if isinstance(value, list):
        return {"type": "array", "items": shape_of(value[0])} if value else {"type": "array"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    return {"type": "null"}


def empty_value_like(value: Any) -> Any:
    """
    A value of the same shape with nothing in it.

    It is the default a plugin shows for the source when a retrieve fails:
    an object keeps its fields, each emptied in turn; a list is empty; a
    number is 0, a text "", a truth value False.
    """
    if isinstance(value, dict):
        return {name: empty_value_like(field) for name, field in value.items()}
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

    Attributes:
        list_file_path: The JSON file holding the list.
        source_name: The name the source goes by in /config and /retrieve.
        next_position: The index of the element the next retrieve sends. It
            carries on across changes to the file.
    """

    def __init__(self, list_file_path: str, source_name: str = DEFAULT_SOURCE_NAME):
        self.list_file_path = list_file_path
        self.source_name = source_name
        self.next_position = 0
        self._lock = threading.Lock()

    def read_list(self) -> list[Any]:
        """
        Read the list from the file.

        Raises:
            ValueError: The file cannot be read, is not JSON, is nested too
                deeply for Python to read, or does not hold a list with
                something in it. The message says which, and names the file.
        """
        try:
            # utf-8-sig: a file saved with a byte-order mark is still JSON.
            with Path(self.list_file_path).open(encoding="utf-8-sig") as list_file:
                elements = json.load(list_file)
        except OSError as error:
            raise ValueError(f"cannot read {self.list_file_path}: {error.strerror or error}") from None
        except RecursionError:
            raise ValueError(f"{self.list_file_path} is nested too deeply to read") from None
        except ValueError:
            raise ValueError(f"{self.list_file_path} is not JSON") from None
        if not isinstance(elements, list) or not elements:
            raise ValueError(f"{self.list_file_path} does not hold a list with something in it")
        return elements

    def read_file(self) -> ListFileContents:
        """
        Read the file once, for one request.

        The contents are checked for everything a response needs of them: a
        list too deeply nested for Python to describe or to write as JSON is
        reported as a problem here, where it can be, and not left to fail
        half-way through a response. The server sets no limit of its own.
        Never raises.
        """
        try:
            elements = self.read_list()
            shape_of(elements[0])
            empty_value_like(elements[0])
            json.dumps(elements)
        except ValueError as error:
            return ListFileContents(None, str(error))
        except RecursionError:
            return ListFileContents(None, f"{self.list_file_path} is nested too deeply to serve")
        return ListFileContents(elements, "")

    def data_schema(self, contents: ListFileContents | None = None) -> dict[str, Any]:
        """
        The JSON Schema of the source's data, with its default.

        Both come from the first element, which stands for all of them. A
        file that cannot be served has no shape, and a default of null.
        """
        contents = contents or self.read_file()
        if contents.elements is None:
            return {"default": None}
        first_element = contents.elements[0]
        return {**shape_of(first_element), "default": empty_value_like(first_element)}

    def config(self, contents: ListFileContents | None = None) -> dict[str, Any]:
        """The data of a /config response: the source's schema, under its name."""
        return {self.source_name: self.data_schema(contents or self.read_file())}

    def sequence_number(self, contents: ListFileContents | None = None) -> int:
        """
        The number that identifies the config, sent as "seq" in every response.

        It is the first four bytes of the SHA-256 of the config as compact
        JSON with sorted keys, so it changes when the config's content does
        and not with key order or layout. The real server computes the same.
        """
        config = self.config(contents or self.read_file())
        canonical_json = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        return int.from_bytes(hashlib.sha256(canonical_json).digest()[:4], "big")

    def next_entry(self, contents: ListFileContents | None = None) -> tuple[dict[str, Any], str]:
        """
        Take the next element of the list, and move on to the one after.

        Returns:
            The source's entry for a /retrieve response, {"error", "data"},
            and a note for the log saying which element it was. If the file
            cannot be served, the entry's error and the note both say why,
            its data is null, and the position does not move.
        """
        contents = contents or self.read_file()
        with self._lock:
            elements = contents.elements
            if elements is None:
                return {"error": contents.problem, "data": None}, contents.problem
            position = self.next_position % len(elements)
            self.next_position = (position + 1) % len(elements)
            return {"error": "", "data": elements[position]}, f"element {position} of {len(elements)}"

    def server_info(self, port: int, contents: ListFileContents | None = None) -> dict[str, Any]:
        """
        The data of a /server response.

        Beyond what every server reports, it says where the test stands: the
        file, how many elements it holds (0 if it cannot be served), and the
        index of the one the next retrieve sends.
        """
        contents = contents or self.read_file()
        element_count = len(contents.elements) if contents.elements is not None else 0
        return {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocol": {"min": MIN_PROTOCOL_VERSION, "max": MAX_PROTOCOL_VERSION},
            "port": port,
            "file": self.list_file_path,
            "count": element_count,
            "next": self.next_position % element_count if element_count else 0,
        }


class TestServer(ThreadingHTTPServer):
    """
    The HTTP server, with what its request handlers need.

    Attributes:
        source: The source it serves.
        cipher: Encrypts and decrypts with the transport key.
        log: Called with one line of text for each request handled.
    """

    def __init__(self, port: int, source: ListSource, transport_key: bytes, log: Callable[[str], None]):
        super().__init__(("", port), RequestHandler)
        self.source = source
        self.cipher = ChaCha20Poly1305(transport_key)
        self.log = log


class _SayNothing(Exception):
    """The request has not shown the key, so it gets no response. The message is the reason, for the log."""


class _Refuse(Exception):
    """The request decrypted but cannot be served. The message is the reason, sent with status 400."""


class RequestHandler(BaseHTTPRequestHandler):
    """Answers one request to a TestServer."""

    server: TestServer
    protocol_version = "HTTP/1.1"
    timeout = CLIENT_READ_TIMEOUT_SECONDS  # the base class applies it to the connection

    def do_POST(self) -> None:
        """Answer a request: with a response, a refusal that says why, or nothing at all."""
        try:
            request_id = self._check_request(self._decrypt_request_body())
        except _SayNothing as silence:
            self._close_without_answering(str(silence))
        except _Refuse as refusal:
            self._send_refusal(str(refusal))
        else:
            self._send_response(request_id)

    def do_GET(self) -> None:
        """Say nothing to any method but POST."""
        self._close_without_answering("not POST")

    do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = do_GET

    def log_message(self, *args: Any) -> None:
        """Silence the base class's own log; each request writes one line through the server's log."""

    def _decrypt_request_body(self) -> bytes:
        """
        Read the request's body and decrypt it.

        Raises:
            _SayNothing: The path is not an endpoint, the length is missing
                or too large, the body never fully arrived, or it does not
                decrypt with the transport key for this endpoint.
        """
        if self.path not in ENDPOINT_PATHS:
            raise _SayNothing("unknown path")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise _SayNothing("no length") from None
        if not 0 <= length <= MAX_REQUEST_LENGTH_BYTES:
            raise _SayNothing("too large")
        try:
            body = self.rfile.read(length)
        except TimeoutError:
            raise _SayNothing("the rest of the request never came") from None
        nonce, ciphertext = body[:NONCE_LENGTH_BYTES], body[NONCE_LENGTH_BYTES:]
        try:
            return self.server.cipher.decrypt(nonce, ciphertext, request_associated_data(self.path))
        except Exception:
            raise _SayNothing("does not decrypt") from None

    def _check_request(self, plaintext: bytes) -> str:
        """
        Check a decrypted request: {"ts", "id", "protocol"?}.

        Returns:
            The request's ID, for the response to echo.

        Raises:
            _Refuse: "Bad Request" if it is not that; "Stale Timestamp" if
                its time is more than MAX_CLOCK_DIFFERENCE_SECONDS from
                now; "Unsupported Protocol" if it names a version outside
                the range this server speaks, which /server alone ignores.
        """
        try:
            request = json.loads(plaintext)
            timestamp, request_id = request["ts"], request["id"]
            id_is_usable = isinstance(request_id, str) and 0 < len(request_id) <= MAX_REQUEST_ID_LENGTH
            if not isinstance(timestamp, int) or not id_is_usable:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise _Refuse("Bad Request") from None
        if abs(time.time() - timestamp) > MAX_CLOCK_DIFFERENCE_SECONDS:
            raise _Refuse("Stale Timestamp")

        # A request that names no protocol version speaks the first.
        protocol_version = request.get("protocol", 1)
        if not isinstance(protocol_version, int) or isinstance(protocol_version, bool):
            raise _Refuse("Bad Request")
        is_spoken = MIN_PROTOCOL_VERSION <= protocol_version <= MAX_PROTOCOL_VERSION
        if self.path != SERVER_INFO_PATH and not is_spoken:
            raise _Refuse("Unsupported Protocol")
        return request_id

    def _send_response(self, request_id: str) -> None:
        """
        Send the endpoint's data, encrypted, echoing the request's ID.

        The file is read once, and the data and the sequence number both
        come from that reading. Only /retrieve moves the list on.
        """
        source = self.server.source
        contents = source.read_file()
        log_note = ""
        if self.path == SERVER_INFO_PATH:
            data: Any = source.server_info(self.server.server_port, contents)
        elif self.path == CONFIG_PATH:
            data = source.config(contents)
        else:
            entry, log_note = source.next_entry(contents)
            data = {source.source_name: entry}

        message = {"id": request_id, "seq": source.sequence_number(contents), "data": data}
        nonce = os.urandom(NONCE_LENGTH_BYTES)
        ciphertext = self.server.cipher.encrypt(
            nonce, json.dumps(message).encode(), response_associated_data(self.path)
        )
        body = nonce + ciphertext

        self.server.log(f"POST {self.path} -> 200" + (f" ({log_note})" if log_note else ""))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _send_refusal(self, reason: str) -> None:
        """Answer with status 400 and the reason, and no body."""
        self.server.log(f"POST {self.path} -> 400 {reason}")
        self.send_response(400, reason)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _close_without_answering(self, reason: str) -> None:
        """Close the connection with nothing sent; the reason goes to the log only."""
        self.server.log(f"{self.command} {self.path} -> no response ({reason})")
        self.close_connection = True


def create_server(
    list_file_path: str,
    transport_key: bytes,
    port: int,
    source_name: str = DEFAULT_SOURCE_NAME,
    log: Callable[[str], None] = print,
) -> TestServer:
    """
    Make a server, listening and ready to run with ``serve_forever()``.

    Args:
        port: The port to listen on, on every interface; 0 picks a free one,
            which ``server_port`` then gives.
        log: Called with one line of text for each request handled.
    """
    return TestServer(port, ListSource(list_file_path, source_name), transport_key, log)


def decode_transport_key(encoded_key: str) -> bytes | None:
    """The key that encoded_key is the base64 of, or None if it is not the base64 of TRANSPORT_KEY_LENGTH_BYTES bytes."""
    try:
        transport_key = base64.b64decode(encoded_key, validate=True)
    except ValueError:
        return None
    return transport_key if len(transport_key) == TRANSPORT_KEY_LENGTH_BYTES else None


def log_with_time(line: str) -> None:
    """Print a line with the time of day before it, at once, so that a log file is current."""
    print(time.strftime("%H:%M:%S"), line, flush=True)


def main() -> int:
    """
    Run the server as the environment says, until interrupted.

    Returns:
        The process's exit status: 0 after an interrupt, 2 if a setting is
        missing or wrong, which is said on standard error.
    """
    list_file_path = os.environ.get("RETRIEVER_TEST_FILE")
    if not list_file_path:
        print("Set RETRIEVER_TEST_FILE to a JSON file holding a list. See the top of this file.", file=sys.stderr)
        return 2

    encoded_key = os.environ.get("RETRIEVER_TEST_KEY", "").strip()
    key_was_generated = not encoded_key
    if key_was_generated:
        encoded_key = base64.b64encode(os.urandom(TRANSPORT_KEY_LENGTH_BYTES)).decode()
    transport_key = decode_transport_key(encoded_key)
    if transport_key is None:
        print("RETRIEVER_TEST_KEY must be the base64 of 32 bytes.", file=sys.stderr)
        return 2

    try:
        port = int(os.environ.get("RETRIEVER_TEST_PORT", DEFAULT_PORT))
    except ValueError:
        print("RETRIEVER_TEST_PORT must be a number.", file=sys.stderr)
        return 2
    source_name = os.environ.get("RETRIEVER_TEST_SOURCE", DEFAULT_SOURCE_NAME)

    server = create_server(list_file_path, transport_key, port, source_name, log_with_time)
    log_with_time(
        f'{SERVER_NAME} {SERVER_VERSION} on port {server.server_port}, source "{source_name}", file {list_file_path}'
    )
    contents = server.source.read_file()
    if contents.elements is None:
        log_with_time(f"warning: {contents.problem}")
    else:
        log_with_time(f"{len(contents.elements)} elements; the next retrieve sends element 0")
    if key_was_generated:
        log_with_time(f"key (enter it in the plugin's settings): {encoded_key}")

    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
