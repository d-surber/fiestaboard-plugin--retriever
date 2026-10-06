#!/usr/bin/env python3
"""
A Retriever server that misbehaves on purpose, for the system check.

It speaks the protocol well enough to be talked to, and then does whatever
the current scenario says: sends data no real source would, breaks the
envelope, answers slowly, or does not answer. See README.md beside this file
for when and how it is used; it is not part of the plugin's tests.

The scenario is a JSON file, read again on every request, so the check can
change it between one case and the next:

  {"case": "<any text; a change of it starts the steps again>",
   "/server":   [<step>, ...],
   "/config":   [<step>, ...],
   "/retrieve": [<step>, ...]}

Each request to an endpoint takes that endpoint's next step, and the last
step repeats. An endpoint with no steps answers properly, with nothing in it.
A step is an object; empty, it also answers properly. It may set:

  data                what the response carries, in place of the usual
  config_fingerprint  the fingerprint to send (1 if not set)
  request_id          the ID to send, in place of the request's
  omit                names of fields to leave out of the response
  plain               the whole plaintext, in place of a response
  raw                 what to do to the encrypted body: "empty", "random",
                      "cut short" or "bytes added"
  sealed_for          the endpoint path to authenticate the response for
  status              [code, "reason"]: answer with that and no body
  location            with a status, a Location header for a redirect
  delay               seconds to wait before answering
  dribble             [bytes, seconds, limit]: send the body that many bytes
                      at a time, that far apart, giving up after the limit
  close               true to say nothing at all

Anywhere in data, {"generate": "list" | "text" | "nesting", "size": N} is
replaced by a list of N objects, a text of N characters, or an object nested
N deep: data too large to be worth writing out in a scenario.

Settings, from the environment:

  RETRIEVER_CHECK_KEY       the key shared with the plugin: base64 of 32 bytes (required)
  RETRIEVER_CHECK_SCENARIO  the scenario file (default: scenario.json beside this file)
  RETRIEVER_CHECK_PORT      the port to listen on (default 42512)

It writes one line per request to standard output.
"""

import base64
import contextlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_LENGTH_BYTES = 12
DEFAULT_PORT = 42512
# What each endpoint carries when its step does not say.
USUAL_DATA = {
    "/server": {"name": "MisbehavingServer", "version": "0", "supported_protocol_version_range": {"min": 1, "max": 1}},
    "/config": {},
    "/retrieve": {},
}


def generated(data: Any) -> Any:
    """Replace each {"generate": kind, "size": N} in a scenario's data with the data it asks for."""
    if isinstance(data, list):
        return [generated(element) for element in data]
    if not isinstance(data, dict):
        return data
    kind, size = data.get("generate"), data.get("size", 0)
    if kind == "list":
        return [{"title": f"item number {position}", "n": position} for position in range(size)]
    if kind == "text":
        return "x" * size
    if kind == "nesting":
        nested: Any = "bottom"
        for _ in range(size):
            nested = {"k": nested}
        return nested
    return {name: generated(value) for name, value in data.items()}


class Scenario:
    """
    The scenario file, and how far through each endpoint's steps the current case has got.

    The count starts again whenever the file's "case" changes.
    """

    def __init__(self, scenario_file: Path):
        self.scenario_file = scenario_file
        self._case: Any = None
        self._requests_so_far: dict[str, int] = {}
        self._lock = threading.Lock()

    def next_step(self, endpoint_path: str) -> tuple[Any, dict[str, Any]]:
        """
        Take the next step for a request to an endpoint.

        Returns:
            The current case's name, for the log, and the step: an empty
            one if the endpoint has none.

        Raises:
            OSError, ValueError: The scenario file cannot be read or is not JSON.
        """
        scenario = json.loads(self.scenario_file.read_text())
        with self._lock:
            if scenario.get("case") != self._case:
                self._case, self._requests_so_far = scenario.get("case"), {}
            request_number = self._requests_so_far.get(endpoint_path, 0)
            self._requests_so_far[endpoint_path] = request_number + 1
        steps = scenario.get(endpoint_path) or [{}]
        return self._case, steps[min(request_number, len(steps) - 1)]


class MisbehavingServer(ThreadingHTTPServer):
    """The HTTP server, with the cipher and the scenario its request handlers work from."""

    def __init__(self, port: int, transport_key: bytes, scenario: Scenario):
        super().__init__(("", port), RequestHandler)
        self.cipher = ChaCha20Poly1305(transport_key)
        self.scenario = scenario


class RequestHandler(BaseHTTPRequestHandler):
    """Answers one request as the scenario's next step says."""

    server: MisbehavingServer

    def log_message(self, *args: Any) -> None:
        """Silence the base class's own log; each request writes one line itself."""

    def do_GET(self) -> None:
        """Say nothing to a GET, which is what a redirect turns a POST into."""
        note("GET", self.path, "-> closed")
        self.close_connection = True

    def do_POST(self) -> None:
        """Take the endpoint's next step and do what it says."""
        self.close_connection = True
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        case, step = self.server.scenario.next_step(self.path)
        try:
            nonce, ciphertext = body[:NONCE_LENGTH_BYTES], body[NONCE_LENGTH_BYTES:]
            request = json.loads(self.server.cipher.decrypt(nonce, ciphertext, f"retriever/1 request {self.path}".encode()))
        except Exception:
            note(case, self.path, "a request that does not decrypt: nothing said")
            return
        asked_of_step = {name: value for name, value in step.items() if name != "data"}
        note(case, self.path, "requiring protocol version", request.get("required_protocol_version"), asked_of_step or "")

        time.sleep(step.get("delay", 0))
        if step.get("close"):
            return
        if "status" in step:
            self._send_status(step)
            return
        self._send_body(self._response_body(step, request), step.get("dribble"))

    def _response_body(self, step: dict[str, Any], request: dict[str, Any]) -> bytes:
        """The encrypted body the step asks for: a proper response, or one spoiled in the way it names."""
        response = {
            "request_id": step.get("request_id", request["request_id"]),
            "config_fingerprint": step.get("config_fingerprint", 1),
            "data": generated(step.get("data", USUAL_DATA.get(self.path, {}))),
        }
        for field in step.get("omit", []):
            response.pop(field, None)
        plaintext = step["plain"].encode() if "plain" in step else json.dumps(response).encode()
        associated_data = f"retriever/1 response {step.get('sealed_for', self.path)}".encode()
        nonce = os.urandom(NONCE_LENGTH_BYTES)
        body = nonce + self.server.cipher.encrypt(nonce, plaintext, associated_data)
        spoiled = {"empty": b"", "random": os.urandom(64), "cut short": body[:-5], "bytes added": body + b"extra"}
        return spoiled.get(step.get("raw"), body)

    def _send_status(self, step: dict[str, Any]) -> None:
        """Answer with the step's status and reason and no body, and its redirect if it has one."""
        code, reason = step["status"]
        redirect = f"Location: {step['location']}\r\n" if "location" in step else ""
        self.wfile.write(f"HTTP/1.1 {code} {reason}\r\n{redirect}Content-Length: 0\r\nConnection: close\r\n\r\n".encode())

    def _send_body(self, body: bytes, dribble: list[float] | None) -> None:
        """Send a 200 with this body, all at once or a little at a time as `dribble` says."""
        self.wfile.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode())
        if dribble is None:
            self.wfile.write(body)
            return
        bytes_at_a_time, seconds_apart, give_up_after = int(dribble[0]), dribble[1], dribble[2]
        started = time.monotonic()
        try:
            for start in range(0, len(body), bytes_at_a_time):
                if time.monotonic() - started > give_up_after:
                    note("gave up dribbling")
                    return
                self.wfile.write(body[start : start + bytes_at_a_time])
                self.wfile.flush()
                time.sleep(seconds_apart)
        except OSError:
            note("the client went away after", round(time.monotonic() - started, 1), "s of dribbling")


def note(*words: Any) -> None:
    """Write one line to standard output, with the time of day before it."""
    print(time.strftime("%H:%M:%S"), *words, flush=True)


def main() -> int:
    """
    Run the server as the environment says, until interrupted.

    Returns:
        The exit status: 0 after an interrupt, 2 if the key is missing or wrong.
    """
    try:
        transport_key = base64.b64decode(os.environ.get("RETRIEVER_CHECK_KEY", "").strip(), validate=True)
    except ValueError:
        transport_key = b""
    if len(transport_key) != 32:
        print("Set RETRIEVER_CHECK_KEY to the key the plugin has: the base64 of 32 bytes.", file=sys.stderr)
        return 2
    scenario_file = Path(os.environ.get("RETRIEVER_CHECK_SCENARIO", Path(__file__).parent / "scenario.json"))
    port = int(os.environ.get("RETRIEVER_CHECK_PORT", DEFAULT_PORT))

    server = MisbehavingServer(port, transport_key, Scenario(scenario_file))
    note(f"misbehaving on port {server.server_port}, as {scenario_file} says")
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
