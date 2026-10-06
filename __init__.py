"""
Retriever plugin for FiestaBoard.

Fetches data from a companion server and exposes it to templates.
"""

import base64
import binascii
import http.client
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.plugins.base import PluginBase, PluginResult
from src.templates.expressions import evaluate, validate_expression

try:
    from src.plugins.base import PreviewUnavailable
except ImportError:  # a FiestaBoard without the plugin-supplied preview

    class PreviewUnavailable(Exception):
        """The plugin cannot supply preview text right now."""


logger = logging.getLogger(__name__)

# FiestaBoard abandons a fetch that takes longer than 5 s, and quarantines a
# plugin after three such fetches in a row. Stay inside that: this is the
# budget for one fetch_data, however many requests it makes.
TIMEOUT_SECONDS = 4

# The wire format; RetrieverServer's Wire.swift is the other half. Request and
# response bodies are each one ChaCha20-Poly1305 message: 12-byte nonce,
# ciphertext, 16-byte tag. The associated data names the envelope
# ("retriever/1", which is fixed), the direction and the path.
SERVER_PATH = "/server"
CONFIG_PATH = "/config"
RETRIEVE_PATH = "/retrieve"
KEY_BYTES = 32
NONCE_BYTES = 12

# The protocols this plugin speaks. /server gives the range the server
# speaks; the highest protocol in both is named in every /config and
# /retrieve request.
PROTOCOLS = (1,)

CONFIG_PENDING = "config pending"

# The name the plugin's values go by in templates and in value definitions:
# {{retriever.reminders.data.count}}. The formula engine resolves a name only
# under a source like this one, so definitions use it too.
NAMESPACE = "retriever"


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


def seal_request(key: bytes, now: float, path: str, protocol: int | None = None) -> tuple[bytes, str]:
    """Return a request body for *path* and the ID the response must echo."""
    request_id = secrets.token_hex(16)
    request = {"ts": int(now), "id": request_id}
    if protocol is not None:
        request["protocol"] = protocol
    plaintext = json.dumps(request).encode()
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


def choose_protocol(server_info: dict[str, Any]) -> int:
    """Return the highest protocol both sides speak. Raises if the server's range is unusable or shares none."""
    offered = server_info.get("protocol")
    if not isinstance(offered, dict):
        raise ValueError("no protocol range in server info")
    low, high = offered.get("min"), offered.get("max")
    if not all(isinstance(bound, int) and not isinstance(bound, bool) for bound in (low, high)):
        raise ValueError("no protocol range in server info")
    common = [protocol for protocol in PROTOCOLS if low <= protocol <= high]
    if not common:
        raise ValueError("no common protocol")
    return max(common)


# --- Values the user defines -------------------------------------------------
#
# A row names a variable and defines it by an expression over the server's
# values, which FiestaBoard's own formula engine evaluates:
#
#   due          retriever.reminders.data.count
#   first        UPPER(retriever.reminders.data.items[0].title)
#
# A name with a parameter in brackets defines a list. The parameter is the
# position of each element, counting from 0. In the definition it does two
# jobs: in brackets it indexes a list, which also decides how many elements
# there are, and bare it is a number like any other:
#
#   todo[x].what   retriever.reminders.data.items[x].title
#   todo[x].line   (x + 1) & ". " & retriever.reminders.data.items[x].title
#   todo[x].n      x + 1
#
# The last row indexes nothing, so it adds its field to however many elements
# the other rows for the same list gave.
#
# Parameters nest, each with its own name, for lists inside lists:
#
#   lists[x].name            retriever.todo.data.lists[x].name
#   lists[x].items[y].what   retriever.todo.data.lists[x].items[y].title
#
# Every definition reads the server's values, never another row's result, so
# rows cannot depend on each other and their order does not matter. A row may
# take the name of one of the server's values, and then it is the row that
# templates see.

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_VARIABLE = re.compile(rf"^({_NAME})((?:\[{_NAME}\](?:\.{_NAME})*)*)$")
_SEGMENT = re.compile(rf"\[({_NAME})\]|\.({_NAME})")
_PARAMETER = re.compile(rf"\[({_NAME})\]")
_PATH = re.compile(r"^[A-Za-z_]\w*(?:\.\w+)*$")
_NUMBER_INDEX = re.compile(r"\[(\d+)\]")
_ERROR_CODE = re.compile(r"^#(?:REF|VALUE|SYNTAX|NUM|NAME\?|DIV/0)(?::\d+)?$")
_MISSING = object()

# One step into a variable's structure: ("index", parameter) or ("key", field).
Step = tuple[str, str]


def parse_variable(name: Any) -> tuple[str, list[Step]] | None:
    """
    Split a row's name into its variable and the steps to where the definition's value goes.

    ``due`` has no steps. ``todo[x].what`` has two: each element, then its
    ``what``. None if it is not a name, or uses one parameter twice.
    """
    match = _VARIABLE.match(name.strip()) if isinstance(name, str) else None
    if not match:
        return None
    steps: list[Step] = [
        ("index", segment.group(1)) if segment.group(1) else ("key", segment.group(2))
        for segment in _SEGMENT.finditer(match.group(2))
    ]
    parameters = [step[1] for step in steps if step[0] == "index"]
    if len(set(parameters)) != len(parameters) or NAMESPACE in parameters:
        return None
    return match.group(1), steps


def resolve(path: str, context: dict[str, Any]) -> Any:
    """Follow a dotted path through *context*; ``_MISSING`` if it leads nowhere."""
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def value_of(definition: str, context: dict[str, Any], default: str = "", positions: dict[str, int] | None = None) -> Any:
    """
    The value a definition gives.

    A definition that is only a path gives the value there unchanged,
    whatever its type. Anything else is a formula, whose result is text; in
    it each of *positions* is a number by its parameter's name. When the path
    leads nowhere or the formula fails, the result is *default* if there is
    one, and otherwise the formula engine's error code.
    """
    definition = _NUMBER_INDEX.sub(r".\1", definition.strip())
    if _PATH.match(definition) and definition not in (positions or {}):
        found = resolve(definition, context)
        return found if found is not _MISSING else (default or "#REF")
    if positions:
        bindings = "".join(f"{name}, {position}, " for name, position in positions.items())
        definition = f"LET({bindings}{definition})"
    result = evaluate(definition, context)
    return default if default and _ERROR_CODE.match(result) else result


def list_length(definition: str, parameter: str, context: dict[str, Any]) -> int | None:
    """
    How many positions *parameter* takes: as many as the shortest list the definition indexes with it.

    None if the definition indexes nothing with it, and so does not say.
    """
    indexed = re.compile(rf"([A-Za-z_]\w*(?:\.\w+|\[\d+\])*)\[{re.escape(parameter)}\]")
    lengths = []
    for match in indexed.finditer(definition):
        found = resolve(_NUMBER_INDEX.sub(r".\1", match.group(1)), context)
        lengths.append(len(found) if isinstance(found, list) else 0)
    return min(lengths, default=None)


def _build(
    steps: list[Step], definition: str, context: dict[str, Any], default: str, positions: dict[str, int], existing: Any
) -> Any:
    """The value at *steps* into a variable, merged into what earlier rows put there."""
    if not steps:
        return value_of(definition, context, default, positions)
    kind, name = steps[0]
    if kind == "key":
        fields = existing if isinstance(existing, dict) else {}
        fields[name] = _build(steps[1:], definition, context, default, positions, fields.get(name))
        return fields
    elements = existing if isinstance(existing, list) else []
    length = list_length(definition, name, context)
    # A definition that indexes nothing with this parameter adds to the
    # elements other rows gave; define() runs those rows first.
    for position in range(len(elements) if length is None else length):
        if position == len(elements):
            elements.append(None)
        elements[position] = _build(
            steps[1:],
            definition.replace(f"[{name}]", f".{position}"),
            context,
            default,
            {**positions, name: position},
            elements[position],
        )
    return elements


def define(rows: Any, context: dict[str, Any]) -> dict[str, Any]:
    """The variables *rows* define from *context*. Rows that are not rows are skipped."""
    usable = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("definition"), str):
            continue
        parsed = parse_variable(row.get("variable"))
        if parsed is not None:
            usable.append((*parsed, row["definition"], row.get("default") if isinstance(row.get("default"), str) else ""))

    def says_how_long(row: tuple[str, list[Step], str, str]) -> bool:
        _name, steps, definition, _default = row
        return all(f"[{step[1]}]" in definition for step in steps if step[0] == "index")

    # Rows that say how long their lists are go first, so that the order the
    # user wrote the rows in never matters.
    defined: dict[str, Any] = {}
    for name, steps, definition, default in sorted(usable, key=lambda row: not says_how_long(row)):
        # Several rows may each give one part of the same list's elements.
        defined[name] = _build(steps, definition, context, default, {}, defined.get(name) if steps else None)
    return defined


def value_errors(rows: Any) -> list[str]:
    """What is wrong with the value rows, for the settings form."""
    if rows in (None, ""):
        return []
    if not isinstance(rows, list):
        return ["Values must be a list"]
    errors = []
    kinds: dict[str, bool] = {}
    # For each list, the parameters some row indexes a list with: those have a length.
    sized: set[tuple[str, str]] = set()
    for row in rows:
        parsed = parse_variable(row.get("variable")) if isinstance(row, dict) else None
        if parsed and isinstance(row.get("definition"), str):
            sized.update((parsed[0], parameter) for parameter in _PARAMETER.findall(row["definition"]))
    for number, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            errors.append(f"Value {number} is not a row")
            continue
        parsed = parse_variable(row.get("variable"))
        if parsed is None:
            errors.append(
                f"Value {number}: the name must look like name, name[x] or name[x].field, with each parameter used once"
            )
            continue
        name, steps = parsed
        parameters = [step[1] for step in steps if step[0] == "index"]
        label = f"Value {row['variable'].strip()!r}"
        if kinds.setdefault(name, bool(steps)) != bool(steps):
            errors.append(f"{label}: {name} is defined both as a list and as a single value")
        definition = row.get("definition")
        if not isinstance(definition, str) or not definition.strip():
            errors.append(f"{label} has no definition")
            continue
        used = set(_PARAMETER.findall(definition))
        for parameter in parameters:
            if (name, parameter) not in sized:
                errors.append(f"{label}: some row for {name} must index a list with [{parameter}], to say how long it is")
        for parameter in sorted(used - set(parameters)):
            errors.append(f"{label}: [{parameter}] in the definition needs [{parameter}] in the name")
        formula = _NUMBER_INDEX.sub(r".\1", _PARAMETER.sub(".0", definition).strip())
        if not _PATH.match(formula):
            bindings = "".join(f"{parameter}, 0, " for parameter in parameters)
            formula = f"LET({bindings}{formula})" if bindings else formula
            errors.extend(f"{label}: {issue.message}" for issue in validate_expression(formula))
    return errors


def describe(error: Exception) -> str:
    """A short reason for a failed fetch. What distinguishes it comes first, because a board truncates."""
    if isinstance(error, urllib.error.HTTPError):
        return f"{error.code} {error.reason}"
    if isinstance(error, urllib.error.URLError) and isinstance(error.reason, Exception):
        error = error.reason
    if isinstance(error, TimeoutError):
        return "timed out"
    # A server closes the connection without answering a request it cannot
    # decrypt, so this is what a wrong key looks like.
    if isinstance(error, (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
        return "no response (wrong key?)"
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
        # sequence number, {source: JSON Schema of that source's data}, its
        # /server info, and the protocol chosen from that. None until read.
        # One tuple, so a concurrent fetch sees all of it or none.
        self._server_config: tuple[int, dict[str, Any], dict[str, Any], int] | None = None

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
            - data: the server's values unchanged, plus ``server`` and
              ``error``: {<source>: {"error": ..., "data": ...}, ...,
              "server": <the server's /server info>, "error": ""}.
              After a failed retrieve, every source the server's config lists
              has its schema's default as data, and ``error`` is the reason.
              Before the server's info and config have been read nothing
              about it is known, so there is only ``error``, ending in
              "config pending".
            - error: The same reason, for FiestaBoard itself
        """
        errors = self._connection_errors(self.config)
        if errors:
            return PluginResult(available=False, error="; ".join(errors))

        server_url = self.config["server_url"].strip().rstrip("/")
        key = decode_key(self.config["key"])
        deadline = time.monotonic() + TIMEOUT_SECONDS

        if self._server_config is None:
            try:
                self._server_config = self._read_server(server_url, key, deadline)
            except Exception as e:
                return self._failed(server_url, f"{describe(e)}; {CONFIG_PENDING}", {})

        config_seq, sources, server_info, protocol = self._server_config
        try:
            seq, values = self._fetch(server_url, RETRIEVE_PATH, key, deadline, protocol)
        except Exception as e:
            unknown = {name: {"error": "", "data": default_for(schema)} for name, schema in sources.items()}
            return self._failed(server_url, describe(e), {**unknown, "server": server_info})

        if seq != config_seq:
            # The server's config changed, in either direction. The values
            # just retrieved are good; the server is read again, now or on
            # the next fetch.
            try:
                self._server_config = self._read_server(server_url, key, deadline)
                server_info = self._server_config[2]
            except Exception as e:
                return self._failed(server_url, f"{describe(e)}; {CONFIG_PENDING}", {**values, "server": server_info})

        return PluginResult(available=True, data=self._variables({**values, "server": server_info, "error": ""}))

    def _read_server(self, server_url: str, key: bytes, deadline: float) -> tuple[int, dict[str, Any], dict[str, Any], int]:
        """Read what the server says about itself: its info, then its config in the protocol chosen from that."""
        _, server_info = self._fetch(server_url, SERVER_PATH, key, deadline)
        protocol = choose_protocol(server_info)
        seq, sources = self._fetch(server_url, CONFIG_PATH, key, deadline, protocol)
        return seq, sources, server_info, protocol

    def _failed(self, server_url: str, reason: str, values: dict[str, Any]) -> PluginResult:
        """The result of a fetch in which a request failed: *values*, and the reason in ``error``."""
        logger.warning(f"Fetch from {server_url} failed: {reason}")
        return PluginResult(available=True, data=self._variables({**values, "error": reason}), error=reason)

    def _variables(self, values: dict[str, Any]) -> dict[str, Any]:
        """The template variables: what the fetch gave, and over it the values the user defines from that."""
        return {**values, **define(self.config.get("values"), {NAMESPACE: values})}

    def get_preview_text(self) -> str:
        """
        Supply the settings form's "Test & Preview" with the server's values, as JSON.

        Core's own preview fetches a URL, which cannot work here: the server
        only answers encrypted requests. The values are fetched with the
        unsaved settings and shown under the name definitions use for them.
        """
        config = self.config
        if self._connection_errors(config):
            raise PreviewUnavailable("Enter the server URL and key first")
        server_url = config["server_url"].strip().rstrip("/")
        key = decode_key(config["key"])
        deadline = time.monotonic() + TIMEOUT_SECONDS
        try:
            _, server_info = self._fetch(server_url, SERVER_PATH, key, deadline)
            _, values = self._fetch(server_url, RETRIEVE_PATH, key, deadline, choose_protocol(server_info))
        except Exception as e:
            raise PreviewUnavailable(describe(e)) from None
        return json.dumps({NAMESPACE: {**values, "server": server_info, "error": ""}})

    def _fetch(
        self, server_url: str, path: str, key: bytes, deadline: float, protocol: int | None = None
    ) -> tuple[int, dict[str, Any]]:
        """
        Make one request to the server; return its config sequence number and data.

        The only place that talks to the server. Raises on any failure: no
        answer by *deadline*, a non-2xx status, or a response that is not the
        server's answer to this request.
        """
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise TimeoutError
        body, request_id = seal_request(key, time.time(), path, protocol)
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
        return self._connection_errors(config) + value_errors(config.get("values"))

    def _connection_errors(self, config: dict[str, Any]) -> list[str]:
        """What stops the plugin reaching its server. Nothing else stops a fetch."""
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
