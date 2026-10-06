"""
Retriever plugin for FiestaBoard.

Fetches data from a companion server and exposes it to templates.
"""

import base64
import binascii
import copy
import http.client
import json
import logging
import math
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from typing import Any, NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.plugins.base import PluginBase, PluginResult
from src.templates.expressions import evaluate, validate_expression

try:
    from src.plugins.base import PreviewUnavailable
except ImportError:  # a FiestaBoard without the plugin-supplied preview

    class PreviewUnavailable(Exception):
        """The plugin cannot supply preview text right now."""


try:
    from src.templates.expressions import ErrorValue, evaluate_value
except ImportError:  # a FiestaBoard whose formula engine only renders its results as text
    ErrorValue = evaluate_value = None

logger = logging.getLogger(__name__)

# FiestaBoard abandons a fetch that takes longer than 5 s, and quarantines a
# plugin after three such fetches in a row. Stay inside that: this is the
# time allowed for one fetch_data, however many requests it makes.
FETCH_TIME_LIMIT_SECONDS = 4

# The wire format; RetrieverServer's Wire.swift is the other half. Request and
# response bodies are each one ChaCha20-Poly1305 message: nonce, ciphertext,
# 16-byte tag. The associated data names the envelope ("retriever/1", which is
# fixed), the direction and the endpoint.
SERVER_INFO_PATH = "/server"
CONFIG_PATH = "/config"
RETRIEVE_PATH = "/retrieve"
TRANSPORT_KEY_LENGTH_BYTES = 32
NONCE_LENGTH_BYTES = 12

# /server gives the range of protocol versions the server speaks; the highest
# version in both is named in every /config and /retrieve request.
SUPPORTED_PROTOCOL_VERSIONS = (1,)

# Ends the failure reason while the server's info and config are still unread.
CONFIG_PENDING_SUFFIX = "config pending"

# Names the plugin gives its own values, which a server's source cannot take.
RESERVED_SOURCE_NAMES = ("error", "server")

# The name the plugin's values go by in templates and in value definitions:
# {{retriever.reminders.data.count}}. The formula engine resolves a name only
# under a source like this one, so definitions use it too.
TEMPLATE_NAMESPACE = "retriever"

# The setting that holds the transport key. FiestaBoard hides a setting's
# value in its API and its forms only if the setting has one of a fixed list
# of names, and this is one of them. It was called "key" before, which is not;
# a value stored under the former name is still read, until it is entered
# again.
TRANSPORT_KEY_SETTING = "api_key"
FORMER_TRANSPORT_KEY_SETTING = "key"


@dataclass(frozen=True)
class ServerSelfDescription:
    """
    What a server said about itself, as opposed to the data it serves.

    Read once and kept between fetches. Frozen, and replaced whole, so that a
    concurrent fetch sees all of one description or all of another.

    Attributes:
        sequence_number: Identifies the config the schemas came from; a
            retrieve response carrying a different number means it changed.
        source_schemas: {source name: JSON Schema of that source's data}.
        server_info: The server's /server info, passed to templates unchanged.
        protocol_version: The version chosen from the range in server_info.
    """

    sequence_number: int
    source_schemas: dict[str, Any]
    server_info: dict[str, Any]
    protocol_version: int


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


def stored_transport_key(config: dict[str, Any]) -> Any:
    """
    The transport key as the settings hold it, unchecked: under its setting's
    name, or else under the name it had before.
    """
    return config.get(TRANSPORT_KEY_SETTING) or config.get(FORMER_TRANSPORT_KEY_SETTING)


def decode_transport_key(encoded_key: Any) -> bytes | None:
    """
    Decode a transport key from the base64 text a user enters.

    Returns:
        The key, or None if the text is not the base64 of exactly
        TRANSPORT_KEY_LENGTH_BYTES bytes.
    """
    if not isinstance(encoded_key, str):
        return None
    try:
        transport_key = base64.b64decode(encoded_key.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return transport_key if len(transport_key) == TRANSPORT_KEY_LENGTH_BYTES else None


def encrypt_request(
    transport_key: bytes, current_time: float, endpoint_path: str, protocol_version: int | None = None
) -> tuple[bytes, str]:
    """
    Build the encrypted body of one request.

    Args:
        current_time: Seconds since the epoch. A server refuses a request whose
            time is more than a minute from its own.
        protocol_version: Named in the request unless None; a /server request
            names none.

    Returns:
        The body, and the random ID in it that the response must echo.
    """
    request_id = secrets.token_hex(16)
    request = {"ts": int(current_time), "id": request_id}
    if protocol_version is not None:
        request["protocol"] = protocol_version
    plaintext = json.dumps(request).encode()
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    ciphertext = ChaCha20Poly1305(transport_key).encrypt(nonce, plaintext, request_associated_data(endpoint_path))
    return nonce + ciphertext, request_id


def decrypt_response(
    transport_key: bytes, body: bytes, request_id: str, endpoint_path: str
) -> tuple[int, dict[str, Any]]:
    """
    Decrypt a response body and check that it answers one particular request.

    Returns:
        The config sequence number and the data in the response.

    Raises:
        ValueError: The body was not encrypted with this key for this endpoint,
            is not JSON, does not echo request_id, or lacks an integer "seq" or
            an object "data". The message says which.
    """
    try:
        nonce, ciphertext = body[:NONCE_LENGTH_BYTES], body[NONCE_LENGTH_BYTES:]
        plaintext = ChaCha20Poly1305(transport_key).decrypt(nonce, ciphertext, response_associated_data(endpoint_path))
    except (InvalidTag, ValueError):
        raise ValueError("wrong key or corrupt response") from None
    try:
        message = json.loads(plaintext)
    except ValueError:
        raise ValueError("not JSON in response") from None
    if not isinstance(message, dict) or message.get("id") != request_id:
        raise ValueError("wrong ID in response")
    sequence_number = message.get("seq")
    if not isinstance(sequence_number, int) or isinstance(sequence_number, bool):
        raise ValueError("no seq in response")
    if not isinstance(message.get("data"), dict):
        raise ValueError("no data in response")
    return sequence_number, message["data"]


def reject_reserved_source_names(values_by_source: dict[str, Any]) -> None:
    """
    Refuse a /config or /retrieve answer that names a source by one of the
    plugin's own names.

    Raises:
        ValueError: A source has one of RESERVED_SOURCE_NAMES.
    """
    taken = [name for name in RESERVED_SOURCE_NAMES if name in values_by_source]
    if taken:
        raise ValueError(f"source named {taken[0]}: reserved name")


def choose_protocol_version(server_info: dict[str, Any]) -> int:
    """
    Choose the highest protocol version both sides speak.

    A server's info gives the versions it speaks as "protocol": {"min", "max"},
    an inclusive range.

    Raises:
        ValueError: The info has no usable range, or the range holds none of
            SUPPORTED_PROTOCOL_VERSIONS.
    """
    offered = server_info.get("protocol")
    if not isinstance(offered, dict):
        raise ValueError("no protocol range in server info")
    lowest, highest = offered.get("min"), offered.get("max")
    if not all(isinstance(bound, int) and not isinstance(bound, bool) for bound in (lowest, highest)):
        raise ValueError("no protocol range in server info")
    in_common = [version for version in SUPPORTED_PROTOCOL_VERSIONS if lowest <= version <= highest]
    if not in_common:
        raise ValueError("no common protocol")
    return max(in_common)


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
# A name with dots puts the value inside an object, which rows build up field
# by field. If the object is one of the server's values, the rows add to it:
#
#   reminders.count   retriever.reminders.data.count
#   reminders.next    retriever.reminders.data.items[0].title
#
# leaves reminders.error and reminders.data as the server sent them.
#
# Every definition reads the server's values, never another row's result, so
# rows cannot depend on each other and their order does not matter. A row may
# take the name of one of the server's values outright, and then it is the
# row that templates see.

# How deep a name, a path or a formula may go: this many "." and "[ ]" steps
# from the root of a name or path to its leaf, and this many brackets inside
# one another in a formula. The formula engine fails beyond a depth of its
# own, far past anything a board can show.
MAX_NESTING_DEPTH = 32

_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_VARIABLE_NAME_PATTERN = re.compile(rf"^({_IDENTIFIER})((?:\[{_IDENTIFIER}\]|\.{_IDENTIFIER})*)$")
_NAME_STEP_PATTERN = re.compile(rf"\[({_IDENTIFIER})\]|\.({_IDENTIFIER})")
_BRACKETED_PARAMETER_PATTERN = re.compile(rf"\[({_IDENTIFIER})\]")
_BRACKETED_NUMBER_PATTERN = re.compile(r"\[(\d+)\]")
_PATH_ONLY_PATTERN = re.compile(r"^[A-Za-z_]\w*(?:\.\w+)*$")
_PATH_WITH_STEPS_PATTERN = re.compile(r"[A-Za-z_]\w*((?:\.\w+|\[\w+\])+)")
_PATH_STEP_PATTERN = re.compile(r"\.\w+|\[\w+\]")
_FORMULA_ERROR_CODE_PATTERN = re.compile(r"^#(?:REF|VALUE|SYNTAX|NUM|NAME\?|DIV/0)(?::\d+)?$")

# What look_up_dotted_path returns for a path that leads nowhere; None is a
# value a path can lead to.
_MISSING = object()

# The two kinds of step into a variable's structure.
FIELD_STEP = "field"  # .what: a field of an object
ELEMENT_STEP = "element"  # [x]: each element of a list, x being its parameter


class NameStep(NamedTuple):
    """
    One step from a variable into its structure, as a row's name writes it.

    Attributes:
        kind: FIELD_STEP or ELEMENT_STEP.
        name: The field's name, or the parameter that numbers the elements.
    """

    kind: str
    name: str


@dataclass(frozen=True)
class ValueRow:
    """
    One row of the Values setting that is fit to be worked out.

    Attributes:
        written_name: The name as the user wrote it, such as "todo[x].what".
        variable: The variable the name begins with: "todo".
        name_steps: The steps from the variable to where the value goes.
        definition: The path or formula that gives the value.
        default_value: What to use when the definition gives no value; ""
            for none.
    """

    written_name: str
    variable: str
    name_steps: list[NameStep]
    definition: str
    default_value: str

    @property
    def parameters(self) -> list[str]:
        """The parameters in the name, outermost first."""
        return [step.name for step in self.name_steps if step.kind == ELEMENT_STEP]

    @property
    def adds_a_field(self) -> bool:
        """Whether the row puts a field into an object, which may be one of the server's."""
        return bool(self.name_steps) and self.name_steps[0].kind == FIELD_STEP


def parse_variable_name(written_name: Any) -> tuple[str, list[NameStep]] | None:
    """
    Split a row's name into its variable and the steps to where the value goes.

    ``due`` has no steps. ``reminders.count`` has one, the field ``count``.
    ``todo[x].what`` has two: each element, then its ``what``.

    Returns:
        None if the name is not a name, uses one parameter twice, or uses the
        plugin's own name (a definition put in the name's box).
    """
    match = _VARIABLE_NAME_PATTERN.match(written_name.strip()) if isinstance(written_name, str) else None
    if not match:
        return None
    variable, written_steps = match.group(1), match.group(2)
    name_steps = [
        NameStep(ELEMENT_STEP, step.group(1)) if step.group(1) else NameStep(FIELD_STEP, step.group(2))
        for step in _NAME_STEP_PATTERN.finditer(written_steps)
    ]
    parameters = [step.name for step in name_steps if step.kind == ELEMENT_STEP]
    if len(set(parameters)) != len(parameters) or TEMPLATE_NAMESPACE in parameters or variable == TEMPLATE_NAMESPACE:
        return None
    return variable, name_steps


def parse_value_row(row: Any) -> ValueRow | None:
    """
    Read one stored row of the Values setting: {"variable", "definition",
    "default"}.

    Returns:
        None if the name does not parse or the definition is not text. A
        default that is not text counts as none.
    """
    if not isinstance(row, dict) or not isinstance(row.get("definition"), str):
        return None
    parsed_name = parse_variable_name(row.get("variable"))
    if parsed_name is None:
        return None
    variable, name_steps = parsed_name
    default_value = row.get("default") if isinstance(row.get("default"), str) else ""
    return ValueRow(row["variable"].strip(), variable, name_steps, row["definition"], default_value)


def usable_value_rows(value_rows: Any) -> list[ValueRow]:
    """The rows of the Values setting that can be worked out, in the order written; the rest are left out."""
    parsed_rows = [parse_value_row(row) for row in value_rows] if isinstance(value_rows, list) else []
    return [row for row in parsed_rows if row is not None]


def nesting_depth(definition: str) -> int:
    """
    How deep a definition goes: the most "." and "[ ]" steps in any one path,
    or the most round brackets open at once outside quoted text, whichever is
    more.
    """
    paths = _PATH_WITH_STEPS_PATTERN.finditer(definition)
    deepest = max((len(_PATH_STEP_PATTERN.findall(path.group(1))) for path in paths), default=0)
    open_brackets, open_quote = 0, ""
    for character in definition:
        if open_quote:
            open_quote = "" if character == open_quote else open_quote
        elif character in "\"'":
            open_quote = character
        elif character == "(":
            open_brackets += 1
            deepest = max(deepest, open_brackets)
        elif character == ")":
            open_brackets -= 1
    return deepest


def look_up_dotted_path(dotted_path: str, formula_context: dict[str, Any]) -> Any:
    """
    Follow a dotted path such as "retriever.reminders.data.items.0.title"
    through nested objects and lists.

    Returns:
        The value there, which may be None, or _MISSING if the path leads
        nowhere.
    """
    current: Any = formula_context
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        # isdecimal, not isdigit: a superscript two is a digit that int() refuses.
        elif isinstance(current, list) and part.isdecimal() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def evaluate_definition(
    definition: str,
    formula_context: dict[str, Any],
    default_value: str = "",
    parameter_positions: dict[str, int] | None = None,
) -> Any:
    """
    Work out the value a row's definition gives.

    A definition that is only a path gives the value there unchanged, whatever
    its type. Anything else is a formula. Where FiestaBoard's engine can return
    a formula's result with its type (evaluate_value) a number stays a number;
    an older engine only renders text, so there a number comes back as text and
    an error is known only by what it looks like.

    Args:
        formula_context: What the definition reads: {TEMPLATE_NAMESPACE: the
            server's values}.
        default_value: Used when the definition gives no value; "" for none.
        parameter_positions: The position of each list parameter in scope; in a
            formula each is a number by its name. Every "[x]" for one must
            already be replaced by its position.

    Returns:
        The value. When there is none (the path leads nowhere or to a null, the
        formula fails, or the definition is deeper than MAX_NESTING_DEPTH):
        default_value if set, otherwise the formula engine's error code such as
        "#REF", or the null itself. Never raises.
    """
    definition = _BRACKETED_NUMBER_PATTERN.sub(r".\1", definition.strip())
    if nesting_depth(definition) > MAX_NESTING_DEPTH:
        return default_value or "#SYNTAX"

    is_only_a_path = _PATH_ONLY_PATTERN.match(definition) and definition not in (parameter_positions or {})
    if is_only_a_path:
        value_at_path = look_up_dotted_path(definition, formula_context)
        if value_at_path is _MISSING:
            return default_value or "#REF"
        return default_value if value_at_path is None and default_value else value_at_path

    formula = definition
    if parameter_positions:
        bindings = "".join(f"{parameter}, {position}, " for parameter, position in parameter_positions.items())
        formula = f"LET({bindings}{definition})"
    if evaluate_value is None:
        return _evaluate_as_text(formula, formula_context, default_value)
    return _evaluate_with_type(formula, formula_context, default_value)


def _evaluate_with_type(formula: str, formula_context: dict[str, Any], default_value: str) -> Any:
    """
    Evaluate a formula with an engine that returns its result's type.

    A whole float becomes an int, since the engine counts in floats, and a date
    becomes the engine's text for it, since a template variable cannot hold
    one. A failure or a null gives default_value if set, else the engine's
    error code. Never raises.
    """
    try:
        result = evaluate_value(formula, formula_context)
    except Exception:
        result = ErrorValue("#VALUE")
    if isinstance(result, ErrorValue):
        return default_value or result.code
    if result is None and default_value:
        return default_value
    if isinstance(result, float) and result.is_integer():
        return int(result)
    if isinstance(result, date):
        return evaluate(formula, formula_context)
    return result


def _evaluate_as_text(formula: str, formula_context: dict[str, Any], default_value: str) -> str:
    """
    Evaluate a formula with an engine that only renders text.

    default_value, if set, replaces anything that reads as an error code, which
    here includes data that merely looks like one. Never raises.
    """
    try:
        result = evaluate(formula, formula_context)
    except Exception:
        # The engine is documented never to raise, and did: on a number that
        # is not one (NaN), on an infinity, on a formula too deep for it.
        result = "#NUM" if _not_a_number(formula, formula_context) else "#VALUE"
    return default_value if default_value and _FORMULA_ERROR_CODE_PATTERN.match(result) else result


def _not_a_number(formula: str, formula_context: dict[str, Any]) -> bool:
    """Whether any path in a formula leads to a NaN or an infinity."""
    for path in _PATH_WITH_STEPS_PATTERN.finditer(formula):
        value_at_path = look_up_dotted_path(path.group(0), formula_context)
        if isinstance(value_at_path, float) and not math.isfinite(value_at_path):
            return True
    return False


def list_length(definition: str, parameter: str, formula_context: dict[str, Any]) -> int | None:
    """
    How many elements a list parameter stands for in a definition.

    Returns:
        The length of the shortest list the definition indexes with
        [parameter], counting anything that is not a list as empty. None if it
        indexes nothing with it, and so does not say.
    """
    indexed_path_pattern = re.compile(rf"([A-Za-z_]\w*(?:\.\w+|\[\d+\])*)\[{re.escape(parameter)}\]")
    lengths = []
    for indexed_path in indexed_path_pattern.finditer(definition):
        dotted_path = _BRACKETED_NUMBER_PATTERN.sub(r".\1", indexed_path.group(1))
        indexed_value = look_up_dotted_path(dotted_path, formula_context)
        lengths.append(len(indexed_value) if isinstance(indexed_value, list) else 0)
    return min(lengths, default=None)


class _NotAContainerError(Exception):
    """A row would put a field or an element into a value that is neither an object nor a list."""


def _place_value(
    name_steps: list[NameStep],
    row: ValueRow,
    definition: str,
    formula_context: dict[str, Any],
    parameter_positions: dict[str, int],
    current_value: Any,
    location: str,
) -> Any:
    """
    Put a row's value where its name says, inside what is already there.

    A row adds a field to an object and an element to a list, and may give a
    new value to a leaf. It never turns a text, a number or a list into an
    object, nor anything into a list.

    Args:
        name_steps: The steps still to take from here to where the value goes.
        definition: The row's definition, with "[x]" replaced by a position for
            every parameter in parameter_positions.
        current_value: What is here now, from the server or an earlier row;
            None for nothing. An object or a list is changed in place.
        location: Where "here" is, for an error message: "todo[0].what".

    Returns:
        What to have here: current_value with the row's value added, or the
        row's value itself when no steps remain.

    Raises:
        _NotAContainerError: A step needs an object or a list and current_value
            is something else. Its message is the location. Whatever the row
            had already added elsewhere stays.
    """
    if not name_steps:
        return evaluate_definition(definition, formula_context, row.default_value, parameter_positions)
    step, later_steps = name_steps[0], name_steps[1:]

    if step.kind == FIELD_STEP:
        if current_value is not None and not isinstance(current_value, dict):
            raise _NotAContainerError(location)
        fields = current_value if current_value is not None else {}
        fields[step.name] = _place_value(
            later_steps,
            row,
            definition,
            formula_context,
            parameter_positions,
            fields.get(step.name),
            f"{location}.{step.name}",
        )
        return fields

    if current_value is not None and not isinstance(current_value, list):
        raise _NotAContainerError(location)
    elements = current_value if current_value is not None else []
    # A definition that indexes nothing with this parameter adds to the
    # elements other rows gave; build_user_variables runs those rows first.
    length = list_length(definition, step.name, formula_context)
    for position in range(len(elements) if length is None else length):
        if position == len(elements):
            elements.append(None)
        elements[position] = _place_value(
            later_steps,
            row,
            definition.replace(f"[{step.name}]", f".{position}"),
            formula_context,
            {**parameter_positions, step.name: position},
            elements[position],
            f"{location}[{position}]",
        )
    return elements


# Warnings already written to the log, so that a row that fails on every
# fetch is reported once and not every few minutes.
_logged_warnings: set[str] = set()
_MAX_LOGGED_WARNINGS = 1000


def _report(message: str) -> None:
    """Write a warning to FiestaBoard's log, unless the same one has been written already."""
    if message not in _logged_warnings and len(_logged_warnings) < _MAX_LOGGED_WARNINGS:
        _logged_warnings.add(message)
        logger.warning(message)


def sets_every_list_length(row: ValueRow) -> bool:
    """
    Whether a row's definition indexes a list with every parameter in its name,
    and so says how long each of its lists is.
    """
    return all(f"[{parameter}]" in row.definition for parameter in row.parameters)


def build_user_variables(value_rows: Any, formula_context: dict[str, Any]) -> dict[str, Any]:
    """
    Work out the variables the user's rows define.

    A row that names a field of one of the server's own objects adds to a copy
    of that object; any other row's variable is the row's alone.

    Args:
        value_rows: The Values setting as stored. Rows that cannot be read, or
            whose names go deeper than MAX_NESTING_DEPTH, are skipped.
        formula_context: {TEMPLATE_NAMESPACE: the server's values}. Not
            changed.

    Returns:
        The value of each variable. A row that would make an object or a list
        of a value that is neither is skipped with one warning in the log,
        leaving that value as it was. A row that fails any other way gives its
        default, or "#VALUE", unless the variable already has a value. Never
        raises on account of a row.
    """
    server_values = formula_context.get(TEMPLATE_NAMESPACE)
    server_values = server_values if isinstance(server_values, dict) else {}

    # Rows that say how long their lists are go first, so that the order the
    # user wrote the rows in never matters.
    rows_in_working_order = sorted(usable_value_rows(value_rows), key=lambda row: not sets_every_list_length(row))

    user_variables: dict[str, Any] = {}
    for row in rows_in_working_order:
        if len(row.name_steps) > MAX_NESTING_DEPTH:
            continue
        variable = row.variable
        try:
            current_value = _value_to_add_to(row, user_variables, server_values)
            user_variables[variable] = _place_value(
                row.name_steps, row, row.definition, formula_context, {}, current_value, variable
            )
        except _NotAContainerError as not_a_container:
            # Saving the settings checks for this against what the server
            # says it sends; it gets here only if the server sends otherwise.
            _report(
                f"Value {row.written_name!r} skipped: {not_a_container} is not an object or a list that a row can add to"
            )
        except Exception as error:
            logger.warning(f"Value {variable!r} could not be worked out: {type(error).__name__}: {error}")
            if variable not in user_variables and variable not in server_values:
                user_variables[variable] = row.default_value or "#VALUE"
    return user_variables


def _value_to_add_to(row: ValueRow, user_variables: dict[str, Any], server_values: dict[str, Any]) -> Any:
    """
    What a row's variable holds before the row is worked out, for the row to
    add to.

    That is what an earlier row gave it. Failing that, for a row that adds a
    field, it is a copy of the server's value of that name, since the server's
    values are never changed. Otherwise it is None, and the row starts afresh.
    """
    if not row.name_steps:
        return None
    from_earlier_rows = user_variables.get(row.variable)
    if from_earlier_rows is None and row.adds_a_field and server_values.get(row.variable) is not None:
        return copy.deepcopy(server_values[row.variable])
    return from_earlier_rows


# --- Checking the rows when the settings are saved ----------------------------

# What each kind of thing a part of a name can be is called in a message.
_SINGLE_VALUE = ""
_NAME_PART_DESCRIPTIONS = {_SINGLE_VALUE: "a single value", FIELD_STEP: "an object", ELEMENT_STEP: "a list"}


def value_row_errors(value_rows: Any) -> list[str]:
    """
    Find what is wrong with the Values setting, for the settings form.

    Checks only what the rows themselves show; shape_errors checks them against
    the server.

    Returns:
        One message per problem, in row order. Never raises.
    """
    if value_rows in (None, ""):
        return []
    if not isinstance(value_rows, list):
        return ["Values must be a list"]

    parameters_with_a_length = _parameters_with_a_length(value_rows)
    kind_of_each_name_part: dict[str, str] = {}
    complete_names: set[str] = set()
    errors = []
    for row_number, stored_row in enumerate(value_rows, start=1):
        if not isinstance(stored_row, dict):
            errors.append(f"Value {row_number} is not a row")
            continue
        parsed_name = parse_variable_name(stored_row.get("variable"))
        if parsed_name is None:
            errors.append(_unusable_name_error(row_number, stored_row.get("variable")))
            continue
        variable, name_steps = parsed_name
        if len(name_steps) > MAX_NESTING_DEPTH:
            errors.append(f"Value {row_number}: the name goes more than {MAX_NESTING_DEPTH} steps deep")
            continue
        label = f"Value {stored_row['variable'].strip()!r}"
        errors.extend(
            _disagreements_with_earlier_rows(label, variable, name_steps, kind_of_each_name_part, complete_names)
        )
        parameters = [step.name for step in name_steps if step.kind == ELEMENT_STEP]
        errors.extend(
            _definition_errors(label, variable, parameters, stored_row.get("definition"), parameters_with_a_length)
        )
    return errors


def _parameters_with_a_length(value_rows: list[Any]) -> set[tuple[str, str]]:
    """
    The (variable, parameter) pairs that some row uses in brackets in its
    definition, which is what gives a list its length.
    """
    parameters_with_a_length = set()
    for row in usable_value_rows(value_rows):
        bracketed = _BRACKETED_PARAMETER_PATTERN.findall(row.definition)
        parameters_with_a_length.update((row.variable, parameter) for parameter in bracketed)
    return parameters_with_a_length


def _unusable_name_error(row_number: int, written_name: Any) -> str:
    """The settings form's message for a row whose name is missing or is not a name."""
    if not isinstance(written_name, str) or not written_name.strip():
        return f"Value {row_number} has no name: give it one, such as due or todo[x].what"
    return (
        f"Value {row_number}: {written_name.strip()!r} is not a name. A name looks like due, reminders.count, "
        "todo[x] or todo[x].what, with each parameter used once; the expression goes in the definition"
    )


def _disagreements_with_earlier_rows(
    label: str,
    variable: str,
    name_steps: list[NameStep],
    kind_of_each_name_part: dict[str, str],
    complete_names: set[str],
) -> list[str]:
    """
    Check that a row's name agrees with the names of the rows before it.

    Every part of a name must be the same kind of thing in every row: "o.a"
    cannot be a single value in one row and an object, "o.a.b", in another. Nor
    may two rows define the same name.

    Args:
        label: How messages refer to this row.
        kind_of_each_name_part: What earlier rows made of each part of a name,
            keyed by the part with parameters left out ("q[].f"). This row's
            parts are added to it.
        complete_names: The names earlier rows defined, keyed the same way.
            This row's name is added to it.

    Returns:
        At most one message.
    """
    part, part_as_written = variable, variable
    for step in [*name_steps, NameStep(_SINGLE_VALUE, "")]:
        kind_already_given = kind_of_each_name_part.setdefault(part, step.kind)
        if kind_already_given != step.kind:
            was, now_is = _NAME_PART_DESCRIPTIONS[kind_already_given], _NAME_PART_DESCRIPTIONS[step.kind]
            return [f"{label}: {part_as_written} is defined both as {was} and as {now_is}"]
        if step.kind == _SINGLE_VALUE:
            break
        if step.kind == ELEMENT_STEP:
            part, part_as_written = f"{part}[]", f"{part_as_written}[{step.name}]"
        else:
            part, part_as_written = f"{part}.{step.name}", f"{part_as_written}.{step.name}"

    if part in complete_names:
        return [f"{label}: {part_as_written} is defined twice"]
    complete_names.add(part)
    return []


def _definition_errors(
    label: str, variable: str, parameters: list[str], definition: Any, parameters_with_a_length: set[tuple[str, str]]
) -> list[str]:
    """
    Check one row's definition: that there is one, that some row gives every
    list in the name a length, that it uses no parameter the name lacks, and
    that it is no deeper than MAX_NESTING_DEPTH and parses.

    Args:
        label: How messages refer to this row.
        parameters_with_a_length: From _parameters_with_a_length.
    """
    if not isinstance(definition, str) or not definition.strip():
        return [f"{label} has no definition"]

    errors = []
    for parameter in parameters:
        if (variable, parameter) not in parameters_with_a_length:
            errors.append(
                f"{label}: some row for {variable} must index a list with [{parameter}], to say how long it is"
            )
    parameters_in_definition = set(_BRACKETED_PARAMETER_PATTERN.findall(definition))
    for parameter in sorted(parameters_in_definition - set(parameters)):
        errors.append(f"{label}: [{parameter}] in the definition needs [{parameter}] in the name")

    if nesting_depth(definition) > MAX_NESTING_DEPTH:
        errors.append(f"{label}: the definition goes more than {MAX_NESTING_DEPTH} steps or brackets deep")
    else:
        errors.extend(_formula_errors(label, parameters, definition))
    return errors


def _formula_errors(label: str, parameters: list[str], definition: str) -> list[str]:
    """
    Ask the formula engine what is wrong with a definition, with every
    parameter at position 0.

    A definition that is only a path is not a formula, and has nothing to
    check. Never raises.
    """
    at_first_position = _BRACKETED_PARAMETER_PATTERN.sub(".0", definition).strip()
    formula = _BRACKETED_NUMBER_PATTERN.sub(r".\1", at_first_position)
    if _PATH_ONLY_PATTERN.match(formula):
        return []
    bindings = "".join(f"{parameter}, 0, " for parameter in parameters)
    if bindings:
        formula = f"LET({bindings}{formula})"
    try:
        return [f"{label}: {issue.message}" for issue in validate_expression(formula)]
    except Exception as error:
        return [f"{label}: the definition could not be checked ({type(error).__name__})"]


# What a message calls each JSON Schema type.
_JSON_TYPE_DESCRIPTIONS = {
    "string": "text",
    "integer": "a number",
    "number": "a number",
    "boolean": "true or false",
    "array": "a list",
    "object": "an object",
}


def json_type_of(schema: Any) -> str:
    """
    The JSON type a schema says a value has, or "" if it does not say: it has
    no "type", or allows several besides null.
    """
    declared_type = schema.get("type") if isinstance(schema, dict) else None
    if isinstance(declared_type, list):
        types_besides_null = [each for each in declared_type if each != "null"]
        declared_type = types_besides_null[0] if len(types_besides_null) == 1 else None
    is_known = isinstance(declared_type, str) and declared_type in _JSON_TYPE_DESCRIPTIONS
    return declared_type if is_known else ""


def shape_of(value: Any) -> dict[str, Any]:
    """
    Describe the shape of a value in hand as a JSON Schema, taking a list's
    first element to stand for them all. {} for a null, whose type says
    nothing.
    """
    if isinstance(value, dict):
        return {"type": "object", "properties": {name: shape_of(field) for name, field in value.items()}}
    if isinstance(value, list):
        return {"type": "array", "items": shape_of(value[0])} if value else {"type": "array"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int | float):
        return {"type": "number"}
    return {"type": "string"} if isinstance(value, str) else {}


def rows_adding_to_objects(value_rows: Any) -> list[str]:
    """
    The written names of the rows that put a field into an object.

    The object may be one of the server's, and only the server can say whether
    such a row fits.
    """
    return [row.written_name for row in usable_value_rows(value_rows) if row.adds_a_field]


def shape_errors(value_rows: Any, shapes: dict[str, Any]) -> list[str]:
    """
    Find the rows that do not fit the shape of what the server sends.

    A row may add a field to an object or give a leaf a new value. It may not
    put a field or an element into something the server sends as neither an
    object nor a list. A source that only ever adds to what it sends keeps
    passing a check it has passed.

    Args:
        shapes: The JSON Schema of each of the plugin's own values, by name,
            the server's sources among them. Where a schema does not say what a
            value is, nothing is wrong.
    """
    errors = []
    for row in usable_value_rows(value_rows):
        if row.adds_a_field and row.variable in shapes:
            error = _shape_error(row, shapes[row.variable])
            if error:
                errors.append(error)
    return errors


def _shape_error(row: ValueRow, schema: Any) -> str | None:
    """
    The message for the first part of a row's name that needs an object or a
    list where the schema says the server sends something else; None if the row
    fits.
    """
    location = row.variable
    for step in row.name_steps:
        type_sent = json_type_of(schema)
        if not type_sent:
            return None
        type_needed = "object" if step.kind == FIELD_STEP else "array"
        if type_sent != type_needed:
            cannot_have = f"the field {step.name}" if step.kind == FIELD_STEP else "elements"
            sent_as = _JSON_TYPE_DESCRIPTIONS[type_sent]
            return (
                f"Value {row.written_name!r}: the server sends {location} as {sent_as}, which cannot have {cannot_have}"
            )
        if step.kind == FIELD_STEP:
            properties = schema.get("properties")
            schema = properties.get(step.name) if isinstance(properties, dict) else None
            location = f"{location}.{step.name}"
        else:
            schema = schema.get("items")
            location = f"{location}[{step.name}]"
    return None


def failure_reason(error: Exception) -> str:
    """
    Put a failed request into a few words for a board, with what distinguishes
    it first, because a board truncates: "timed out", "400 Stale Timestamp",
    "no response (wrong key?)".
    """
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


def default_value_for_schema(schema: Any) -> Any:
    """
    What to show for a value when nothing is known of it: the schema's
    "default", or else an empty value of its type. None if the schema names no
    single known type.
    """
    if not isinstance(schema, dict):
        return None
    if "default" in schema:
        return schema["default"]
    declared_type = schema.get("type")
    if declared_type == "object":
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return {}
        return {name: default_value_for_schema(property_schema) for name, property_schema in properties.items()}
    if declared_type == "array":
        return []
    if declared_type == "string":
        return ""
    if declared_type in ("integer", "number"):
        return 0
    if declared_type == "boolean":
        return False
    return None


class RetrieverPlugin(PluginBase):
    """Retriever plugin implementation."""

    def __init__(self, manifest: dict[str, Any]):
        """Create the plugin from the parsed manifest.json."""
        super().__init__(manifest)
        # Nothing about a server is built in. None until read, and again
        # after the settings change.
        self._server_self_description: ServerSelfDescription | None = None

    @property
    def plugin_id(self) -> str:
        """Return the plugin ID matching manifest.json."""
        return "retriever"

    def on_config_change(self, old_config: dict[str, Any], new_config: dict[str, Any]) -> None:
        """Settings were saved: forget what the server said about itself, so the next fetch reads it again."""
        self._server_self_description = None

    def fetch_data(self) -> PluginResult:
        """
        Assign the template variables from one fetch.

        _send_encrypted_request tells the truth about each request; what the
        variables become when one fails is decided here.

        Returns:
            PluginResult with:
            - available: False only if the plugin is not configured
            - data: the server's values unchanged, plus ``server`` and
              ``error``: {<source>: {"error": ..., "data": ...}, ...,
              "server": <the server's /server info>, "error": ""}, and over
              those the variables the user's rows define.
              After a failed retrieve, every source the server's config lists
              has its schema's default as data, and ``error`` is the reason.
              Before the server's info and config have been read nothing
              about it is known, so there is only ``error``, ending in
              "config pending".
            - error: The same reason, for FiestaBoard itself

            Never raises, and returns within FETCH_TIME_LIMIT_SECONDS unless
            a server sends its answer a little at a time.
        """
        setting_errors = self._connection_setting_errors(self.config)
        if setting_errors:
            return PluginResult(available=False, error="; ".join(setting_errors))

        server_url = self.config["server_url"].strip().rstrip("/")
        transport_key = decode_transport_key(stored_transport_key(self.config))
        deadline = time.monotonic() + FETCH_TIME_LIMIT_SECONDS

        if self._server_self_description is None:
            try:
                self._server_self_description = self._read_server_self_description(server_url, transport_key, deadline)
            except Exception as error:
                return self._failed_fetch_result(server_url, f"{failure_reason(error)}; {CONFIG_PENDING_SUFFIX}", {})

        known = self._server_self_description
        try:
            sequence_number, server_values = self._send_encrypted_request(
                server_url, RETRIEVE_PATH, transport_key, deadline, known.protocol_version
            )
            reject_reserved_source_names(server_values)
        except Exception as error:
            defaults = {
                source: {"error": "", "data": default_value_for_schema(schema)}
                for source, schema in known.source_schemas.items()
            }
            return self._failed_fetch_result(
                server_url, failure_reason(error), {**defaults, "server": known.server_info}
            )

        server_info = known.server_info
        if sequence_number != known.sequence_number:
            # The server's config changed, in either direction. The values
            # just retrieved are good; the server is read again, now or on
            # the next fetch.
            try:
                self._server_self_description = self._read_server_self_description(server_url, transport_key, deadline)
                server_info = self._server_self_description.server_info
            except Exception as error:
                reason = f"{failure_reason(error)}; {CONFIG_PENDING_SUFFIX}"
                return self._failed_fetch_result(server_url, reason, {**server_values, "server": server_info})

        template_variables = self._template_variables({**server_values, "server": server_info, "error": ""})
        return PluginResult(available=True, data=template_variables)

    def _read_server_self_description(
        self, server_url: str, transport_key: bytes, deadline: float
    ) -> ServerSelfDescription:
        """
        Ask a server about itself: its info, then its config in the protocol
        version chosen from that.

        Args:
            deadline: The time.monotonic() value by which both requests must
                have been answered.

        Raises:
            Exception: A request failed, no protocol version is shared, or the
                config names a source by a reserved name. failure_reason puts
                it into words.
        """
        _, server_info = self._send_encrypted_request(server_url, SERVER_INFO_PATH, transport_key, deadline)
        protocol_version = choose_protocol_version(server_info)
        sequence_number, source_schemas = self._send_encrypted_request(
            server_url, CONFIG_PATH, transport_key, deadline, protocol_version
        )
        reject_reserved_source_names(source_schemas)
        return ServerSelfDescription(sequence_number, source_schemas, server_info, protocol_version)

    def _failed_fetch_result(self, server_url: str, reason: str, known_values: dict[str, Any]) -> PluginResult:
        """
        Build the result of a fetch in which a request failed.

        The result is still available, so that templates render. It holds
        known_values (defaults, values already retrieved, the server's info;
        possibly nothing), the user's variables worked out from those, and the
        reason as ``error``.
        """
        logger.warning(f"Fetch from {server_url} failed: {reason}")
        template_variables = self._template_variables({**known_values, "error": reason})
        return PluginResult(available=True, data=template_variables, error=reason)

    def _template_variables(self, server_values: dict[str, Any]) -> dict[str, Any]:
        """
        The server's values, and over them the variables the user's rows define
        from them; a user's variable wins a clash of names.

        Never raises: if the rows cannot be worked out, the result is the
        server's values alone.
        """
        try:
            user_variables = build_user_variables(self.config.get("values"), {TEMPLATE_NAMESPACE: server_values})
        except Exception as error:
            # build_user_variables guards each row; this is so that
            # fetch_data cannot raise whatever happens there.
            logger.warning(f"The values could not be worked out: {type(error).__name__}: {error}")
            return server_values
        return {**server_values, **user_variables}

    def get_preview_text(self) -> str:
        """
        Supply the settings form's "Test & Preview" with the server's values.

        Core's own preview fetches a URL, which cannot work here: the server
        only answers encrypted requests. The values are fetched with the
        unsaved settings.

        Returns:
            JSON text whose root is TEMPLATE_NAMESPACE, so that a path clicked
            in the preview is a valid definition.

        Raises:
            PreviewUnavailable: The URL or key is missing or malformed, or the
                server could not be read; the message says which.
        """
        config = self.config
        if self._connection_setting_errors(config):
            raise PreviewUnavailable("Enter the server URL and API key first")
        server_url = config["server_url"].strip().rstrip("/")
        transport_key = decode_transport_key(stored_transport_key(config))
        deadline = time.monotonic() + FETCH_TIME_LIMIT_SECONDS
        try:
            _, server_info = self._send_encrypted_request(server_url, SERVER_INFO_PATH, transport_key, deadline)
            protocol_version = choose_protocol_version(server_info)
            _, server_values = self._send_encrypted_request(
                server_url, RETRIEVE_PATH, transport_key, deadline, protocol_version
            )
            reject_reserved_source_names(server_values)
        except Exception as error:
            raise PreviewUnavailable(failure_reason(error)) from None
        return json.dumps({TEMPLATE_NAMESPACE: {**server_values, "server": server_info, "error": ""}})

    def _send_encrypted_request(
        self,
        server_url: str,
        endpoint_path: str,
        transport_key: bytes,
        deadline: float,
        protocol_version: int | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """
        Make one request to the server. The only place that talks to it.

        Args:
            deadline: The time.monotonic() value by which the server must have
                answered.
            protocol_version: Named in the request unless None.

        Returns:
            The config sequence number and the data in the server's answer.

        Raises:
            TimeoutError: The deadline has passed, or passes with no answer.
            urllib.error.URLError: The server could not be reached, or answered
                with a status other than 2xx (an HTTPError).
            OSError: The connection failed part-way.
            ValueError: The response is not the server's answer to this request
                (see decrypt_response).
        """
        seconds_left = deadline - time.monotonic()
        if seconds_left <= 0:
            raise TimeoutError
        body, request_id = encrypt_request(transport_key, time.time(), endpoint_path, protocol_version)
        # The scheme is restricted to http(s) by validate_config.
        request = urllib.request.Request(  # noqa: S310
            server_url + endpoint_path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=seconds_left) as response:  # noqa: S310
            return decrypt_response(transport_key, response.read(), request_id, endpoint_path)

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """
        Validate plugin configuration, when the settings are saved.

        Asks the server what it sends if any row adds a field to an object,
        since only the server can say whether such a row fits.

        Returns:
            List of error messages (empty if valid)
        """
        errors = self._connection_setting_errors(config)
        value_rows = config.get("values")
        if not errors and rows_adding_to_objects(value_rows):
            errors += self._shape_errors(config, value_rows)
        return errors + value_row_errors(value_rows)

    def _shape_errors(self, config: dict[str, Any], value_rows: Any) -> list[str]:
        """
        Check the rows that add to an object against what the server says it
        sends.

        Only the server knows which names are its own and what shape their
        values have, so this asks it, with the settings being saved. A row that
        cannot be checked cannot be saved.

        Returns:
            A message for each row that does not fit, or a single message
            naming the rows that could not be checked if the server does not
            answer.
        """
        server_url = config["server_url"].strip().rstrip("/")
        transport_key = decode_transport_key(stored_transport_key(config))
        deadline = time.monotonic() + FETCH_TIME_LIMIT_SECONDS
        try:
            server = self._read_server_self_description(server_url, transport_key, deadline)
        except Exception as error:
            unchecked = ", ".join(rows_adding_to_objects(value_rows))
            return [
                f"The server did not answer ({failure_reason(error)}), "
                f"so these values could not be checked against what it sends: {unchecked}"
            ]
        # Every source is sent as {"error": text, "data": what its schema describes}.
        shapes = {
            source: {"type": "object", "properties": {"error": {"type": "string"}, "data": schema}}
            for source, schema in server.source_schemas.items()
        }
        shapes["server"] = shape_of(server.server_info)
        shapes["error"] = {"type": "string"}
        return shape_errors(value_rows, shapes)

    def _connection_setting_errors(self, config: dict[str, Any]) -> list[str]:
        """Check the settings the plugin needs to reach its server, without reaching it. Nothing else stops a fetch."""
        errors = []

        server_url = config.get("server_url")
        if not isinstance(server_url, str) or not server_url.strip():
            errors.append("Server URL is required")
        elif not server_url.strip().lower().startswith(("http://", "https://")):
            errors.append("Server URL must start with http:// or https://")

        if not stored_transport_key(config):
            errors.append("API key is required")
        elif decode_transport_key(stored_transport_key(config)) is None:
            errors.append("API key must be the base64 of 32 bytes")

        return errors
